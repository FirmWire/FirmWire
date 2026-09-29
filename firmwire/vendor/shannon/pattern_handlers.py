## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct
import logging
from firmwire.util.BinaryPattern import BinaryPattern

from .task import get_task_layouts
from .queue import QUEUE_STRUCT_SIZE

from capstone import *
from capstone.arm import *
import re

log = logging.getLogger(__name__)

TASK_NAME_TO_FIND = b"GLAPD"


class ShannonMemEntry(object):
    def __init__(self, src, dst, size, fn):
        self.src = src
        self.dst = dst
        self.size = size
        self.fn = fn

    def __repr__(self):
        return "ShannonMemEntry<src=%08x dst=%08x sz=%08x fn=%08x>" % (
            self.src,
            self.dst,
            self.size,
            self.fn,
        )


def dereference(self, sym, data, offset):
    main_toc = self.modem_file.get_section("MAIN")
    offset = sym.address - main_toc.load_address
    data = main_toc.data
    new_address = struct.unpack("I", data[offset : offset + 4])[0]

    log.info("Dereference [0x%08x] -> 0x%08x", sym.address, new_address)
    self.symbol_table.remove(sym.name)
    self.symbol_table.add(sym.name, new_address)

    return True


def fixup_bios_symbol(self, sym, data, offset):
    bios_start = self.symbol_table.lookup("TCM_COPY_START")
    bios_end = self.symbol_table.lookup("TCM_COPY_END")

    if not bios_end or not bios_start:
        return False

    bios_start = bios_start.address
    bios_end = bios_end.address

    if sym.address >= bios_start and sym.address <= bios_end:
        new_address = sym.address - bios_start + 0x04000000
        log.info(
            "Fixing up TCM region symbol %s (%08x -> %08x)",
            sym.name,
            sym.address,
            new_address,
        )
        self.symbol_table.remove(sym.name)

        self.symbol_table.add(sym.name, new_address)
        return True

    return False


def parse_memory_table(self, sym, data, offset):
    main_toc = self.modem_file.get_section("MAIN")
    address = sym.address - main_toc.load_address
    data = main_toc.data

    entries = []
    # scan forwards
    while True:
        src, dst, size, fn = struct.unpack("IIII", data[address : address + 0x10])
        address += 0x10

        # we dont know the table size, so process entries until they look funny
        if src > 0x50000000 or size >= 0x10000000 or fn > 0x50000000 or fn < 0x40010000:
            break

        entries += [ShannonMemEntry(src, dst, size, fn)]

    address = sym.address - main_toc.load_address

    # scan backwards
    while True:
        src, dst, size, fn = struct.unpack("IIII", data[address : address + 0x10])
        address -= 0x10

        # we dont know the table size, so process entries until they look funny
        if src > 0x50000000 or size >= 0x10000000 or fn > 0x50000000 or fn < 0x40010000:
            break

        entries += [ShannonMemEntry(src, dst, size, fn)]

    # make sure we find (somewhat) safe regions for placing new code that dont get overwritten later!
    for entry in entries:
        self.unsafe_regions += [(entry.dst, entry.dst + entry.size)]

    for entry in entries:
        # TCM region copy
        if entry.dst == 0x04000000:
            self.symbol_table.add("TCM_COPY_START", entry.src)
            self.symbol_table.add("TCM_COPY_END", entry.src + entry.size)
            return True

    return False


#  4162e604 04 10 9f e5     ldr        r1,[PTR_DAT_4162e610]                            = 0480109c
#  4162e608 04 00 81 e5     str        param_1,[r1,#0x4]=>DAT_048010a0                  = ??
#  4162e60c 1e ff 2f e1     bx         lr
#                       PTR_DAT_4162e610
#  4162e610 9c 10 80 04     addr       DAT_0480109c                                     = ??
def find_current_task_ptr(data, offset):
    bp = BinaryPattern("task_set_function", offset=0xC)
    bp.from_hex("04 10 9f e5 04 00 81 e5 1e ff 2f e1")

    locs = bp.findall(data, maxresults=2)

    if len(locs) == 0:
        return None

    for loc in locs:
        # make sure our find is byte aligned
        if loc[0] & 0x3:
            continue

        ptr = struct.unpack("I", data[loc[0] : loc[0] + 4])[0]

        # make sure the pointer is valid
        # MM: we only check upper bound, needed for some modems apparantly
        if ptr >= (offset + len(data)):
            continue

        return ptr + 4

    return None


def find_current_task_ptr_a(data, offset):
    bp = BinaryPattern("get_task_function", offset=0x0)
    bp.from_hex("?? ?? ?? e3 ?? ?? ?? e3 00 01 91 e7 1e ff 2f e1")

    locs = bp.findall(data, maxresults=2)

    for loc in locs:
        # make sure our find is byte aligned
        if loc[0] & 0x3:
            continue

        instr1 = struct.unpack("<I", data[loc[0]: loc[0] + 4])[0]
        if instr1 & 0xfff0f000 != 0xe3001000:  # movw r1, ??
            continue
        right = instr1 & 0x00000fff | (instr1 & 0x000f0000) >> 0x4
        instr2 = struct.unpack("<I", data[loc[0] + 4: loc[0] + 8])[0]
        if instr2 & 0xfff0f000 != 0xe3401000:  # movt r1, ??
            continue
        left = instr2 & 0x00000fff | (instr2 & 0x000f0000) >> 0x4
        ptr = (left << 0x10) | right
        return ptr
    return None


def find_schedulable_task_table(data, offset):
    bp = BinaryPattern("OSTaskGetArg0", offset=0x1C)
    bp.from_hex("420e50e3 0000a003 0200000a 08109fe5 000191e7 ??0090e5")

    locs = bp.findall(data, maxresults=2)
    if len(locs) == 0:
        return None

    for loc in locs:
        # make sure our find is byte aligned
        if loc[0] & 0x3:
            continue
        ptr = struct.unpack("I", data[loc[0] : loc[0] + 4])[0]

        # NB: no sanity checks here
        return ptr

    return None


"""
                       **************************************************************
                       *                          FUNCTION                          *
                       **************************************************************
                       void __stdcall exception_stack_switch(void)
       void              <VOID>         <RETURN>
       OSTaskStruct *    r0:4           task
                       exception_stack_switch
  40c71734 0c 12 9f e5     ldr        r1,[->SCHED_VAR]                           = 418385f4
  40c71738 00 10 91 e5     ldr        r1,[r1,#0x0]=>SCHED_VAR                    = 00000420h
  40c7173c 42 0e 51 e3     cmp        r1,#0x420
  40c71740 1f 00 00 0a     beq        LAB_40c717c4
  ...
  ...
  ...
  40c71948 f4 85 83 41     addr       SCHED_VAR                                  = 00000420h
  40c7194c 68 6e a3 43     addr       OsSchedulableTaskList                      = 00000000
  40c71950 e0 8d e4 43     addr       SAVED_STACK
  40c71954 24 86 83 41     addr       IRQ_VAR
  40c71958 28 86 83 41     addr       SCHED_LR_STORAGE
  40c7195c 2c 86 83 41     addr       TASKID_WHICH_DISABLED_INTR
  40c71960 ef be ad de     undefined4 DEADBEEFh
"""


def find_exception_switch(data, offset):
    bp = BinaryPattern("fn")
    bp.from_hex("????9fe5 001091e5 420e51e3 ??????0a")

    locs = bp.findall(data, maxresults=2)

    for loc in locs:
        # make sure our find is byte aligned
        if loc[0] & 0x3:
            continue

        return loc[0] + offset

    return None

# S5123 is the first string found
# S5123AP:G991BXXSIHYK1 is the second string found
def find_queue_table(data, offset):
    bp = BinaryPattern("queue_name", offset=1)
    bp.from_str(b"\x00AdcTask\x00")

    # Find the null terminated strings like 'task'
    locs = []
    npos = 0

    # Iteratively mark the positions of the matching patterns.
    while True:
        res = bp.find(data, pos=npos)
        if res is None:
            break

        npos = res[1]
        locs += [res]


    if len(locs) == 0:
        return None

    if locs is None:
        return None

    xref_target = locs[0][0] + offset # absolute address in memory

    bp_x = BinaryPattern("xref")
    bp_x.from_str(struct.pack("I", xref_target))
    rez = bp_x.findall(data, maxresults=2)

    if rez is None or len(rez) < 1:
        # Try again but on the other string reference.
        # It appears that S5123AP:G991BXXSIHYK1 uses locs[1][0] instead of locs[0][0]
        xref_target = locs[1][0] + offset
        bp_task_x = BinaryPattern("xref")
        bp_task_x.from_str(struct.pack("I", xref_target))
        rez = bp_task_x.findall(data, maxresults=2)
    if rez is None:
        return None

    ptr = rez[0][0] # first reference for both

    # Walk backwards from AdcTask to find the true start of the queue list.
    # Validate each candidate entry: name pointer targets printable ASCII,
    # and the 3 padding bytes after qtype (offsets 9-11) are zero.
    while ptr >= QUEUE_STRUCT_SIZE:
        candidate = ptr - QUEUE_STRUCT_SIZE
        name_ptr = struct.unpack_from("<I", data, candidate)[0]
        name_off = name_ptr - offset
        pad = data[candidate + 9 : candidate + 12]
        if (
            0 <= name_off < len(data)
            and 0x20 <= data[name_off] < 0x7F
            and pad == b"\x00\x00\x00"
        ):
            ptr = candidate
        else:
            break

    return offset + ptr


def find_boot_mmu_table(data, offset):
    print(f"find_boot_mmu_table: len(data)={len(data)}")
    print(f"find_boot_mmu_table: table={data[0x2b76720]}")
    struct_size = 0x10
    num = 0x1b
    for i in range(num):
        off = 0x2b76720 + i * struct_size
        entry_data = data[off: off + struct_size]
        (addr, start, end, flags) = struct.unpack("<IIII", entry_data)
        dst = (addr >> 0x12) | 0x40008000
        val = addr & 0xfff00000 | flags | 2
        print(f"addr={addr:#010x}, start={start:#010x}, end={end:#010x}, size={end-start:#010x}, flags={flags:#07x}, dst={dst:#010x}, val={val:#010x}")


def validate_t1_bl(insn):
    return ((insn >> 27) & 0x1f == 0x1e) and ((insn >> 14) & 3 == 3) and ((insn >> 12) & 1 == 1)


def decode_thumb_bl_target(insn, insn_addr):
    """
    insn_addr: address of the first halfword (0x7f) of the BL instruction
    returns:   32-bit target address
    """

    # Form halfwords in little-endian
    hw1 = insn & 0xffff  # first halfword
    hw2 = (insn >> 0x10) & 0xffff  # second halfword

    # Extract fields (BL encoding, Thumb-2)
    S = (hw1 >> 10) & 0x1
    imm10 = hw1 & 0x03ff
    J1 = (hw2 >> 13) & 0x1
    J2 = (hw2 >> 11) & 0x1
    imm11 = hw2 & 0x07ff

    # Reconstruct I1, I2
    I1 = (~(J1 ^ S)) & 0x1
    I2 = (~(J2 ^ S)) & 0x1

    # Build 25-bit immediate: S:I1:I2:imm10:imm11:0
    imm25 = (S << 24) | \
            (I1 << 23) | \
            (I2 << 22) | \
            (imm10 << 12) | \
            (imm11 << 1)

    # Sign-extend 25-bit immediate to 32 bits
    if S:
        imm32 = imm25 | (~0 << 25)
    else:
        imm32 = imm25

    # In Thumb state, PC is instruction address + 4 (2-byte alignment)
    pc = (insn_addr + 4) & ~0x1

    # Target address
    target = (pc + imm32) & 0xffffffff
    return target


def find_pal_sleep(data, offset):
    bp = BinaryPattern("pal_Sleep", offset=8)
    bp.from_hex("4af22010 c0f20700 ?+ 44f640?? ?+ c0f24c?? 00?? 0128 ?+ ??46 ?+ ??46")  # G991B, oriole

    locs = bp.findall(data)
    assert len(locs) == 1, f"Found more than one instance or failed to find any ({len(locs)})"

    insn_addr = 0x40010000 + locs[0][0]
    offset = locs[0][0]
    insn = data[offset: offset + 4]
    insn = struct.unpack("<I", insn)[0]
    assert validate_t1_bl(insn), "Invalid instruction ({:#010x})".format(insn)

    return decode_thumb_bl_target(insn, insn_addr)


def decode_movw(insn):
    # Form halfwords in little-endian
    hw1 = insn & 0xffff  # first halfword
    hw2 = (insn >> 0x10) & 0xffff  # second halfword

    imm8 = hw2 & 0xff
    imm3 = (hw2 >> 12) & 7
    imm4 = hw1 & 0xf
    i = (hw1 >> 10) & 1

    imm32 = (imm4 << 12) | \
            (i << 11) | \
            (imm3 << 8) | \
            (imm8)

    return imm32


def decode_movw_arm(insn):
    imm12 = insn & 0x00000fff
    imm4 = (insn >> 16) & 0x000f
    return (imm4 << 12) | imm12


def ror32(value, n):
    n &= 31
    return ((value >> n) | (value << (32 - n))) & 0xffffffff


def thumb_expand_imm(imm12):
    """
    Implements ThumbExpandImm()/ThumbExpandImmWithC for the 12-bit
    immediate i:imm3:imm8 (ARM ARM A5.2). Returns imm32.
    """
    top2 = (imm12 >> 10) & 0b11
    if top2 == 0:
        mode = (imm12 >> 8) & 0b11
        imm8 = imm12 & 0xff

        if mode == 0b00:
            # 0x000000XY
            return imm8
        if imm8 == 0:
            # UNPREDICTABLE; treat as 0 for robustness
            return 0

        if mode == 0b01:
            # 0x00XY00XY
            return (imm8 << 16) | imm8
        elif mode == 0b10:
            # 0xXY00XY00
            return (imm8 << 24) | (imm8 << 8)
        elif mode == 0b11:
            # 0xXYXYXYXY
            return (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8
    else:
        # rotated 1:imm7 pattern
        imm7 = imm12 & 0x7f
        rot = (imm12 >> 7) & 0x1f          # imm12<11:7>
        unrot = ((1 << 7) | imm7) & 0xff   # '1':imm7
        unrot32 = unrot                    # zero-extended
        return ror32(unrot32, rot)


def decode_mov_w(insn):
    hw1 = insn & 0xffff  # first halfword
    hw2 = (insn >> 0x10) & 0xffff  # second halfword

    i = (hw1 >> 10) & 0x1
    imm3 = (hw2 >> 12) & 0x7
    imm8 = hw2 & 0xff

    imm12 = (i << 11) | (imm3 << 8) | imm8
    imm32 = thumb_expand_imm(imm12)
    return imm32


def decode_mov_immediate(insn, insn_len):
    if insn_len == 2:
        assert (insn >> 8) & 0xf8 == 0x20, "not a movs instruction: {:x}".format(insn)
        return insn & 0xff
    assert insn_len == 4, "invalid instruction len {}".format(insn_len)

    hw1 = insn & 0xffff  # first halfword
    # hw2 = (insn >> 0x10) & 0xffff  # second halfword

    if hw1 & 0xf04f == 0xf04f:  # mov.w
        return decode_mov_w(insn)
    elif hw1 & 0xf240 == 0xf240:  # movw
        return decode_movw(insn)
    else:
        raise ValueError("not a MOV (immediate) instruction: {:x}".format(insn))


def find_sym_event_group_list(data, offset):
    bp = BinaryPattern("SYM_EVENT_GROUP_LIST")
    bp.from_hex("30482de9 0040a0e1 00300fe1 80000cf1 78009fe5 0110a0e3 9f2fd0e1 010052e1 02f02003 912fc011 01005211 f9ffff0a 59f07ff5 201094e5 4d00a0e3 000051e3 0000000a 3088bde8 ???????? 0410a0e1 805003e2 ???????? ???????? 380094e5")

    locs = bp.findall(data)
    assert len(locs) == 1, f"Found more than one instance or failed to find any ({len(locs)})"

    offset = locs[0][1] - 0xc
    insn2 = data[offset: offset + 4]
    insn2 = struct.unpack("<I", insn2)[0]
    addr_t = decode_movw_arm(insn2)

    offset -= 0xc
    insn1 = data[offset: offset + 4]
    insn1 = struct.unpack("<I", insn1)[0]
    addr_w = decode_movw_arm(insn1)

    addr = (addr_t << 16) | addr_w
    return addr


def find_rf_hwid(data, offset):
    bp = BinaryPattern("rf_hwid")
    bp.from_hex("2de9f047 c4b0 0df11008 4ff48071 4046 ?+ d9f80010 0029")

    locs = bp.findall(data)
    assert len(locs) == 1, f"Found more than one instance or failed to find any ({len(locs)})"

    offset = locs[0][1] - 14
    insn1 = data[offset: offset + 4]
    insn1 = struct.unpack("<I", insn1)[0]
    addr_w = decode_movw(insn1)

    insn2 = data[offset + 4: offset + 8]
    insn2 = struct.unpack("<I", insn2)[0]
    addr_t = decode_movw(insn2)

    addr = (addr_t << 16) | addr_w
    return addr


def find_board_rf_config(data, offset):
    bp = BinaryPattern("board_rf_config")
    bp.from_hex("2de9f047 c4b0 0df11008 4ff48071 4046 ?+ d9f80010 0029 ?+ ?+ c928")

    locs = bp.findall(data)
    assert len(locs) == 1, f"Found more than one instance or failed to find any ({len(locs)})"

    offset = locs[0][1] - 12
    insn1 = data[offset: offset + 4]
    insn1 = struct.unpack("<I", insn1)[0]
    addr_w = decode_movw(insn1)

    insn2 = data[offset + 4: offset + 8]
    insn2 = struct.unpack("<I", insn2)[0]
    addr_t = decode_movw(insn2)

    addr = (addr_t << 16) | addr_w
    return addr


def find_trng_init(data, offset):
    bp = BinaryPattern("trng_init", offset=10)
    bp.from_hex("f0b5 81b0 0e46 0446 50b3 ???????? ???????? 0078 a0b9 ???????? 0128 10d0 ???????? 33a1 2de90f00 bff35f8f 01df bff35f8f bde80f00 ???????? 8160")

    locs = bp.findall(data)
    assert len(locs) == 1, f"Found more than one instance or failed to find any ({len(locs)})"

    offset = locs[0][0]
    insn1 = data[offset: offset + 4]
    insn1 = struct.unpack("<I", insn1)[0]
    addr_w = decode_movw(insn1)

    insn2 = data[offset + 4: offset + 8]
    insn2 = struct.unpack("<I", insn2)[0]
    addr_t = decode_movw(insn2)

    addr = (addr_t << 16) | addr_w
    return addr


def find_counter(data, offset):
    bp = BinaryPattern("counter")
    bp.from_hex("0168 0329 ?+ 01b0 bde8f08f ?+ 50 41 4c 54 73 6b 53 73 00")

    locs = bp.findall(data)
    assert len(locs) == 1, f"Found more than one instance or failed to find any ({len(locs)})"

    offset = locs[0][0] - 8
    insn1 = data[offset: offset + 4]
    insn1 = struct.unpack("<I", insn1)[0]
    addr_w = decode_movw(insn1)

    insn2 = data[offset + 4: offset + 8]
    insn2 = struct.unpack("<I", insn2)[0]
    addr_t = decode_movw(insn2)

    addr = (addr_t << 16) | addr_w
    return addr


def s5123_get_dsp_sync0(self, sym, data, offset):
    insn_offset = sym.address - offset
    insn = struct.unpack("<H", data[insn_offset: insn_offset + 2])[0]
    sync_word = decode_mov_immediate(insn, 2)
    self.symbol_table.set(sym.name, sync_word)
    log.info(f"Retrieved sync word 0: {sync_word:#x}")

    return True


def s5123_get_dsp_sync1(self, sym, data, offset):
    insn_offset = sym.address - offset
    insn = struct.unpack("<I", data[insn_offset: insn_offset + 4])[0]
    sync_word = decode_mov_immediate(insn, 4)
    self.symbol_table.set(sym.name, sync_word)
    log.info(f"Retrieved sync word 1: {sync_word:#x}")

    return True


def _decode_thumb_bl(bl_addr, hw1, hw2):
    """Decode a 32-bit Thumb BL/BLX (T1) at `bl_addr` to its absolute target."""
    S = (hw1 >> 10) & 1
    imm10 = hw1 & 0x3FF
    J1 = (hw2 >> 13) & 1
    J2 = (hw2 >> 11) & 1
    imm11 = hw2 & 0x7FF
    I1 = (~(J1 ^ S)) & 1
    I2 = (~(J2 ^ S)) & 1
    imm = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
    if S:
        imm -= 1 << 25
    return (bl_addr + 4 + imm) & 0xFFFFFFFF


def _publish_phy_ipc_ring_base(self, base, detail):
    """Publish SYM_PHY_IPC_C2P_RING_BASE (consumed by the PhyIpc peripheral)."""
    self.symbol_table.set("SYM_PHY_IPC_C2P_RING_BASE", base)
    log.info("PHY IPC C2P ring base: %#010x (%s)", base, detail)
    return True


def get_phy_ipc_c2p_ring_base_thunked(self, sym, data, offset):
    """S5123AP (e.g. G991B): the ring base is loaded via a function call.

    `sym` is PHY_IPC_C2P_Sender's entry. Its first `bl` (at +0xa: push / sub sp
    / mov r6,r1 / mov r4,r0) calls a tiny thunk that returns the base via
    `movw rD,#lo; movt rD,#hi`. Decode the bl to find the thunk, then its
    immediates. The base is scatter-loaded RAM (per-build); the field offsets
    used by the PhyIpc peripheral are compile-time constants.
    """
    fn = sym.address - offset
    bl_off = fn + 0xA
    if bl_off + 4 > len(data):
        log.error("PHY_IPC_C2P_Sender bl out of section range")
        return False
    hw1, hw2 = struct.unpack("<HH", data[bl_off : bl_off + 4])
    thunk = _decode_thumb_bl(sym.address + 0xA, hw1, hw2)

    t = thunk - offset
    if t < 0 or t + 8 > len(data):
        log.error("PHY IPC base thunk %#010x outside section", thunk)
        return False

    movw = decode_movw(struct.unpack("<I", data[t : t + 4])[0])
    movt = decode_movw(struct.unpack("<I", data[t + 4 : t + 8])[0])
    base = (movt << 16) | movw
    return _publish_phy_ipc_ring_base(
        self, base, "sender %#010x, thunk %#010x" % (sym.address, thunk)
    )


def get_phy_ipc_c2p_ring_base_inline(self, sym, data, offset):
    """S5123 (e.g. oriole): the ring base is loaded inline, no function call.

    `sym` is PHY_IPC_C2P_Sender's entry. The base is built directly in the
    prologue as `movw rD,#lo` (at +0x6) and `movt rD,#hi` (at +0xe), bracketing
    the `mov r5,r0; mov r8,r1` arg saves. Decode those two immediates.
    """
    fn = sym.address - offset
    if fn + 0x12 > len(data):
        log.error("PHY_IPC_C2P_Sender inline movw/movt out of section range")
        return False
    movw = decode_movw(struct.unpack("<I", data[fn + 0x6 : fn + 0xA])[0])
    movt = decode_movw(struct.unpack("<I", data[fn + 0xE : fn + 0x12])[0])
    base = (movt << 16) | movw
    return _publish_phy_ipc_ring_base(self, base, "sender %#010x, inline" % sym.address)


def find_task_table(data, offset):
    bp_task = BinaryPattern("task", offset=1)
    bp_task.from_str(b"\x00" + TASK_NAME_TO_FIND + b"\x00")

    # Find the null terminated strings like 'task'
    locs = []
    npos = 0

    # Iteratively mark the positions of the matching patterns.
    while True:
        res = bp_task.find(data, pos=npos)
        if res is None:
            break
        npos = res[1]
        locs += [res]


    if len(locs) == 0:
        return None


    # Finds two locations of task
    xref_target = locs[0][0] + offset

    bp_task_x = BinaryPattern("xref")
    bp_task_x.from_str(struct.pack("I", xref_target))

    rez = bp_task_x.findall(data, maxresults=2)

    if rez is None or len(rez) < 2:
        # Try again but on the other string reference.
        # It appears that S5123AP:G991BXXSIHYK1 uses locs[1][0] instead of locs[0][0]
        xref_target = locs[1][0] + offset
        bp_task_x = BinaryPattern("xref")
        bp_task_x.from_str(struct.pack("I", xref_target))
        rez = bp_task_x.findall(data, maxresults=2)

    if len(rez) < 2:
        return None

    # the first result is another reference we dont care about
    ptr = rez[1][0]

    return ptr


def fixup_set_task_layout(self, sym, data, offset):
    ptr = sym.address

    # try to figure out task layout:
    found_layout = None

    for layout in get_task_layouts():
        test_ptr = ptr
        test_ptr -= layout.SIZE()
        task_name_p = struct.unpack("I", data[test_ptr : test_ptr + 4])[0]
        task_name_p_off = task_name_p - offset
        name = data[task_name_p_off : task_name_p_off + 10]
        name_bytes = name.tobytes()
        end_of_string = name_bytes.find(b"\x00")
        # not a cstring
        if end_of_string == -1:
            continue
        # contents are as expected
        if all(
            [c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ__" for c in name_bytes[:end_of_string]]
        ):
            log.info(f"Found likely task name: {name_bytes}, keeping task layout")
            found_layout = layout
            break
    if found_layout is None:
        log.error("Couldn't retrieve correct task layout, aborting!")
        raise ValueError("Missing task layout")

    while True:
        ptr -= found_layout.SIZE()
        task_name_p = struct.unpack("I", data[ptr : ptr + 4])[0]
        task_name_p_off = task_name_p - offset
        name = data[task_name_p_off : task_name_p_off + 10]
        # print(hex(task_name_p), name.tobytes())

        # search backwards until we see an invalid address
        if task_name_p < offset or task_name_p >= (offset + len(data)):
            self.task_layout = found_layout
            self.symbol_table.replace(
                sym.name,
                offset + ptr + found_layout.SIZE() - found_layout.TASK_NAME_PTR_OFFSET,
            )
            return True

    raise ValueError("Invalid task layout")


def find_lterrc_int_mob_cmd_ho_from_irat_msgid(data, offset):
    bp = BinaryPattern("lte_rrc_int_mob_cmd_ho_from_irat_msgid", offset=0x12)
    bp.from_hex(
        "?? ?? 14 ?? ?? d0 ?? ?? ?? d0 ?? ?? ?? d0 ?? f5 43 ?? ?? ?? ?? d0 ?* 01 20"
    )

    off = bp.find(data)[0]
    res = 0xC3 << 8 | data[off]
    return res


def get_dsp_sync0(self, sym, data, offset):
    main_toc = self.modem_file.get_section("MAIN")

    sync_word = main_toc.data[sym.address - main_toc.load_address]
    self.symbol_table.remove(sym.name)
    self.symbol_table.add(sym.name, sync_word)
    log.info(f"Retrieved sync word 0: {sync_word}")
    return True


def get_dsp_sync1(self, sym, data, offset):
    main_toc = self.modem_file.get_section("MAIN")


    # This is a horrible hack, however, DSP SYNC1 is provided in two different
    # instruction encodings. If the sync word is smaller than 255, it uses the resolved value directly,
    # Otherwise it's multiplied by two.
    # We deal with this by assuming that resolved words lower than 250 are meant to be multiplied by two,
    # Otherwise we use it directly as sync word
    resolved_byte = main_toc.data[sym.address - main_toc.load_address]
    sync_word = resolved_byte * 2 if resolved_byte < 250 else resolved_byte

    self.symbol_table.remove(sym.name)
    self.symbol_table.add(sym.name, sync_word)
    log.info(f"Retrieved sync word 1: {sync_word}")
    return True


def find_msg_id_lte_pdcp_data_ind(self, sym, data, offset):
    main_toc = self.modem_file.get_section("MAIN")
    val = int.from_bytes(
        main_toc.data[sym.address - main_toc.load_address: sym.address - main_toc.load_address + 4], "little"
    )
    val = val & 0xFF
    self.symbol_table.remove(sym.name)
    self.symbol_table.add(sym.name, val)
    log.info(f"Resolved MSG_ID_LTE_PDCP_DATA_IND to : {val:#x}")
    return True

def find_msg_id_lte_pdcp_data_req(data, offset):

    # Not the cleanest pattern, but search for code that
    # prepares an LTE_PDCP_DATA_REQ message, using an `adr`
    # or `ldr` instruction

    bp = BinaryPattern("msg_id_lte_pdcp_data_req")
    bp.from_str(b"LTE_PDCP_DATA_REQ\x00")

    locs = []
    llocs = []
    npos = 0


    # LTE_PDCP_DATA_REQ strings
    locs = [l[0] for l in bp.findall(data)]
    llocs += locs

    # pointers to string

    for l in locs:
        bp_x = BinaryPattern("xref")
        bp_x.from_str(struct.pack("I", l+offset))
        rez = bp_x.findall(data, maxresults=10)
        for r in rez:
            llocs.append(r[0])

    bp_code = BinaryPattern("bp_code", offset=0x4)
    bp_code.from_hex("??20 ??60 ???? ??61")

    while True:
        res = bp_code.find(data, pos=npos)
        if res is None:
            break

        ins = int.from_bytes(data[res[0]:res[0]+2], "little")

        target = 0

        if((ins >> 11) == 0x14):
            # adr
            target = res[0] + 4 + 4 * (ins & 0xFF)
        elif((ins >> 11) == 0x9):
            # pc relative ldr
            target = res[0] + 4 + 4 * (ins & 0xFF)

        if(target in llocs):
            # +0x18 is the type: LTE_PDCP_DATA_REQ
            # +0x8  is the message id == ??20 ??60
            # Probably 0xc2
            val = int.from_bytes(data[res[0]-0x4:res[0]-0x4+0x2], "little") & 0xFF
            log.info(f"Resolved MSG_ID_LTE_PDCP_DATA_REQ to : {val:#x}")
            return val

        npos = res[1]

def parse_scatterload_table(saddress, data, main_toc):
    __scatterload_bp =  BinaryPattern("__scatterload__")
    __scatterload_bp.from_hex("0a a0 90 e8 00 0c 82 44 83 44 aa f1 01 07 da 45 ???? ???????? ???????? ba e8 0f 00 13 f0 01 0f 18 bf fb 1a 43 f0 01 03 18 47")
    (start, end) = __scatterload_bp.find(data)
    __scatterload_table_start = (end+main_toc.load_address) + int.from_bytes(data[end:end+4], byteorder="little", signed=True)
    __scatterload_table_end = (end+main_toc.load_address) + int.from_bytes(data[end+4:end+8], byteorder="little", signed=True)

    entry_size = 16

    __scatter_load_copy_bp = BinaryPattern("__scatterload_copy")
    __scatter_load_copy_bp.from_hex("10 3a 24 bf 78 c8 78 c1 ???? 52 07 24 bf 30 c8 30 c1 44 bf 04 68 0c 60 70 47")
    __scatter_load_copy_off = __scatter_load_copy_bp.find(data)
    to_match = main_toc.load_address + __scatter_load_copy_off[0]
    idx_start = __scatterload_table_start - main_toc.load_address

    for i in range((__scatterload_table_end - __scatterload_table_start) // entry_size):
        table_entry = data[idx_start+(i*entry_size):idx_start+(i*entry_size)+entry_size]
        fn = int.from_bytes(table_entry[12:], "little")
        if(fn == to_match):
            src_ptr = int.from_bytes(table_entry[:4], "little")
            size = int.from_bytes(table_entry[8:12], "little")
            dst_ptr = int.from_bytes(table_entry[4:8], "little")

            if(saddress >= src_ptr and saddress <= src_ptr + size):
                dst_ptr = int.from_bytes(table_entry[4:8], "little")
                target_addr = dst_ptr + (saddress - src_ptr)
                break

    return (src_ptr, dst_ptr, target_addr)

def heap_metadata(fn_code, code, mnem, pattern):
    thumb_offset = 2
    arch = Cs(CS_ARCH_ARM, CS_MODE_THUMB)


    re_pattern = re.compile(pattern)
    res = []
    ins = []

    for (address, size, mnemonic, op_str) in arch.disasm_lite(code, 0):
        if(mnemonic == "ret"):
            break
        ins.append((fn_code+address, mnemonic, op_str))
        if(mnemonic == mnem):
            ops = op_str.split(", ")
            src_reg = ops[0]
            offset = 0
            if(len(ops) == 3):
                offset = int(ops[2].strip("[#]\n"), 16)
            elif(len(ops) != 2):
                print(f"ERROR len(ops) = {len(ops)}")
                return
            source_reg = ops[0]
            target_reg = ops[1].strip("[]\n")

            if(src_reg == target_reg):
                taint_reg = target_reg
                back_offset = offset
                pc_offset = 0
                target = 0
                last_addr = 0

                for(ins_addr, mnem_back, op_str_back) in ins[::-1]:
                    if(taint_reg in op_str_back):
                        if(mnem_back == "ldr"):
                            ops = op_str_back.split(", ")
                            if(taint_reg == ops[0]):
                                if(len(ops) == 3):
                                    pc_offset = int(ops[2].strip("[#]\n"), 16)
                                if(len(ops) > 3):
                                    print("Decompile error")
                                    return False
                                dst_reg = ops[1].strip("[")
                                if(dst_reg == "pc"):
                                    target = ins_addr + pc_offset + abs(ins_addr - last_addr)
                                    res.append((source_reg, target_reg, target, back_offset))  #pc already updated

                                    break
                                else:
                                    taint_reg = dst_reg
                        elif(mnem_back == "adds"):
                            ops = op_str_back.split(", ")
                            if(taint_reg == ops[0]):
                                back_offset += int(ops[1].strip("#\n"), 16)
                        elif(mnem_back == "add.w"):
                            ops = op_str_back.split(", ")
                            if(taint_reg == ops[0]):
                                if(len(ops) == 3):
                                    back_offset += int(ops[2].strip("#\n"), 16)
                                    taint_reg = ops[1]
                                else:
                                    print("adds with unsupported args")
                                    return False
                    last_addr = ins_addr


        #todo match the actual instruction : DIRECT BRANCH / INDIRECT BRANCH
        if(mnemonic == "b" or mnemonic == "bl" or mnemonic == "blx" or mnemonic == "bx"):
            #branch may switch instruction set
            target = int(op_str.strip("#\n"), 16)
            if(target & 1 != 0):
                thumb_offset = 2
            else:
                thumb_offset = 4

    assert(len(res) == 10)
    for i in range(1, 10):
        assert(res[i][3] - res[i-1][3] == 4)
        assert(res[i][2] == res[i-1][2])
        assert(res[i][0] == res[i-1][0])
        assert(res[i][1] == res[i-1][1])

    return res[0]

def find_heap_metadata(self, sym, d, o):
    main_toc = self.modem_file.get_section("MAIN")
    offset = sym.address - main_toc.load_address
    data = main_toc.data
    code_len = 200

    pattern = "r[0-c], \[r[0-c](, #(0x)?[0-f]+)?\]"

    meta = heap_metadata(sym.address, data[offset:offset+code_len], "str", pattern)
    (src_ptr, dst_ptr, target_addr) = parse_scatterload_table(sym.address, data, main_toc)

    final_offset = src_ptr + target_addr + meta[2] - sym.address - dst_ptr - main_toc.load_address
    name = "SYM_HEAP_PARTITION"
    final_ptr = int.from_bytes(data[final_offset:final_offset+4], "little") + meta[3]
    self.symbol_table.add(name, final_ptr)

    return True

def find_LteRrcBoolPrintLog(self, sym, data, offset):
    # instruction should be a relative load to the PC (load literal)

    ins = int.from_bytes(data[sym.address-offset:sym.address-offset+2], "little")
    if(ins >> 8 != 0x4a):
        return False

    maddr = sym.address + 2 + (ins & 0xff) * 4
    moffset = maddr - offset
    new_address = int.from_bytes(data[moffset:moffset+4], "little")
    self.symbol_table.remove(sym.name)
    self.symbol_table.add(sym.name, new_address)
    return True


def _function_start(data, site, span=0x40):
    """Entry of the function containing `site`, i.e. the nearest `push` before it."""
    for i in range(0, span, 2):
        fn = site - i
        if data[fn + 1] in (0xB4, 0xB5) or data[fn : fn + 2] == b"\x2d\xe9":
            return fn

    return None


def _branch_target_at(data, offset, insn_off, link=True):
    # wide Thumb branch: hw1 = 11110 S imm10; hw2 bit14 set for BL, clear for B.W
    insn = struct.unpack("<I", data[insn_off : insn_off + 4])[0]
    if insn & 0xF800 != 0xF000:
        return None
    if (insn >> 16) & 0xD000 != (0xD000 if link else 0x9000):
        return None
    return decode_thumb_bl_target(insn, offset + insn_off)


def _encode_movw_movt(value, rd):
    out = []
    for op, imm16 in ((0xF240, value & 0xFFFF), (0xF2C0, (value >> 16) & 0xFFFF)):
        hw1 = op | (((imm16 >> 11) & 1) << 10) | ((imm16 >> 12) & 0xF)
        hw2 = (((imm16 >> 8) & 7) << 12) | (rd << 8) | (imm16 & 0xFF)
        out += [struct.pack("<HH", hw1, hw2)]
    return out


def _find_movw_movt(data, value, gap=0x14):
    """Sites building `value` with a movw/movt pair, which need not be adjacent."""
    sites = []

    for rd in range(8):
        movw, movt = _encode_movw_movt(value, rd)
        bp = BinaryPattern("movw")
        bp.from_str(movw)
        for loc in bp.findall(data):
            if movt in bytes(data[loc[0] + 4 : loc[0] + 4 + gap]):
                sites += [loc[0]]

    return sites


def _find_trace_entries(data, offset, needle, reject=None):
    """TraceEntry structs whose message string contains `needle` (see shannon.h)."""
    bp = BinaryPattern("trace_string")
    bp.from_str(needle)

    entries = []
    for loc in bp.findall(data):
        start = loc[0]
        while start > 0 and data[start - 1] != 0:
            start -= 1
        if reject is not None and reject in bytes(data[start : loc[0]]):
            continue

        bp_ptr = BinaryPattern("trace_ptr")
        bp_ptr.from_str(struct.pack("<I", offset + start))
        entries += [offset + p[0] - 0x10 for p in bp_ptr.findall(data)]

    return entries


def _find_handler_registration(data, offset, needle, reject=None):
    """Entry of a message handler plus the code sites that load it for registration.

    The handler is reached through its first log line rather than an xref: the
    trace string gives a TraceEntry, the movw/movt pair materialising that entry
    sits a prologue away from the function start, and the registration site is
    wherever that start (Thumb, so |1) is itself materialised.
    """
    for entry in _find_trace_entries(data, offset, needle, reject):
        for site in _find_movw_movt(data, entry):
            for prologue in range(2, 0x40, 2):
                fn = site - prologue
                if data[fn + 1] not in (0xB4, 0xB5) and data[fn : fn + 2] != b"\x2d\xe9":
                    continue
                sites = _find_movw_movt(data, offset + fn + 1)
                if sites:
                    return offset + fn, sites

    return None, []


def _movw_movt_value_before(data, loc, rd, span=0x400):
    """Value of the last movw/movt pair written to `rd` before `loc`.

    A `mov rd, rn` on the way is followed, because S5123AP builds the base id in
    a low register and parks it in the one the entries index off.
    """
    high = None

    for i in range(2, span, 2):
        insn = struct.unpack("<I", data[loc - i : loc - i + 4])[0]
        hw = insn & 0xFFFF

        if high is None and hw & 0xFF00 == 0x4600:  # mov rd, rn
            if (((hw >> 4) & 8) | (hw & 7)) == rd:
                rd = (hw >> 3) & 0xF
            continue

        if (insn >> 24) & 0xF != rd:
            continue
        if high is None and insn & 0xFBF0 == 0xF2C0:
            high = decode_movw(insn)
        elif high is not None and insn & 0xFBF0 == 0xF240:
            return (high << 16) | decode_movw(insn)

    return None


def _msg_id_near(data, offset, loc, window=0x40, gap=0x14):
    """Message id built near `loc`.

    Registration code keeps a base id in a register and reaches each entry with
    a displacement, so both a plain movw/movt pair and `add rd,rn,#imm` have to
    be resolved. Message ids sit below the section load address, which is what
    separates them from the handler pointers loaded by the same code.
    """
    for i in range(0, window, 2):
        insn = struct.unpack("<I", data[loc + i : loc + i + 4])[0]
        hw1 = insn & 0xFFFF
        imm12 = (((hw1 >> 10) & 1) << 11) | (((insn >> 28) & 7) << 8) | ((insn >> 16) & 0xFF)
        value = None

        if hw1 & 0xFBE0 == 0xF100:  # add rd, rn, #imm (T3)
            base = _movw_movt_value_before(data, loc + i, hw1 & 0xF)
            if base is not None:
                value = base + thumb_expand_imm(imm12)
        elif hw1 & 0xFBF0 == 0xF200:  # addw rd, rn, #imm12 (T4)
            base = _movw_movt_value_before(data, loc + i, hw1 & 0xF)
            if base is not None:
                value = base + imm12
        elif hw1 & 0xFBF0 == 0xF2C0:  # movt rd
            rd = (insn >> 24) & 0xF
            for j in range(2, gap, 2):
                prev = struct.unpack("<I", data[loc + i - j : loc + i - j + 4])[0]
                if prev & 0xFBF0 == 0xF240 and (prev >> 24) & 0xF == rd:
                    value = (decode_movw(insn) << 16) | decode_movw(prev)
                    break
                if prev & 0xF800 == 0x2000 and (prev >> 8) & 7 == rd:
                    value = (decode_movw(insn) << 16) | (prev & 0xFF)
                    break
            adds = struct.unpack("<H", data[loc + i + 4 : loc + i + 6])[0]
            if value is not None and adds & 0xF800 == 0x3000 and (adds >> 8) & 7 == rd:
                value += adds & 0xFF

        if value is not None and 0x400000 <= value < offset:
            return value

    return None


def find_msg_id_mm_rrc_data_ind(data, offset):
    """MM_RRC_DATA_IND message id: dst_ft << 22 | src_ft << 12 | msg_num.

    Read from the handler registration, which stores the handler pointer and
    then the id it is registered under.
    """
    handler, sites = _find_handler_registration(
        data, offset, b"MM_RRC_DATA_IND_Handler\x00", reject=b"MmFt"
    )
    assert handler is not None, "Failed to find the MM_RRC_DATA_IND handler"

    found = {v for v in (_msg_id_near(data, offset, s) for s in sites) if v is not None}
    assert len(found) == 1, f"Conflicting message ids {sorted(map(hex, found))}"

    log.info("MM_RRC_DATA_IND handler at %#010x", handler)
    return found.pop()


def find_smpf_create_msg(data, offset):
    # inlined template, so one identical copy per 0x48 byte message class; the
    # message id is a parameter, so any copy serves
    bp = BinaryPattern("smpf_CreateMsg")
    bp.from_hex(
        "f0b5 81b0 0c46 ???????? 0546 4820 ??22 0023 0026 ???????? "
        "???????? 0746 ??b1 3846 2946 4822 ???????? 07f12c06 3c61 3046 01b0 f0bd"
    )

    loc = bp.find(data)
    assert loc is not None, "Failed to find smpf_CreateMsg"
    return offset + loc[0]


def find_smpf_mem_alloc(data, offset):
    # several byte-identical copies exist; take the one smpf_CreateMsg calls
    create = find_smpf_create_msg(data, offset) - offset
    target = _branch_target_at(data, offset, create + 0x18)
    assert target is not None, "No BL at smpf_CreateMsg+0x18"
    return target


def _find_sendmsg_task_check(data):
    """The `if (SMPF_TASK_CREATED)` guard at the top of SendMsg__'s body.

    Anchored on the body rather than on the function entry, because S5123AP
    builds SendMsg__ with a stack cookie prologue (an extra movw/movt pair and
    a wider push) that S5123 does not have. Everything from this guard on is
    byte identical on both, the two immediates aside.
    """
    bp = BinaryPattern("SendMsg__")
    bp.from_hex(
        "a068 10f4007f ??d1 ???????? ???????? "
        "0978 0029 ??d0 617b 4029 01d3 0021 6173"
    )

    locs = bp.findall(data)
    assert (
        len(locs) == 1
    ), f"Found more than one instance or failed to find any ({len(locs)})"

    return locs[0][0]


def find_smpf_send_msg(data, offset):
    bp = BinaryPattern("smpf_SendMsg")
    bp.from_hex(
        "58b1 10f82b2c a0f12c01 1207 02d5 0622 00f80c2c 0846 ???????? 1f20 7047"
    )

    locs = bp.findall(data)
    assert (
        len(locs) == 1
    ), f"Found more than one instance or failed to find any ({len(locs)})"

    loc = locs[0][0]
    target = _branch_target_at(data, offset, loc + 0x16, link=False)
    expected = offset + _function_start(data, _find_sendmsg_task_check(data))
    assert (
        target == expected
    ), f"Tail call goes to {target:#010x}, SendMsg__ is at {expected:#010x}"

    return offset + loc


def find_smpf_task_created(data, offset):
    # the flag the guard loads, built by the movw/movt pair inside it
    loc = _find_sendmsg_task_check(data)
    addr_w = decode_movw(struct.unpack("<I", data[loc + 8 : loc + 12])[0])
    addr_t = decode_movw(struct.unpack("<I", data[loc + 12 : loc + 16])[0])

    return (addr_t << 16) | addr_w


def find_fake_test_assist_get_instance(data, offset):
    """Lazy getter for the MM fake test assist singleton.

    smpf_MemAlloc call sites pass __FILE__, so the sole reference to
    cn_MmFakeTestUtil.hpp's path string is the getter's own allocation, which
    sits a fixed prologue past the function start.
    """
    bp = BinaryPattern("cn_MmFakeTestUtil.hpp")
    bp.from_str(b"cn_MmFakeTestUtil.hpp\x00")

    sites = []
    for loc in bp.findall(data):
        start = loc[0]
        while start > 0 and data[start - 1] != 0:
            start -= 1
        sites += _find_movw_movt(data, offset + start)

    assert (
        len(sites) == 1
    ), f"Expected one reference to cn_MmFakeTestUtil.hpp, found {len(sites)}"

    fn = sites[0] - 0x10
    prologue = BinaryPattern("FakeTestAssist_GetInstance")
    prologue.from_hex("10b5 ???????? ???????? 2068 00b1 10bd")
    assert (
        prologue.find(data[fn : sites[0]]) is not None
    ), f"Unexpected getter prologue at {offset + fn:#010x}"

    return offset + fn


def _word_refs(data, offset, value):
    """Aligned words holding `value`, the closest thing to an xref we have."""
    bp = BinaryPattern("word")
    bp.from_str(struct.pack("<I", value))

    return [offset + loc[0] for loc in bp.findall(data) if loc[0] % 4 == 0]


def _find_cxx_vtable(data, offset, cxx_class):
    """Vtable of a C++ class, reached through its RTTI type_info.

    The images keep Itanium ABI RTTI, where type_info holds a pointer to the
    mangled class name at +4 and the vtable holds a pointer to the type_info at
    +4. Two word searches therefore walk name -> type_info -> vtable without
    needing xrefs. Mangled names are readable enough to grep for in Ghidra's
    string list ("N2cn2mm10NrmmFacadeE" is cn::mm::NrmmFacade).
    """
    bp = BinaryPattern(cxx_class)
    bp.from_str(cxx_class.encode() + b"\x00")

    vtables = set()
    for loc in bp.findall(data):
        for name_ref in _word_refs(data, offset, offset + loc[0]):
            for typeinfo_ref in _word_refs(data, offset, name_ref - 4):
                vtables.add(typeinfo_ref - 4)

    assert (
        len(vtables) == 1
    ), f"Expected one vtable for {cxx_class}, found {sorted(map(hex, vtables))}"

    return vtables.pop()


def _cxx_vtable_slot(data, offset, vtable, slot):
    """Method in a vtable slot. Slots start at vtable+8, past offset_to_top and
    the type_info pointer, so vtable+8 is also the value objects store."""
    loc = vtable + 8 + 4 * slot - offset

    return struct.unpack("<I", data[loc : loc + 4])[0] & ~1


def _find_cxx_ctor(data, offset, vtable):
    """Constructor, from the code installing the vtable pointer.

    Objects get their vptr written as `movw/movt rd, <vtable>; adds rd, #8`, so
    it is the vtable base that appears in code. The destructors reinstall the
    vptr the same way, which makes the constructor the one such site that is
    not itself a vtable entry.
    """
    slots = {_cxx_vtable_slot(data, offset, vtable, i) for i in range(64)}
    ctors = set()

    for site in _find_movw_movt(data, vtable):
        fn = _function_start(data, site, span=12)
        if fn is not None and offset + fn not in slots:
            ctors.add(offset + fn)

    assert (
        len(ctors) == 1
    ), f"Expected one constructor for vtable {vtable:#010x}, found {sorted(map(hex, ctors))}"

    return ctors.pop()


def cxx_vtable(cxx_class):
    def lookup(data, offset):
        return _find_cxx_vtable(data, offset, cxx_class)

    return lookup


def cxx_ctor(cxx_class):
    def lookup(data, offset):
        return _find_cxx_ctor(data, offset, _find_cxx_vtable(data, offset, cxx_class))

    return lookup


def cxx_vmethod(cxx_class, slot, prologue):
    """Virtual method by slot index, confirmed by the method's own prologue.

    Slot indices are only stable within a firmware generation, so `prologue`
    guards against a vtable layout change silently returning the wrong method.
    """

    def lookup(data, offset):
        vtable = _find_cxx_vtable(data, offset, cxx_class)
        addr = _cxx_vtable_slot(data, offset, vtable, slot)

        bp = BinaryPattern(f"{cxx_class}+{slot}")
        bp.from_hex(prologue)
        loc = bp.find(data, pos=addr - offset, maxpos=addr - offset + 0x40)
        assert (
            loc is not None and loc[0] == addr - offset
        ), f"Slot {slot} of {cxx_class} ({addr:#010x}) does not match its expected prologue"

        return addr

    return lookup
