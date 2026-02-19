## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct
import logging
from firmwire.util.BinaryPattern import BinaryPattern

from .task import get_task_layouts
from .queue import QUEUE_STRUCT_SIZE

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

    # AdcTask's queue is the third item in the list (might not be stable)
    # Stable for S5123AP:G991BXXSIHYK1
    ptr -= QUEUE_STRUCT_SIZE * 2

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
