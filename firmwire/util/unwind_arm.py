## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging
from capstone import *
from capstone.arm import *

log = logging.getLogger("firmwire.util.unwind_arm")


class CachedRange(object):
    def __init__(self, start, data):
        self.start = start
        self.end = len(data) + start
        self.data = data


class ARM32Unwinder(object):
    def __init__(self, qemu, debug=False):
        self.qemu = qemu
        self.debug = debug

        # Technically this will affect all instances of the class
        # but it works for a quick hack
        if debug:
            log.setLevel(logging.DEBUG)

        self.memory_cache = []

    def read_memory(self, addr, word_size, num_words, raw=False):
        """read_memory

        A helper function and cache for read memory.

        :param addr: The address of the read.
        :param word_size: The word size of the read.
        :param num_words: The number of words to read.
        :param raw: Whether the result should be a string of bytes.
        """
        if raw:
            byte_count = word_size * num_words
            for c in self.memory_cache:
                offset = addr - c.start
                if offset >= 0 and offset + byte_count <= len(c.data):
                    return c.data[offset : offset + byte_count]

        try:
            res = self.qemu.read_memory(addr, word_size, num_words, raw=raw)
        except Exception as e:
            raise ValueError("Failed to read memory %08x" % (addr))

        # raw and uncached
        if raw:
            self.memory_cache += [CachedRange(addr, res)]

        return res

    def format_insn(self, insn, show_address=True):
        """format_insn

        :param insn: The Capstone instruction to format.
        :param show_address: Whether to include an address prefix.
        """
        if show_address:
            return "0x%08x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str)
        else:
            return "%s\t%s" % (insn.mnemonic, insn.op_str)

    def unwind_frame(self, start_addr, stack_frame_start, lr_reg=None, thumb=False):
        """unwind_frame

        :param start_addr: The instruction address to start unwinding from.
        :param stack_frame_start: The address of the top of the stack at the start_addr.
        :param lr_reg: An optional value of LR (if it is determined to be valid pre-unwind)
        :param thumb: Whether to decode instructions as Thumb/2 or ARM
        """
        if thumb:
            insns = self.disasm_function_backwards(start_addr, mode=CS_MODE_THUMB)
        else:
            insns = self.disasm_function_backwards(start_addr, mode=0)

        log.debug("Function size %d instructions", len(insns))

        lr_is_okay = True and lr_reg is not None
        stack_offset = 0
        lr_offset = None

        for i in insns[1:]:
            show = False
            side_effects = self.disasm_get_insn_side_effects(i)
            rr = side_effects["regs_read"]
            rw = side_effects["regs_write"]

            if ARM_REG_SP in rw:
                adjustment = 0

                if i.id == ARM_INS_PUSH:
                    stack_offset -= len(i.operands) * 4

                    # lr is always the first thing pushed on to the stack
                    if ARM_REG_LR in rr:
                        lr_offset = stack_offset + 4
                elif i.id == ARM_INS_STR:
                    if i.writeback:
                        stack_offset += i.operands[0].value.mem.disp

                        if ARM_REG_LR in rr:
                            lr_offset = stack_offset
                    else:
                        log.warning(
                            "Unhandled stack STR instruction pattern: %s",
                            self.format_insn(i),
                        )
                elif i.id == ARM_INS_SUB:
                    if i.operands[1].type in [ARM_OP_IMM, ARM_OP_CIMM]:
                        stack_offset -= i.operands[1].value.imm
                    else:
                        log.warning(
                            "Unhandled stack SUB instruction pattern: %s",
                            self.format_insn(i),
                        )
                else:
                    log.warning("Unhandled stack instruction: %s", self.format_insn(i))

                show = True

            if ARM_REG_LR in i.regs_write:
                lr_is_okay = False

            if show and self.debug:
                log.debug("%s (offset=%d)", self.format_insn(i), stack_offset)

                c = 0
                for r in rw:
                    log.debug("\tREG_WRITE %s", i.reg_name(r))

                for r in rr:
                    log.debug("\tREG_READ %s", i.reg_name(r))

                for o in i.operands:
                    c += 1

                    if o.type == ARM_OP_REG:
                        log.debug(
                            "\toperands[%u].type: REG = %s", c, i.reg_name(o.value.reg)
                        )
                    else:
                        pass

            if lr_offset:
                break

        stack_offset = -stack_offset
        prev_stack_frame = stack_frame_start + stack_offset

        if lr_is_okay:
            log.debug("Current LR %08x", lr_reg)

        log.debug("Current SP %08x", stack_frame_start)
        log.debug("Stack offset %d", stack_offset)

        if lr_is_okay:
            return lr_reg, prev_stack_frame
        elif lr_offset:
            lr_offset = -lr_offset
            saved_lr_address = stack_frame_start + lr_offset
            saved_lr = self.read_memory(saved_lr_address, 4, 1)

            log.debug("Saved LR [%08x] = %08x", saved_lr_address, saved_lr)

            return saved_lr, prev_stack_frame
        else:
            raise ValueError(
                "Unable to unwind %08x: stack frame failed to recover" % (start_addr)
            )

    def disasm_back_single(self, addr, mode=CS_MODE_THUMB, detail=True):
        """disasm_back_single

        :param addr: the starting address to disassemble back from
        :param mode: the Capstone ARM mode
        :param detail: whether or not Capstone should include detail in the instruction decoding
        """
        # dont use detail by default (it's slower)
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = detail

        self.read_memory((addr - 0x1000) & ~0xFFF, 1, 0x2000, raw=True)

        addr -= 6
        data = self.read_memory(addr, 1, 6, raw=True)

        if len(data) != 6:
            raise ValueError("Short read when disassembling backwards")

        A = data[:2]
        B = data[2:4]
        C = data[4:6]
        # D = data[6:8]

        A1 = list(md.disasm(A, addr))
        Af = list(md.disasm(A + B + C, addr))

        B1 = list(md.disasm(B, addr + 2))
        Bf = list(md.disasm(B + C, addr + 2))

        C1 = list(md.disasm(C, addr + 4))
        # Cf = md.disasm(C+D, addr+4)

        # D1 = md.disasm(D, addr+6)

        from binascii import hexlify

        # print("---------", hex(addr), hexlify(data), "A1=%d, B1=%d, C1=%d, Af=%d, Bf=%d" % (
        #        len(A1), len(B1), len(C1), len(Af), len(Bf)))

        # we're probably disassembling data...
        if len(Af) == 0 and len(Bf) == 0 and len(C1) == 0:
            return None

        # Instruction patterns to consider:
        #   Thumb[16], Thumb[16], Thumb[16]         RET=C1 [A1=1, B1=1, C1=1, Af=3, Bf=2]
        #   Thumb[32], Thumb[16]                    RET=C1 [A1=0, B1=0|1, C1=1, Af=2, Bf=0|1|2]
        #   OFFCUT_Thumb[32], Thumb[16], Thumb[16]  RET=C1 [A1=0|1, B1=1, C1=1, Af=1|3, Bf=2]
        #   OFFCUT_Thumb[32], Thumb[32]             RET=Bf [A1=0|1, B1=0, C1=0|1, Af=0|1|2, Bf=1]
        #   Thumb[16], Thumb[32]                    RET=Bf [A1=1, B1=0, C1=0|1, Af=2, Bf=1]

        patterns = [
            [1, 1, 1, 3, 2, False],
            [0, -1, 1, 2, -1, False],
            [-1, 1, 1, -1, 2, False],
            [-1, 0, -1, -1, 1, True],
            [1, 0, -1, 2, 1, True],
        ]

        cmp_pat = [len(A1), len(B1), len(C1), len(Af), len(Bf)]

        is_thumb_32 = False
        is_thumb_16 = False

        for pn, pat in enumerate(patterns):
            match = True
            for i in range(len(pat) - 1):
                if pat[i] != -1 and pat[i] != cmp_pat[i]:
                    match = False

            if match:
                if pat[i + 1]:
                    is_thumb_32 = True
                else:
                    is_thumb_16 = True

        final_insn = None

        if is_thumb_16 and is_thumb_32:
            r1s = ""
            r2s = ""
            r1s = "%s %s" % (C1[0].mnemonic, C1[0].op_str)
            r2s = "%s %s" % (Bf[0].mnemonic, Bf[0].op_str)

            log.debug("DUEL [%s] [%s]", r1s, r2s)
            assert len(Bf) == 1

            l = C1[0].address
            r = Bf[0].address
            initial_r1 = None
            initial_r2 = None

            for i in range(6):
                r1 = self.disasm_back_single(l)
                r2 = self.disasm_back_single(r)

                if i == 0:
                    initial_r1 = r1
                    initial_r2 = r2

                if r1:
                    r1s = "%s %s" % (r1.mnemonic, r1.op_str)
                if r2:
                    r2s = "%s %s" % (r2.mnemonic, r2.op_str)

                if r1 and r2:
                    log.debug("DUEL AGAIN [%s] [%s]", r1s, r2s)
                    l = r1.address
                    r = r2.address
                else:
                    if not r1:
                        initial_r1 = None
                    if not r2:
                        initial_r2 = None

                    log.debug("DUEL WORKED [%s] [%s]", r1s, r2s)
                    break

            if initial_r1 and initial_r2:
                raise ValueError("DUEL FAILED [%s] [%s]" % (r1s, r2s))

            if initial_r1:
                final_insn = initial_r1
            if initial_r2:
                final_insn = initial_r2
        elif is_thumb_16:
            final_insn = C1[0]
        elif is_thumb_32:
            final_insn = Bf[0]
        # failure
        else:
            pass

        if final_insn is None:
            return None

        if detail:
            md.detail = True
            final_insn = list(md.disasm(final_insn.bytes, final_insn.address))[0]

        return final_insn

    def disasm_single(self, addr, mode=CS_MODE_THUMB, detail=False):
        md = Cs(CS_ARCH_ARM, mode)
        md.detail = detail

        data = self.read_memory(addr, 1, 4, raw=True)

        if len(data) != 4:
            raise ValueError("Short read when disassembling single")

        first_insns = list(md.disasm(data[:4], addr))

        # we're probably disassembling data...
        if len(first_insns) == 0:
            return None

        return first_insns[0]

    def disasm_get_insn_side_effects(self, insn):
        i = insn
        rr = i.regs_read
        rw = i.regs_write

        for pos, o in enumerate(i.operands):
            if o.type == ARM_OP_REG:
                if i.id in [ARM_INS_PUSH]:
                    rr += [o.value.reg]
                elif i.id in [ARM_INS_POP]:
                    rw += [o.value.reg]
                elif i.id in [ARM_INS_STR]:
                    if pos == 0:
                        rr += [o.value.reg]
                elif i.id in [ARM_INS_LDR]:
                    if pos == 0:
                        rw += [o.value.reg]
                elif i.id in [
                    ARM_INS_ADD,
                    ARM_INS_ADDW,
                    ARM_INS_MOV,
                    ARM_INS_MOVW,
                    ARM_INS_SUB,
                    ARM_INS_SUBW,
                ]:
                    if pos == 0:
                        rw += [o.value.reg]
                    else:
                        rr += [o.value.reg]
            elif o.type == ARM_OP_MEM:
                if i.id in [ARM_INS_STR, ARM_INS_LDR]:
                    if pos > 0:
                        rr += [o.value.mem.base, o.value.mem.index]

                        if i.writeback:
                            rw += [o.value.mem.base]
            else:
                pass

        return {"regs_read": rr, "regs_write": rw}

    def disasm_function_backwards(self, addr, mode=CS_MODE_THUMB):
        """disasm_function_backwards

        Attempt to recover the start of a function prolog from an initial address.
        Based on heuristics and assumed calling conventions.

        :param addr: The address midway through a function.
        :param mode: The Capstone ARM mode.
        """
        end_addr = addr

        insns = []

        insn = self.disasm_single(end_addr, mode=mode, detail=True)

        """
        TODO: we may want to make an effort to disassemble forward to
        determine if the function is a leaf (bx lr) or a non-leaf function
        (pop {..., lr}). This will allow us to avoid missing the possibly
        non-existant function prolog in a leaf function (e.g., only r0-r3 used)
        """

        INSN_STRIDE = 400

        while len(insns) < INSN_STRIDE:
            if insn is None:
                break

            insns += [insn]
            addr = insn.address

            side_effects = self.disasm_get_insn_side_effects(insn)
            rr = side_effects["regs_read"]
            rw = side_effects["regs_write"]

            # fucntion prolog likely found (in a non-leaf function at least)
            if (
                ARM_REG_SP in rw
                and ARM_REG_LR in rr
                and insn.id in [ARM_INS_PUSH, ARM_INS_STR]
            ):
                break

            insn = self.disasm_back_single(addr, mode=mode, detail=True)

        if len(insns) == 0:
            raise ValueError("Function is zero sized (wrong mode?)")

        if len(insns) == INSN_STRIDE:
            log.warning("Function likely leaf or larger than stride")

        log.debug("FUNCTION BOUNDS [0x%08x, 0x%08x]", insns[-1].address, end_addr)

        return insns
