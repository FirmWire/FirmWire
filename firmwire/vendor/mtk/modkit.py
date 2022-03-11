## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import os
import copy
import struct
from elftools.elf.elffile import ELFFile


class TaskMod(object):
    def __init__(self, name):
        self.name = name

        self.elf = None
        self.data = b""

        self.address = 0
        self.main_addr = 0
        self.name_addr = 0
        self.stack_base = 0
        self.stack_size = 0

        self.symbols = {}

    def rebase(self, base):
        old_base = self.address

        task_copy = copy.copy(self)
        rebased_sym = copy.deepcopy(self.symbols)
        rebased_data = copy.deepcopy(self.data)

        task_copy.main_addr = self.main_addr - old_base + base
        task_copy.name_addr = self.name_addr - old_base + base
        task_copy.stack_base = self.stack_base - old_base + base

        for name, sym in rebased_sym.items():
            sym["write_address"] = sym["write_address"] - old_base + base
            print(f"sym '{name}' -> {sym['write_address']:x}, sym: {sym}")

        task_copy.address = base
        task_copy.symbols = rebased_sym
        task_copy.data = rebased_data

        # rebase the GOT and data relocations
        self._rebase_section(task_copy, base, ".got")
        self._rebase_section(task_copy, base, ".data.rel.local")

        return task_copy

    def _rebase_section(self, task_copy, base, section):
        section = self.elf.get_section_by_name(section)

        if not section:
            return

        old_base = self.address
        offset = section.header.sh_addr
        offset_end = offset + section.header.sh_size

        from binascii import hexlify

        print(
            f"Rebasing section {section} from old_base={old_base:x} to new_base={base:x}"
        )
        for off in range(offset, offset_end, 4):
            d = self.data[off : off + 4]
            entry = struct.unpack("<I", d)[0]
            print("Rebasing entry ", hexlify(d), "=>", entry, hex(entry))
            new_entry = entry - old_base + base
            print("New entry: ", new_entry, hex(new_entry))
            try:
                task_copy.data = (
                    task_copy.data[:off]
                    + struct.pack("<I", new_entry)
                    + task_copy.data[off + 4 :]
                )
            except struct.error:
                # Skip for values which go out of the 32 bit range (which means we are relocating metadata)
                continue

    def resolve_symbol(self, symbol):
        """
        Resolves a symbol of the task ELF file (and not of the shannon-fw)
        """
        symtab = self.elf.get_section_by_name(".symtab")
        return symtab.get_symbol_by_name(symbol)[0].entry.st_value

    @staticmethod
    def FromFile(elf_file, raw_file):
        self = TaskMod(os.path.basename(elf_file))

        self.elf_file = open(elf_file, "rb")
        elf = ELFFile(self.elf_file)
        self.elf = elf
        symtab = elf.get_section_by_name(".symtab")

        # base address of binary
        self.address = self.resolve_symbol("_TASK_START")

        stack = elf.get_section_by_name(".stack")

        # all offsets are relative to start of .text section (for PIE)
        self.main_addr = self.resolve_symbol("task_main") | 1
        self.name_addr = self.resolve_symbol("TASK_NAME")
        self.stack_size = self.resolve_symbol("_STACK_SIZE")

        self.stack_base = stack.header.sh_addr + self.stack_size  # base is on the top

        for sym in symtab.iter_symbols():
            # __SYMREQ_FUNC_<name>
            # __SYMREQ_DATA_<name>
            if sym.name.startswith("__SYMREQ_"):
                sym_name = sym.name[len("__SYMREQ_") :]
                sym_type = sym_name.split("_")[0]

                if sym_type not in ["DATA", "FUNC"]:
                    raise ValueError(
                        "Unsupported symbol type %s from %s" % (sym_type, sym.name)
                    )

                sym_name = sym_name[len(sym_type) + 1 :]

                self.symbols[sym_name] = {
                    "write_address": sym.entry.st_value,
                    "type": sym_type,
                }

        with open(raw_file, "rb") as f:
            self.data = f.read()

        return self

    def __repr__(self):
        return "<TaskMod '%s' base 0x%08x>" % (self.name, self.address)


NOP_TASK_SNIPPET = """
push	{{lr}}

looper:

ldr r1, sleep
mov  r0, #255
lsl r0, r0, #12

blx	r1
b.n	looper
.balign 16
sleep:
.word	0x{:x}
"""
