"""Load the known ThreadX timer ELF through FirmWire's normal loader path."""
import logging
from pathlib import Path

from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

import firmwire.loader
from firmwire.util.symbol import SymbolType
from firmwire.vendor.shannon.loader import ARM_CORTEX_R7

from .board import RAM_BASE, RAM_SIZE, add_board_memory
from .machine import ThreadXTestMachine

log = logging.getLogger(__name__)

REQUIRED_SYMBOLS = {
    "main", "threadx_board_timer_init", "threadx_board_irq_dispatch",
    "thread_0", "thread_0_counter", "_tx_thread_current_ptr",
    "_tx_timer_system_clock", "_tx_thread_sleep",
    "board_timer_irq_count", "board_unexpected_irq_count",
}


class ThreadXTestLoader(firmwire.loader.Loader):
    NAME = "threadx_test"
    LOADER_ARGS = {
        "verify": {
            "type": int, "choices": [0, 1], "default": 1,
            "help": "Log the first timer-driven ThreadX sleep/wake check (default: 1)",
        },
    }

    @property
    def ARCH(self):
        return ARM_CORTEX_R7

    @staticmethod
    def is_relevant(path):
        try:
            with open(path, "rb") as stream:
                header = stream.read(20)
            return (len(header) == 20 and header[:6] == b"\x7fELF\x01\x01"
                    and header[18:20] == b"\x28\x00")
        except OSError:
            return False

    def try_load(self):
        try:
            image = Path(self.path).resolve(strict=True)
            with image.open("rb") as stream:
                elf = ELFFile(stream)
                if (elf.elfclass != 32 or not elf.little_endian
                        or elf["e_machine"] != "EM_ARM" or elf["e_type"] != "ET_EXEC"):
                    raise ValueError("Expected a 32-bit little-endian ARM executable.")

                symbols = elf.get_section_by_name(".symtab")
                if symbols is None:
                    raise ValueError("Use the unstripped sample_threadx_timer.out.")
                self.elf_symbols = {}
                for symbol in symbols.iter_symbols():
                    if not symbol.name or symbol["st_shndx"] == "SHN_UNDEF":
                        continue
                    symbol_type = symbol["st_info"]["type"]
                    if symbol_type not in ("STT_FUNC", "STT_OBJECT", "STT_NOTYPE"):
                        continue
                    if symbol.name.startswith("$"):
                        continue
                    address = int(symbol["st_value"])
                    self.elf_symbols[symbol.name] = address
                    ty = SymbolType.FUNCTION if symbol_type == "STT_FUNC" else SymbolType.DATA_LABEL
                    self.symbol_table.add(symbol.name, address, ty=ty)

                missing = REQUIRED_SYMBOLS - self.elf_symbols.keys()
                if missing:
                    raise ValueError("This is the ThreadX test-board loader, not a general ELF loader. "
                                     "Missing symbols: " + ", ".join(sorted(missing)))

                segments = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
                if len(segments) != 1:
                    raise ValueError("Expected the test ELF's single LOAD segment.")
                segment = segments[0]
                if segment["p_paddr"] != RAM_BASE or segment["p_vaddr"] != RAM_BASE:
                    raise ValueError("The test image must load at address zero.")
                if not 0 < segment["p_filesz"] <= segment["p_memsz"] <= RAM_SIZE:
                    raise ValueError("Invalid segment sizes or image exceeds test RAM.")
                if segment["p_offset"] + segment["p_filesz"] > image.stat().st_size:
                    raise ValueError("LOAD segment extends beyond the ELF file.")
                self.entry_point = int(elf["e_entry"])
                if self.entry_point & 3 or not 0 <= self.entry_point < segment["p_filesz"]:
                    raise ValueError("Expected an aligned ARM entry in the loaded image.")
                segment_bytes = segment.data()

            storage = self.workspace.path("/loader")
            storage.mkdir()
            segment_path = storage.join("threadx_segment.bin").to_path()
            segment_path.write_bytes(segment_bytes)
            add_board_memory(self, segment_path)
            self._machine_class = ThreadXTestMachine
            log.info("ThreadX test ELF: entry=0x%08x, file=0x%x, RAM=0x%x",
                     self.entry_point, len(segment_bytes), RAM_SIZE)
            return True
        except (OSError, ELFError, ValueError, KeyError) as error:
            log.error("Cannot load ThreadX test ELF: %s", error)
            return False


firmwire.loader.register_loader(ThreadXTestLoader)
