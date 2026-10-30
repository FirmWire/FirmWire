#!/usr/bin/env python3
"""Run the ThreadX timer demo with FirmWire/Shannon emulated peripherals.

Place this launcher in the FirmWire checkout and use the working FirmWire
Python environment/container. Build sample_threadx_timer.out with the companion
installer and build script. The machine contains RAM, Shannon's Cortex-R7 CPU
definition, an a9mpcore_priv GIC, and a periodic shannon_timer on IRQ 34.

Usage:
    python3 run_threadx_timer.py /path/to/sample_threadx_timer.out
    python3 run_threadx_timer.py /path/to/sample_threadx_timer.out --inspect-only

This is a separate test board using FirmWire's PANDA backend. It does not register
a new vendor loader in the FirmWire CLI. Confirm the actual wake behavior in GDB.

Sources:
https://github.com/FirmWire/FirmWire/blob/master/firmwire/vendor/shannon/loader.py
https://github.com/FirmWire/panda/blob/main/hw/timer/shannon_timer.c
https://github.com/FirmWire/panda/blob/main/hw/cpu/a9mpcore.c
https://github.com/FirmWire/panda/blob/main/hw/avatar/configurable_machine.c
"""

import argparse
import json
import shlex
import sys
import tempfile
from pathlib import Path


RAM_SIZE = 2 * 1024 * 1024
GIC_BASE = 0x80000000
TIMER_BASE = 0x82008000
TIMER_IRQ = 34
TIMER_CLOCK_HZ = 100000


def timer_peripherals():
    # The Shannon timer looks up the interrupt controller by the name "gic".
    # The native configurable machine connects the GIC's outputs to the CPU.
    return [
        {
            "name": "gic", "address": GIC_BASE, "size": 0x2000,
            "qemu_name": "a9mpcore_priv", "bus": "sysbus",
            "properties": [
                {"name": "num-cpu", "type": "uint32", "value": 1},
                {"name": "num-irq", "type": "uint32", "value": 64},
            ],
        },
        {
            "name": "threadx_tick_timer", "address": TIMER_BASE, "size": 0x100,
            "qemu_name": "shannon_timer", "bus": "sysbus",
            "properties": [
                {"name": "irq_num", "type": "uint32", "value": TIMER_IRQ},
                {"name": "freq", "type": "uint32", "value": TIMER_CLOCK_HZ},
                {"name": "gic_model", "type": "uint32", "value": 0},
            ],
        },
    ]


def image_config(image):
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError as exc:
        raise RuntimeError(
            "pyelftools is missing. Use the Python environment where FirmWire "
            "and its requirements are installed."
        ) from exc

    with image.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.elfclass != 32 or not elf.little_endian:
            raise ValueError("This launcher expects a 32-bit little-endian ELF.")
        if elf["e_machine"] != "EM_ARM" or elf["e_type"] != "ET_EXEC":
            raise ValueError("This launcher expects an ARM executable ELF.")

        symbols = elf.get_section_by_name(".symtab")
        names = set() if symbols is None else {symbol.name for symbol in symbols.iter_symbols()}
        required = {"threadx_board_timer_init", "threadx_board_irq_dispatch"}
        if not required.issubset(names):
            raise ValueError("Use sample_threadx_timer.out built with the timer demo hooks.")

        segments = [s for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        if len(segments) != 1:
            raise ValueError("This launcher supports the sample's single LOAD segment.")
        segment = segments[0]
        if segment["p_paddr"] != 0 or segment["p_vaddr"] != 0:
            raise ValueError("The sample LOAD segment must start at address zero.")
        if not 0 < segment["p_filesz"] <= segment["p_memsz"] <= RAM_SIZE:
            raise ValueError("Invalid LOAD sizes or image exceeds the 2 MiB test RAM.")
        if segment["p_offset"] + segment["p_filesz"] > image.stat().st_size:
            raise ValueError("The LOAD segment extends beyond the ELF file.")
        entry = elf["e_entry"]
        if entry & 3 or not 0 <= entry < segment["p_filesz"]:
            raise ValueError("Expected an ARM-mode entry within the loaded image.")

        memory = {
            "name": "threadx_ram",
            "address": 0,
            "size": RAM_SIZE,
            "permissions": "rwx",
            "file": str(image),
            "file_offset": segment["p_offset"],
            "file_bytes": segment["p_filesz"],
        }
        config = {
            # Use the actual ELF entry (_start); exception vectors stay at zero.
            "entry_address": entry,
            "memory_mapping": [memory, *timer_peripherals()],
        }
        print(f"ELF: {image}")
        print(f"Entry: 0x{entry:08x}")
        print(f"Loaded bytes: 0x{segment['p_filesz']:x}")
        print(f"Image memory: 0x{segment['p_memsz']:x}")
        print(f"Test RAM: 0x00000000..0x{RAM_SIZE - 1:08x}")
        return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf", type=Path, help="The rebuilt sample_threadx_timer.out")
    parser.add_argument("--port", type=int, default=3333, help="Local GDB port (3333)")
    parser.add_argument("--inspect-only", action="store_true", help="Check the ELF without starting PANDA")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")

    try:
        image = args.elf.expanduser().resolve(strict=True)
        config = image_config(image)
        if args.inspect_only:
            print(json.dumps(config, indent=2))
            return 0

        try:
            from firmwire.vendor.shannon.loader import ARM_CORTEX_R7
            from pandare import Panda
        except ImportError as exc:
            raise RuntimeError(
                f"FirmWire runtime import failed: {exc}. Put this launcher in "
                "the FirmWire checkout and run it in FirmWire's working Python "
                "environment/container. Use FirmWire's PANDA fork."
            ) from exc

        config["cpu_model"] = ARM_CORTEX_R7.cpu_model
        print(f"CPU model from Shannon: {config['cpu_model']}")
        print(f"Shannon timer: 0x{TIMER_BASE:08x}, IRQ {TIMER_IRQ}, input {TIMER_CLOCK_HZ} Hz")

        # The configuration points at the ELF's segment bytes directly. The rest
        # of the RAM is initially zero, including .bss and spare application RAM.
        with tempfile.TemporaryDirectory(prefix="threadx-panda-") as work:
            config_file = Path(work) / "threadx-machine.json"
            config_file.write_text(json.dumps(config, indent=2))

            print("In another terminal in the same host/container, run:")
            print(f"  gdb-multiarch -q {shlex.quote(str(image))}")
            print("Then enter these GDB commands:")
            print(f"  target remote 127.0.0.1:{args.port}")
            print("  set $cpsr = 0xd3")
            print("  tbreak main")
            print("  continue")
            print("  watch thread_0_counter")
            print("  continue")
            print("  print thread_0_counter")
            print("  print _tx_timer_system_clock")
            print("  continue")
            print("  print thread_0_counter")
            print("  print _tx_timer_system_clock")
            print("  print board_timer_irq_count")
            print("  print board_unexpected_irq_count")
            print("Wake test: counter should change 1 -> 2 as the tick clock advances.")
            print("The target starts paused; keep this terminal open.", flush=True)

            panda = Panda(
                arch="arm",
                extra_args=[
                    "-M", "configurable",
                    "-kernel", str(config_file),
                    "-S",
                    "-gdb", f"tcp:127.0.0.1:{args.port}",
                    "-display", "none",
                    "-serial", "none",
                    "-monitor", "none",
                ],
            )
            # FirmWire's fork defines the private method, while Panda.run()
            # calls the public name. Keep the actual signal handling active.
            if not hasattr(panda, "setup_internal_signal_handler"):
                panda.setup_internal_signal_handler = panda._setup_internal_signal_handler
            # GDB controls this run; an empty Python task queue is intentional.
            panda.athread.warned = True
            panda.run()
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"Launcher error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
