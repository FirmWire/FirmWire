"""Manage the test board through FirmWireEmu and avatar2's PyPandaTarget."""
import logging
import struct
from pathlib import Path

from avatar2 import PyPandaTarget
from firmwire.emulator.firmwire import FirmWireEmu

log = logging.getLogger(__name__)


def _avatar_owns_signal_handling(*args, **kwargs):
    # Match ShannonMachine.initialize: Avatar/FirmWire owns process signals.
    # Both names are needed because this PANDA fork's run() calls the public
    # name while avatar2 calls the private name.
    pass


def _verify_sleep_checkpoint(machine):
    symbols = machine.loader.elf_symbols
    if machine.read_u32("_tx_thread_current_ptr") != symbols["thread_0"]:
        return True

    counter = machine.read_u32("thread_0_counter")
    ticks = machine.read_u32("_tx_timer_system_clock")
    irqs = machine.read_u32("board_timer_irq_count")
    unexpected = machine.read_u32("board_unexpected_irq_count")

    if machine.verify_start_ticks is None:
        if counter != 1:
            machine.verification_passed = False
            log.error("THREADX TEST FAIL: first sleep checkpoint had unexpected counter %d", counter)
            machine.remove_breakpoint(machine.verify_breakpoint)
            machine.verify_breakpoint = None
            return False
        machine.verify_start_ticks = ticks
        machine.verify_start_irqs = irqs
        log.info("THREADX TEST: thread 0 reached its first sleep (counter=1, ticks=%d)", ticks)
    elif counter >= 2:
        elapsed = (ticks - machine.verify_start_ticks) & 0xffffffff
        irq_delta = (irqs - machine.verify_start_irqs) & 0xffffffff
        machine.verification_passed = elapsed >= 10 and irq_delta >= 10 and unexpected == 0
        report = log.info if machine.verification_passed else log.error
        report("THREADX TEST %s: counter=%d elapsed_ticks=%d timer_irqs=%d "
               "irq_delta=%d unexpected_irqs=%d",
               "PASS" if machine.verification_passed else "FAIL", counter,
               elapsed, irqs, irq_delta, unexpected)
        machine.remove_breakpoint(machine.verify_breakpoint)
        machine.verify_breakpoint = None
    return True


class ThreadXTestMachine(FirmWireEmu):
    def __init__(self):
        super().__init__()
        self.instance_name = "ThreadXTestEMU"
        self.ports = {"qemu_gdb": 3333, "qemu_qmp": 3334}
        self._fuzzing = False
        self.verify_breakpoint = None
        self.verify_start_ticks = None
        self.verify_start_irqs = None
        self.verification_passed = None

    def initialize(self, loader, args):
        if any(getattr(args, key, None) for key in
               ("fuzz", "fuzz_triage", "fuzz_persistent", "injected_task")):
            log.error("The ThreadX test-board plugin currently supports execution/debugging; "
                      "ModKit and fuzzing hooks have not been implemented.")
            return False
        if not super().initialize(loader):
            return False

        first_port = getattr(args, "consecutive_ports", None)
        if first_port is not None:
            if not 1 <= first_port <= 65534:
                log.error("Need two valid consecutive ports.")
                return False
            self.ports = {"qemu_gdb": first_port, "qemu_qmp": first_port + 1}

        additional_args = [
            "-drive", "if=none,id=drive0,file=%s,format=qcow2" %
            self.snapshot_manager.snapshot_qcow_path,
        ]
        qemu = self.avatar.add_target(
            PyPandaTarget,
            name=self.instance_name,
            cpu_model=loader.ARCH.cpu_model,
            entry_address=loader.entry_point,
            gdb_executable="gdb-multiarch",
            # Give Avatar's internal GDB the ARM/Thumb mapping symbols too.
            gdb_additional_args=["--se=" + str(Path(loader.path).resolve())],
            gdb_port=self.ports["qemu_gdb"],
            qmp_port=self.ports["qemu_qmp"],
            additional_args=additional_args,
            log_items=["in_asm"] if getattr(args, "raw_asm_logging", False) else None,
            log_file="/dev/stdout",
        )
        self.qemu = qemu
        self.apply_memory_map(loader.memory_map)

        from pandare import Panda
        Panda.setup_internal_signal_handler = _avatar_owns_signal_handling
        Panda._setup_internal_signal_handler = _avatar_owns_signal_handling
        self.avatar.init_targets()
        self.panda = qemu.pypanda
        self.panda.athread.warned = True

        qemu.write_register("cpsr", 0xd3)
        qemu.write_register("pc", loader.entry_point)
        qemu.write_register("VBAR", 0)

        if loader.loader_args["verify"]:
            self.verify_breakpoint = self.set_breakpoint(
                loader.elf_symbols["_tx_thread_sleep"] & ~1,
                _verify_sleep_checkpoint,
                continue_after=True,
            )
            if self.verify_breakpoint < 0:
                log.error("Could not install the ThreadX verification breakpoint.")
                return False
        log.info("ThreadX test board initialized through FirmWire: CPU=%s, entry=0x%08x",
                 loader.ARCH.cpu_model, loader.entry_point)
        return True

    def read_u32(self, symbol_name):
        address = self.loader.elf_symbols[symbol_name]
        data = self.qemu.read_memory(address, 1, num_words=4, raw=True)
        return struct.unpack("<I", data)[0]
