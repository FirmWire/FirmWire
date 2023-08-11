## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct
import logging
import os
import sys
import time

import firmwire.vendor.shannon as shannon
import firmwire.vendor.shannon.soc
import firmwire.vendor.shannon.hooks
import firmwire.util.logging
import avatar2
import capstone
from firmwire.vendor.shannon.osi import ShannonOSI

from avatar2 import *

import firmwire.vendor.shannon.task

from firmwire.vendor.shannon.modkit import TaskMod, NOP_TASK_SNIPPET
from firmwire.emulator.firmwire import FirmWireEmu

from firmwire.util.BinaryPattern import BinaryPattern
from firmwire.util.unwind_arm import ARM32Unwinder
from firmwire.util.port import find_free_port
from firmwire.util.hex import hexdump

log = logging.getLogger(__name__)


class ShannonMachine(FirmWireEmu, ShannonOSI):
    def __init__(self):
        super().__init__()

        self.instance_name = "ShannonEMU"

        ################
        # TODO save these vars as snapshot metadata
        self.playground = None
        self.playground_offset = 0
        self.nop_task_address = None
        ################

        self.ports = {}
        self._fuzzing = False
        self.packet_log = None

    def pal_msg_logging_enable(self, log_file):
        if log_file == "-":
            self.packet_log = sys.stdout
        else:
            try:
                self.packet_log = open(log_file, "a")
            except IOError as e:
                log.error("Cannot open packet log file: %s", e)
                return

        log.info("Logging PAL packets to %s", self.packet_log)

    def pal_msg_logging_disable(self):
        if self.packet_log is None:
            return

        self.packet_log = None
        log.info("PAL packet log disabled")

    def pal_log_send_msg(self, task_name, qid_name, msg):
        if self.packet_log is None:
            return

        header = "[%.5f][TASK %s] PKT TX(%s) %s\n" % (
            self.time_running(),
            task_name,
            qid_name,
            repr(msg),
        )
        body = "No payload\n"

        if msg.size > 0:
            body = hexdump(msg.data, group=4, columns=8)

        self.packet_log.write("%s\n%s\n" % (header, body))

    def pal_log_recv_msg(self, task_name, qid_name, msg):
        if self.packet_log is None:
            return

        header = "[%.5f][TASK %s] PKT RX(%s) %s\n" % (
            self.time_running(),
            task_name,
            qid_name,
            repr(msg),
        )
        body = "No payload\n"

        if msg.size > 0:
            body = hexdump(msg.data, group=4, columns=8)

        self.packet_log.write("%s\n%s\n" % (header, body))

    def get_backtrace(self):
        qemu = self.qemu

        start_addr = qemu.regs.pc
        start_sp = qemu.regs.sp
        lr_reg = qemu.regs.lr

        is_thumb = bool((qemu.regs.cpsr >> 5) & 1)

        self.get_backtrace_at(start_addr, start_sp, lr_reg, is_thumb)

    def get_backtrace_at(self, start_addr, start_sp, lr_reg, is_thumb):
        unwound_frames = [[start_addr, start_sp]]

        log.info(
            "Getting backtrace from %08x [sp=%08x, thumb=%s]",
            start_addr,
            start_sp,
            is_thumb,
        )

        unwinder = ARM32Unwinder(self.qemu)

        log.info("~~~~~ Stack Trace ~~~~~")

        frame_count = 0

        # backtrace until a fault
        while True:
            try:
                prev_frame_pc, prev_frame_stack = unwinder.unwind_frame(
                    start_addr, start_sp, lr_reg=lr_reg, thumb=is_thumb
                )
            except ValueError as e:
                log.error(
                    "Failed to get full backtrace (last frame may be unreliable): %s", e
                )
                break

            if prev_frame_pc == 0:
                break

            # LR is not valid after one frame
            lr_reg = None

            unwound_frames += [[prev_frame_pc, prev_frame_stack]]

            log.info(
                "%s #%d %08x [sp=%08x]",
                "->" if frame_count == 0 else "  ",
                frame_count,
                prev_frame_pc,
                prev_frame_stack,
            )

            is_thumb = prev_frame_pc & 1
            start_addr = prev_frame_pc & ~1
            start_sp = prev_frame_stack
            frame_count += 1

        return unwound_frames

    def dump_at(self, addr, once=False):
        if once:
            log.info("Will dump CPU state once when 0x%0x is reached", addr)
        else:
            log.info("Will dump CPU state continuously when 0x%0x is reached", addr)

        def dump_fn(self):
            self.register_dump()
            self.qemu.cont()

        self.set_breakpoint(addr, dump_fn, temporary=once)

    # Override breakpointing to account for Thumb functions
    def set_breakpoint(self, address, handler, temporary=False, **kwargs):
        if address & 1:
            new_address = address & ~1
            log.warning(
                "Cannot set breakpoints on odd addresses in ARM mode. Adjusting %08x -> %08x",
                address,
                new_address,
            )
            address = new_address

        super().set_breakpoint(address, handler, temporary=temporary, **kwargs)

    def post_breakpoint_handler(self, bp_obj, result):
        if result is False:
            log.info("\nFATAL BREAKPOINT in %s" % bp_obj["handler"].__name__)
            self.register_dump()
            saved_cpsr = self.qemu.regs.cpsr
            saved_lr = self.qemu.regs.lr

            self.qemu.regs.cpsr = (saved_cpsr & 0xFFFFFFF0) | 0x3
            self.get_backtrace_at(saved_lr, self.qemu.regs.sp, self.qemu.regs.lr, True)
            self.qemu.regs.cpsr = saved_cpsr

    def register_dump(self):
        R = self.qemu.regs
        dump = """pc:  %08x      lr:  %08x      sp:  %08x
r0:  %08x      r1:  %08x      r2:  %08x
r3:  %08x      r4:  %08x      r5:  %08x
r6:  %08x      r7:  %08x      r8:  %08x
r9:  %08x      r10: %08x      r11: %08x
r12: %08x     cpsr: %08x""" % (
            R.pc,
            R.lr,
            R.sp,
            R.r0,
            R.r1,
            R.r2,
            R.r3,
            R.r4,
            R.r5,
            R.r6,
            R.r7,
            R.r8,
            R.r9,
            R.r10,
            R.r11,
            R.r12,
            R.cpsr,
        )

        log.info(dump)

        log.info(
            "lr: "
            + self.qemu.disassemble_pretty(
                addr=R.lr, mode=capstone.CS_MODE_THUMB
            ).strip()
        )
        log.info("pc: " + self.qemu.disassemble_pretty(addr=R.pc).strip())

    def hook_debug(self):
        self.install_hooks(shannon.hooks.mappings)

        panda = self.qemu.pypanda
        shannon.hooks.panda = panda

    def dump_memory_ranges(self):
        print("~~~ Memory ranges ~~~")
        for m in sorted(self.avatar.memory_ranges, key=lambda x: x.begin):
            if m.data.forwarded_to:
                print(
                    "%08x - %08x %s (%s)"
                    % (m.begin, m.end, m.data.name, m.data.forwarded_to.__class__)
                )
            else:
                print(
                    "%08x - %08x %s (%s)"
                    % (m.begin, m.end, m.data.name, m.data.permissions)
                )

    def find_safe_rwx_region(self):
        # find the top most, non-initialized, RWX region that isnt a peripheral
        for m in sorted(self.avatar.memory_ranges, key=lambda x: x.begin, reverse=True):
            size = m.end - m.begin
            if (
                size >= 0x10000
                and not m.data.forwarded_to
                and not m.data.file
                and m.data.permissions == "rwx"
                and m.begin != 0x45700000
            ):

                good = True

                # double check that our region wont be overwritten during the boot process
                for start, end in self.unsafe_regions:
                    if (
                        m.begin >= start
                        and m.begin < end
                        or m.end > start
                        and m.end < end
                    ):
                        good = False
                        break

                if good:
                    return m

        return None

    def inject_irq(self, irq, level):

        gic = self.qemu.pypanda.libpanda.configurable_get_peripheral(
            b"gic"
        )  # hardcoded mr-range name
        # the first 32irq are internal, nothing we cna do about them for now
        self.qemu.pypanda.libpanda.configurable_a9mp_inject_irq(gic, irq - 32, level)

    def initialize(self, loader, args):
        if not super().initialize(loader):
            return False

        avatar = self.avatar
        avatar.shannon = self  # create backwards reference for irq injection

        self.ports["qemu_gdb"] = 3333
        self.ports["qemu_qmp"] = 3334

        # Allocate ports
        if args.consecutive_ports:
            log.info(
                f"Using {len(self.ports.keys())} consecutive ports, starting with {args.consecutive_ports}"
            )
            for port_id, name in enumerate(self.ports):
                self.ports[name] = args.consecutive_ports + port_id

        # used for unique temporary directories and shared memory queues for avatar
        self.instance_name = "ShannonEMU" + str(self.ports["qemu_qmp"])

        # Load Ghidra symbols if available
        p, _ = os.path.splitext(loader.path)
        symbols_csv = p + ".csv"
        symbols_json = p + ".sym"
        symbols_json_lz4 = p + ".sym.lz4"

        # check for a jsonified symbol table first
        if os.access(symbols_json_lz4, os.R_OK):
            log.info("Loading compressed cached symbols from %s", symbols_json_lz4)

            self.symbol_table.load_compressed_json(symbols_json_lz4)

            log.info("Loaded %d symbols", len(self.symbol_table))
        elif os.access(symbols_json, os.R_OK):
            log.info("Loading cached symbols from %s", symbols_json)

            self.symbol_table.load_json(symbols_json)

            log.info("Loaded %d symbols", len(self.symbol_table))
        elif os.access(symbols_csv, os.R_OK):
            log.info("Loading symbols from %s", symbols_csv)

            self.symbol_table.load_ghidra_csv(symbols_csv)

            log.info("Loaded %d symbols", len(self.symbol_table))
            log.info("Saving symbols to %s", symbols_json)
            self.symbol_table.save_json(symbols_json)
        else:
            log.warning("No Ghidra symbol table found. Output will be addresses only")

        # XXX: Not tested with spaces in the file path (quotes dont work)
        additional_args = [
            "-drive",
            "if=none,id=drive0,file=%s,format=qcow2"
            % self.snapshot_manager.snapshot_qcow_path,
        ]
        # additional_args=['-drive', 'if=none,id=drive0,file=%s,format=qcow2' % snapshot_img,
        #'-trace', 'events=trace_events.txt']

        if args.fuzz_input is not None or args.fuzz_crashlog_replay is not None:
            if args.fuzz_input is not None:
                log.info(f"Inputs will be provided via {args.fuzz_input}")
                os.environ["AFL_INPUT_FILE"] = args.fuzz_input

            if args.fuzz_crashlog_replay is not None:
                log.info(f"Replaying inputs from {args.fuzz_crashlog_replay}")
                os.environ["AFL_INPUT_REPLAY_FILE"] = args.fuzz_crashlog_replay

            if args.fuzz_crashlog_dir is not None:
                os.environ["AFL_PERSISTENT_CRASH_LOG_DIR"] = args.fuzz_crashlog_dir

            # Limited to 255 panic addresses
            panic_addresses = [
                self.modem_soc.ENTRY_ADDRESS,  # reset vector
                self.modem_soc.ENTRY_ADDRESS + 0x4,  # undefined instruction
                self.modem_soc.ENTRY_ADDRESS + 0xC,  # prefetch abort
                self.modem_soc.ENTRY_ADDRESS + 0x10,
            ]  # data abort

            sym = self.symbol_table.lookup("OS_fatal_error")

            if not sym:
                log.error(
                    "Unable to tell AFL the modem's panic address due to a missing symbol"
                )
                return False

            panic_addresses += [sym.address]
            panic_addresses_fmt = ",".join([hex(x) for x in panic_addresses])
            os.environ["AFL_PANIC_ADDR"] = panic_addresses_fmt

            log.info("AFL panic address set [%s]", panic_addresses_fmt)

        # QEMU 'guest_errors' was used to figure out that Shannon has more than 16 MPU slots
        # Also try 'mmu' for fun
        # Try 'int' for interrupt debugging

        # log_items=["guest_errors", "mmu"]
        log_items = []

        if args.raw_asm_logging:
            log_items += ["in_asm"]

        qemu = avatar.add_target(
            PyPandaTarget,
            name=self.instance_name,
            gdb_executable="gdb-multiarch",
            gdb_port=self.ports["qemu_gdb"],
            qmp_port=self.ports["qemu_qmp"],
            entry_address=self.modem_soc.ENTRY_ADDRESS,
            log_file="/dev/stdout",
            additional_args=additional_args,
            log_items=log_items if len(log_items) else None,
        )

        self.qemu = qemu

        # Transfer the loader memory map to the target
        self.apply_memory_map(self.loader.memory_map)

        if log.isEnabledFor(logging.DEBUG):
            self.dump_memory_ranges()

        rwx_region = self.find_safe_rwx_region()

        if rwx_region is None:
            log.error("Unable to find safe RWX region in baseband memory to store code")
            return False
        else:
            log.info("Found RWX region [%08x - %08x]", rwx_region.begin, rwx_region.end)
            self.playground = rwx_region

        ##############################################################
        # Initialize the targets
        ##############################################################

        if args.fuzz:
            log.info("Fuzzing mode active (no debug output)")
            self._fuzzing = True

            # Panda will use _exit instead of exit to avoid cleanup
            # don't use during fuzz-triage to enable Panda coverage to be saved
            os.environ["AFL_FAST_EXIT"] = "1"

        if args.fuzz_persistent:
            loops = args.fuzz_persistent

            # NOTE: you MUST set this before avatar.init_targets !
            os.environ["AFL_ENABLE_PERSISTENT_MODE"] = str(loops)
            log.info("Fuzzing in persistent mode with %d iterations ", loops)

        # hijack PANDA's signal handling. we know better
        def fake_signal_handler(*args, **kwargs):
            # print("HIJACKED ", repr(args), repr(kwargs))
            pass

        from pandare import Panda

        Panda.setup_internal_signal_handler = fake_signal_handler
        Panda._setup_internal_signal_handler = fake_signal_handler
        avatar.init_targets()
        avatar.load_plugin("assembler")

        # Display debug information whenever not fuzzing and register plugins
        if not self._fuzzing:
            self.hook_debug()
            avatar.load_plugin("disassembler")

        if args.fuzz_triage:
            coverage_dir = self.workspace.path("/coverage")
            coverage_dir.mkdir()

            coverage_fn = coverage_dir.join(
                "coverage_" + os.path.basename(args.fuzz_input) + ".csv"
            )

            # TIP: if you want to see ALL basic blocks, including duplicates, pass {"full" : True}
            # Useful for spotting hot loops
            qemu.pypanda.load_plugin(
                "coverage", args={"filename": coverage_fn.to_path()}
            )
            log.info(
                "Triage mode active. Logging code coveage to %s", coverage_fn.to_path()
            )

        # if we're not starting at 0x0, change our vector table
        qemu.write_register("VBAR", self.modem_soc.ENTRY_ADDRESS)

        soc_per = self.get_peripheral("SOC")
        soc_per.chip_id = self.modem_soc.CHIP_ID

        # bypass an initial boot check to avoid crash (0x82001000)
        soc_per.warm_boot[0] = 0x1

        # write a 0x1 to signify that this is a cold RESET (0x82001004)
        soc_per.warm_boot[1] = 0x1

        # Boot packet
        shannon_cp = self.get_peripheral("SHM")
        shannon_cp.send_raw_packet(b"\x00" * 4 + b"\x0d\x90\x00\x00")
        shannon_cp.send_raw_packet(b"\x00" * 4 + b"\x00\x9f\x00\x00")

        # optional: disable log_printf for more speedup during fuzzing
        # logging will still be shown through PANDA hooks, but the target won't buffer it
        # self.qemu.wm(self.symbol_table.lookup("log_printf").address, 2, b"\x70\x47", raw=True)

        # Associate the symbol table with our peripherals
        for mem in self.avatar.memory_ranges:
            if hasattr(mem.data, "python_peripheral"):
                per = mem.data.python_peripheral
                per.symbol_table = self.symbol_table

        self.panda = self.qemu.pypanda
        shannon.hooks.panda = self.panda

        # Recent versions of Panda emit a warning when it is not used for more
        # than 5 seconds. However, we don't use the usual PANDA API, so this
        # warning would trigger. This is a temporary workaround, until we can
        # fix the warning behaviour in upstream.
        self.panda.athread.warned = True

        self.guest_logger.add_ban_string("/pal_NvStoreFlash.c")
        self.guest_logger.add_ban_string("/pal_Reg.c")

        if not self.handle_soc_quirks():
            log.error("SoC quirk error")
            return False

        return True

    def load_task_module(self, name):
        module = self.modkit.find_module(name)

        if module is None:
            log.error(
                "Unable to find module %s with search paths %s. Was it built?",
                name,
                [str(x) for x in self.modkit.get_search_paths()],
            )
            return None

        return TaskMod.FromFile(module.elf_path, module.bin_path)

    def load_and_inject_task(self, task):
        module = self.load_task_module(task)

        if module is None:
            log.error("Failed to load %s module", task)
            return False

        # make the task the lowest priority so it get scheduled once everything is initialized (during boot)
        # and conversely once any message it sends out is done processing
        res = self.inject_task(module, prio=0xFF)
        if not res:
            log.error("Failed to inject task into OS")
            return False

        return True

    def disable_task_by_id(self, idx):
        sym = self.symbol_table.lookup("pal_Sleep")

        if not sym:
            log.error("Unable to disable task without pal_Sleep symbol")
            return False

        if self.nop_task_address is None:
            self.nop_task_address = self.playground.begin + 0x4000
            log.info("Creating NOP task at 0x%08x", self.nop_task_address)

            pal_sleep = sym.address | 1
            nop_bytes = self.qemu.assemble(
                NOP_TASK_SNIPPET.format(pal_sleep), addr=self.nop_task_address
            )
            self.qemu.write_memory(
                self.nop_task_address, 1, nop_bytes, len(nop_bytes), raw=True
            )

        task_arr = self.symbol_table.lookup("SYM_TASK_LIST").address

        task_struct_addr = task_arr + idx * self.task_layout.SIZE()
        task_struct_data = self.qemu.rm(
            task_struct_addr, self.task_layout.SIZE(), raw=True
        )

        nulltask = shannon.task.Task(
            task_struct_addr, self.task_layout, raw_bytes=task_struct_data
        )

        nulltask.main_fn = self.nop_task_address | 0x1  # force thumb mode
        nulltask.pre_fn = 0  # zero disables this from being called

        self.qemu.wm(task_struct_addr, len(nulltask.data), nulltask.data, raw=True)

        return True

    def find_empty_task_slot(self):
        task_arr = self.symbol_table.lookup("SYM_TASK_LIST").address

        num_tasks = len(self.get_task_list())
        free_task_struct = task_arr + num_tasks * self.task_layout.SIZE()
        empty_task_idx = num_tasks

        return empty_task_idx, free_task_struct

    def find_empty_or_existing_task_slot(self, name):
        for idx, task in enumerate(self.get_task_list()):
            if task.name == name:
                return idx

        idx, _ = self.find_empty_task_slot()
        return idx

    def create_task(self, task, prio=0x7F):
        """
        Create a task using GLINK. This lets you create tasks after the baseband is booted

        NOTE: we still are using a hardcoded address here for
        CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar
        """
        if self.modem_soc.name != "S5000AP":
            log.error("New tasks can only be created at runtime for S5000AP")
            return False

        # find storage for our new task metadata
        empty_task_idx, empty_task_struct_addr = self.find_empty_task_slot()

        log.info(
            "Found empty task slot %d at 0x%08x", empty_task_idx, empty_task_struct_addr
        )

        # inject task into memory
        addr = self.inject_task(task, idx=empty_task_idx, prio=prio)
        if addr is None:
            return False

        log.info("Creating new task in slot %d", empty_task_idx)
        glink = self.get_peripheral("glink")

        log.info("Creating new task %s", repr(task))

        # create task using glink
        # Call pal_CreateTask to start it!
        # TODO: use symbol
        # 1 = start task now
        glink.call_function(0x40CBA468 + 1, [empty_task_struct_addr, 1])
        return addr

    def inject_task(self, task, idx=None, prio=0x7F):
        """
        injects a task in TASK_LIST at given idx
        """

        assert type(task) == TaskMod

        if task.address != 0:
            log.error("Mods must be position independent code (-fPIE)!")
            return False

        playground_size = self.playground.end - (
            self.playground.begin + self.playground_offset
        )

        if len(task.data) > playground_size:
            log.error("Out of space to inject task data!")
            return False

        # find empty or existing task name
        if idx is None:
            for i, t in enumerate(self.get_task_list()):
                if t.name == task.task_name:
                    idx = i
                    log.warning(
                        "Found existing injected task %s. Overwriting...", t.name
                    )
                    break

            if idx is None:
                idx, _ = self.find_empty_task_slot()
                log.info("Found empty task slot %d for injection", idx)

        task_base = self.playground.begin + self.playground_offset

        task = task.rebase(task_base)
        log.info("Injecting task %s -> slot %d", repr(task), idx)

        # inject code
        self.qemu.write_memory(task.address, len(task.data), task.data, raw=True)

        # TODO: fix this to actually calculate the task size
        self.playground_offset += 0x8000  # len(task.data) #+ task.stack_size

        # align up
        if self.playground_offset % 0x1000:
            self.playground_offset += 0x1000 - (self.playground_offset % 0x1000)

        # perform dynamic linking to baseband symbols and functions
        for sym_name, kw in task.symbols.items():
            sym = self.symbol_table.lookup(sym_name, single=True)

            if sym is None:
                log.error(
                    "Unable to resolve requested dynamic modkit symbol %s", sym_name
                )
                return False

            sym_type = kw["type"]
            kw["symbol"] = sym

            write_address = kw["write_address"]
            write_size = kw["size"]

            if write_size > 4:
                log.error("Symbols must be <= 4 bytes")
                return False

            if sym_type == "FUNC":
                # XXX: this assumes all requested baseband symbols are thumb functions!!!
                addr = sym.address | 1
            else:
                addr = sym.address

            log.info(
                "Resolved dynamic symbol %s (0x%08x) -> 0x%08x (%s, %d bytes)",
                sym_name,
                addr,
                write_address,
                sym_type,
                write_size,
            )
            self.qemu.wm(write_address, write_size, struct.pack("<I", addr), raw=True)

        # resolve a free place in OSTASK_ARR
        task_arr = self.symbol_table.lookup("SYM_TASK_LIST").address

        task_struct_addr = task_arr + idx * self.task_layout.SIZE()
        task_struct_data = self.qemu.rm(
            task_struct_addr, self.task_layout.SIZE(), raw=True
        )

        task_struct = shannon.task.Task(
            task_struct_addr, self.task_layout, raw_bytes=task_struct_data
        )

        if any(b != 0 for b in task_struct_data):
            log.warning("Overwriting an existing task")

        task_struct.name_ptr = task.name_addr
        task_struct.main_fn = task.main_addr

        # TODO: just let the baseband allocate the stack
        # It will do so if the stackbase is 0!
        task_struct.stackbase = task.stack_base
        task_struct.stacksize = task.stack_size
        task_struct.sched_prio = prio

        log.info(
            "Injecting Task at 0x{:x} (stack: 0x{:x})".format(
                task.address, task.stack_base
            )
        )

        self.qemu.wm(
            task_struct_addr, len(task_struct.data), task_struct.data, raw=True
        )

        log.info("Injected!")

        return task.address

    def get_queue_list(self):
        return self.get_queues()

    def get_task_list(self):
        return self.get_tasks()

    def print_task_list(self):
        log.info("==== Task List ====")

        # print task table
        for i, task in enumerate(self.get_task_list()):
            if (task.main_fn & ~1) == self.nop_task_address:
                log.info("TASK%d: %s [DISABLED]", i, task.name)
            elif task.main_fn == 0:
                log.info("TASK%d: %s [HISR TASK]", i, task.name)
            else:
                log.info("TASK%d: %s (0x%08x)", i, task.name, task.main_fn)

    def handle_soc_quirks(self):
        def set_key(self):
            print("Changing boot key")
            self.qemu.wm(self.qemu.regs.r0, 1, 1)
            self.qemu.regs.r0 = 1
            self.qemu.cont(blocking=False)
            return True

        def single_step(self):
            shannon_debug.panda_step_debug(self)
            self.qemu.cont(blocking=False)
            return True

        def get_backtrace(x):
            self.get_backtrace()

        def ipy(self):
            import IPython

            IPython.embed()

        tasks = self.get_task_list()

        if len(tasks) < 10:
            log.error("Task list too small - likely OSI error")
            return False

        # fixup dsp sync word
        dsp_periph = self.peripheral_map["DSPPeripheral"]
        sym_sync_0 = self.symbol_table.lookup("DSP_SYNC_WORD_0")
        sym_sync_1 = self.symbol_table.lookup("DSP_SYNC_WORD_1")
        if sym_sync_0 is not None and sym_sync_1 is not None:
            dsp_periph.dsp_sync0 = self.symbol_table.lookup("DSP_SYNC_WORD_0").address
            dsp_periph.dsp_sync1 = self.symbol_table.lookup("DSP_SYNC_WORD_1").address

        disable_list = []

        if self.modem_soc.name == "S5000AP":
            self.set_breakpoint(
                self.symbol_table.lookup("boot_key_check").address, set_key
            )
            disable_list += ["SHM"]  # need to configure SBD

        # HACK for CP_G950FXXU1AQI7 and G960
        elif self.modem_soc.name in ["S355AP", "S360AP"]:

            def ff2(self):
                # Dynamic Voltage and Frequency Scaling!
                # This is the minimum amount of mhz (?) in the DVFS table
                # We need to modify clkperipheral to have this value be generated naturally
                # 0x0215  0x0100  0xffff  0x0707
                # self.qemu.regs.r0 = 0x215 # 533MHz
                self.qemu.regs.r0 = self.qemu.regs.r1
                self.qemu.cont(blocking=False)

            # "error - Unkown Freq value in hw_ClkFindSysClkCofigInfoIndex()"
            self.set_breakpoint(
                self.symbol_table.lookup("QUIRK_SXXXAP_DVFS_HACK").address, ff2
            )

            disable_list += ["UDATA"]  # Rabm timer NULL
            disable_list += ["InitPacketHandler"]  # similar to SHM on S5000
            disable_list += ["PacketHandler"]
            disable_list += ["Acpm"]  # timeout twice OS_fatal_error
            disable_list += ["L1C"]  # hang for S360

        elif self.modem_soc.name == "S335AP":

            def ff2(self):
                self.qemu.regs.r0 = self.qemu.regs.r1
                self.qemu.cont(blocking=False)

            # "error - Unkown Freq value in hw_ClkFindSysClkCofigInfoIndex()"
            self.set_breakpoint(
                self.symbol_table.lookup("QUIRK_SXXXAP_DVFS_HACK").address, ff2
            )

            # [ERROR] FATAL ERROR (L1C): from 0x4071e7dd [L1_Exit.c:173 - DBG_Point : file:L1AUDSQ, line:147,[P1:0x00000000,P2:0x00000000,P2:0x00000000], reason:Dev Assert SqIniAllocDspBuffer Fail [0 : 0 : 0]]
            disable_list += ["L1C"]  # see above

            disable_list += ["InitPacketHandler"]  # similar to SHM on S5000
            disable_list += ["PacketHandler"]
            disable_list += ["SIM"]

        elif self.modem_soc.name == "S337AP":
            # This is a hack to prevent a memclr of the SHM region
            # The clear is really slow because SHM is via remote memory
            addr = self.symbol_table.lookup("QUIRK_S337AP_SHM_HACK").address
            self.qemu.wm(addr, 4, 0) # 4 zero bytes is effectively a nop (andeq r0, r0, r0)

            disable_list += ["UDATA"]  # Rabm timer NULL
            disable_list += ["SHM"]  # takes a ton of CPU time
            disable_list += ["SIM_SAP"]  # hangs when initing DS_SIM

        task_id_by_name = {
            name: i for i, name in enumerate([t.name for t in self.get_task_list()])
        }

        for task_name in disable_list:
            if task_name not in task_id_by_name:
                log.error("Cannot find task '%s' to disable", task_name)
                return False

            log.info("Disabling task '%s'", task_name)

            task_id = task_id_by_name[task_name]

            if not self.disable_task_by_id(task_id):
                log.error("Failed to disable task '%s' (id=%d)", task_name, task_id)
                return False

        return True
