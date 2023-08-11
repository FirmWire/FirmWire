## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging
import sys
import os
import time
import tempfile

from abc import ABC, abstractmethod
from types import MethodType  # Panda unassigned access

from ..modkit import ModKit
from .guestlogs import FirmWireGuestLogger
from .snapshot import QemuSnapshotManager
from ..hw.soc import SOCPeripheral

from firmwire.util.misc import copy_function

from firmwire.memory_map import MemoryMapEntryType
from avatar2 import Avatar, TargetStates
from avatar2.peripherals.avatar_peripheral import AvatarPeripheral

log = logging.getLogger(__name__)


class FirmWireEmu(ABC):
    """The base class for the FirmWire baseband emulation platform

    This class contains the common functions and data to create baseband vendor specific plugins.
    """

    def __init__(self):
        self.instance_name = "FirmwireEMU"

        self.avatar = None
        self.qemu = None
        self.panda = None
        self.loader = None
        self.modkit = ModKit()

        self.snapshot_manager = None

        self.installed_hooks = {}
        self._bp_map = {}
        self.peripheral_map = {}
        self.guest_logger = FirmWireGuestLogger(self)

        self.signal_count = 0
        self.start_time = None

    def set_breakpoint(self, address, handler, temporary=False, continue_after=False):
        """
        Wrap a QEMU breakpoint into a FirmWire breakpoint at a target address with a provided handler

        There are some complications regarding snapshots. If breakpoint functions are defined in a
        <local> namespace, snapshot pickling/restoring will not work. If all possible functions that
        can be used as snapshot handlers are not hoisted BEFORE a snapshot operation, bad things will
        occur (AttributeError).
        """
        bid = self.qemu.set_breakpoint(address, temporary=temporary)
        assert bid not in self._bp_map

        # Avoid recursive hoisting - when restoring, we call set_breakpoint
        if not handler.__name__.startswith("FirmWireEmu."):
            basename = "_bp_firmwire_%s_%s" % (handler.__name__, address)
            new_name = "FirmWireEmu." + basename

            # In order to properly snapshot, we need to maintain breakpoint state.
            # This means the handler functions too.
            # These might be local functions though, so we need to hoist them to the global namespace
            # Lambda functions are NOT supported
            handler = copy_function(handler, __name__, new_name)
            setattr(FirmWireEmu, basename, handler)

        self._bp_map[bid] = {
            "address": address,
            "handler": handler,
            "temporary": temporary,
            "continue_after": continue_after,
        }
        return bid

    def remove_breakpoint(self, bid):
        """Remove a FirmWire breakpoint by its ID"""
        if bid not in self._bp_map:
            raise ValueError(
                "Breakpoint ID %d does not exist or was not created by FirmWire" % (bid)
            )

        self.qemu.remove_breakpoint(bid)
        del self._bp_map[bid]

    def remove_breakpoint_by_address(self, address):
        """Remove all FirmWire breakpoints at an address"""
        to_remove = set([])
        for bid, value in self._bp_map.items():
            if value["address"] == address:
                to_remove |= set([bid])

        for bid in to_remove:
            self.qemu.remove_breakpoint(bid)
            del self._bp_map[bid]

        return bool(len(to_remove))

    def time_running(self):
        return time.time() - self.start_time

    # read-only passthrough of attributes to the loader
    def __getattr__(self, name):
        return getattr(self.loader, name)

    @abstractmethod
    def initialize(self, loader):
        """Initializes the common FirmWire subsystems"""

        # Only initialized once
        assert self.loader == None, "%s initialized more than once" % __class__

        self.loader = loader

        output_directory = loader.workspace.path("/")

        self.snapshot_manager = QemuSnapshotManager(output_directory.to_path())

        if not self.snapshot_manager.check():
            log.error("Snapshot manager sanity check fail")
            return False

        # TODO: add more timers than just this
        self.start_time = time.time()

        log.info("FirmWire workspace %s", loader.workspace)
        self.avatar = Avatar(
            arch=loader.ARCH(),
            output_directory=output_directory.to_path(),
            configure_logging=False,
        )

        self.avatar.watchmen.add(
            "BreakpointHit", "before", self._breakpoint_cb, is_async=True
        )
        self.avatar.watchmen.add(
            "RemoteMemoryRead", "before", self._pyperipheral_set_pc_cb
        )
        self.avatar.watchmen.add(
            "RemoteMemoryWrite", "before", self._pyperipheral_set_pc_cb
        )

        # hijack avatar2's sigint handler as we take priority
        # TODO: if firmwire is used as a library, this is probably not a good idea
        self.avatar.sigint_handler = self._sigint_handler

        # Alternative: restore python default signal handler
        # import signal
        # signal.signal(signal.SIGINT, signal.default_int_handler)

        return True

    def start(self, start_suspended=False, console=False):
        """Start the emulator"""
        assert self.qemu is not None

        qemu = self.qemu
        avatar = self.avatar

        try:
            print("==> BOOT")

            # TODO: with new snapshot metadata, restore start_time? make option?
            self.start_time = time.time()

            if not start_suspended:
                if self._fuzzing is True:
                    qemu.cont(blocking=False)
                    # if we are fuzzing with AFL, we don't want these threads to be running
                    qemu.protocols.monitor.shutdown()
                    # MTKEmu requires breakpoints (and hence, execution) to get to fuzzing,
                    # so we only shutdown execution in other cases
                    if not "MtkEMU" in self.instance_name:
                        qemu.protocols.execution.shutdown()
                else:
                    qemu.cont()
            else:
                print("==> HALTED")

            if console:
                print("==> CONSOLE")
                print(
                    "(?) Connect on another terminal with `jupyter console --existing`"
                )
                print("(?) Use `self` to access the machine!")
                import IPython

                IPython.embed_kernel()

            print("==> WAIT SHUTDOWN")
            self.qemu.wait(TargetStates.EXITED)
        except KeyboardInterrupt:
            print("==> BREAK")

            if not (self.qemu.state & TargetStates.STOPPED):
                self.qemu.stop()

            import IPython

            IPython.embed()

        print("==> SHUTDOWN")
        avatar.shutdown()

    def install_hooks(self, mappings):
        """Installs and enables user provided hooks. Hooks are fast and should be preferred to breakpoints"""
        # Enable hooks using either GDB or panda
        for hook in mappings:
            if "symbol" in hook:
                sym = self.symbol_table.lookup(hook["symbol"])

                if sym is None:
                    log.warning(
                        "Unable to find symbol for hook %s. Not enabling", hook["name"]
                    )
                    continue
                else:
                    hook["address"] = sym.address

            if not isinstance(hook["address"], list):
                hook["address"] = [hook["address"]]

            for addr in hook["address"]:
                if hook.get("gdb", False) is True:
                    self.set_breakpoint(addr, hook["handler"])
                else:
                    self.add_panda_hook(addr, hook["handler"])

    def add_panda_hook(self, address, hook):
        """Create a PANDA hook with FirmWireMachine context"""
        assert isinstance(address, int)
        assert callable(hook)

        # Wrapper to pass `self' to panda hooks
        def hook_wrapper(fun):
            def inner(*args, **kw):

                fun(self, *args, **kw)
                # PANDA hooks need to return a boolean to determine if another hook should be run
                return None

            return inner

        self.qemu.add_hook(address, hook_wrapper(hook))

    def pre_breakpoint_handler(self, bp_obj):
        """An overrideable callback that is called before a breakpoint is dispatched"""
        pass

    def post_breakpoint_handler(self, bp_obj, result):
        """An overrideable callback that is called after a breakpoint is dispatched"""
        pass

    def pre_snapshot_handler(self, snapshot_name):
        """
        An overrideable callback that is called before a snapshot is taken

        The return value can be a dict for additional metadata to store during a snapshot operation
        All keys and values in the dict must be Picklable.
        Feel free to include a version number if backwards compatibility with snapshots is required
        """
        return {}

    def post_snapshot_handler(self, snapshot_name):
        """An overrideable callback that is called after a snapshot is taken, but before the target is running"""
        pass

    def pre_snapshot_restore_handler(self, snapshot_name):
        """An overrideable callback that is called before a snapshot restore"""
        pass

    def post_snapshot_restore_handler(
        self, snapshot_name, snapshot_metadata, machine_state
    ):
        """An overrideable callback that is called after a snapshot restore. This function MUST still be called (super)"""

        # Remove all breakpoints that FirmWire owns
        for bid in list(self._bp_map.keys()):
            self.remove_breakpoint(bid)

        assert len(self._bp_map) == 0

        breakpoints = machine_state["breakpoints"]

        for bp_obj in breakpoints.values():
            self.set_breakpoint(**bp_obj)

    # TODO: handle breakpoint deleted messages
    def _breakpoint_cb(self, thread_info, message, **kwargs):
        """A callback to dispatch breakpoint events to handlers"""
        bid = message.breakpoint_number

        # Target received a SIGTRAP signal instead of a GDB stop
        # This can be caused by targets with immature GDB stubs
        breakpoint_via_sigtrap = bid == -1

        if breakpoint_via_sigtrap:
            # This is not ideal, but the alternative is a unhandled breakpoint
            for our_bid, fields in sorted(self._bp_map.items(), key=lambda x: x[0]):
                # Some targets (ARM thumb, MIPS) return addresses that are off-by-one
                if (fields["address"] & ~1) == (message.address & ~1):
                    bid = our_bid
                    break

        # breakpoint was created directly on QEMU and not through FirmWire
        if bid not in self._bp_map:
            return

        address = message.address
        log.debug("hit breakpoint %d at 0x%x", bid, address)

        bp_obj = self._bp_map[bid]

        self.pre_breakpoint_handler(bp_obj)
        # TODO: pass fields to allow for stateful breakpoints/address
        res = bp_obj["handler"](self)
        self.post_breakpoint_handler(bp_obj, res)

        if bp_obj["temporary"]:
            # The GDB stub is not working well, manually handle the temporary case
            if breakpoint_via_sigtrap:
                self.remove_breakpoint(bid)
            else:
                # QEMU will automatically remove the breakpoint
                # Just delete our metadata
                del self._bp_map[bid]

        if bp_obj["continue_after"]:
            self.qemu.cont(blocking=False)

    def snapshot_state_at_address(
        self, addr, snapshot_name, reason="BP snapshot", once=True
    ):
        if once:
            log.info(
                "Will snapshot once to %s when 0x%0x is reached", snapshot_name, addr
            )
        else:
            log.info(
                "Will snapshot continuously to %s when 0x%0x is reached",
                snapshot_name,
                addr,
            )

        self.set_breakpoint(
            addr,
            lambda x: self.snapshot(snapshot_name, reason, resume=False),
            continue_after=True,
            temporary=once,
        )

    def snapshot(self, snapshot_name, reason="user requested snapshot", resume=True):
        assert self.qemu.state & TargetStates.STOPPED

        peripherals = {}
        for mem in self.avatar.memory_ranges:
            if hasattr(mem.data, "python_peripheral"):
                per = mem.data.python_peripheral
                peripherals[mem.begin] = per

        # make sure that peripheral order is maintained for pre/post calls
        peripheral_list = [
            x[1] for x in sorted(peripherals.items(), key=lambda x: x[0])
        ]

        for p in peripheral_list:
            p.pre_snapshot_handler(snapshot_name)

        breakpoints = dict(self._bp_map)

        for k in list(breakpoints.keys()):
            bp_item = breakpoints[k]
            handler = bp_item["handler"]

            if "<lambda>" in handler.__name__:
                log.warning(
                    "Cannot save lambda-based breakpoint handlers. Removing %s @ 0x%x from snapshot...",
                    bp_item["handler"],
                    bp_item["address"],
                )
                del breakpoints[k]

        machine_state = {
            "firmwire_machine_state_version": 1,
            "breakpoints": breakpoints,
        }

        additional_machine_state = self.pre_snapshot_handler(snapshot_name)

        if additional_machine_state:
            assert (
                type(additional_machine_state) == dict
            ), "Additional machine state must be a dict or None"

            # avoid key conflicts (FirmWire base class takes presidence)
            for key in additional_machine_state.keys():
                assert (
                    key not in machine_state
                ), "Machine state key '%s' conflict. Already defined by FirmWire" % (
                    key
                )

            machine_state.update(additional_machine_state)

        result = self.snapshot_manager.take(
            snapshot_name,
            self.qemu.protocols.monitor,
            peripherals,
            machine_state,
            {
                "address": int(self.qemu.regs.pc),
                "qemu_arguments": self.qemu.assemble_cmd_line(),
                # TODO: revisit when firmwire becomes more of a library (argv won't be interesting)
                "firmwire_arguments": sys.argv,
                "reason": reason,
            },
        )

        if not result:
            raise RuntimeError("Snapshot failure!")

        for p in peripheral_list:
            p.post_snapshot_handler(snapshot_name)

        self.post_snapshot_handler(snapshot_name)

        if resume:
            log.info("Resuming...")
            self.qemu.cont(blocking=False)

    def restore_snapshot(self, snapshot_name):
        assert self.qemu.state & TargetStates.STOPPED

        self.pre_snapshot_restore_handler(snapshot_name)

        result = self.snapshot_manager.restore(
            snapshot_name, self.qemu.protocols.monitor
        )

        if result is None:
            raise RuntimeError("Snapshot restore failure!")

        peripherals = result["peripherals"]
        machine_state = result["machine_state"]

        for mem in self.avatar.memory_ranges:
            if not hasattr(mem.data, "python_peripheral"):
                continue

            if mem.begin not in peripherals:
                log.warning(
                    "Unable to restore peripheral at %08x as it wasnt snapshotted"
                    % mem.begin
                )
                continue

            old_per = mem.data.python_peripheral
            per = peripherals[mem.begin]

            # FirmWirePeripheral.machine not a pickled field. must be restored manually
            per.machine = self

            log.info("Restoring " + str(per))

            # Order matters here
            per.post_snapshot_restore_handler(snapshot_name)
            # per.peripheral_replacement_handler(old_per)
            # old_per.peripheral_removal_handler(per)

            # TODO: instead of replacing the instance, which can break references, why not just replace all attributes (__dict__)?
            mem.data.python_peripheral = per
            mem.data.forwarded_to = per
            self.peripheral_map[mem.data.name] = per

        self.post_snapshot_restore_handler(snapshot_name, result, machine_state)

        self.snapshot_manager.print_info(snapshot_name)

    def apply_memory_map(self, memory_map):
        """Realize a memory map description list into Avatar memory ranges"""
        for entry in memory_map:
            if (
                entry.ty == MemoryMapEntryType.GENERIC
                or entry.ty == MemoryMapEntryType.FILE_BACKED
            ):
                if "emulate" in entry.kwargs:
                    raise ValueError(
                        "Memory map entry contains `emulate`. You must use type PERIPHERAL"
                    )

                self.add_memory_range(entry.start, entry.size, **entry.kwargs)
            elif entry.ty == MemoryMapEntryType.PERIPHERAL:
                if "emulate" not in entry.kwargs:
                    raise ValueError(
                        "Memory map PERIPHERAL entry must contain `emulate`"
                    )

                self.create_peripheral(
                    entry.kwargs["emulate"], entry.start, entry.size, **entry.kwargs
                )
            elif entry.ty == MemoryMapEntryType.ANNOTATION:
                # TODO
                pass
            else:
                raise ValueError("Unhandled memory map type %s" % entry.ty)

    def add_memory_range(self, start, size, **kwargs):
        """A wrapper function to adding a memory range"""
        if "emulate" in kwargs:
            raise ValueError(
                "add_memory_range kwargs contains `emulate`. You must use create_peripheral"
            )

        if "name" not in kwargs:
            raise ValueError("add_memory_range must have a name")

        name = kwargs["name"]

        if start & 0xFFF:
            log.warning(
                "Memory %s start address 0x%x is not page aligned. This may causes crashes",
                name,
                start,
            )

        if size & 0xFFF:
            log.warning(
                "Memory %s size 0x%x is not page aligned. Force aligning", name, size
            )
            size += 0x1000 - (size & 0xFFF)

        return self.avatar.add_memory_range(start, size, overwrite=True, **kwargs)

    def add_memory_annotation(self, start, size, name, **kwargs):
        """Name a region of memory (not implemented)"""
        # return self.avatar.add_memory_range(start, size, name=name, **kwargs)
        return None

    def create_peripheral(self, peripheral_class, start, size, name, **kwargs):
        """Associate a FirmWire peripheral with a memory range"""
        if start & 0xFFF:
            log.warning(
                "Peripheral %s at 0x%x is not page aligned. This may causes crashes",
                name,
                start,
            )

        if size & 0xFFF:
            log.warning(
                "Peripheral %s size 0x%x is not page aligned. Force aligning",
                name,
                size,
            )
            size += 0x1000 - (size & 0xFFF)

        # FirmWire's usage of peripherals doesn't work that well with avatar2 owning the creation
        # We need more control over the allowed kwargs versus peripheral __init__ arguments
        # Don't use the `emulate` KW, just do what avatar would do if that KW was passed instead
        if not isinstance(peripheral_class, SOCPeripheral) and not issubclass(
            peripheral_class, AvatarPeripheral
        ):
            raise TypeError("Unexpected peripheral object %s" % peripheral_class)

        # Create the peripheral object and get it ready to receive remote memory packets
        peripheral_obj = peripheral_class(
            name, start, size, firmwire_machine=self, **kwargs
        )

        # Only allow a strict set of KW
        avatar_kw = {}

        for k, v in kwargs.items():
            if k in ["qemu_name", "qemu_properties"]:
                avatar_kw[k] = v

        # Bit of a leaky abstraction
        avatar_kw["forwarded"] = True
        avatar_kw["forwarded_to"] = peripheral_obj
        avatar_kw["python_peripheral"] = peripheral_obj

        mr = self.avatar.add_memory_range(
            start,
            size,
            name=name,
            inline=False,
            overwrite=True,
            permissions="rw-",
            **avatar_kw,
        )

        # Confirm that avatar2 accepted the KWs
        self.peripheral_map[name] = mr.python_peripheral

        return mr

    def _pyperipheral_set_pc_cb(self, avatar, message, **kwargs):
        range = avatar.get_memory_range(message.address)
        if not range or range.forwarded is False:
            return
        # if range.forwarded_to is None:
        # raise Exception("Forward request for non existing target received.\
        # (Address = 0x%x)" % message.address)
        if isinstance(range.forwarded_to, AvatarPeripheral) is True:
            range.forwarded_to.pc = message.pc

    def get_peripheral(self, peripheral_name):
        """Get a peripheral by name"""
        return self.peripheral_map[peripheral_name]

    def get_peripherals(self):
        """Get a all peripherals"""
        return dict(self.peripheral_map)

    def set_peripheral_log_level(self, peripheral_name, level):
        """Set a peripheral log level"""
        self.peripheral_map[peripheral_name].log.setLevel(level)

    def register_unassigned_access_callbacks(self):
        pp = self.qemu.pypanda

        pp.enable_precise_pc()

        def log_mem_read(self, cpustate, pc, addr, size, buf_p):
            # hackish solution as pyperipherals are counted as unassigned mem
            if len(self.avatar.memory_ranges.at(addr)):
                return True
            self.guest_logger.log_emit(
                "FIRMWIRE: unassigned read from 0x{:x} (pc: 0x{:x})".format(addr, pc)
            )

            return True

        def log_mem_write(self, cpustate, pc, addr, size, val):
            # hackish solution as pyperipherals are counted as unassigned mem
            if len(self.avatar.memory_ranges.at(addr)):
                return True
            self.guest_logger.log_emit(
                "FIRMWIRE: unassigned write 0x{:x} to 0x{:x} (pc: 0x{:x})".format(
                    val, addr, pc
                )
            )

            return True

        self._lmr = MethodType(log_mem_read, self)
        self._lmw = MethodType(log_mem_write, self)

        # This tedious calling is due to the fact that pypanda normally uses decorators
        pp.register_callback(
            pp.callback.unassigned_io_read,
            pp.callback.unassigned_io_read(self._lmr),
            "unassigned_io_read",
        )

        pp.register_callback(
            pp.callback.unassigned_io_write,
            pp.callback.unassigned_io_write(self._lmw),
            "unassigned_io_write",
        )

    def register_basic_block_trace(self):
        """
        Prints, whenever a new basic block is translated (if `trace_bb_translation` is enabled)
        """

        def trace(cpustate, env):
            sys.stdout.write(
                f"\nNEW BLOCK: 0x{self.qemu.pypanda.arch.get_pc(cpustate):x}\n"
            )
            sys.stdout.flush()

        self.qemu.register_callback("before_block_translate", trace)

    def spawn_gdb_server(self, port):
        """
        Create a GDB server listening on the specified port. Creates threads - don't use while fuzzing with AFL.
        NOTE: the target must be initialized!
        """
        self.avatar.load_plugin("gdbserver")
        self.avatar.spawn_gdb_server(self.qemu, port, True)
        log.info("FirmWire GDB server listening on tcp::%d", port)

    def _sigint_handler(self):
        self.signal_count += 1

        if self.signal_count == 1:
            log.critical("SIGINT Received. Ctrl+C again to force exit")

        # in the event that shutdown isn't working and user is spamming Ctrl+c
        # keep above avatar calls since they may not return
        if self.signal_count >= 2:
            log.critical("Force exit by user")
            os._exit(1)

        if self.qemu and self.qemu.state == TargetStates.RUNNING:
            self.qemu.stop(blocking=False)
            self.qemu.wait()
            log.info("Target stopped! FirmWire shutting down...")

        self.avatar.shutdown()

        return True

    def run_for(self, t):
        """
        Run the target for the specified amount of seconds before stopping again
        """
        self.qemu.cont()
        time.sleep(t)
        self.qemu.stop()
