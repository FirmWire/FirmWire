## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct
import logging

from ..emulator.firmwire import FirmWireEmu
from avatar2 import *

log = logging.getLogger(__name__)


class FirmWirePeripheral(avatar2.AvatarPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size)

        machine = kwargs.get("firmwire_machine", None)

        if machine is None or not isinstance(machine, FirmWireEmu):
            raise ValueError(
                "FirmWire peripherals must have a reference to their machine (did you pass kwargs in super().__init__?)"
            )

        # Not pickled
        self.machine = machine

        # This is an abstract class - derived classes must implement the below functions
        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write

        # Per-peripheral logger
        self.log_level = kwargs.get("log_level", logging.INFO)
        self.log = log.getChild("%s.%s" % (self.__class__.__name__, self.name))
        self.log.setLevel(self.log_level)

        self.pc = 0  # dummy value in case of inlining
        self.cycle_idx = 0

    def __getstate__(self):
        state = self.__dict__.copy()

        # SPECIAL CASE: this is restored by FirmWire
        # NOTE: machine will NOT be available during __setstate__. Use post_restore for any lingering restoration bookkeeping
        del state["machine"]

        return state

    def log_read(self, value, size, offset_name):
        self.log.debug(
            "%s: %0" + str(size * 2) + "x <- %s[%s]",
            self.format_address(self.pc),
            value,
            self.name,
            offset_name,
        )

    def log_write(self, value, size, offset_name):
        self.log.debug(
            "%s: %s[%s] <- %0" + str(size * 2) + "x",
            self.format_address(self.pc),
            self.name,
            offset_name,
            value,
        )

    def format_address(self, addr):
        if not self.machine.symbol_table:
            return "0x%08x" % addr
        else:
            sym = self.machine.symbol_table.lookup(addr)
            if sym is None:
                return "0x%08x" % addr

            offset = addr - sym.address

            if abs(offset) > 0x1000:
                return "0x%08x" % addr
            else:
                return sym.format(offset)

    def cyclic_bit(self, pattern=1, cycle_len=33):
        """p2im inspired cyclic bit pattern to get past status bit checks"""
        val = (pattern << self.cycle_idx) % 0xFFFFFFFF
        self.cycle_idx = (self.cycle_idx + 1) % cycle_len
        return val

    def pre_snapshot_handler(self, snapshot_name):
        """Called right before a snapshot has started when the target is stopped"""
        pass

    def post_snapshot_handler(self, snapshot_name):
        """Called after a snapshot has completed and before the target is running"""
        pass

    def post_snapshot_restore_handler(self, snapshot_name):
        """Called after a peripheral has been restored from a snapshot"""
        pass

    # def peripheral_removal_handler(self, new_instance):
    #    """Override to receive a callback when `self` is being replaced by a restored instance. Only called on the instance being removed"""
    #    pass

    # def peripheral_replacement_handler(self, old_instance):
    #    """Override to receive a callback when `self` is replacing an older peripheral instance. Only called on the new instance"""
    #    pass


class PassthroughPeripheral(FirmWirePeripheral):
    def hw_read(self, offset, size):
        value = self.read_raw(offset, size)
        return value

    def hw_write(self, offset, size, value):
        self.write_raw(offset, size, value)
        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.mem = [0] * size

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write

    def write_raw(self, offset, size, value):
        for i in range(size):
            self.mem[offset + i] = (value >> (i * 8)) & 0xFF

    def read_raw(self, offset, size):
        data = self.mem[offset : offset + size]
        value = 0
        for i in range(size):
            value |= data[i] << (i * 8)

        return value


class LoggingPeripheral(PassthroughPeripheral):
    def hw_read(self, offset, size):
        value = super().hw_read(offset, size)
        offset_name = "LOG %08x" % (self.address + offset)
        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        offset_name = "LOG %08x" % (self.address + offset)
        self.log_write(value, size, offset_name)

        super().hw_write(offset, size, value)

        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write


class CyclicBitPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        return self.cyclic_bit()

    def hw_write(self, offset, size, value):
        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
