## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from avatar2 import *

from . import PassthroughPeripheral, CyclicBitPeripheral, LoggingPeripheral


class DSPPeripheral(PassthroughPeripheral):
    def hw_read(self, offset, size):
        # Message: Dev Assert Please check code sync between CPU and DSP [141 : 286 : 0] LCPU task[0xffffffff]
        # Original code:
        #   qemu.write_memory(0x47389c00, 4, 141)
        #   qemu.write_memory(0x47389c04, 4, 286)
        if offset == 0x0:
            value = self.dsp_sync0
            offset_name = "DSP_SYNC0"
        elif offset == 0x4:
            value = self.dsp_sync1
            offset_name = "DSP_SYNC1"
        else:
            # ignore other reads
            return 0

        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        # Ignore all writes (read only)
        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        if "sync" not in kwargs:
            raise ValueError("DSP sync codes required")

        self.dsp_sync0 = kwargs["sync"][0]
        self.dsp_sync1 = kwargs["sync"][1]
        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write


class S355DSPBufferPeripheral(PassthroughPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x0334:
            value = 0
            offset_name = "qIniAllocDspBuffer_retval"
        else:
            value = 0
            offset_name = "UNK_{:4x}".format(offset)

        self.log_read(value, size, offset_name)
        return value

    def hw_write(self, offset, size, value):
        offset_name = "UNK_{:4x}".format(offset)
        self.log_write(value, size, offset_name)
        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)


class MarconiPeripheral(CyclicBitPeripheral):
    def hw_read(self, offset, size):
        return self.cyclic_bit()

    def parity_cyclic(self, offset, size):
        val = self.cyclic_bit() >> 2 << 2

        # bit 0: parity enabled?
        # bit1: parity bit
        # note: it looks like the firmware accesses the periph twice,
        #       so maybe we need parity of last read number
        val_unpar = val & 0x3FFFFFF
        parity = bin(val_unpar).count("1") % 2
        val |= 1
        val |= parity << 1
        return val

    def hw_write(self, offset, size, value):
        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        # self.parity_cyccle_idx = 0

        self.read_handler.clear()
        self.read_handler[0:0x4010] = self.hw_read
        self.read_handler[0x4010:0x4014] = self.parity_cyclic
        self.read_handler[0x4014:size] = self.hw_read

        self.write_handler[0:size] = self.hw_write
