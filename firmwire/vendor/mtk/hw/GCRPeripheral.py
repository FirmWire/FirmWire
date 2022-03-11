## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging

from . import PassthroughPeripheral


class GCR_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        # GCR_CONFIG
        # 2 cores (otherwise we die in symbol kal_set_hisr_affinity)
        self.mem[0x0] = 1

        # trying to hack around bootup
        self.mem[0x4008] = 0x13


class GCRCustom_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.timer = 0

    def hw_read(self, offset, size):
        if offset == 0x34:
            # ready
            value = 1
        elif offset == 0x40:
            # timer low
            # TODO
            self.timer = (self.timer + 1) & 0xFFFFFFFF
            value = self.timer
        elif offset == 0x44:
            # timer high
            assert False
        elif offset == 0x48:
            # OS timer
            # FIXME
            value = self.timer
        elif offset == 0x50:
            # TODO
            self.timer = (self.timer + 1) & 0xFFFFFFFF
            value = self.timer
        else:
            return super().hw_read(offset, size)
        return value
