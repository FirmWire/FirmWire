## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import sys
import struct
from avatar2 import *

from . import LoggingPeripheral


class ShannonSOCPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x4:
            value = self.chip_id
            offset_name = "CHIP_ID"
            self.log.info("CHIP_ID read: %08x", self.chip_id)
        elif offset == 0x1000:
            value = self.warm_boot[0]
            offset_name = "WARM_BOOT_0"
        elif offset == 0x1004:
            value = self.warm_boot[1]
            offset_name = "WARM_BOOT_1"
        elif offset == 0x105C:
            value = 0x2
            offset_name = "PWR_MBUS"
        elif offset == 0x1060:
            value = 0x2
            offset_name = "PWR_UNK"
        elif offset == 0x1110:
            value = 0xF80 | 0x070 | 0x00F
            offset_name = "PWR_"
        elif offset == 0x1150:
            # 00000000 <= ShannonSOCPeripheral[1150]
            # 0x405fd9dc:     tst.w   r1, #0x400
            # TODO: figure out what this needs to be! also there is magical code at 040174e4 now
            # value = 0x400 | 0x2 | 0x8 | 0x100 | 0x1 | 0x20| 0x200
            value = (1 << self.cycle_idx) % 0xFFFFFFFF
            self.cycle_idx = (self.cycle_idx + 1) % 32
            offset_name = "PWR_RFCTRL"
        else:
            value = 0
            offset_name = ""
            value = super().hw_read(offset, size)

        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.chip_id = 0x50000000
        self.warm_boot = [1, 1]

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write

        self.cycle_idx = 0
