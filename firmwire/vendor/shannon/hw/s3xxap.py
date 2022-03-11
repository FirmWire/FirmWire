## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from avatar2 import *

from . import PassthroughPeripheral, LoggingPeripheral


class S3xxAPBoot(LoggingPeripheral):
    def hw_read(self, offset, size):
        # S355
        if offset == 0x88:
            value = 2
            offset_name = "UNK"
            self.log_read(value, size, offset_name)
        elif offset == 0x90:
            value = 1
            offset_name = "UNK"
            self.log_read(value, size, offset_name)
        else:
            value = super().hw_read(offset, size)

        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
