## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from avatar2 import *

from . import LoggingPeripheral


class ShannonAbox(LoggingPeripheral):
    def hw_read(self, offset, size):
        value = 0
        if offset == 0x8:
            value = 1
        if offset == 0x18:
            value = 1
        if offset == 0x08:
            value = 0
        if offset == 0x8FB8:
            value = 0
        if offset == 0x8FBE:
            value = 2
        if offset == 0x8F68:
            return 1

        # print(f'R: {offset:x}: {value}')
        return value

    def hw_write(self, offset, size, value):
        # print(f'W: {offset:x}: {value:x}')
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)
        self.read_count = 0

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
