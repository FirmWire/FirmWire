## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import sys
from avatar2 import *

from . import LoggingPeripheral


class PMICPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x20:
            value = 1
            offset_name = "UNK_LOOP"
        elif offset == 0x28:
            value = 2
            offset_name = "UNK_LOOP2"
        elif offset == 0x80:
            value = self.cmd
            offset_name = "ACPM_SEQ_CMD"
        elif offset == 0x88:
            value = self.seq << 0x1A >> 10  # seq
            value |= 0xC000000  # protocol
            offset_name = "ACPM_SEQ_READ"
        else:
            return super(PMICPeripheral, self).hw_read(offset, size)

        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        if offset == 0x20:
            if value == 0xFFFFFFFF:
                self.seq = (self.cmd >> 0x10) & 0x3F

            offset_name = "CMD_START_%d" % self.seq
        elif offset == 0x80:
            self.cmd = value
            offset_name = "ACPM_SEQ_CMD"
        else:
            return super(PMICPeripheral, self).hw_write(offset, size, value)

        self.log_write(value, size, offset_name)

        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.seq = 0
        self.cmd = 0
        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
