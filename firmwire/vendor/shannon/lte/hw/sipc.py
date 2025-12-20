## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import sys
import struct
from avatar2 import *

from . import LoggingPeripheral


class SIPCPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x80:
            # value = 0xc9 # causes a CP crash
            value = self.ap2cp_cmd
            offset_name = "AP2CP_CMD"
        elif offset == 0x84:
            value = self.cp2ap_cmd
            offset_name = "CP2AP_CMD"
        elif offset == 0x88:
            # TODO: add these fields
            # hwVerVal = (byte)((uint)(DAT_8f920088 << 0x16) >> 0x1c);
            # hwBoardID = (byte)((uint)(DAT_8f920088 << 0x12) >> 0x1c);
            # _hwIsDualSim = (uint)(DAT_8f920088 << 0x10) >> 0x1e;
            value = 2
            offset_name = "UNK_BOOT_CHECK"
        elif offset == 0x90:
            value = 1
            offset_name = "UNK"
        else:
            return super().hw_read(offset, size)

        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        if offset == 0x80:
            self.ap2cp_cmd = value
            offset_name = "AP2CP_CMD"
        elif offset == 0x84:
            if value & 0xFF == 0xC1:
                self.ap2cp_cmd = 0xCD
            elif value & 0xFF == 0xC8:
                self.ap2cp_cmd = 0xC2

            offset_name = "CP2AP_CMD"
        else:
            return super().hw_write(offset, size, value)

        self.log_write(value, size, offset_name)

        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.ap2cp_cmd = 0
        self.cp2ap_cmd = 0

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
