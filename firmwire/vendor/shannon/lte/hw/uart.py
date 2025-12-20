## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import sys
from avatar2 import *

from . import FirmWirePeripheral, LoggingPeripheral

# from firmwire.hw.peripheral import *


class UARTPeripheral(FirmWirePeripheral):
    def hw_read(self, offset, size):
        if offset == 0x18:
            return self.status

        return 0

    def hw_write(self, offset, size, value):
        if offset == 0:
            sys.stderr.write(chr(value & 0xFF))
            sys.stderr.flush()
        else:
            self.log_write(value, size, "UART")

        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.status = 0

        self.write_handler[0:size] = self.hw_write
        self.read_handler[0:size] = self.hw_read

        # init of this peripheral bypasses shannon peripheral, hence we set pc
        # dummy value manually
        self.pc = 0


class MotoUARTPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        return super().hw_read(offset, size)

    def hw_write(self, offset, size, value):
        if offset == 0x20:
            sys.stderr.write(chr(value & 0xFF))
            sys.stderr.flush()
            return True
        else:
            return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.write_handler[0:size] = self.hw_write
        self.read_handler[0:size] = self.hw_read
