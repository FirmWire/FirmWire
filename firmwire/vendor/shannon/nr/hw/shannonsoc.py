from avatar2 import *

from . import LoggingPeripheral


class ShannonSOCPeripheralCortexA(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0:
            value = self.warm_boot[0]
            offset_name = "WARM_BOOT_0"
        elif offset == 0x4:
            value = self.warm_boot[1]
            offset_name = "WARM_BOOT_1"
        elif offset == 0x5c:
            value = 3
            offset_name = f"{offset:x}"
        elif offset == 0x70:
            value = super().hw_read(offset, size)
            value |= 2
            offset_name = f"{offset:x}"
        elif offset == 0x110:
            value = 0x67fff | 0x18000 | 0x80000
            offset_name = f"{offset:x}"
        elif offset == 0x150:
            value = 0x4000 | 0x6f | 0x3f90
            offset_name = f"{offset:x}"
        elif offset == 0xa24:
            value = 1
            offset_name = f"{offset:x}"
        elif offset == 0xa3c:
            value = 1
            offset_name = f"{offset:x}"
        elif offset == 0xa50:
            value = 1
            offset_name = f"{offset:x}"
        else:
            value = super().hw_read(offset, size)
            offset_name = ""

        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.warm_boot = [1, 1]

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
