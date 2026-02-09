from avatar2 import *

from . import LoggingPeripheral


class McTimerPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x110:  # rG_CNT_WSTAT
            value = 0x3
            offset_name = f"UNK_{offset:x}"
        elif offset == 0x340:
            value = 1 << 3 | 1 << 2
            offset_name = "rMCT_LT_WSTAT"
        elif offset == 0x24c:  # rG_WSTAT
            # something & 0x10000 != 0
            value = 0x10013
            offset_name = f"UNK_{offset:x}"
        else:
            return super().hw_read(offset, size)

        self.log_read(value, size, offset_name)
        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
