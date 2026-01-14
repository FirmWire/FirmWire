from avatar2 import *

from . import LoggingPeripheral


class SysCmuPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x10c or offset == 0x14c:
            value = super().hw_read(offset, size)
            value = value | 0x20000000
            offset_name = "UNK"
            self.log_read(value, size, offset_name)
        else:
            value = super().hw_read(offset, size)

        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
