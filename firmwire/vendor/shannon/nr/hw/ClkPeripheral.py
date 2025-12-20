from avatar2 import *

from . import LoggingPeripheral


class S5123APClkPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x10c:
            value = self.boot_clk[0]
            offset_name = f"BOOT_CLK_0"
            self.log_read(value, size, offset_name)
        elif offset == 0x118:
            value = 0x20000000
            offset_name = f"UNK_{offset:x}"
            self.log_read(value, size, offset_name)
        elif offset == 0x14c:
            value = self.boot_clk[1]
            offset_name = "BOOT_CLK_2"
            self.log_read(value, size, offset_name)
        elif offset == 0x900:
            value = 0
            offset_name = "UNK"
            self.log_read(value, size, offset_name)
        elif offset == 0x2140:
            value = 0xe0000
            offset_name = "CLK_D"
            self.log_read(value, size, offset_name)
        else:
            value = super().hw_read(offset, size)

        return value

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)
        self.boot_clk = [0x20000000, 0x20000000]
