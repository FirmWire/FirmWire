## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from avatar2 import *

from . import PassthroughPeripheral, LoggingPeripheral


class S5000APClkPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x120:
            value = self.boot_clk[0]
            offset_name = "BOOT_CLK_0"
            self.log_read(value, size, offset_name)
        elif offset == 0x140:
            value = self.boot_clk[1]
            offset_name = "BOOT_CLK_2"
            self.log_read(value, size, offset_name)
        else:
            value = super().hw_read(offset, size)

        return value

    def hw_write(self, offset, size, value):
        if offset == 0x400:
            if value & 1 == 1:
                value |= 0x1F000000 | 0x20000000
        elif offset == 0x1084:
            if value & 1 == 1:
                value = (value & ~0x1) | 0x4
        # 817d0310 <= LOG_clk_per[83000100]
        elif offset == 0x100:
            if value & 0x80000000:
                self.clk_0x100 = value | 0x20000000
                value = self.clk_0x100
            if value & 0x10:
                self.clk_0x100 = value | 0x80
                value = self.clk_0x100

        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)
        # 0x83000120, 0x83000140
        self.boot_clk = [0x20000000, 0x20000000]
        self.clk_0x100 = 0

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write


class S360APClkPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x100:
            value = self.clk_0x100
            offset_name = "UNK_CLK"
            value = self.cyclic_bit()
            self.log_read(value, size, offset_name)
        elif offset == 0x120:
            value = self.boot_clk[0]
            offset_name = "BOOT_CLK_0"
            self.log_read(value, size, offset_name)
        elif offset == 0x140:
            value = self.boot_clk[1]
            offset_name = "BOOT_CLK_2"
            self.log_read(value, size, offset_name)
        elif offset == 0x2004:
            value = 0x30000
        elif offset == 0x201C:
            value = 0x2
        elif offset == 0x202C:
            value = 0x1
        elif offset == 0x2070:
            value = 0x40000000
        elif offset == 0x2078:
            value = 0x40000000 | 0x80000000
        elif offset == 0x4308:
            value = self.store_4300
        else:
            value = super().hw_read(offset, size)

        return value

    def hw_write(self, offset, size, value):
        if offset == 0x400:
            if value & 1 == 1:
                value |= 0x1F000000 | 0x20000000
            return super().hw_write(offset, size, value)
        elif offset == 0x1084:
            if value & 1 == 1:
                value = (value & ~0x1) | 0x4
        # 817d0310 <= LOG_clk_per[83000100]
        elif offset == 0x100:
            if value & 0x80000000:
                self.clk_0x100 = 0x20000000
            if value & 0x10:
                self.clk_0x100 = 0x80
            # print("AAAAAAAAAAAA CLK %08x" % (self.clk_0x100))
        elif offset == 0x4300:
            self.store_4300 = value
        else:
            return super().hw_write(offset, size, value)

        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)
        # 0x83000120, 0x83000140
        self.boot_clk = [0x20000000, 0x20000000]
        self.clk_0x100 = 0
        self.store_4300 = 0

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write


class S355APClkPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        offset += 0x2000
        offset_name = None

        if offset == 0x100:
            value = self.clk_0x100
            offset_name = "UNK_CLK"
            self.log_read(value, size, offset_name)
        elif offset == 0x120:
            value = self.boot_clk[0]
            offset_name = "BOOT_CLK_0"
            self.log_read(value, size, offset_name)
        elif offset == 0x140:
            value = self.boot_clk[1]
            offset_name = "BOOT_CLK_2"
            self.log_read(value, size, offset_name)
        elif offset == 0x2004:
            value = 0x30000
        elif offset == 0x201C:
            value = self.val_201c
        elif offset == 0x2020:
            value = self.next_val
        elif offset == 0x2028:
            value = self.next_val
        elif offset == 0x202C:
            # value = self.val_202c
            value = self.cyclic_bit(pattern=0xFFFFF)
            # print(value, "0x202c")
        elif offset == 0x2070:
            value = 0x40000000
        elif offset == 0x2078:
            value = 0x40000000 | 0x80000000
        elif offset == 0x2088:
            value = 0x40000000 | 0x80000000
        elif offset == 0x2090:
            # 0x1000 signifies that the clk is on
            value = 0x20000000 | 0x40000000 | 0x1E000000 | 0x1000

            offset_name = "MPLL_CLK"
            self.log_read(value, size, offset_name)
        elif offset == 0x21B0:
            value = 0  # default clk
            offset_name = "DFS_SEL"
            self.log_read(value, size, offset_name)
        elif offset == 0x4308:
            value = self.store_4300
        elif offset == 0x5000:
            value = 0x10  # CHIP revision?
        elif offset == 0xA004:
            value = 0
            offset_name = "UNK_GSM"
            self.log_read(value, size, offset_name)
        else:
            offset -= 0x2000
            value = super().hw_read(offset, size)

        if offset_name is None:
            offset_name = "LOG %08x" % (self.address + offset)
            self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        offset += 0x2000

        if offset == 0x400:
            if value & 1 == 1:
                value |= 0x1F000000 | 0x20000000
        elif offset == 0x1084:
            if value & 1 == 1:
                value = (value & ~0x1) | 0x4
        # 817d0310 <= LOG_clk_per[83000100]
        elif offset == 0x100:
            if value & 0x80000000:
                self.clk_0x100 = 0x20000000
            if value & 0x10:
                self.clk_0x100 = 0x80
        elif offset == 0x2010:
            self.val_201c = self.val_201c & ~value
        elif offset == 0x2014:
            self.val_201c = 2
        elif offset == 0x2020:
            self.next_val = 0x0
            if value & 2:
                self.val_202c = self.val_202c & ~2
        elif offset == 0x2024:
            self.next_val = 0xFFFFFFFF
        elif offset == 0x4300:
            self.store_4300 = value

        offset -= 0x2000
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)
        # 0x83000120, 0x83000140
        self.boot_clk = [0x20000000, 0x20000000]
        self.clk_0x100 = 0
        self.store_4300 = 0
        self.next_val = 0
        self.val_201c = 0x1 | 0x2
        self.val_202c = 0x1 | 0x2

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write


# Unclear if this will work for any other S337AP SoC unless its MOTO, not Samsung
class S337APClkPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x100:
            value = self.clk_0x100
            offset_name = "UNK_CLK"
            self.log_read(value, size, offset_name)
        elif offset == 0x120:
            value = self.boot_clk[0]
            offset_name = "BOOT_CLK_0"
            self.log_read(value, size, offset_name)
        elif offset == 0x140:
            value = self.boot_clk[1]
            offset_name = "BOOT_CLK_2"
            self.log_read(value, size, offset_name)
        elif offset == 0x400:
            # vvvv this was the only change really needed for the MOTO
            value = 0x30001000
            offset_name = "MPLL_CLK"
            self.log_read(value, size, offset_name)
        elif offset == 0x2004:
            value = 0x30000
        elif offset == 0x201C:
            value = 0x2
        elif offset == 0x202C:
            value = 0x1
        elif offset == 0x2070:
            value = 0x40000000
        elif offset == 0x2078:
            value = 0x40000000 | 0x80000000
        elif offset == 0x4308:
            value = self.store_4300
        else:
            value = super().hw_read(offset, size)

        return value

    def hw_write(self, offset, size, value):
        if offset == 0x400:
            if value & 1 == 1:
                value |= 0x1F000000 | 0x20000000
        elif offset == 0x1084:
            if value & 1 == 1:
                value = (value & ~0x1) | 0x4
        # 817d0310 <= LOG_clk_per[83000100]
        elif offset == 0x100:
            if value & 0x80000000:
                self.clk_0x100 = 0x20000000
            if value & 0x10:
                self.clk_0x100 = 0x80
            print("AAAAAAAAAAAA CLK %08x" % (self.clk_0x100))
        elif offset == 0x4300:
            self.store_4300 = value
        else:
            return super().hw_write(offset, size, value)

        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)
        # 0x83000120, 0x83000140
        self.boot_clk = [0x20000000, 0x20000000]
        self.clk_0x100 = 0
        self.store_4300 = 0

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
