from avatar2 import *

from . import LoggingPeripheral


class Unknown5Peripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x84 or offset == 0x104 or offset == 0x184 or offset == 0xb84:
            # something != 0
            value = 1
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


class Unknown6Peripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x4:
            value = 1
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


class Unknown7Peripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x11c:
            value = 3
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


class Unknown8Peripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x14:
            value = 0x20
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


class Unknown9Peripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x50:
            value = 0x1000000  # value & 0x1000000 != 0
        elif offset == 0xb4:
            value = 0x40000  # value & 0x40000 >= 1
        elif offset == 0x3cc:
            value = 0x1  # value & 1 != 0
        else:
            value = super().hw_read(offset, size)

        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write


class Unknown10Peripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0xf0:
            value = 0x1  # value & 1 != 0
        else:
            value = super().hw_read(offset, size)

        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write


class Unknown11Peripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x8:
            value = 0x80000000  # value >= 0x80000000
        else:
            value = super().hw_read(offset, size)

        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
