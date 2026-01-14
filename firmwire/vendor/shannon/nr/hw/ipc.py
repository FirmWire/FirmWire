import struct

from avatar2 import *

from . import LoggingPeripheral


class GIPCPeripheral(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x800:
            # value = 0xc9 # causes a CP crash
            value = self.ap2cp_cmd
            offset_name = "AP2CP_CMD"
        elif offset == 0x804:
            value = self.cp2ap_cmd
            offset_name = "CP2AP_CMD"
        else:
            return super().hw_read(offset, size)

        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        self.machine.physical_memory_write(0x14d60000, struct.pack("<I", 1))  # Door Bell 0
        if offset == 0x800:
            self.ap2cp_cmd = value
            offset_name = "AP2CP_CMD"
        elif offset == 0x804:
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
