from avatar2 import *

from . import PassthroughPeripheral


class DSPPeripheralCortexA(PassthroughPeripheral):
    def hw_read(self, offset, size):
        if offset == 0xa00:
            value = self.dsp_sync0
            offset_name = "DSP_SYNC0"
        elif offset == 0xa04:
            value = self.dsp_sync1
            offset_name = "DSP_SYNC1"
        else:
            # ignore other reads
            return 0

        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        # Ignore all writes (read only)
        return True

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        if "sync" not in kwargs:
            raise ValueError("DSP sync codes required")

        self.dsp_sync0 = kwargs["sync"][0]
        self.dsp_sync1 = kwargs["sync"][1]
        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
