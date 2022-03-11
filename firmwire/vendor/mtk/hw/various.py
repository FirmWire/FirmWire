## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from . import PassthroughPeripheral


class CDMM_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)


class TOPSM_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

    def hw_read(self, offset, size):
        if offset == 0x590:
            # SM_PLL_STA
            # TODO: boot hack, set all the bits?
            return 0xFFFFFFFF
        else:
            return super().hw_read(offset, size)


class MODEML1_TOPSM_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

    def hw_read(self, offset, size):
        if offset == 0xD4:
            # probably some PWR_STA
            # TODO: for now, just set all the bits
            self.log.info(f"{self.name}: read PWR_STA")
            return 0xFFFFFFFF
        else:
            return super().hw_read(offset, size)


class MDPERISYS_MISC_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        # AP2MD_DUMMY (is AP blocked from MD?)
        self.mem[0x300] = 1


class TDMABase_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)
        self.timerHack = 0

    def hw_read(self, offset, size):
        if offset == 0x0:
            # TQ_CURRENT_COUNT (TDMA timer)
            # TODO
            self.timerHack = self.timerHack + 1
            return self.timerHack
        else:
            return super().hw_read(offset, size)


# dummy reads/writes to act as a barrier
class MCUSync_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)
