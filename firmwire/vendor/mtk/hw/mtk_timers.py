## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging

from . import PassthroughPeripheral


class CLKSW_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

    def hw_read(self, offset, size):
        # BUS_FLEXCKGEN_STS
        if offset == 0x84:
            self.log.debug("read BUS_FLEXCKGEN_STS")
            return 0xFFFFFFFF
        else:
            return super().hw_read(offset, size)


class OSTimer_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

    def hw_read(self, offset, size):
        if offset == 0x10 or offset == 0x1C:
            # fine, see below
            pass
        elif offset == 0x18:
            # STA, see hacks below
            pass
        elif offset == 0x40:
            # interrupt mask? TODO maybe off-by-4 depending on hw revision
            self.log.debug(f"OSTIMER read {offset:x} - mask?")
        elif offset == 0x50:
            # interrupt status? TODO maybe off-by-4 depending on hw revision
            self.log.debug(f"OSTIMER read {offset:x} - status?")
        else:
            self.log.debug(f"OSTIMER read {offset:x}")
            assert 0

        return super().hw_read(offset, size)

    def hw_write(self, offset, size, value):
        if offset == 0x10:
            # control reg
            # bit 0 is enable, bit 1 is UFN enable, bit 2 is debug
            self.log.debug(f"OSTIMER: CON <- {value:x}")
        elif offset == 0x14:
            # cmd reg, ignore upper 16 bits [key]
            # bit 0 is enable pause, bit 2 is copy all config into SYSCLK
            self.log.debug(f"OSTIMER: CMD <- {value:x}")
            # TODO hack immediately report completion in STA
            super().hw_write(0x18, 4, 2)
        elif offset == 0x1C:
            # frame duration, in us
            self.log.debug(f"OSTIMER: frame duration <- {value} us")
        elif offset == 0x24:
            # set the unalignment (works also in pause) frame countdown
            self.log.debug(f"OSTIMER: UFN <- {value:x}")
        elif offset == 0x28:
            # set the alignment frame countdown
            self.log.debug(f"OSTIMER: AFN <- {value:x}")
        elif offset == 0x40:
            # interrupt mask
            self.log.debug(f"OSTIMER: interrupt mask <- {value:x}")
        elif offset == 0x50:
            # interrupt status
            self.log.debug(f"OSTIMER: interrupt status <- {value:x}")
        elif offset == 0x60 or offset == 0x64:
            # is this one used during pause..?
            self.log.debug(f"OSTIMER: wakeup mask ({offset:x}) <- {value:x}")
        elif offset == 0x80 or offset == 0x84:
            # is this one used before going into pause..?
            self.log.debug(f"OSTIMER: wakeup mask ({offset:x}) <- {value:x}")
        else:
            self.log.debug(f"OSTIMER write {offset:x} {value:x}")
            assert 0

        return super().hw_write(offset, size, value)
