## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging

from . import PassthroughPeripheral


class MDCFGCTL_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

    def hw_read(self, offset, size):
        self.log.debug("MDCFGCTL read")
        if offset == 0x0:
            return 0  # HW_VER
        elif offset == 0x4:
            return 0  # SW_VER
        elif offset == 0x8:
            return 0  # HW_CODE
        elif offset == 0xC:
            return 0  # HW_SUBCODE
        elif offset == 0x10:
            # TODO: where does this come from, should it be in MISC_INFO_SBP_ID ?
            return 0  # SW_MISC_L (boot mode?)
        elif offset == 0x14:
            return 0  # SW_MISC_H
        else:
            self.log.debug(f"MDCFGCTL {offset:x}")
            assert 0


class MDCIRQ_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

    def hw_write(self, offset, size, value):
        if offset >= 0 and offset <= 0x20:
            pass  # int status
        elif offset >= 0x20 and offset < 0x40:
            pass  # mask status
        elif offset >= 0x40 and offset < 0x60:
            pass  # mask clear
        elif offset >= 0x60 and offset < 0x80:
            pass  # mask set
        elif offset >= 0x80 and offset < 0xA0:
            pass  # sw trigger
        elif offset >= 0xA0 and offset < 0xC0:
            pass  # sensitivity
        elif offset >= 0xC0 and offset < 0xE0:
            pass  # broadcast
        elif offset >= 0xE0 and offset < 0x100:
            pass  # valid
        elif offset >= 0x100 and offset < 0x120:
            pass  # type (is NMI?)
        elif offset >= 0x120 and offset < 0x140:
            pass  # sw trigger set
        elif offset >= 0x140 and offset < 0x160:
            pass  # sw trigger clear
        elif offset >= 0x160 and offset < 0x180:
            pass  # sensitivity set
        elif offset >= 0x180 and offset < 0x1A0:
            pass  # sensitivity clear
        elif offset == 0x1A0:
            pass  # wait mode
        elif offset == 0x1A8:
            pass  # mask incoming GCR signals
        return super().hw_write(offset, size, value)
