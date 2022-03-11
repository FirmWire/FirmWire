## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from ..hw import *
from firmwire.hw.soc import FirmWireSOC, SOCPeripheral, register_soc
from firmwire.util.BinaryPattern import BinaryPattern


class MediaTekSOC(FirmWireSOC):
    # Start in BOOT (can be overwritten)
    ENTRY_ADDRESS = 0x0

    name = "Unknown"

    def __init__(self, date, main_section=None):
        self.date = date

    def __repr__(self):
        return "<MediaTekSOC %s - %s>" % (self.name, self.date)


class MT6768(MediaTekSOC):
    # As used by Samsung A41/A31

    peripherals = [
        SOCPeripheral(PassthroughPeripheral, 0xC1CE0000, 0x1000, name="EFUSE"),
        SOCPeripheral(
            PassthroughPeripheral, 0xC0002000, 0x1000, name="IOCFG_LB_BASE"
        ),  # FIXME check
        SOCPeripheral(
            PMIC_WRAP_Periph,
            0xC000D000,
            0x2000,
            name="APMCU_MISC",
            wacs_init_done_offset=22,
        ),
    ]

    # TODO: KAL_TOTAL_TASKS seems more FW, than SoC specific. However, this works for now
    KAL_TOTAL_TASKS = 0xBF  # 191
    AFFINITY_ONLY_CPU_0 = b"\1"
    AFFINITY_ONLY_CPU_1 = b"\x0c"
    PCCIF_VERSION = 3
    SHM_QUEUE_NUM = 16
    SHM_LAYOUT = {
        "rx_sizes": [80, 80, 40, 80, 20, 20, 64, 0, 8, 0, 0, 0, 0, 0, 0, 0],
        "tx_sizes": [128, 40, 8, 40, 20, 20, 64, 0, 8, 0, 0, 0, 0, 0, 0, 0],
        "rx_sizes_exp": [12, 32, 8, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        "tx_sizes_exp": [12, 32, 8, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    }

    name = "MT6768"

    def __init__(self, date):
        super().__init__(date)
        ringbuffer = SOCPeripheral(
            SHM_CCIF_Periph,
            0x69200000,
            0x100000,
            name="SharedMemoryCCIF",
            queue_num=self.SHM_QUEUE_NUM,
            queue_layout=self.SHM_LAYOUT,
        )

        self.peripherals += [
            ringbuffer,
            SOCPeripheral(
                PCCIF_Periph,
                0xC020A000,
                0x1000,
                name="PCCIF0_MD",
                ringbuffer=ringbuffer,
                pccifid=0,
                version=self.PCCIF_VERSION,
            ),
            SOCPeripheral(
                PCCIF_Periph,
                0xC020C000,
                0x1000,
                name="PCCIF1_MD",
                ringbuffer=ringbuffer,
                pccifid=1,
                version=self.PCCIF_VERSION,
            ),
        ]


class MT6765(MediaTekSOC):
    # As used by Samsung A10s
    peripherals = [
        SOCPeripheral(PassthroughPeripheral, 0xC1C50000, 0x1000, name="EFUSE"),
        # SOCPeripheral(AES_TOP0_Periph,0xc0016000, 0x1000, name='AES_TOP0', permissions='rw-'),
        SOCPeripheral(
            PMIC_WRAP_Periph,
            0xC000D000,
            0x2000,
            name="APMCU_MISC",
            wacs_init_done_offset=22,
        ),
    ]

    KAL_TOTAL_TASKS = 0xBB  # a10s fw
    AFFINITY_ONLY_CPU_0 = b"\1"
    AFFINITY_ONLY_CPU_1 = b"\x02"
    PCCIF_VERSION = 1
    SHM_QUEUE_NUM = 8
    SHM_LAYOUT = {
        "rx_sizes": [80, 80, 40, 80, 20, 20, 64, 0],
        "tx_sizes": [128, 40, 8, 40, 20, 20, 64, 0],
        "rx_sizes_exp": [12, 32, 8, 0, 0, 0, 8, 0],
        "tx_sizes_exp": [12, 32, 8, 0, 0, 0, 8, 0],
    }

    name = "MT6765"

    def __init__(self, date):
        super().__init__(date)
        ringbuffer = SOCPeripheral(
            SHM_CCIF_Periph,
            0x69200000,
            0x100000,
            name="SharedMemoryCCIF",
            queue_num=self.SHM_QUEUE_NUM,
            queue_layout=self.SHM_LAYOUT,
        )

        self.peripherals += [
            ringbuffer,
            SOCPeripheral(
                PCCIF_Periph,
                0xC020A000,
                0x1000,
                name="PCCIF0_MD",
                ringbuffer=ringbuffer,
                pccifid=0,
                version=self.PCCIF_VERSION,
            ),
            SOCPeripheral(
                PCCIF_Periph,
                0xC020C000,
                0x1000,
                name="PCCIF1_MD",
                ringbuffer=ringbuffer,
                pccifid=1,
                version=self.PCCIF_VERSION,
            ),
        ]


register_soc("mtk", MT6768)
register_soc("mtk", MT6765)
