## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from ..hw import *
from firmwire.hw.soc import FirmWireSOC, SOCPeripheral, register_soc
from firmwire.util.BinaryPattern import BinaryPattern


class ShannonSOC(FirmWireSOC):
    # Start in BOOT (can be overwritten)
    ENTRY_ADDRESS = 0x0

    # Whether the OSI for the TaskStruct should use the Moto or Samsung version

    name = "Unknown"

    def __init__(self, date, main_section=None):
        self.date = date

    def __repr__(self):
        return "<ShannonSOC %s - %d>" % (self.name, self.date)


def dsp_base_search(main_section):
    # SoC init is before symbol resolving, so we do it here on our own
    # We abuse that the data pointer is right before the DSP_SUBSYS_CRTLDSP string
    bp = BinaryPattern("CRTLDSP_LOC", -4)
    bp.from_str(b"DSP_SUBSYS_CRTLDSP")

    str_loc = bp.find(main_section.data)
    if str_loc is None:
        print("Failed retrieving DSP base, defaulting to 0x47382000")
        return 0x47382000
    else:
        off = str_loc[0]
        return struct.unpack("<I", main_section.data[off : off + 4])[0]


class S5123(ShannonSOC):
    peripherals = []

    CHIP_ID = 0x20000000
    SIPC_BASE = 0x28000000
    SHM_BASE = 0x50000000
    SHM_PERIPHERAL = SHMPeripheralCortexA
    SOC_BASE = 0x82020000
    SOC_PERIPHERAL = ShannonSOCPeripheralCortexA
    SOC_CLK_BASE = 0x14400000
    CLK_PERIPHERAL = S5123APClkPeripheral
    IPC_PERIPHERAL = GIPCPeripheral
    TIMER_BASE = SOC_BASE + 0x50000  # Timer IRQ already taken.
    NUM_TIMERS = 8
    iTINT0 = 32
    GIC_MODEL = GicModel.A15_MPCORE

    name = "S5123"

    def __init__(self, date, main_section):
        super().__init__(date, main_section)

        self.peripherals += [
            SOCPeripheral(DSPPeripheralCortexA, 0x4f45a000, 0x1000, name="DSPPeripheral", sync=[0xc1, 0x1c8]),
            SOCPeripheral(self.CLK_PERIPHERAL,  0x10400000, 0x1000, name="SOC_CLK2"),
            SOCPeripheral(self.CLK_PERIPHERAL,  0x12050000, 0x1000, name="SOC_CLK3"),
            SOCPeripheral(SysCmuPeripheral,     0x83000000, 0x4000, name="SYS_CMU"),
            SOCPeripheral(Unknown5Peripheral,   0x11861000, 0x1000, name="UNK5"),
            SOCPeripheral(MsiPeripheral,        0x15000000, 0x1000, name="MSI"),
            SOCPeripheral(Unknown7Peripheral,   0x10000000, 0x1000, name="UNK7"),
            SOCPeripheral(Unknown11Peripheral,  0x83050000, 0x1000, name="UNK11"),
        ]


class S5000AP(ShannonSOC):
    peripherals = [
        # Faulting address: 0x8f910010
        # Faulting PC: 0x4103cd52:        str     r1, [r0, #0x10]
        SOCPeripheral(PMICPeripheral, 0x8F910000, 0x1000, name="PMIC"),
    ]

    CHIP_ID = 0x50000000
    SIPC_BASE = 0x8F920000
    SHM_BASE = 0x4B200000
    SOC_BASE = 0x82000000
    SOC_CLK_BASE = 0x83000000
    CLK_PERIPHERAL = S5000APClkPeripheral
    TIMER_BASE = SOC_BASE + 0x8000

    name = "S5000AP"

    def __init__(self, date, main_section):
        super().__init__(date)

        dsp_load_addr = dsp_base_search(main_section)
        self.peripherals += [
            SOCPeripheral(
                DSPPeripheral,
                dsp_load_addr,
                0x100,
                name="DSPPeripheral",
                sync=[141, 286],
            )
        ]


class S360AP(ShannonSOC):
    peripherals = [
        SOCPeripheral(S3xxAPBoot, 0x95B40000, 0x100, name="S3xxboot"),
        SOCPeripheral(PMICPeripheral, 0x8F110000, 0x1000, name="PMIC"),
    ]

    CHIP_ID = 0x03600000
    SIPC_BASE = 0x8F170000
    SHM_BASE = 0x48000000
    SOC_BASE = 0x82000000
    SOC_CLK_BASE = 0x83000000
    CLK_PERIPHERAL = S360APClkPeripheral
    TIMER_BASE = SOC_BASE + 0x8000

    name = "S360AP"

    def __init__(self, date, main_section):
        super().__init__(date)

        dsp_load_addr = dsp_base_search(main_section)
        if date > 20190000:
            self.peripherals += (
                SOCPeripheral(
                    DSPPeripheral,
                    dsp_load_addr,
                    0x100,
                    name="DSPPeripheral",
                    sync=[147, 296],
                ),
            )
        elif date > 20180600:
            self.peripherals += [
                SOCPeripheral(
                    DSPPeripheral,
                    dsp_load_addr,
                    0x100,
                    name="DSPPeripheral",
                    sync=[148, 300],
                )
            ]
        else:
            self.peripherals += [
                SOCPeripheral(
                    DSPPeripheral,
                    dsp_load_addr,
                    0x100,
                    name="DSPPeripheral",
                    sync=[145, 294],
                )
            ]


class S355AP(ShannonSOC):
    peripherals = [
        SOCPeripheral(PMICPeripheral, 0x96450000, 0x1000, name="PMIC"),
        SOCPeripheral(S355DSPBufferPeripheral, 0x47504000, 0x1000, name="DSPB"),
    ]

    CHIP_ID = 0x03550000
    SIPC_BASE = 0x95B40000
    SHM_BASE = 0x48000000
    SOC_BASE = 0x83000000
    SOC_CLK_BASE = 0x83002000
    CLK_PERIPHERAL = S355APClkPeripheral
    TIMER_BASE = SOC_BASE + 0xC000

    name = "S355AP"

    def __init__(self, date, main_section):
        super().__init__(date)
        if date > 20180000:
            self.peripherals += (
                SOCPeripheral(
                    DSPPeripheral,
                    0x4751B000,
                    0x100,
                    name="DSPPeripheral",
                    sync=[138, 290],
                ),
            )
        else:
            self.peripherals += (
                SOCPeripheral(
                    DSPPeripheral,
                    0x4751B000,
                    0x100,
                    name="DSPPeripheral",
                    sync=[137, 292],
                ),
            )


class S353AP(ShannonSOC):
    peripherals = []

    CHIP_ID = 0x03530000
    name = "S353AP"

    def __init__(self, date, main_section):
        super().__init__(date)


# S337AP MOTOONE
class S337AP(ShannonSOC):
    peripherals = [
        SOCPeripheral(MotoUARTPeripheral, 0x84005000, 0x1000, name="boot_uart"),
        SOCPeripheral(PMICPeripheral, 0x8F910000, 0x1000, name="PMIC"),
    ]
    # Quite similar to the S5000AP despite the SoC gap
    CHIP_ID = 0x03370000
    SIPC_BASE = 0x8F920000
    SHM_BASE = 0x48000000
    SOC_BASE = 0x82000000
    SOC_CLK_BASE = 0x83000000
    CLK_PERIPHERAL = S337APClkPeripheral
    TIMER_BASE = SOC_BASE + 0x8000

    # Overwrite the entry address to start at MAIN
    # Why? Well for some reason the WARM boot flags when set to 1,1 causes the BOOT
    # to fail with "Unknown", BUT changing these to 1,0 causes MAIN to fail as it doesn't
    # __scatterload (it expected WARM boot with code still in memory)
    #
    # So solution is to just skip BOOT
    ENTRY_ADDRESS = 0x40010000

    name = "S337AP"

    def __init__(self, date, main_section):
        super().__init__(date)

        if date < 2199970:
            self.peripherals += (
                SOCPeripheral(
                    DSPPeripheral,
                    0x4781E000,
                    0x100,
                    name="DSPPeripheral",
                    sync=[162, 324],
                ),
            )
        else:
            self.peripherals += (
                SOCPeripheral(
                    DSPPeripheral,
                    0x4781E000,
                    0x100,
                    name="DSPPeripheral",
                    sync=[164, 324],
                ),
            )


class S335AP(ShannonSOC):
    peripherals = [
        SOCPeripheral(S3xxAPBoot, 0x90540000, 0x100, name="S3xxboot"),
    ]

    CHIP_ID = 0x03350000
    SIPC_BASE = 0x8F170000
    SHM_BASE = 0x48000000
    SOC_BASE = 0x83000000
    SOC_CLK_BASE = 0x83002000
    CLK_PERIPHERAL = S355APClkPeripheral
    TIMER_BASE = SOC_BASE + 0xC000

    name = "S335AP"

    def __init__(self, date, main_section):
        super().__init__(date)

        dsp_load_addr = dsp_base_search(main_section)
        self.peripherals += [
            SOCPeripheral(
                DSPPeripheral,
                dsp_load_addr,
                0x100,
                name="DSPPeripheral",
                sync=[125, 255],
            )
        ]


CORTEX_A_SOC = ["S5123"]
CORTEX_R_SOC = ["S335AP", "S337AP", "S353AP", "S355AP", "S360AP", "S5000AP"]

register_soc("shannon", S335AP)
register_soc("shannon", S337AP)
register_soc("shannon", S353AP)
register_soc("shannon", S355AP)
register_soc("shannon", S360AP)
register_soc("shannon", S5000AP)
register_soc("shannon", S5123)
