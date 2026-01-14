from ..hw import *
from firmwire.hw.soc import SOCPeripheral, register_soc
from firmwire.vendor.shannon.common.hw import GicModel
from firmwire.vendor.shannon.common.soc import ShannonSOC

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


CORTEX_A_SOC = ["S5123"]

register_soc("shannon", S5123)
