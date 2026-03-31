from ..hw import *
from firmwire.hw.soc import FirmWireSOC


class ShannonSOC(FirmWireSOC):
    # Start in BOOT (can be overwritten)
    ENTRY_ADDRESS = 0x0
    GIC_MODEL = GicModel.A9_MPCORE

    # Whether the OSI for the TaskStruct should use the Moto or Samsung version

    name = "Unknown"

    def __init__(self, date, main_section=None):
        self.date = date

    def __repr__(self):
        return "<ShannonSOC %s - %d>" % (self.name, self.date)
