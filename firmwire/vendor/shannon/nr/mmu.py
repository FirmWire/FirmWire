import struct

from firmwire.vendor.shannon.common.mem import MemEntry

AP_STR = {
    0b000: "--", 0b001: "rw", 0b010: "rw", 0b011: "rw",
    0b100: "--", 0b101: "r-", 0b110: "r-", 0b111: "r-"
}


class MMUEntry(MemEntry):
    def __init__(self, slot, base, size, flags):
        super().__init__(base, size, flags, slot)
        self.prot = extract_prot_from_flags(flags)

        self.executable = True if "x" in self.prot else False
        self.writable = True if "w" in self.prot else False
        self.readable = True if "r" in self.prot else False

    def get_rwx_str(self):
        return self.prot

    def __repr__(self):
        return "<MMUEntry [{:08x}, {:08x}] id={} perm={}>".format(
            self.get_start(), self.get_end(), self.slot, self.prot
        )


def extract_prot_from_flags(flags):
    ap = ((flags >> 10) & 3) | ((flags >> 13) & 4)
    prot = AP_STR[ap]
    pxn = flags & 1
    xn = flags & (1 << 4)
    if pxn == 1:
        xn = 1
    if prot != "--" and xn == 0:
        prot += "x"
    else:
        prot += "-"
    return prot


def parse_mmu_table(modem_main, address):
    entries = []
    unsafe_regions = []

    data = modem_main.data
    address -= modem_main.load_address

    slot = 0
    while True:
        array = data[address: address + 0x10]
        num_sections, virt_addr, phys_addr, flags = struct.unpack("<IIII", array)
        size = num_sections * 0x100000
        prot = extract_prot_from_flags(flags)

        if num_sections == 0:
            break

        if prot == "rwx":
            unsafe_regions.append((phys_addr, phys_addr + size))

        entry = MMUEntry(slot, phys_addr, size, flags)
        entries += [entry]

        address += 0x10
        slot += 1

    return entries, unsafe_regions
