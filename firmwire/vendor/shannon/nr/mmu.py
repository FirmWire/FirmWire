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

    @classmethod
    def unpack(cls, slot, array):
        num_sections, virt_addr, phys_addr, flags = struct.unpack("<IIII", array)

        if num_sections == 0:
            return None

        size = num_sections * 0x100000
        return cls(slot, phys_addr, size, flags)

    def __repr__(self):
        return "<MMUEntry [{:08x}, {:08x}] id={} perm={}>".format(
            self.get_start(), self.get_end(), self.slot, self.prot
        )

"""
struct MMUEntry2 {
	// Virtual start address of this section
	void *virt_addr;
	// Physical start address of this section
	void *phys_addr;
	// Physical end address of this section (exclusive)
	void *end_addr;
	// Flags as described in https://developer.arm.com/documentation/ddi0406/c/System-Level-Architecture/Virtual-Memory-System-Architecture--VMSA-/Short-descriptor-translation-table-format/Short-descriptor-translation-table-format-descriptors?lang=en
	uint32_t flags;
};
"""
class MMUEntry2(MemEntry):
    def __init__(self, slot, base, size, flags):
        super().__init__(base, size, flags, slot)
        self.prot = extract_prot_from_flags(flags)

        self.executable = True if "x" in self.prot else False
        self.writable = True if "w" in self.prot else False
        self.readable = True if "r" in self.prot else False

    def get_rwx_str(self):
        return self.prot

    @classmethod
    def unpack(cls, slot, array):
        virt_addr, phys_start, phys_end, flags = struct.unpack("<IIII", array)
        size = phys_end - phys_start

        if size == 0:
            return None

        return cls(slot, phys_start, size, flags)

    def __repr__(self):
        return "<MMUEntry_2 [{:08x}, {:08x}] id={} perm={}>".format(
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


def parse_mmu_table(modem_main, address, entry_cls):
    entries = []
    unsafe_regions = []

    data = modem_main.data
    address -= modem_main.load_address

    slot = 0
    while True:
        array = data[address: address + 0x10]
        entry = entry_cls.unpack(slot, array)
        
        if entry is None:
            break

        if entry.get_rwx_str() == "rwx":
            unsafe_regions.append((entry.get_start(), entry.get_end()))

        entries += [entry]

        address += 0x10
        slot += 1

    return entries, unsafe_regions
