## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct
import intervaltree
import logging

AP_NAME = ["NA", "P_RW", "P_RW/U_RO", "RW", "RESV", "P_RO/U_NA", "RO", "RESV"]

log = logging.getLogger(__name__)


class MPUEntry(object):
    def __init__(self, slot, base, size, flags):
        self.slot = slot
        self.base = base
        self.size = size
        self.flags = flags

        XN = (flags >> 12) & 1
        AP = (flags >> 8) & 0b111
        B = (flags) & 1
        C = (flags >> 1) & 1
        S = (flags >> 2) & 1
        TEX = (flags >> 3) & 0b111

        self.executable = not bool(XN)
        self.writable = AP == 1 or AP == 2 or AP == 3
        self.readable = AP != 0 and AP != 4 and AP != 7

    def get_start(self):
        return self.base

    def get_end(self):
        return self.base + self.size - 1

    def get_rwx_str(self):
        r = "r" if self.readable else "-"
        w = "w" if self.writable else "-"
        x = "x" if self.executable else "-"
        return "%c%c%c" % (r, w, x)

    def __repr__(self):

        return "<MPUEntry [%08x, %08x] id=%d perm=%s>" % (
            self.get_start(),
            self.get_end(),
            self.slot,
            self.get_rwx_str(),
        )


class AddressItem(object):
    def __init__(self, addr, mpu, priority, end):
        self.addr = addr
        self.mpu = mpu
        self.priority = priority
        self.end = end

    def __repr__(self):
        return "<AddressItem [%08x] end=%s>" % (self.addr, self.end)


class AddressRange(object):
    def __init__(self, start, size, mpu):
        self.start = start
        self.size = size
        self.mpu = mpu

    def __repr__(self):
        return "<AddressRange [%08x, %08x] mpu=%s>" % (
            self.start,
            self.start + self.size,
            self.mpu,
        )


def parse_mpu_table(modem_main, address):
    entries = []

    data = modem_main.data
    address -= modem_main.load_address

    while True:
        # print(hex(address+modem_main.load_address))

        slot, base, size = struct.unpack("3I", data[address : address + 0x4 * 3])
        address += 0xC
        access_control = struct.unpack("6I", data[address : address + 0x4 * 6])
        address += 0x4 * 6
        enable = struct.unpack("I", data[address : address + 0x4])
        address += 0x4

        # in the binary these are effectively OR'd using ADD
        access_control = sum(access_control)
        size_select = (size >> 1) & 0b11111

        if size_select < 7:
            log.warning(
                "MPU table entry has an illegal size choice (%d). As per the Cortex-R reference manual, 7 should be the lowest. Rounding up...",
                size_bytes,
            )
            #  Even this size is a bit small for QEMU, which expects stricter alignment
            size_select = 7

        size_bytes = 2 ** (8 + size_select - 7)

        if slot == 0xFF:
            break

        entry = MPUEntry(slot, base, size_bytes, access_control)
        entries += [entry]

    return entries


"""
Takes a list of MPU entries and converts them to a list of memory ranges with permissions
while taking into account how MPU entries are processed in the hardware. This handles
the case of MPU entry ranges overlapping with each other with different permissions.

For instance, one large range of read only memory with small spots of executable or
writable memory.
"""


def consolidate_mpu_table(entries):
    addr_entries = []
    final_entries = []
    for e in entries:
        addr_entries += [AddressItem(e.get_start(), e, e.slot, False)]
        addr_entries += [AddressItem(e.get_end(), e, e.slot, True)]

    addr_entries = sorted(addr_entries, key=lambda x: (x.addr, int(x.end)))
    active = {}

    # https://softwareengineering.stackexchange.com/questions/363091/split-overlapping-ranges-into-all-unique-ranges
    for i, e in enumerate(addr_entries[:-1]):
        en = addr_entries[i + 1]
        if e.end:
            del active[e.priority]
        else:
            active[e.priority] = e.mpu

        start = e.addr if not e.end else e.addr + 1
        end = en.addr - 1 if not en.end else en.addr

        if start <= end and len(active):
            mpu = active[max(active)]
            final_entries += [AddressRange(start, end - start + 1, mpu)]

    return final_entries
