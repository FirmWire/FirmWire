## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import sys
import struct
import logging
import binascii

from avatar2 import *

from . import FirmWirePeripheral
from firmwire.hw.fifo import CircularFIFO

log = logging.getLogger(__name__)

# TX and RX are from perspective of AP
# Same for head/tail and write/read
# e.g. TX means AP2CP
memory_map = {
    "magic": 0x00,
    "access": 0x04,
    "fmt_tx_head": 0x08,
    "fmt_tx_tail": 0x0C,
    "fmt_rx_head": 0x10,
    "fmt_rx_tail": 0x14,
    "raw_tx_head": 0x18,
    "raw_tx_tail": 0x1C,
    "raw_rx_head": 0x20,
    "raw_rx_tail": 0x24,
    # "reserved"    : 0x28, # 4056 bytes for padding to next page (0x1000)
}

memory_map_inv = dict([[v, k] for k, v in memory_map.items()])

# exact map to drivers/misc/modem_v1/link_device_memory.h
# struct __packed shmem_4mb_phys_map
class SHMPeripheral(FirmWirePeripheral):
    def hw_read(self, offset, size):
        offset_name = None
        if offset == 0x0:
            value = self.magic
            self.magic = 0xAA
            self.access = 1
        elif offset == 0x4:
            value = self.access

        elif offset == 0x8:
            value = self.fmt_tx_buff.head
        elif offset == 0xC:
            value = self.fmt_tx_buff.tail
        elif offset == 0x10:
            value = self.fmt_rx_buff.head
        elif offset == 0x14:
            value = self.fmt_rx_buff.tail

        elif offset == 0x18:
            value = self.raw_tx_buff.head
        elif offset == 0x1C:
            value = self.raw_tx_buff.tail
        elif offset == 0x20:
            value = self.raw_rx_buff.head
        elif offset == 0x24:
            value = self.raw_rx_buff.tail

        else:
            found = False
            for i, fifo in enumerate(
                [self.fmt_tx_buff, self.fmt_rx_buff, self.raw_tx_buff, self.raw_rx_buff]
            ):
                if fifo.within(offset):
                    found = True
                    fo = fifo.rebase(offset)
                    value = fifo.read_raw(fo, size)
                    offset_name = "%s_READ[%x]" % (fifo.name, fo)
                    break

            if not found:
                value = 0
                offset_name = "%x" % offset

        if offset_name is None:
            if offset in memory_map_inv:
                offset_name = memory_map_inv[offset]
            else:
                offset_name = "unknown"

        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        offset_name = None
        if offset == 0x0:
            self.magic = value
        elif offset == 0x4:
            self.access = value

        elif offset == 0x8:
            self.fmt_tx_buff.head = value
        elif offset == 0xC:
            self.fmt_tx_buff.tail = value
        elif offset == 0x10:
            self.fmt_rx_buff.head = value
            # TODO: dequeue elsewhere for handling
            self.fmt_rx_buff.dequeue()
        elif offset == 0x14:
            self.fmt_rx_buff.tail = value

        elif offset == 0x18:
            self.raw_tx_buff.head = value
        elif offset == 0x1C:
            self.raw_tx_buff.tail = value
        elif offset == 0x20:
            self.raw_rx_buff.head = value
            # TODO: dequeue elsewhere for handling
            self.raw_rx_buff.dequeue()
        elif offset == 0x24:
            self.raw_rx_buff.tail = value

        else:
            found = False
            for i, fifo in enumerate(
                [self.fmt_tx_buff, self.fmt_rx_buff, self.raw_tx_buff, self.raw_rx_buff]
            ):
                if fifo.within(offset):
                    found = True
                    fo = fifo.rebase(offset)
                    fifo.write_raw(fo, size, value)
                    offset_name = "%s_WRITE[%x]" % (fifo.name, fo)
                    break

            if not found:
                value = 0
                offset_name = "%x" % offset

        if offset_name is None:
            if offset in memory_map_inv:
                offset_name = memory_map_inv[offset]
            else:
                offset_name = "unknown"

        self.log_write(value, size, offset_name)

        return True

    def send_raw_packet(self, pkt):
        self.raw_tx_buff.queue(pkt)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.access = 0
        self.magic = struct.unpack(">I", b"BOOT")[0]  # Or mode DUMP

        # TX/RX relative to AP
        self.fmt_tx_buff = CircularFIFO("fmt_tx_buff", 0x1000, 0x1000)  # CP recv
        self.fmt_rx_buff = CircularFIFO("fmt_rx_buff", 0x2000, 0x1000)  # CP send
        self.raw_tx_buff = CircularFIFO("raw_tx_buff", 0x3000, 0x1FD000)  # CP recv
        self.raw_rx_buff = CircularFIFO("raw_rx_buff", 0x200000, 0x200000)  # CP send

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
