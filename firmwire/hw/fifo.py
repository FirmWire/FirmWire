## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging
import binascii

log = logging.getLogger(__name__)


class CircularFIFO(object):
    def __init__(self, name, offset, size):
        self.size = size
        self.head = 0
        self.tail = 0
        self.name = name
        self.start_offset = offset
        self.fifo = [0] * self.size

    def queue(self, item):
        # TODO: add mutex
        # TODO: make sure we have enough space for the packet
        for i, c in enumerate(item):
            o = (self.head + i) % self.size
            self.fifo[o] = c

        self.head = (self.head + len(item)) % self.size

        log.info("SHM %s[QUEUE] %s %d", self.name, self.dump_item(item), self.head)

    def dump_item(self, item):
        hexitem = binascii.hexlify(item).decode()
        return "".join(["\\x" + hexitem[i * 2 : (i + 1) * 2] for i in range(len(item))])

    def dequeue(self):
        if self.tail == self.head:
            return None

        # TODO: add mutex
        # TODO: make sure we have enough space for the packet

        item = []
        tail = self.tail
        head = self.head
        while tail != head:
            item += [self.fifo[tail]]
            tail = (tail + 1) % self.size

        self.tail = tail

        item = bytes(item)

        log.info("SHM %s[DEQUEUE] %s", self.name, self.dump_item(item))

        return item

    def write_raw(self, offset, size, value):
        for i in range(size):
            self.fifo[offset + i] = (value >> (i * 8)) & 0xFF

    def read_raw(self, offset, size):
        data = self.fifo[offset : offset + size]
        value = 0
        for i in range(size):
            value |= data[i] << (i * 8)

        return value

    def within(self, offset):
        return offset >= self.start_offset and (offset < self.start_offset + self.size)

    def rebase(self, offset):
        return offset - self.start_offset
