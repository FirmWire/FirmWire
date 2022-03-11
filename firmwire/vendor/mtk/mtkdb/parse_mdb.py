## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct
import lzma
import logging

log = logging.getLogger(__name__)


def reads32(f):
    x = f.read(4)
    return struct.unpack("<i", x)[0]


def read32(f):
    x = f.read(4)
    return struct.unpack("<I", x)[0]


def read16(f):
    x = f.read(2)
    return struct.unpack("<H", x)[0]


def read8(f):
    x = f.read(1)
    return struct.unpack("<B", x)[0]


def readCATD(f):
    magic = f.read(4)
    assert magic == b"CATD"
    idk1 = read32(f)
    idk2 = read32(f)
    magic = f.read(4)
    assert magic == b"HEAD"
    idk3 = read32(f)
    entrycount = read32(f)
    entries = []
    for n in range(entrycount):
        idke1 = read32(f)
        entryoffset = read32(f)
        entrysize = read32(f)
        entries.append((idke1, entryoffset, entrysize))
        log.debug(idke1, hex(entryoffset), hex(entrysize))
    entries2 = []
    for idke1, entryoffset, entrysize in entries:
        assert entrysize >= 16
        f.seek(entryoffset)
        magic = f.read(4)
        assert magic == b"DATA"
        idkee1 = read32(f)
        offset = read32(f)
        size = read32(f)
        if entrysize < 20:
            uncompsize = size  # a41..?
        else:
            uncompsize = read32(f)
        remainder = f.read(entrysize - 20)
        # log.debug(idke1, hex(size), hex(uncompsize), remainder.encode('hex'))
        log.debug(idke1, hex(size), hex(uncompsize))
        entries2.append((idkee1, offset, remainder, size, uncompsize))
    segments = []
    for idkee1, offset, remainder, size, uncompsize in entries2:
        f.seek(offset)
        log.debug("%x (uncomp %x) bytes @ %x" % (size, uncompsize, offset))
        s = f.read(16)
        log.debug(s.hex())
        # if size != uncompsize:
        if size != uncompsize and s[:4] != b"CATD":  # FIXME
            f.seek(offset)
            props = read8(f)
            dict_size = read32(f)
            lc = props % 9
            props = int(props / 9)
            pb = int(props / 5)
            lp = props % 5
            filters = [
                {
                    "id": lzma.FILTER_LZMA1,
                    "dict_size": dict_size,
                    "lc": lc,
                    "lp": lp,
                    "pb": pb,
                }
            ]
            decomp = lzma.decompress(
                f.read(size - 5), format=lzma.FORMAT_RAW, filters=filters
            )
            segments += [decomp]
        else:
            f.seek(offset)
            data = f.read(size)
            segments += [data]
    return segments
