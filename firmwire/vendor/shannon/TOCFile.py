## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct


class TOCFileException(Exception):
    def __init__(self, message):
        super().__init__(message)


class TOCFile(object):
    def __init__(self, fp):
        self.entries = []
        self.entry_map = {}

        self._parse(fp)

    def get_section(self, name):
        return self.entry_map[name]

    def has_section(self, name):
        return name in self.entry_map

    def _parse(self, fp):
        self.header = TOCEntry(fp)

        if self.header.name != "TOC":
            raise TOCFileException("Invalid TOC file magic")

        while fp.tell() < self.header.size:
            hdr = TOCEntry(fp)

            if len(hdr.name) > 0:
                if hdr.name in self.entry_map:
                    raise TOCFileException("Duplicate TOC entry name found")

                self.entry_map[hdr.name] = hdr
                self.entries += [hdr]
            else:
                break

        fp.seek(0)

        for e in self.entries:
            # skip entries that are just a memory map placeholder
            if (e.offset == 0 or e.load_address == 0) and e.name != "BOOT":
                e.meta_section = True
                continue

            fp.seek(e.offset)
            e.data = memoryview(fp.read(e.size))

    """Saves a copy of the (modified) TOC File to disk"""

    def save(self, filename):
        with open(filename, "wb") as f:
            f.write(bytes(self.header))
            for e in self.entries:
                f.write(bytes(e))

            f.write(b"\x00" * (self.header.size - f.tell()))

            for s in sorted(self.entries, key=lambda x: x.offset):
                if s.meta_section is False:
                    f.write(s.data)


class TOCEntry(object):
    def __init__(self, fp):
        need_bytes = 0x20
        self.header = fp.read(need_bytes)

        if len(self.header) != need_bytes:
            raise TOCFileException(
                "Not enough data to decode TOC entry (got %d bytes, needed %d)"
                % (len(self.header), need_bytes)
            )

        self.data = b""
        self.meta_section = False

        self.name = self.header[:12].strip(b"\x00").decode("ascii", "ignore")
        self.offset = struct.unpack("i", self.header[12:16])[0]
        self.load_address = struct.unpack("i", self.header[16:20])[0]
        self.size = struct.unpack("i", self.header[20:24])[0]
        self.crc = struct.unpack("i", self.header[24:28])[0]
        self.id = struct.unpack("i", self.header[28:32])[0]

    def __bytes__(self):
        """returns only the tocentry header, not the data"""
        toc_bytes = b""
        toc_bytes += self.name.ljust(12, "\x00").encode()
        toc_bytes += struct.pack("i", self.offset)
        toc_bytes += struct.pack("i", self.load_address)
        toc_bytes += struct.pack("i", self.size)
        toc_bytes += struct.pack("i", self.crc)
        toc_bytes += struct.pack("i", self.id)

        return toc_bytes

    def __repr__(self):
        return "TOCEntry<%s, offset=%08x, size=%08x, address=%08x>" % (
            self.name,
            self.offset,
            self.size,
            self.load_address,
        )
