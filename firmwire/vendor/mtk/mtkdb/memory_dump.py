## Copyright (c) 2025, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause

import struct
import logging
import os
import snappy

FILE_MAGIC = b"EDBGINFO"
MUXZ_MAGIC = b"\x4d\x55\x5a\x1a"

log = logging.getLogger(__name__)

def is_muxz(file_path):
    with open(file_path, "rb") as f:
        magic = f.read(len(MUXZ_MAGIC))
    return magic == MUXZ_MAGIC

def uncompress_muxz(file_path):
    with open(file_path, "rb") as f:
        result_chunks = []
        first_content_chunk = f.read(0x100)

        header_start = first_content_chunk.find(MUXZ_MAGIC)+4
        data_start = first_content_chunk.find(MUXZ_MAGIC, header_start)+4
        if data_start <= 0:
            print("Could not find start of MUXZ data")
            return None
        f.seek(data_start)

        # 6 byte header
        # 3 bytes: size of uncompressed contents
        # 3 bytes: number of compressed bytes to uncompress
        while True:
            uncompressed_size_entry_chunk = f.read(3)
            if len(uncompressed_size_entry_chunk) != 3:
                break
            uncompressed_chunk_size, = struct.unpack("<I", uncompressed_size_entry_chunk + b"\0")
            chunk_size, = struct.unpack("<I", f.read(3) + b"\0")

            try:
                compressed = f.read(chunk_size)
                assert(len(compressed) == chunk_size)
                uncompressed_chunk = snappy.uncompress(compressed)

                result_chunks.append(uncompressed_chunk)
                data_start += chunk_size
                assert(uncompressed_chunk_size == len(uncompressed_chunk))
            except Exception as e:
                print("Exception: {}".format(e))
                break

        joined = b''.join(result_chunks)
        out_path = file_path + "_uncompressed"
        with open(out_path, "wb") as out_f:
            out_f.write(joined)
        return out_path

class MtkMemoryDump:
    def __init__(self, path):
        self.sections = []
        if is_muxz(path):
            log.info("Memory dump appears to be MUXZ compressed, uncompressing...")
            uncompressed_path = uncompress_muxz(path)
            if uncompressed_path is None:
                raise ValueError("Failed to uncompress MUXZ memory dump")
            path = uncompressed_path

        with open(path, "rb") as f:
            if not self.has_magic(f):
                raise ValueError("Memory dump does not have expected magic bytes")

            if not self.get_version(f) == 2:
                raise ValueError("Unsupported memory dump version")

            while f.tell() < os.path.getsize(path):
                section = MtkMemoryDumpSection(f)
                if not section.has_mapping():
                    continue
                self.sections.append(section)

    def get(self, addr, length):
        for section in self.sections:
            if section.get_virtual_offset() <= addr and (section.get_virtual_offset() + section.length) >= (addr + length):
                start = addr - section.get_virtual_offset()
                end = start + length
                return section.data[start:end]

    def has_magic(self, f):
        f.seek(0)
        return f.read(len(FILE_MAGIC)) == FILE_MAGIC

    def get_version(self, f):
        f.seek(len(FILE_MAGIC))
        version_bytes = f.read(4)
        version = struct.unpack("<I", version_bytes)[0]
        return version

class MtkMemoryDumpSection:
    def __init__(self, f):
        self.header_offset = f.tell()
        header_length, = struct.unpack("<I", f.read(0x4))
        header_length = (header_length - 8) ^ 0xffffffff
        inverse_section_name = f.read(header_length)
        self.section_name = (''.join([chr(c ^ 0xff) for c in inverse_section_name[::-1]]))
        self.length, = struct.unpack("<I", f.read(0x4))
        self.data_offset = f.tell()
        self.end_of_section = self.data_offset + self.length
        self.data = f.read(self.length)
        log.debug(f"Found section {self.section_name} with length {self.length}, starts at 0x{self.data_offset}, ends at 0x{self.end_of_section:X}")

        if self.get_virtual_offset() is None:
            log.debug(f"... ignoring section {self.section_name} during restoring")
            return
        log.debug(f"...mapping to 0x{self.get_virtual_offset():X}")

    def get_virtual_offset(self):
        if self.section_name.startswith("sys_mem_"):
            return int(self.section_name[len("sys_mem_"):], 16)
        else:
            return None
    
    def has_mapping(self):
        return self.get_virtual_offset() is not None

    def get_data(self):
        return self.data
