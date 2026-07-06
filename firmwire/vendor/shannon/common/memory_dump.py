import sys
import re
import struct
import os

class DumpMapping():
    def from_dump(self, offset):
        addr = offset + self.dump_base
        if(addr >= self.restore_start and addr < self.restore_end):
            return addr
        return -1

    def to_dump(self, addr):
        if(addr >= self.restore_start and addr < self.restore_end):
            return addr - self.dump_base
        else:
            return -1



class ShannonMemoryDump(DumpMapping):
    def __init__(self, path, restore_start, restore_end, dump_base):
        with open(path, "rb") as f:
            self.dump = memoryview(f.read())

        self.restore_start = restore_start
        self.restore_end = restore_end
        self.dump_base = dump_base
        self.heap = ShannonHeap(path, self.dump, restore_start, restore_end, dump_base)


    def get(self, addr, length):
        offset = self.to_dump(addr)
        if(offset > 0):
            return bytes(self.dump[offset:offset+length])
        return None



class ShannonHeap(DumpMapping):
    def __init__(self, fp, dump, restore_start, restore_end, dump_base):
        self.restore_start = restore_start
        self.restore_end = restore_end
        self.dump_base = dump_base

        self.find_heap_data(dump)



    # Find Heap Metadata
    def find_heap_data(self, dump):
        pattern = b"MemoryInterface/MemoryDriver/src/pal_MemDriverPmd.c"
        res = re.finditer(pattern, dump)
        ptr = 0
        N = 0

        for r in res:
            i = r.start() - 1
            while True:
                #read back until zero byte / end of string
                if(dump[i] == 0x0):
                    break
                i -= 1
            heap_metadata_fileptr = self.from_dump(i+1)
            N+=1

        assert(N==1)
        hp_block = 0
        # There is exactly 1 allocation using the above pointer, this is the heap metadata chunk
        res = re.finditer(struct.pack("<I", heap_metadata_fileptr), dump)
        for r in res:
            if(dump[r.start()-8:r.start()-4] == b"\x01\x00\x00\x00"):
                hp_block = r.start() + 0x18

        assert(hp_block != 0)

        self.heap_metadata_start = self.from_dump(hp_block-0x20)

        self.heap_start = int.from_bytes(dump[hp_block+0x4:hp_block+0x4+0x4], "little")
        self.heap_end = int.from_bytes(dump[hp_block+0x8:hp_block+0x8+0x4], "little")


    def read_c_string(self, fmt_ptr, binary):
        i = 0
        fmt = b""
        offset = self.to_dump(fmt_ptr)
        while(True):
            b = bytes(binary[offset:offset+1])
            if(b == b"\x00"):
                break
            fmt+=b
            offset +=1
        return fmt



