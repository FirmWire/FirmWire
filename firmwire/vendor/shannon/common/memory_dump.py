import re
import struct
import json
import bisect


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
        self.path = path
        self.heap = ShannonHeap(path, self.dump, restore_start, restore_end, dump_base)
        self.metadata = {}
        self.stack = []


    def get(self, addr, length):
        offset = self.to_dump(addr)
        if(offset > 0):
            return bytes(self.dump[offset:offset+length])
        return None

    def print_metadata(self):
        print(json.dumps({k: [{k2 : hex(v2) for k2, v2 in vv.items()} for vv in v] for k,v in self.metadata.items()}, indent=4))


    

    def dump_metadata_to_file(self, path):
        # restore_start, restore_end, dump_base, heap_metadata_start, heap_start, heap_end, filtered
        filtered = []
        for key, vals in self.metadata.items():
            if(key == "STACK"):
                continue
            for val in vals:
                idx = bisect.bisect_left(filtered, val["start"], key=lambda x: x["start"])
                filtered.insert(idx, val)
                
                if(idx > 0):
                    if(filtered[idx]["start"] <= filtered[idx-1]["end"]):
                        assert(filtered[idx]["start"] >= filtered[idx-1]["start"])
                        filtered[idx]["start"] = filtered[idx-1]["start"]
                        if(filtered[idx-1]["end"] >= filtered[idx]["end"]):
                            filtered[idx]["end"] = filtered[idx - 1]["end"]
                        del(filtered[idx-1])

                while(idx < len(filtered) - 1):
                    if(filtered[idx]["end"] >= filtered[idx + 1]["start"]):
                        if(filtered[idx]["end"] <= filtered[idx + 1]["end"]):
                            filtered[idx]["end"] = filtered[idx + 1]["end"]
                            del(filtered[idx + 1])
                            break
                        else:
                            del(filtered[idx + 1])                
                    else:
                        break
        
        metadata =  {
                        "restore_start" : hex(self.restore_start),
                        "restore_end" : hex(self.restore_end),
                        "dump_base" : hex(self.dump_base),
                        "heap_metadata_start": hex(self.heap.heap_metadata_start),
                        "heap_start" : hex(self.heap.heap_start),
                        "heap_end" : hex(self.heap.heap_end),
                        # "filter" : [{k : hex(v)  for k,v in obj.items() } for obj in filtered]
                    }
        
        if(len(filtered) > 0):
            metadata["filter"] = [{k : hex(v)  for k,v in obj.items() } for obj in filtered]

        if("STACK" in self.metadata):
            metadata["stack"] = [{k : hex(v)  for k,v in obj.items() } for obj in
                                 sorted(self.metadata["STACK"], key = lambda x: x["start"])]

        with open(path, "w") as f:
            f.write(json.dumps
                (
                    metadata,
                    indent = 4
                )
            )


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



