class MemEntry(object):
    def __init__(self, start, size, flags, slot):
        self.start = start
        self.size = size
        assert size > 0
        self.end = self.start + self.size - 1
        self.flags = flags
        self.slot = slot

        self.executable = True
        self.writable = True
        self.readable = True
    
    def get_start(self):
        return self.start

    def get_end(self):
        return self.end
