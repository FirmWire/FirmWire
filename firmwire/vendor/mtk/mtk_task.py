## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import inspect
from struct import unpack

TASK_STRUCT_SIZE = 0x20

TASK_NAME_PTR_OFFSET = 0
TASK_SCHED_PRIO_OFFSET = 8
TASK_STACKSIZE_OFFSET = 0xC
TASK_MAIN_FN_OFFSET = 0x10


class TaskEntry:
    def __init__(self, parent_task, offset):
        pass


class MtkTask:
    def __getattribute__(self, name):
        if name == "__dict__" or name == "entries":
            return super().__getattribute__(name)
        elif name in self.entries:
            off = self.entries[name]
            return unpack("<I", self.data[off : off + 4])[0]
        return super().__getattribute__(name)

    def __setattr__(self, name, value):
        if name == "entries":
            super().__setattr__(name, value)
        elif name in self.entries:
            off = self.entries[name]
            self.set_int(off, value)
        else:
            super().__setattr__(name, value)

    def set_int(self, off, raw):
        self.data[off : off + 4] = raw.to_bytes(4, byteorder="little")

    def __init__(self, raw_bytes=None, name_ptr=None, create_fn=None, sched_prio=None):
        """
        Creates a task data based on the input.
        If raw_bytes is not set, all non specified fields are initialized to 0
        """

        glb = inspect.stack()[0].frame.f_globals  # get globals on file scope
        offsets = [
            g for g in filter(lambda x: x[0:5] == "TASK_" and x[-7:] == "_OFFSET", glb)
        ]
        self.entries = {o[5:-7].lower(): glb[o] for o in offsets}

        self.data = (
            bytearray(TASK_STRUCT_SIZE) if raw_bytes is None else bytearray(raw_bytes)
        )

        if name_ptr:
            self.set_int(TASK_NAME_PTR_OFFSET, name_ptr)
        if create_fn:
            self.set_int(TASK_MAIN_FN_OFFSET, create_fn)
        if sched_prio:
            self.set_int(TASK_SCHED_PRIO_OFFSET, sched_prio)


if __name__ == "__main__":
    t = Task()
