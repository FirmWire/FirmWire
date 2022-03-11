## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from collections import OrderedDict
from abc import ABC, abstractmethod
from struct import unpack


class TaskLayout(ABC):
    @property
    @abstractmethod
    def NAME():
        pass

    @classmethod
    def SIZE(cls):
        return cls.TASK_STRUCT_SIZE


class SamsungTaskLayout(TaskLayout):
    NAME = "samsung"

    TASK_STRUCT_SIZE = 0x108

    TASK_STACKBASE_OFFSET = 0x10
    TASK_NAME_PTR_OFFSET = 0x24
    TASK_SCHED_PRIO_OFFSET = 0x28
    TASK_STACKSIZE_OFFSET = 0x2C
    TASK_MAIN_FN_OFFSET = 0x30
    TASK_PRE_FN_OFFSET = 0x34

    SUBTASK_MAGIC_OFFSET = 0x8
    SUBTASK_NAME_OFFSET = 0x5C
    SUBTASK_TASK_P_OFFSET = 0x68
    SUBTASK_NAME_SIZE = 0x8


class MotoTaskLayout(TaskLayout):
    NAME = "moto"

    TASK_STRUCT_SIZE = 0x118

    TASK_STACKBASE_OFFSET = 0x10
    TASK_NAME_PTR_OFFSET = 0x24
    TASK_SCHED_PRIO_OFFSET = 0x28
    TASK_STACKSIZE_OFFSET = 0x2C
    TASK_MAIN_FN_OFFSET = 0x30
    TASK_PRE_FN_OFFSET = 0x34

    SUBTASK_MAGIC_OFFSET = 0x8
    SUBTASK_NAME_OFFSET = 0x5C
    SUBTASK_TASK_P_OFFSET = 0x70
    SUBTASK_NAME_SIZE = 0x10


TASK_LAYOUT_BY_NAME = OrderedDict(
    {
        SamsungTaskLayout.NAME: SamsungTaskLayout,
        MotoTaskLayout.NAME: MotoTaskLayout,
    }
)


def get_task_layout_by_name(name):
    return TASK_LAYOUTS_BY_NAME[name]


def get_task_layouts():
    return list(TASK_LAYOUT_BY_NAME.values())


class Task:
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

    def __init__(
        self,
        address,
        task_layout,
        raw_bytes=None,
        name_ptr=None,
        stackbase=None,
        main_fn=None,
        pre_fn=None,
    ):
        """
        Creates a task data based on the input.
        If raw_bytes is not set, all non specified fields are initialized to 0
        """

        self.entries = {}
        self.name = ""
        self.address = address

        for k, v in task_layout.__dict__.items():
            if k.startswith("TASK_") and k.endswith("_OFFSET"):
                self.entries[k[5:-7].lower()] = v

        self.data = (
            bytearray(task_layout.SIZE()) if raw_bytes is None else bytearray(raw_bytes)
        )

        if name_ptr:
            self.set_int(task_layout["TASK_NAME_PTR_OFFSET"], name_ptr)
        if stackbase:
            self.set_int(task_layout["TASK_STACKBASE_OFFSET"], stackbase)
        if main_fn:
            self.set_int(task_layout["TASK_MAIN_FN_OFFSET"], main_fn)
        if pre_fn:
            self.set_int(task_layout["TASK_PRE_FN_OFFSET"], pre_fn)
