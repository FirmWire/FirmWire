## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from enum import Enum, auto
from .hw.soc import SOCPeripheral


class MemoryMapEntryType(Enum):
    GENERIC = auto()
    FILE_BACKED = auto()
    PERIPHERAL = auto()
    ANNOTATION = auto()


class MemoryMapEntry:
    def __init__(self, ty, start, size, **kwargs):
        assert type(ty) == MemoryMapEntryType
        assert isinstance(start, int), start
        assert isinstance(size, int), size

        self.ty = ty
        self.start = start
        self.size = size
        self.kwargs = kwargs

    def __repr__(self):
        return "<MemoryMapEntry %s [%x - %x]>" % (
            self.ty,
            self.start,
            self.start + self.size,
        )


class MemoryMap:
    def __init__(self):
        self.memory_map = []

    def add_file_backed_memory(self, start, size, file, **kwargs):
        self.memory_map += [
            MemoryMapEntry(
                MemoryMapEntryType.FILE_BACKED, start, size, file=file, **kwargs
            )
        ]

    def add_memory_range(self, start, size, **kwargs):
        # backwards compatibility
        if "emulate" in kwargs:
            peripheral_cls = kwargs["emulate"]
            del kwargs["emulate"]

            return self.create_peripheral(peripheral_cls, start, size, **kwargs)

        self.memory_map += [
            MemoryMapEntry(MemoryMapEntryType.GENERIC, start, size, **kwargs)
        ]

    def add_memory_annotation(self, start, size, name):
        self.memory_map += [
            MemoryMapEntry(MemoryMapEntryType.ANNOTATION, start, size, name=name)
        ]

    def create_peripheral(self, peripheral_cls, start, size, **kwargs):
        self.memory_map += [
            MemoryMapEntry(
                MemoryMapEntryType.PERIPHERAL,
                start,
                size,
                emulate=peripheral_cls,
                **kwargs
            )
        ]

    def create_soc_peripheral(self, peripheral):
        assert isinstance(peripheral, SOCPeripheral)

        # The SOCPeripheral class captures the reference
        self.create_peripheral(
            peripheral, peripheral._address, peripheral._size, **peripheral._attr
        )
