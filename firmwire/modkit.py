## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from pathlib import PurePath, Path


class Module:
    def __init__(self, elf_path, bin_path):
        self.elf_path = elf_path
        self.bin_path = bin_path


class ModKit:
    def __init__(self):
        self._search_paths = []

    def insert_search_path(self, path):
        self._search_paths = [PurePath(path)] + self._search_paths

    def append_search_path(self, path):
        self._search_paths = self._search_paths + [PurePath(path)]

    def get_search_paths(self):
        return self._search_paths

    def find_module(self, name):
        for search_path in self._search_paths:
            elf_path = Path(search_path / PurePath("%s.elf" % name))
            bin_path = Path(search_path / PurePath("%s.bin" % name))

            if elf_path.exists() and bin_path.exists():
                return Module(elf_path, bin_path)

        return None
