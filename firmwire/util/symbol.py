## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import csv
import json
import lz4.frame

from enum import IntEnum


class SymbolType(IntEnum):
    UNKNOWN = 0
    FUNCTION = 1
    THUNK_FUNCTION = 2
    EXT_FUNCTION = 3
    LABEL = 4
    DATA_LABEL = 5
    INSN_LABEL = 6

    @staticmethod
    def FromName(name):
        if name == "Function":
            return SymbolType.FUNCTION
        elif name == "Thunk Function":
            return SymbolType.THUNK_FUNCTION
        elif name == "External Function":
            return SymbolType.EXT_FUNCTION
        elif name == "Label":
            return SymbolType.LABEL
        elif name == "Data Label":
            return SymbolType.DATA_LABEL
        elif name == "Instruction Label":
            return SymbolType.INSN_LABEL
        else:
            return SymbolType.UNKNOWN


class Symbol(object):
    __slots__ = (
        "address",
        "name",
        "symbol_ty",
    )

    def __init__(self, name, address, symbol_ty):
        if not isinstance(name, str):
            raise TypeError("Invalid constructor type")
        if not isinstance(address, int):
            raise TypeError("Invalid constructor type")
        if not isinstance(symbol_ty, SymbolType):
            raise TypeError("Invalid constructor type")

        self.address = address
        self.name = name
        self.symbol_ty = symbol_ty

    def format(self, offset=0):
        if offset > 0:
            return "%s+0x%x" % (self.name, offset)
        elif offset < 0:
            return "%s-0x%x" % (self.name, -offset)
        else:
            return "%s" % (self.name)

    def __repr__(self):
        return "<Symbol %s @ 0x%x, ty=%s>" % (self.name, self.address, self.symbol_ty)


class SymbolTable(object):
    def __init__(self):
        self.symbols = []
        self.by_name = {}

    def __len__(self):
        return len(self.symbols)

    def load_compressed_json(self, filename, overwrite=False):
        with open(filename, "rb") as fp:
            with lz4.frame.open(fp) as lzfp:
                loaded_symbols = json.load(lzfp, object_hook=as_symbol)

        if overwrite:
            self.symbols = loaded_symbols
        else:
            self.symbols += loaded_symbols

        self._sort()
        self._build_name_table()

    def load_json(self, filename, overwrite=False):
        with open(filename, "r") as fp:
            loaded_symbols = json.load(fp, object_hook=as_symbol)

        if overwrite:
            self.symbols = loaded_symbols
        else:
            self.symbols += loaded_symbols

        self._sort()
        self._build_name_table()

    def save_json(self, filename):
        self._sort()

        with open(filename, "w") as fp:
            json.dump(self.symbols, fp, cls=SymbolEncoder)

    def load_ghidra_csv(self, filename):
        self.symbols = []
        addrs_seen = {}

        with open(filename) as fp:
            for i, row in enumerate(csv.reader(fp, delimiter=",")):
                if i == 0:
                    continue

                (
                    name,
                    location,
                    symbol_type,
                    namespace,
                    source,
                    refcount,
                    offcut_refcount,
                ) = row

                # GHIDRA generates these and they are pretty noisy and useless to have as symbol
                # Example: "caseD_0","405fc714","Instruction Label","","switchD_405fc70a","Analysis","1","0"
                if namespace.startswith("switch"):
                    continue

                symbol_type_obj = SymbolType.FromName(symbol_type)

                if symbol_type_obj == SymbolType.EXT_FUNCTION:
                    location = location[len("External[") : -1]

                try:
                    location = int(location, 16)
                    refcount = int(refcount)
                except ValueError:
                    continue

                # hack to have the most desirable symbol (demangled names)
                if location in addrs_seen:
                    refs = addrs_seen[location]

                    if refcount <= addrs_seen[location]:
                        continue

                addrs_seen[location] = refcount

                sym = Symbol(name, location, symbol_type_obj)
                self.symbols += [sym]

        self._sort()
        self._build_name_table()

    def add(self, name, location, ty=SymbolType.LABEL):
        sym = Symbol(name, location, ty)
        self.by_name[sym.name] = self.by_name.get(sym.name, []) + [sym]
        self._insert_symbol_inorder(sym)
        return sym

    def set(self, name, location, ty=SymbolType.LABEL):
        sym = Symbol(name, location, ty)
        self.by_name[sym.name] = [sym]
        self._insert_symbol_inorder(sym)
        return sym

    def replace(self, name, location, ty=SymbolType.LABEL):
        self.remove(name)
        self.add(name, location, ty)

    def remove(self, name):
        if name not in self.by_name:
            raise ValueError("Cannot remove symbol %s: does not exist" % name)

        symbols = self.by_name[name]
        del self.by_name[name]

        for sym in symbols:
            idx_to_delete = None
            for idx, found_sym in self._find_by_address(sym.address):
                if id(found_sym) == id(sym):
                    idx_to_delete = idx
                    break

            assert idx_to_delete is not None

            # XXX: O(n) operation
            del self.symbols[idx]

    def lookup(self, where, **kwargs):
        if isinstance(where, str):
            return self._lookup_by_name(where, *kwargs)
        elif isinstance(where, int):
            return self._lookup_by_address(where, *kwargs)
        else:
            raise TypeError("lookup requires an address or symbol name")

    def _lookup_by_address(self, address, exact=False):
        sym = self._find_closest_by_address(address)

        if sym is None:
            return None

        if exact and address != sym.address:
            return None
        else:
            return sym

    def _lookup_by_name(self, name, single=True):
        if name in self.by_name:
            syms = self.by_name[name]

            if single:
                return syms[0]

            return syms
        else:
            return None

    def _build_name_table(self):
        self.by_name = {}

        for sym in self.symbols:
            self.by_name[sym.name] = self.by_name.get(sym.name, []) + [sym]

    def _sort(self):
        self.symbols = sorted(self.symbols, key=lambda x: x.address)

    def _insert_symbol_inorder(self, new_sym):
        if len(self.symbols) == 0:
            self.symbols = [new_sym]
            return

        idx = self._find_index_by_address(new_sym.address)

        # XXX: very expensive (O(n))
        # Use something like blist which is a hybrid tree/array
        if self.symbols[idx].address <= new_sym.address:
            self.symbols = self.symbols[: idx + 1] + [new_sym] + self.symbols[idx + 1 :]
        else:
            self.symbols = self.symbols[:idx] + [new_sym] + self.symbols[idx:]

    def _find_index_by_address(self, address):
        if len(self.symbols) == 0:
            return None

        left = 0
        right = len(self.symbols) - 1

        while left < right:
            mid = (right + left) // 2
            symbol = self.symbols[mid]
            last_idx = mid

            if symbol.address < address:
                left = mid + 1
            else:
                right = mid

        idx = left
        symbol = self.symbols[idx]

        offset = address - symbol.address

        if offset < 0 and left > 0:
            return idx - 1
        else:
            return idx

    def _find_by_address(self, address):
        symbols = []
        idx = self._find_index_by_address(address)

        if idx is None:
            return (0, 0)

        while idx < len(self.symbols):
            sym = self.symbols[idx]
            if sym.address == address:
                yield (idx, sym)
                idx += 1
            else:
                break

    def _find_closest_by_address(self, address):
        idx = self._find_index_by_address(address)

        if idx is None:
            return None

        return self.symbols[idx]


class SymbolEncoder(json.JSONEncoder):
    def default(self, obj):
        if type(obj) == SymbolType:
            return {"E": int(obj)}
        elif type(obj) == Symbol:
            return {"S": {"A": obj.address, "N": obj.name, "T": obj.symbol_ty}}
        return json.JSONEncoder.default(self, obj)


def as_symbol(d):
    if "E" in d:
        return SymbolType(d["E"])
    elif "S" in d:
        d = d["S"]
        return Symbol(d["N"], d["A"], SymbolType(d["T"]))
    else:
        return d


if __name__ == "__main__":
    print("main")
    table = SymbolTable()
    table.load_ghidra_csv("modem_symbols.csv")
    print("Loaded %d symbols (csv)" % len(table.symbols))
    table.save_json("a")
    print("Saved %d symbols" % len(table.symbols))
    table.load_json("a")
    print("Loaded %d symbols (json)" % len(table.symbols))
