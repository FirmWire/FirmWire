## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging
import time
import json
from collections import OrderedDict
from firmwire.util.BinaryPattern import BinaryPattern

log = logging.getLogger(__name__)


def _stable_hasher(obj):
    if isinstance(obj, tuple):
        return hash(tuple([_stable_hasher(x) for x in obj]))
    elif isinstance(obj, str):
        return hash(tuple([ord(x) for x in obj]))
    elif isinstance(obj, (int, bool, float, type(None))):
        return hash(obj)
    elif isinstance(obj, bytes):
        return hash(tuple(obj))
    elif isinstance(obj, list):
        return _stable_hasher(tuple(obj))
    elif isinstance(obj, dict):
        hash_inputs = []

        for k, v in sorted(obj.items(), key=lambda x: x[0]):
            hash_inputs += [_stable_hasher(k), _stable_hasher(v)]

        return hash(tuple(hash_inputs))
    elif callable(obj):
        return _stable_hasher(obj.__code__)
    elif isinstance(obj, type(_stable_hasher.__code__)):
        """
        We try to get a hash of a compiled function.

        Using this, we can invalidate cache items that were produced by functions.
        This is limited to only the current function body. If other functions
        called by this one change, we can't detect this without a recursive hash.
        """
        co = obj
        func = tuple(
            [
                obj.co_code,  # bytecode
                obj.co_consts,  # numbers referenced by code
                obj.co_varnames,  # all local variables
                obj.co_names,  # all referenced names
                obj.co_freevars,
                obj.co_cellvars,
            ]
        )

        # For debugging :)
        # import dis
        # dis.dis(obj)

        return _stable_hasher(func)
    else:
        print()
        raise ValueError("Unable to hash object %s of type %s" % (obj, type(obj)))


class PatternDBEntry:
    def __init__(self, name):
        self.name = name
        self.pattern = None
        self.within = None
        self.offset = None
        self.soc_match = None
        self.offset_end = None
        self.align = None
        self.lookup = None
        self.post_lookup = None
        self.required = False

    def get(self, attr):
        return getattr(self, attr)

    def __contains__(self, key):
        return key in self.__dict__ and self.__dict__[key] is not None

    def __getitem__(self, key):
        return self.__dict__[key]

    def __setitem__(self, key, value):
        self.__dict__[key] = value

    def __hash__(self):
        # build a tuple of values to benefit from tuplehash()
        return _stable_hasher(self.__dict__)

    def __repr__(self):
        return "<PatternDBEntry %s>" % (self.name)


class PatternDB:
    def __init__(self, loader):
        self.patterns = OrderedDict()
        self.loader = loader
        self._pattern_cache_path = self.loader.workspace.path("/patterndb.cache")

        self._pattern_cache = {}
        self._load_pattern_cache()

    def add_pattern(self, pattern):
        assert isinstance(pattern, PatternDBEntry)

        if pattern.name in self.patterns:
            log.warning("Pattern %s already exists. Replacing")

        self.patterns[pattern.name] = pattern

        if not self._validate_pattern(pattern):
            raise ValueError("Invalid pattern: %s" % (pattern))

    def _validate_pattern(self, p):
        # TODO
        return True

    def _load_pattern_cache(self):
        if self._pattern_cache_path.exists():
            self._pattern_cache = json.load(self._pattern_cache_path.open())

    def _save_pattern_cache(self, cache):
        json.dump(cache, self._pattern_cache_path.open(mode="w"))

    def find_patterns(self, data, offset):
        log.info(
            "Searching for patterns in [%08x - %08x]" % (offset, len(data) + offset)
        )
        start_time = time.time()

        new_cache = {}

        for name, entry in self.patterns.items():
            cache_key = "%s_%s" % (name, hash(entry))

            if cache_key in self._pattern_cache:
                address = self._pattern_cache[cache_key]
                sym = self.loader.symbol_table.add(name, address)
                log.info("Found symbol %s -> %08x [CACHED]", name, address)
            else:
                address = self._find_pattern(data, offset, name, entry)

                if address is None:
                    continue

                sym = self.loader.symbol_table.add(name, address)

            new_cache[cache_key] = address

            # post_lookup handlers can side-effect state. they can never be safely cached
            if "post_lookup" in entry:
                res = entry["post_lookup"](self.loader, sym, data, offset)
                if not res:
                    log.error("Symbol %s post processing failed", name)

        total_time = time.time() - start_time
        log.info("Dynamic symbol resolution took %.2f seconds", total_time)

        self._save_pattern_cache(new_cache)

    def _find_pattern(self, data, offset, name, entry):
        required = entry.get("required")
        addr = None

        if "soc_match" in entry:
            if self.loader.modem_soc.name not in entry["soc_match"]:
                log.info("Skipping symbol %s for %s", name, self.loader.modem_soc.name)
                return None

        pat_time_start = time.time()

        if "lookup" in entry:
            addr = entry["lookup"](data, offset)
        elif "pattern" in entry:
            if isinstance(entry["pattern"], str):
                entry["pattern"] = [entry["pattern"]]

            for pat in entry["pattern"]:
                bp = BinaryPattern(name)
                bp.from_hex(pat)

                loc = None

                search_range = (0, len(data))

                # XXX: only works for MTK. SymbolTable needs concept of a range/size
                if "within" in entry:
                    start = self.loader.symbols[entry["within"]]
                    symsize = self.loader.symbol_sizes[entry["within"]]

                    base_addr = start - offset
                    search_range = (base_addr, base_addr + symsize)

                # Ensure the pattern conforms to an alignment
                if "align" in entry:
                    pos = search_range[0]

                    for tryno in range(20):
                        loc = bp.find(data, pos=pos, maxpos=search_range[1])
                        if loc is None:
                            break

                        if (loc[0] & (entry["align"] - 1)) == 0:
                            break

                        # Reset and try again
                        pos = loc[1]
                        loc = None
                else:
                    loc = bp.find(data, pos=search_range[0], maxpos=search_range[1])

                # No match, try alternate pattern
                if loc is None:
                    continue

                if "offset" in entry:
                    addr = loc[0] + offset + entry["offset"]
                elif "offset_end" in entry:
                    addr = loc[1] + offset + entry["offset_end"]
                else:
                    addr = loc[0] + offset

                break

        pat_time_end = time.time()

        if required and addr is None:
            log.warning("Unable to resolve required dynamic symbol %s", name)
            raise ValueError("Symbol resolution")
        elif addr is None:
            log.warning(
                "Unable to resolve dynamic symbol %s. Functionality may be affected",
                name,
            )
            return None

        pat_time = pat_time_end - pat_time_start
        log.info("Found symbol %s -> %08x [%.2fs]", name, addr, pat_time)

        PAT_TIME_WARN = 5
        if pat_time > PAT_TIME_WARN:
            log.warning(
                "%s took more than %d seconds to find. Consider optimizing...",
                name,
                PAT_TIME_WARN,
            )

        return addr
