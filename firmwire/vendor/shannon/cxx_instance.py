## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
"""
Runtime resolution of C++ singleton instances (`this` pointers).

The SMPF classes a 5G harness reaches into are heap allocated during boot, so
no byte pattern can find them. Every instance is found through its class'
vtable and constructor, which PatternDB resolves statically, in three ways:

  scan    search RAM for the vptr (vtable+8) that every instance stores at
          offset 0. Works on a restored snapshot without running any guest
          code, but returns hits in address order, which does not follow the
          stack order.
  ctor    breakpoint the constructor and record `this` (r0) per call. Only
          possible on a cold boot, and the only way that knows which stack an
          instance belongs to: construction order is stack order.
  method  breakpoint a function taking the instance as its first argument and
          record r0. Confirms that a pointer is a live instance of the class,
          but says nothing about its stack.

Images support dual SIM, so each class is constructed once per stack and a
pointer is only trustworthy once something established which stack it belongs
to: a cold boot (ctor), or the metadata a cold boot wrote into the snapshot it
created. Address order is not a substitute -- on oriole the stack 0 context is
the higher of the two instances while the stack 0 facade is the lower one.
"""
import logging
import struct

import firmwire.vendor.shannon.pattern_handlers as handlers

log = logging.getLogger(__name__)

WAY_SCAN = "scan"
WAY_CTOR = "ctor"
WAY_METHOD = "method"

# Discovery order. Earlier ways win when they disagree.
WAYS = (WAY_SCAN, WAY_CTOR, WAY_METHOD)

MACHINE_STATE_KEY = "cxx_instances"

# Which SIM stack a harness wants an instance of. Per-run rather than per-class,
# so classes only override it when they are not built once per stack.
DEFAULT_STACK = 0

# Mangled RTTI names of the classes the 5G harnesses reach into
MM_GENERAL_CONTEXT = "N2cn2mm27MmGeneralContext_MacroClassE"
NRMM_FACADE = "N2cn2mm10NrmmFacadeE"

CXX_INSTANCES = {
    "MmGeneralContext": {
        "cxx_class": MM_GENERAL_CONTEXT,
        "soc_match": ["S5123", "S5123AP"],
        "this_arg_fn": "SetMmState",
    },
    "NrmmFacade": {
        "cxx_class": NRMM_FACADE,
        "soc_match": ["S5123", "S5123AP"],
        "this_arg_fn": "NrmmStartProcedure_Wrapper",
    },
}

# Static symbols every instance needs, named after the class they belong to
CLASS_SYMBOLS = {"vtable": handlers.cxx_vtable, "ctor": handlers.cxx_ctor}


def class_symbol(name, kind):
    return "%s_%s" % (name, kind)


def instance_patterns():
    """PatternDB entries for every class in CXX_INSTANCES, so adding one here is
    all it takes to have its vtable and constructor resolved."""
    return {
        class_symbol(name, kind): {
            "cxx_class": spec["cxx_class"],
            "lookup": lookup(spec["cxx_class"]),
            "soc_match": spec["soc_match"],
        }
        for name, spec in CXX_INSTANCES.items()
        for kind, lookup in CLASS_SYMBOLS.items()
    }


def stack_of(name):
    return CXX_INSTANCES[name].get("stack", DEFAULT_STACK)


def cxx_instance_hit(self):
    """Breakpoint handler for both the ctor and the this-taking function."""
    self.cxx_instances.record(self.qemu.regs.pc, self.qemu.regs.r0)


class CxxInstanceResolver(object):
    def __init__(self, machine):
        self.machine = machine
        self.instances = {}
        self.pending = {}
        self.recorded = {}
        self._breakpoints = {}
        self._scans = {}

        # Nothing is allocated until the guest has booted
        self.scan_enabled = False

    def _symbol(self, name):
        sym = self.machine.symbol_table.lookup(name, single=True)

        return None if sym is None else sym.address

    def _vptr(self, name):
        vtable = self._symbol(class_symbol(name, "vtable"))

        return None if vtable is None else vtable + 8

    def _entry(self, name):
        return self.instances.setdefault(name, {"pointer": None, "ways": {}})

    def _scan(self, name, refresh=False):
        """Addresses whose first word is the class' vptr, in address order.

        Only plain RAM is searched: reading unmapped physical memory takes PANDA
        down, reading a peripheral has side effects, and a hit inside the loaded
        image is a static pointer holding the vptr rather than an instance,
        which is what S5123AP has.
        """
        if not self.scan_enabled:
            return []

        if name in self._scans and not refresh:
            return self._scans[name]

        vptr = self._vptr(name)
        needle = struct.pack("<I", vptr)
        hits = []

        for mem in sorted(self.machine.avatar.memory_ranges, key=lambda x: x.begin):
            if mem.data.forwarded_to or mem.data.file:
                continue

            data = self.machine.qemu.pypanda.physical_memory_read(
                mem.begin, mem.end - mem.begin
            )

            pos = data.find(needle)
            while pos != -1:
                if pos % 4 == 0:
                    hits += [mem.begin + pos]
                pos = data.find(needle, pos + 1)

        if hits:
            self._scans[name] = hits
        else:
            self._scans.pop(name, None)

        return hits

    def install_breakpoints(self, ways=(WAY_CTOR, WAY_METHOD)):
        """Arms the breakpoints of the requested ways for every known class."""
        for name, spec in CXX_INSTANCES.items():
            if self._vptr(name) is None:
                continue

            symbols = {
                WAY_CTOR: class_symbol(name, "ctor"),
                WAY_METHOD: spec["this_arg_fn"],
            }

            for way, sym_name in [(w, symbols[w]) for w in ways]:
                address = self._symbol(sym_name)
                if address is None:
                    log.warning("%s: no %s symbol, %s way disabled", name, sym_name, way)
                    continue

                address &= ~1
                self._breakpoints[address] = (name, way)
                self.machine.set_breakpoint(
                    address, cxx_instance_hit, continue_after=True
                )

    def record(self, address, this):
        self.scan_enabled = True

        name, way = self._breakpoints[address]
        ways = self._entry(name)["ways"]
        seen = ways.setdefault(way, [])

        if this not in seen:
            seen += [this]
            log.info("%s: %s reported instance %#010x (#%d)", name, way, this, len(seen))

        if way == WAY_CTOR:
            # a new instance just appeared, so any earlier scan is incomplete
            self._scans.pop(name, None)
            ways.pop(WAY_SCAN, None)
        else:
            # further calls only repeat what this one already showed
            self.machine.remove_breakpoint_by_address(address)

        self.resolve(name)

    def request(self, name, write_address):
        """Registers a modkit instance symbol and resolves it if possible."""
        if name not in CXX_INSTANCES:
            log.error("%s is not a known C++ instance", name)
            return False

        if self._vptr(name) is None:
            log.error("%s: no vtable symbol, cannot resolve the instance", name)
            return False

        self.pending.setdefault(name, []).append(write_address)
        self.resolve(name)

        return True

    def resolve(self, name):
        stack = stack_of(name)
        ways = self._entry(name)["ways"]
        record = self.recorded.get(name)

        if record is not None and WAY_CTOR not in ways:
            # written by the cold boot that created the snapshot
            ways[WAY_CTOR] = [record["pointer"]]

        if WAY_SCAN not in ways:
            hits = self._scan(name)
            if len(hits) == 1:
                ways[WAY_SCAN] = list(hits)
            elif record is not None and len(hits) == record["hit_count"]:
                ways[WAY_SCAN] = [hits[record["scan_index"]]]
            elif hits:
                log.warning(
                    "%s: %d instances in memory but no recorded stack order. Cold boot "
                    "the image (and re-take the snapshot) to have the constructors "
                    "decide which instance belongs to stack %d",
                    name,
                    len(hits),
                    stack,
                )

        pointer = None
        for way in WAYS:
            index = stack if way == WAY_CTOR else 0
            if len(ways.get(way, [])) > index:
                pointer = ways[way][index]
                source = way
                break

        if pointer is None:
            return None

        if source == WAY_METHOD:
            log.warning(
                "%s: instance %#010x seen by %s only, its stack is unverified",
                name,
                pointer,
                CXX_INSTANCES[name]["this_arg_fn"],
            )

        # `method` sees whichever instance the guest happened to use, so it can
        # only confirm that a pointer is a live instance, never order them
        disagree = {}
        for way, values in ways.items():
            index = stack if way == WAY_CTOR else 0
            if way == WAY_METHOD:
                if pointer not in values:
                    disagree[way] = values[0]
            elif len(values) > index and values[index] != pointer:
                disagree[way] = values[index]

        if disagree:
            log.error(
                "%s: instance pointer disagreement (%s), using the %s value %#010x",
                name,
                ", ".join("%s=%#010x" % (w, v) for w, v in disagree.items()),
                source,
                pointer,
            )

        entry = self._entry(name)
        if entry["pointer"] != pointer:
            entry["pointer"] = pointer
            log.info(
                "%s: instance %#010x for stack %d (%s)",
                name,
                pointer,
                stack,
                ", ".join(way for way in WAYS if way in ways),
            )

        self._flush(name, pointer)

        return pointer

    def _flush(self, name, pointer):
        for write_address in self.pending.pop(name, []):
            log.info(
                "Resolved instance symbol %s (0x%08x) -> 0x%08x", name, pointer, write_address
            )
            self.machine.qemu.wm(write_address, 4, struct.pack("<I", pointer), raw=True)

    def snapshot_state(self):
        """Per-class state to store in a snapshot, so restores of it know which
        instance belongs to which stack without re-running the constructors.

        The constructors saw every instance, which gives the address order a
        later scan will see without searching memory again.
        """
        state = {}

        for name, entry in self.instances.items():
            pointer = entry["pointer"]
            if pointer is None:
                continue

            instances = entry["ways"].get(WAY_CTOR) or self._scan(name, refresh=True)
            if pointer not in instances:
                log.warning(
                    "%s: instance %#010x is not among the known instances", name, pointer
                )
                continue

            ordered = sorted(instances)
            state[name] = {
                "pointer": pointer,
                "scan_index": ordered.index(pointer),
                "hit_count": len(ordered),
                "ways": sorted(entry["ways"]),
            }

        return state

    def load_snapshot_state(self, state):
        self.recorded = state if state else {}
        self.instances = {}
        self._scans = {}
        self.scan_enabled = True

        if not self.recorded:
            return

        for name, record in self.recorded.items():
            log.info(
                "%s: snapshot recorded instance %#010x (found by %s)",
                name,
                record["pointer"],
                ", ".join(record["ways"]),
            )
