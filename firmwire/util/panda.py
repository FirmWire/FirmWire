## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
def read_cstring_panda(panda, addr, max_length=0x200):
    if addr == 0:
        return "NULL"

    s = panda.physical_memory_read(addr, max_length)
    return s[: s.find(b"\x00")].decode("ascii", "ignore")
