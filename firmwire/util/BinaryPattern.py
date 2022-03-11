## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct
import re
from binascii import hexlify

#
# BinaryPattern by Grant Hernandez
#
class BinaryPattern(object):
    def __init__(self, name, offset=0):
        self.name = name
        self.pattern = None
        self.offset = offset

    def __repr__(self):
        return "<BinaryPattern '%s'>" % self.name

    def from_str(self, pat):
        re_pat = rb"" + hexlify(pat)
        self.from_hex(re_pat.decode())

    def find(self, data, pos=0, maxpos=-1):
        if self.pattern is None:
            raise ValueError("Pattern has not been compiled")

        if maxpos < 0:
            maxpos = len(data)

        if pos < 0:
            raise ValueError("pos must be non-negative")
        elif pos >= len(data):
            raise ValueError("pos must be less than the data size")
        elif maxpos > len(data):
            raise ValueError("Maxpos must be less or equal to the data size")
        elif pos >= maxpos:
            raise ValueError("pos must be less than maxpos")

        match = self.pattern.search(data[pos:maxpos])

        if not match:
            return None

        span = match.span()
        return (span[0] + self.offset + pos, span[1] + self.offset + pos)

    def findall(self, data, pos=0, maxpos=-1, maxresults=0):
        found = []

        while True:
            res = self.find(data, pos=pos, maxpos=maxpos)

            if res is None:
                break

            pos = res[1]
            found += [res]

            if maxresults and maxresults <= len(found):
                break

        return found

    def from_hex(self, hexpat):
        re_pat = rb""
        pos = 0

        expect_next_wildcard = False
        expect_next_hex = False

        while pos < len(hexpat):
            c = hexpat[pos : pos + 1]

            if expect_next_wildcard and c[0] not in ["?", "+", "*"]:
                raise ValueError("Expected wildcard at position %d" % pos)

            if expect_next_hex and not re.match(r"[a-fA-F0-9]", c):
                raise ValueError("Expected hex digit at position %d" % pos)

            if re.match("\s", c):
                pos += 1
                continue

            if c[0] in ["?", "+", "*"]:
                if expect_next_wildcard:
                    expect_next_wildcard = False

                    # TODO: make match "fuzziness" configurable
                    # Match as little as possible
                    if c[0] == "+":
                        re_pat += rb"(.{1,100}?)"
                    elif c[0] == "*":
                        re_pat += rb"(.{0,100}?)"
                    else:
                        re_pat += rb"."
                else:
                    expect_next_wildcard = True

            elif re.match(r"[a-fA-F0-9]", c):
                if expect_next_hex:
                    expect_next_hex = False
                    re_pat += b"\\x%s" % hexpat[pos - 1 : pos + 1].encode()
                else:
                    expect_next_hex = True
            else:
                raise ValueError(
                    "Unexpected character '%c' at position %d" % (c[0], pos)
                )

            pos += 1

        if expect_next_wildcard:
            raise ValueError("Incomplete wildcard at end of pattern")

        if expect_next_hex:
            raise ValueError("Incomplete hex value at end of pattern")

        # We're searching through binary data -- Newlines are included
        self.pattern = re.compile(re_pat, flags=re.DOTALL)
