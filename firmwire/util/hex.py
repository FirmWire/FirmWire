## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
def hexdump(
    data, base_addr=0, columns=16, group=2, reverse_group=False, show_ascii=True
):
    output = ""
    i = base_addr
    hexpad = columns * 2 + (columns // group)

    if isinstance(data, str):
        data = data.encode()

    while i < len(data):
        inext = min(len(data), i + columns)

        addrline = "%04x: " % (i)
        line = ""

        iline = i
        for g in range((inext - i) // group):
            groupSlice = data[iline : iline + group]
            if reverse_group:
                groupSlice = groupSlice[::-1]
            line += (("%02x" * group) + " ") % tuple(groupSlice)
            iline += group

        for g in range(inext - iline):
            line += "%02x " % (data[iline])
            iline += 1

        if show_ascii:
            iline = i
            asciiline = ""
            for g in range(inext - i):
                asciiline += ("%c") % tuple(
                    list(
                        map(
                            lambda x: x if x >= ord(" ") and x < 0x7F else ".",
                            data[iline : iline + 1],
                        )
                    )
                )
                iline += 1

        output += ("%s%-" + str(hexpad) + "s") % (addrline, line)

        if show_ascii:
            output += ("| %-" + str(columns) + "s") % asciiline

        output += "\n"
        i = inext

    return output
