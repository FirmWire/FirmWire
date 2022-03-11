## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct
import pickle
import logging

log = logging.getLogger(__name__)


def reads32(f):
    x = f.read(4)
    return struct.unpack("<i", x)[0]


def read32(f):
    x = f.read(4)
    return struct.unpack("<I", x)[0]


def read16(f):
    x = f.read(2)
    return struct.unpack("<H", x)[0]


def read8(f):
    x = f.read(1)
    return struct.unpack("<B", x)[0]


# databases:
#  0 - structs
#  1 - unions
#  2 - enums
#  4 - typedefs
#  5 - messages
#  6/7/10/11 - empty..?
#  8 - tiny/custom weird thing? TODO: has FDD_RLC_TM_PB_SIZE_IN_BITS, FDD_RLC_TM_LP_SIZE_IN_BYTES, one enum type?
#  12 - traces


def readTraceData(f, entries2):
    tracedata = {}
    dbinfo = readDatabase(entries2, 12, f)
    log.debug("TRACE")
    for trcid, trcinfo in dbinfo[2].items():
        trc = dbinfo[0][trcinfo[0]][trcinfo[1]]
        fmt = "<II" + "HHI" * 2 + "II" + "HHI" + "I" + "HHI" * 2 + "I"
        trace = struct.unpack(fmt, trc)
        # TODO: not sure if numbytes is right, it is usually numparams*4, sometimes more?
        (
            traceid,
            moduleid,
            dbgroup1,
            dbentry1,
            dbhash1,
            dbgroup2,
            dbentry2,
            dbhash2,
            numbytes,
            numparams,
            dbgroup3,
            dbentry3,
            dbhash3,
            idk3,
            dbgroup4,
            dbentry4,
            dbhash4,
            dbgroup5,
            dbentry5,
            dbhash5,
            idk4,
        ) = trace
        traceidname = dbinfo[4][dbgroup1][dbentry1].replace(b"\x00", b"").decode()
        try:
            tracestring = dbinfo[4][dbgroup2][dbentry2].replace(b"\x00", b"").decode()
        except UnicodeDecodeError:
            tracestring = "FAILED TO DECODE TRACESTRING"
        log.debug("%x: %r - %r" % (trcid, traceidname, tracestring))

        members = []
        paraminfo = dbinfo[5][dbgroup3][dbentry3]
        for n in range(numparams):
            member = struct.unpack("<HHI", paraminfo[8 * n : 8 * (n + 1)])
            memberinfo = dbinfo[1][member[0]][member[1]]
            memberinfo = struct.unpack("<IIIHHI", memberinfo)
            # TODO: this is *not* typeinfo
            # log.debug memberinfo
            fieldWidth = memberinfo[2]  # e.g. %2d -> 2
            fieldType = None
            typeName = dbinfo[4][memberinfo[3]][memberinfo[4]].decode()
            log.debug(typeName)
            if memberinfo[1] == 0:
                fieldType = "c"
            elif memberinfo[1] == 1:
                fieldType = "d"
            elif memberinfo[1] == 2:
                fieldType = "u"
            elif memberinfo[1] == 3:
                log.debug("FIXME7")
            elif memberinfo[1] == 4:
                fieldType = "X"
            elif memberinfo[1] == 5:
                fieldType = "x"
            elif memberinfo[1] == 6:
                fieldType = "M"  # FIXME: enum type
            elif memberinfo[1] == 8:
                fieldType = "s"
            elif memberinfo[1] == 9:
                log.debug("FIXME4")  # FIXME
            elif memberinfo[1] == 0xA:
                log.debug("FIXME1")  # FIXME
            elif memberinfo[1] == 0xB:
                log.debug("FIXME2")  # FIXME
            elif memberinfo[1] == 0xD:
                log.debug("FIXME5")  # FIXME
            elif memberinfo[1] == 0xE:
                log.debug("FIXME6")  # FIXME: is this hex chars or shorts or so..?
            elif memberinfo[1] == 0xF:
                fieldType = "M"  # FIXME: enum type
            elif memberinfo[1] == 0x10:
                fieldType = "M"  # FIXME: enum type
            else:
                assert False
            fieldFlags = ""
            if memberinfo[0] & 0x1000000:
                fieldFlags = fieldFlags + "0"
            if memberinfo[0] & 0x10000:
                log.debug("FIXMEZ")  # FIXME: maybe another field, maybe #..?
            if memberinfo[0] & 0x100:
                fieldFlags = fieldFlags + "+"
            if memberinfo[0] & 0x1:
                log.debug(
                    "FIXMEY"
                )  # FIXME: maybe another field..? used in 'indexed trace format test'
            if memberinfo[0] & ~(0x1 | 0x100 | 0x10000 | 0x1000000):
                assert False

            # flags, conversion, field width, type name
            members.append(
                (
                    memberinfo[0],
                    memberinfo[1],
                    memberinfo[2],
                    typeName.replace("\x00", ""),
                )
            )

        # ???
        assert idk3 == 0
        e4 = dbinfo[4][dbgroup4][dbentry4]
        assert e4 == b"\x00"
        e5 = dbinfo[4][dbgroup5][dbentry5]
        assert e5 == b"\x00"

        tracedata[trcid] = [traceidname, tracestring, members]

    return tracedata


# TODO: there are two copies of everything for each msgid.. otherwise they seem identical
def readMessageInfo(f, entries2):
    messages = {}
    dbinfo = readDatabase(entries2, 5, f)
    for chunk in dbinfo[0].values():
        for msginfo in chunk.values():
            msgid, dbgroup1, dbentry1, dbhash1 = struct.unpack("<IHHI", msginfo)
            log.debug(
                "msg %x" % msgid,
            )

            # the type info is always just a name of a type, potentially empty string, but decode it anyway..
            msginfo = readTypeInfo(
                dbinfo, dbgroup1, dbentry1, stringTable=4, mayBeIncomplete=True
            )
            log.debug(msginfo)
            messages[msgid] = msginfo
    return messages


def readLTED(f):
    outputinfo = {}

    magic = f.read(4)
    assert magic == b"LTED"
    idk1 = read32(f)
    entrycount = read32(f)
    entries = []
    for n in range(entrycount):
        entryoffset = read32(f)
        entries.append(entryoffset)
    entries2 = []
    for entryoffset in entries:
        f.seek(entryoffset)
        magic = f.read(4)
        assert magic == b"HEAD"
        numentries = read32(f)
        entries2.append([])
        for n in range(numentries):
            myoffset = read32(f)
            mysize = read32(f)
            entries2[-1].append((mysize, myoffset))
    groupn = 0

    # for debugging, log.debug table info, or a whole db
    """for n in range(len(entries2)):
        log.debug n, entries2[n]"""
    """dbinfo = readDatabase(entries2, 11, f)
    for n in dbinfo:
        log.debug "*** new table"
        if n == None: continue
        log.debug n.keys()
        for z in n.keys():
            zz = n[z]
            if isinstance(zz, tuple): continue
            for y in zz.keys():
               #log.debug y, zz[y].hex()
               #log.debug y, repr(zz[y])
               pass
    """

    outputinfo["trace"] = readTraceData(f, entries2)
    outputinfo["message"] = readMessageInfo(f, entries2)
    outputinfo["struct"] = readStructInfo(f, entries2, 0)
    outputinfo["union"] = readStructInfo(f, entries2, 1)
    outputinfo["enum"] = readEnumInfo(f, entries2)
    outputinfo["typedef"] = readTypedefInfo(f, entries2)

    return outputinfo


def readStructInfo(f, entries, entryid):
    # 0 is struct, 1 is union
    structs = {}
    dbinfo = readDatabase(entries, 0 + entryid, f)
    for structinfo in dbinfo[0].values():
        for structi in structinfo.items():
            readStructEntry(dbinfo, structi, structs)
    return structs


def readEnumInfo(f, entries):
    enums = {}
    dbinfo = readDatabase(entries, 2, f)
    for structinfo2 in dbinfo[0].values():
        for struct2i in structinfo2.items():
            readEnumEntry(dbinfo, struct2i, enums)
    return enums


def readTypedefInfo(f, entries):
    typedefs = {}
    dbinfo = readDatabase(entries, 4, f)
    for structinfo2 in dbinfo[0].values():
        for struct2i in structinfo2.items():
            readTypedefEntry(dbinfo, struct2i, typedefs)
    return typedefs


class MtkTypeInfo:
    def __init__(self):
        self.unsigned = False
        self.isBitfield = False
        self.bitfieldInfo = None
        self.isPointer = False
        self.pointerLevels = None
        self.isArray = False
        self.numIndices = None
        self.isFuncPtr = False
        self.baseType = None
        self.baseTypeName = None
        self.isComplexBase = False
        self.baseTypeName = None

    def setType(self, newtype):
        assert self.baseType == None
        self.baseType = newtype

    def isValid(self, allowEmptyBase):
        if self.isPointer and self.pointerLevels < 1:
            return False
        if self.baseType == None and not self.isComplexBase:
            return False

        # e.g. messages? may be incorrect way to think about this
        if allowEmptyBase:
            return True

        # you *can* have a baseType and a complex base, e.g. enums
        if self.isComplexBase and not self.baseTypeName:
            return False
        if not self.isComplexBase and self.baseTypeName:
            return False
        return True

    # for debugging :P
    def __repr__(self):
        return str(self)

    def __str__(self):
        s = []
        if self.unsigned:
            s.append("unsigned")
        if self.baseType:
            s.append(self.baseType)
        if self.isComplexBase:
            s.append(self.baseTypeName)
        if self.isPointer:
            s.append("*" * self.pointerLevels)
        if self.isBitfield:
            s.append("bitfield[%x]" % self.bitfieldInfo)
        if self.isArray:
            s.append("array[dim %x]" % self.numIndices)
        log.debug(s)
        return " ".join(s)


def parseTypeFlags(typeflags):
    typeinfo = MtkTypeInfo()

    if typeflags & 0x80000000:
        typeinfo.unsigned = True

    if typeflags & 0x10000000:
        typeinfo.isComplexBase = True
    if typeflags & 0x8000000:
        typeinfo.setType("union")
        typeinfo.isComplexBase = True
    if typeflags & 0x4000000:
        typeinfo.setType("struct")
        typeinfo.isComplexBase = True
    if typeflags & 0x2000000:
        typeinfo.setType("enum")
        typeinfo.isComplexBase = True
    if typeflags & 0x10000:
        typeinfo.setType("void")
    if typeflags & 0x20000:
        typeinfo.setType("char")
    if typeflags & 0x40000:
        typeinfo.setType("short")
    if typeflags & 0x80000:
        typeinfo.setType("int")
    if typeflags & 0x100000:
        typeinfo.setType("long")
    if typeflags & 0x200000:
        typeinfo.setType("long long")
    if typeflags & 0x400000:
        typeinfo.setType("float")
    if typeflags & 0x800000:
        typeinfo.setType("double")
    if typeflags & 0x1000000:
        typeinfo.setType("long double")

    if typeflags & 0x8000:
        typeinfo.isFuncPtr = True

    if typeflags & 0x4000:
        typeinfo.isBitfield = True
        typeinfo.bitfieldInfo = (typeflags & 0x1F00) >> 8

    if typeflags & 0xF:
        typeinfo.isPointer = True
        typeinfo.pointerLevels = typeflags & 0xF
        if not typeinfo.baseType:
            # TODO: this happens for a few 'kal_uint8 const *' types..
            typeinfo.baseType = "typed weirdptr"

    if typeflags & 0xF0:
        typeinfo.isArray = True
        typeinfo.numIndices = (typeflags & 0xF0) >> 4

    if typeflags & ~(
        0x90000000 | 0xE000000 | 0x1FF0000 | 0x8000 | 0x4000 | 0x1F00 | 0xFF
    ):
        log.debug(
            "FIXME: unknown type flags",
        )
        log.debug(hex(typeflags))

    return typeinfo


# db 0:
#  table 0 is struct info (e.g. member count, ref to other tables, ...)
#  table 1 has member info, i.e. type info for each member of a struct
#  table 5 is names/strings, i.e. stringpool/sp
#  table 6 is misc data, such as struct members and array counts
def readTypeInfo(
    dbinfo, groupid, entryid, stringTable=5, mayBeIncomplete=False, isTypedef=False
):
    typeinfos = dbinfo[1][groupid]
    typeinforaw = typeinfos[entryid]
    fmt = "<HHI" + "HHI" * 5 + "4s"
    typeinfo = struct.unpack(fmt, typeinforaw)

    basetypeinfo = parseTypeFlags(typeinfo[2])
    basetypeinfo.baseTypeName = (
        dbinfo[stringTable][typeinfo[3 + 0]][typeinfo[4 + 0]]
        .replace(b"\x00", b"")
        .decode()
    )

    assert basetypeinfo.isValid(mayBeIncomplete)

    # name
    x = typeinfo[3 + 3]
    y = typeinfo[4 + 3]
    name = dbinfo[stringTable][x][y].replace(b"\x00", b"").decode()

    arraysize = []
    if typeinfo[3 + 9] != 0xFFFF:
        # array size, 4 bytes per element
        x = typeinfo[3 + 9]
        y = typeinfo[4 + 9]
        arraysize1 = dbinfo[6][x][y]

        x = typeinfo[3 + 12]
        y = typeinfo[4 + 12]
        arraysize2 = dbinfo[6][x][y]

        # TODO: unclear why these differ, is one target and one host?
        # might be padding-related, these are arrays with sizes involving sizeof()..
        if arraysize1 != arraysize2:
            log.debug("// MEH: ", arraysize1.hex(), arraysize2.hex())

        numindices = typeinfo[0] // 256  # TODO: only checked for 1/2 indices
        assert numindices * 4 == len(arraysize1)
        assert basetypeinfo.isArray and basetypeinfo.numIndices == numindices
        # assert numindices == (typeflags & 0xf0) >> 4
        assert numindices == typeinfo[1]
        arraysize = struct.unpack("<" + "I" * numindices, arraysize1)
        # log.debug "".join(["[%d]" % a for a in arraysize]),
    elif isTypedef:
        # TODO: wth
        assert not basetypeinfo.isArray
        assert typeinfo[3 + 12] == 0 or typeinfo[3 + 12] == 0xFFFF
        assert typeinfo[1] == 0
        assert typeinfo[0] == 0
    elif mayBeIncomplete:
        assert not basetypeinfo.isArray
        assert typeinfo[3 + 12] == 0
        assert typeinfo[1] == 0
        assert typeinfo[0] == 0
    else:
        assert not basetypeinfo.isArray
        assert typeinfo[3 + 12] == 0xFFFF
        assert typeinfo[1] == 0
        assert typeinfo[0] == 0

    comment = ""
    if typeinfo[3 + 6] != 0xFFFF:
        # comment
        x = typeinfo[3 + 6]
        y = typeinfo[4 + 6]
        comment = dbinfo[stringTable][x][y].replace(b"\x00", b"")

    return (basetypeinfo, arraysize, name, comment)


# valid tables: 0, 1, 5
def readTypedefEntry(dbinfo, structi, typedefs):
    fmt = "HHI" * 2
    dbgroup1, dbentry1, dbhash1, dbgroup2, dbentry2, dbhash2 = struct.unpack(
        fmt, structi[1]
    )
    name = dbinfo[5][dbgroup1][dbentry1].replace(b"\x00", b"").decode()

    # TODO: this is std typeinfo again, parse the type out.. for now, just pull out the name
    # typeinfo = dbinfo[1][dbgroup2][dbentry2]
    # fmt = "<HHHH" + "HHI"*5 + "4s"
    # typeinfo = struct.unpack(fmt, typeinfo)
    # othertypename = dbinfo[5][typeinfo[4]][typeinfo[5]].replace("\x00","")

    # log.debug "typedef %s %s;" % (othertypename.replace("\x00",""), name.replace("\x00","")),
    # nameagain = dbinfo[5][typeinfo[4+3]][typeinfo[5+3]].replace("\x00","")
    # if name != nameagain:
    #    # TODO: these are definitions/macros, not typedefs
    #    log.debug '// %r' % nameagain
    # log.debug

    typeinfo = readTypeInfo(
        dbinfo, dbgroup2, dbentry2, isTypedef=True, mayBeIncomplete=True
    )
    log.debug("typedef %s %s;" % (typeinfo, name))

    # FIXME
    typedefs[name] = typeinfo


# valid tables: 0 (top-level enums), 1 (entry lists), 2 (typeinfo), 6 (strings), 7 (individual entries/values)
def readEnumEntry(dbinfo, structi, enums):
    fmt = "<I" + "HHI" * 3 + "4s"
    (
        numentries,
        dbgroup1,
        dbentry1,
        dbhash1,
        dbgroup2,
        dbentry2,
        dbhash2,
        dbgroup3,
        dbentry3,
        dbhash3,
        blob2,
    ) = struct.unpack(fmt, structi[1])
    name = dbinfo[6][dbgroup1][dbentry1].replace(b"\x00", b"").decode()
    entries = dbinfo[7][dbgroup2][dbentry2]
    entries = struct.unpack("HHI" * numentries, entries)
    log.debug(
        "enum " + name + " {",
    )

    # TODO: this is std typeinfo again, parse the type out (it is all-zero for fake enums)?
    typeinfo = dbinfo[2][dbgroup3][dbentry3]
    fmt = "<HHHH" + "HHI" * 5 + "4s"
    typeinfo = struct.unpack(fmt, typeinfo)
    log.debug(
        typeinfo,
    )

    # the refs in the typeinfo are ALL useless afaict:
    typeinfo1 = dbinfo[6][typeinfo[4 + 0]][typeinfo[5 + 0]]
    typeinfo2 = dbinfo[6][typeinfo[4 + 3]][typeinfo[5 + 3]]
    assert typeinfo1 == b"\x00"
    if typeinfo2 != b"\x00":
        assert typeinfo2.replace(b"\x00", b"").decode() == name
    if typeinfo[4 + 6] != 0xFFFF:
        typeinfo3 = dbinfo[6][typeinfo[4 + 6]][typeinfo[5 + 6]]
        assert typeinfo3 == b""

    entries_out = {}
    for n in range(numentries):
        entry = dbinfo[1][entries[n * 3 + 0]][entries[n * 3 + 1]]
        dbgroup, dbentry, dbhash, value = struct.unpack("HHII", entry)
        entryname = dbinfo[6][dbgroup][dbentry].replace(b"\x00", b"").decode()
        log.debug("  %s = 0x%x, " % (entryname, value))
        entries_out[value] = entryname
    log.debug("};\n")

    enums[name] = (typeinfo, entries_out)


def readStructEntry(dbinfo, structi, structs):
    fmt = "<BBHI4s" + "HHI" * 3 + "4s"
    (
        idk1,
        idk2,
        idk3,
        numentries,
        blob1,
        dbgroup1,
        dbentry1,
        dbhash1,
        dbgroup2,
        dbentry2,
        dbhash2,
        dbgroup3,
        dbentry3,
        dbhash3,
        blob2,
    ) = struct.unpack(fmt, structi[1])

    assert idk3 == 0

    if dbgroup3 != 0xFFFF:
        log.debug(
            "// FIXME: dbgroup3",
        )
        # none of the others seem to make any sense (indexes also work into 5 but they're junk..)
        # if this is set then BLOB1 also seems to be non-zero..
        log.debug(dbinfo[6][dbgroup3][dbentry3].hex())

    name = dbinfo[5][dbgroup2][dbentry2].replace(b"\x00", b"").decode()
    structdata = dbinfo[6][dbgroup1][dbentry1]

    if idk2 != 0 and idk2 != 1:
        log.debug("// FIXME: wtf " + hex(idk2))
    if idk1 == 0:
        log.debug(
            "struct",
        )
    elif idk1 == 1:
        log.debug(
            "union",
        )
    else:
        assert False, idk1
    log.debug("%s {" % name.replace("\x00", ""))
    entries = []
    for n in range(numentries):
        member = struct.unpack("<HHI", structdata[8 * n : 8 * (n + 1)])
        entry = readTypeInfo(dbinfo, member[0], member[1])
        entries.append(entry)

    if blob1 != "\x00" * 4:
        log.debug(
            "// FIXME: BLOB1",
        )
        log.debug(blob1.hex())
    assert blob2 == b"\x00" * 4

    log.debug("};\n")
    structs[name] = entries


# this reads an entire group (==database)
# returns an array containing all the tables
def readDatabase(entries, dbid, f):
    entries = entries[dbid]
    dbinfo = []
    numchunkshack = None
    log.debug("read db")
    entryid = 0
    for entrysize, entryoffset in entries:
        log.debug("table %d: 0x%x bytes @ 0x%x" % (entryid, entrysize, entryoffset))
        entryid = entryid + 1
        # if entryoffset == 0x5e44c40 or entryoffset == 0x4f4230c:
        if (dbid == 5 or dbid == 12) and entryid == 3:
            numchunkshack, table = readSpecialTable(f, entrysize, entryoffset)
            dbinfo.append(table)
            continue
        elif (dbid == 5 or dbid == 12) and entryid == 4:
            # elif entryoffset == 0x5ea64c4 or entryoffset == 0x4f63db8:
            assert numchunkshack * 8 == entrysize
            for n in range(numchunkshack):
                a = read16(f)
                b = read16(f)
                eid = read32(f)
                # reverse lookup table?
                assert a == dbinfo[-1][eid][0]
                assert b == dbinfo[-1][eid][1]
            dbinfo.append(None)
            continue

        table = readTable(f, entrysize, entryoffset)
        dbinfo.append(table)
    return dbinfo


# probably indexes?
def readSpecialTable(f, entrysize, entryoffset):
    myoutput = {}
    f.seek(entryoffset)

    numchunks = read32(f)
    totalentries = read32(f)
    for n in range(numchunks):
        # lookup table on basis of ID, which we don't need
        start = read32(f)
        end = read32(f)
        cnt = read32(f)
        # log.debug "%x-%x: %x entries" % (start, end, cnt)
    for n in range(totalentries):
        entry = read16(f)
        group = read16(f)
        eid = read32(f)
        myoutput[eid] = (entry, group)
    log.debug("end of special at: " + hex(f.tell()))
    return totalentries, myoutput


# reads an entire table
def readTable(f, entrysize, entryoffset):
    myoutput = {}
    n = 0
    valid_n = 0
    groupsize = 0x20000

    f.seek(entryoffset)
    info = []
    while entrysize > 0:
        f.seek(entryoffset + groupsize * n)
        log.debug("subentry at: " + hex(f.tell()))

        maybeid = read16(f)
        unk2 = read16(f)
        blocktype = read32(f)
        block_numentries = read32(f)
        somelen = read32(f)

        log.debug(
            "id %x, unk2 %x, type %x, #entries %x, len %x"
            % (maybeid, unk2, blocktype, block_numentries, somelen)
        )
        assert unk2 == 0 or unk2 == 0xFFFF, hex(unk2)  # <-- nope?

        if blocktype == 2:
            assert len(info) == 0
            assert somelen > 0
            for q in range(somelen):
                # this describes the remaining entries in this group
                # a is .. entry number? aka unk8
                # b is id
                # c is unk5
                a = read32(f)
                b = read32(f)
                c = read32(f)
                info.append((a, b, c))
                log.debug(hex(a), hex(b), hex(c))
            unkZ = read32(f)
            log.debug(hex(unkZ))
            s = f.read(32)
            log.debug(s.hex())
        elif blocktype == 0:
            log.debug("weird")
            s = f.read(somelen)
            log.debug(s.hex())
        elif blocktype == 1:
            unk5 = read32(f)
            unk6 = read32(f)
            log.debug("header: %x/%x" % (unk5, unk6))
            groupsize = (unk6 * 12) + 32
            groupsize = groupsize & 0xFFFFF000  # FIXME: this is all just a guess
        elif blocktype != 1:
            unk5 = read32(f)
            unk6 = read32(f)
            unk7 = read32(f)
            unk8 = read32(f)
            log.debug("unks %x/%x/%x/%x" % (unk5, unk6, unk7, unk8))
            if len(info):
                log.debug("[%s]" % (info[valid_n],))
            if groupsize != 0x100000 and len(info):  # FIXME
                assert info[valid_n][0] == unk8
                assert info[valid_n][1] == maybeid
                # assert info[n-2][2] == unk5
                if info[valid_n][2] != unk5:
                    log.debug("** weird")
            valid_n = valid_n + 1
            mydict = {}
            myoutput[maybeid] = mydict
            rows = []
            f.seek(entryoffset + groupsize * (n + 1) - block_numentries * 2 * 4)
            s = f.read(block_numentries * 2 * 4)
            for q in range(block_numentries):
                rowoffset, rowsize = struct.unpack("<II", s[q * 8 : (q + 1) * 8])
                rows.append((rowoffset, rowsize))
            rowid = 0
            for rowoffset, rowsize in reversed(rows):
                if rowoffset & 0xFFF00000 == 0xFFF00000:
                    log.debug("offset %x, size %x, wtf" % (rowoffset, rowsize))
                    rowoffset = 0x100000000 - rowoffset  # FIXME
                # if rowoffset > groupsize:
                #  log.debug "** broken :("
                #  break
                assert rowoffset <= groupsize, (hex(rowoffset), hex(rowsize))
                f.seek(entryoffset + groupsize * n + rowoffset)
                s = f.read(rowsize)
                mydict[rowid] = s
                rowid = rowid + 1
        n = n + 1
        entrysize = entrysize - groupsize
    return myoutput


if __name__ == "__main__":
    infile = open("out4_comp", "rb")
    # infile = open("out1_comp", "rb")
    outputinfo = readLTED(infile)
    with open("ltedb.pickle", "wb") as f:
        pickle.dump(outputinfo, f)
