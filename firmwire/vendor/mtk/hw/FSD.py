## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
# NOTE: this FSD code is included for research reproducability purposes ONLY
import struct
import logging
import inspect
import os
import re
import time
from stat import *

from enum import Enum, IntEnum

CCCI_FRAGMENT = 0x80000000
FS_API_RESP_ID = 0xFFFF0000

# FS_MAX_REQ_BUF = 5
# FS_MAX_DIR_NUM = 8
FS_FILE_MAX = 129
MAX_FS_PKT_BYTE = 3584 - 128


class FSAttr(IntEnum):
    FS_ATTR_READ_ONLY = 0x01
    FS_ATTR_HIDDEN = 0x02
    FS_ATTR_SYSTEM = 0x04
    FS_ATTR_VOLUME = 0x08
    FS_ATTR_DIR = 0x10
    FS_ATTR_ARCHIVE = 0x20
    FS_LONGNAME_ATTR = 0x0F


class FSOpOpen(IntEnum):
    FS_READ_WRITE = 0x00000000
    FS_READ_ONLY = 0x00000100
    FS_OPEN_SHARED = 0x00000200
    FS_OPEN_NO_DIR = 0x00000400
    FS_OPEN_DIR = 0x00000800
    FS_CREATE = 0x00010000
    FS_CREATE_ALWAYS = 0x00020000
    FS_COMMITTED = 0x01000000
    FS_CACHE_DATA = 0x02000000
    FS_LAZY_DATA = 0x04000000
    FS_NONBLOCK_MODE = 0x10000000
    FS_PROTECTION_MODE = 0x20000000


class FSOpGetDiskInfo(IntEnum):
    FS_DI_BASIC_INFO = 0x00000001
    FS_DI_FREE_SPACE = 0x00000002
    FS_DI_FAT_STATISTICS = 0x00000004


class FSOpGetDrive(IntEnum):
    FS_NO_ALT_DRIVE = 0x00000001
    FS_ONLY_ALT_SERIAL = 0x00000002
    FS_DRIVE_I_SYSTEM = 0x00000004
    FS_DRIVE_V_NORMAL = 0x00000008
    FS_DRIVE_V_REMOVABLE = 0x00000010
    FS_DRIVE_V_EXTERNAL = 0x00000020
    FS_DRIVE_V_SIMPLUS = 0x00000040


class FSOpFlags(IntEnum):
    FS_MOVE_COPY = 0x00000001
    FS_MOVE_KILL = 0x00000002
    FS_FILE_TYPE = 0x00000004
    FS_DIR_TYPE = 0x00000008
    FS_RECURSIVE_TYPE = 0x00000010
    FS_NO_SORT = 0x00000020
    FS_SORT_NAME = 0x00000040
    FS_SORT_SIZE = 0x00000080
    FS_SORT_ATTR = 0x00000100
    FS_SORT_TYPE = 0x00000200
    FS_SORT_TIME = 0x00000400
    FS_COUNT_SIZE = 0x00000800
    FS_REMOVE_CHECK = 0x00001000
    FS_FILTER_SYSTEM_ATTR = 0x00002000
    FS_REC_COPYRIGHT_DEL = 0x00004000
    FS_REC_COPYRIGHT_LIST = 0x00008000
    FS_MOVE_OVERWRITE = 0x00010000
    FS_XDEL_ABORT_WATCH = 0x00020000
    FS_FILTER_HIDDEN_ATTR = 0x00040000


class FSOpSeek(IntEnum):
    FS_FILE_BEGIN = 0
    FS_FILE_CURRENT = 1
    FS_FILE_END = 2


class FSOpFind(IntEnum):
    FS_NOT_MATCH = 0
    FS_LFN_MATCH = 1
    FS_SFN_MATCH = 2


class FSFindResult:
    def __init__(self):
        self.filename = b""
        self.meta = DOSDirEntry()
        # used for handle or error
        self.retval = 0
        self.maxlen = 0


class FSCCCIOp(IntEnum):
    OPEN = 0x1001
    SEEK = 0x1002
    READ = 0x1003
    WRITE = 0x1004
    CLOSE = 0x1005
    CLOSEALL = 0x1006
    CREATEDIR = 0x1007
    REMOVEDIR = 0x1008
    GETFILESIZE = 0x1009
    GETFOLDERSIZE = 0x100A
    RENAME = 0x100B
    MOVE = 0x100C
    COUNT = 0x100D
    GETDISKINFO = 0x100E
    DELETE = 0x100F
    GETATTRIBUTES = 0x1010
    OPENHINT = 0x1011
    FINDFIRST = 0x1012
    FINDNEXT = 0x1013
    FINDCLOSE = 0x1014
    LOCKFAT = 0x1015
    UNLOCKALL = 0x1016
    SHUTDOWN = 0x1017
    XDELETE = 0x1018
    CLEARDISKFLAG = 0x1019
    GETDRIVE = 0x101A
    GETCLUSTERSIZE = 0x101B
    SETDISKFLAG = 0x101C
    OTP_WRITE = 0x101D
    OTP_READ = 0x101E
    OTP_QUERYLEN = 0x101F
    OTP_LOCK = 0x1020
    RESTORE = 0x1021
    CMPT_READ = 0x1022
    BIN_REGION_ACCESS = 0x1023
    CMPT_WRITE = 0x1024
    GETFILEDETAIL = 0x1025
    RESP_ID = 0xFFFF0000


class FSCompact(IntEnum):
    OPEN = 0x1
    GETFILESIZE = 0x2
    SEEK = 0x4
    READ = 0x8
    CLOSE = 0x10
    WRITE = 0x20


class CCCIStatus(IntEnum):
    UNDEFINED = -3
    INVALID = -2
    INIT = -1
    BOOT_READY = 0
    BOOT_UP = 1
    RESET = 2
    STOP = 3
    FLIGHT_MODE = 4
    EXCEPTION = 5


class FSOpQuota(IntEnum):
    FS_QMAX_NO_LIMIT = 0xF1F2F3F4
    FS_COUNT_IN_BYTE = 0x00000001
    FS_COUNT_IN_CLUSTER = 0x00000002


class FSOpBinRegion(IntEnum):
    FS_BIN_REGION_BACKUP = 0x1
    FS_BIN_REGION_RESTORE = 0x2
    FS_BIN_REGION_ERASE = 0x3
    FS_BIN_REGION_CHECK = 0x4


# A fairy flew into my window and gave me these strings. How else would I know them?
class FSPath(Enum):
    FS_ROOT_DIR_MD1 = "/mnt/vendor/nvdata/md"
    FS_ROOT_DIR1_MD1 = "/mnt/vendor/protect_f/md"
    FS_ROOT_DIR2_MD1 = "/mnt/vendor/protect_s/md"
    FS_ROOT_DIR3_MD1 = "/mnt/vendor/etc/mdota"
    FS_ROOT_DIR4_MD1 = "/mnt/vendor/nvcfg"
    FS_ROOT_DIR_MD2 = "/mnt/vendor/nvdata/md2"
    FS_ROOT_DIR1_MD2 = "/mnt/vendor/protect_f/md2"
    FS_ROOT_DIR2_MD2 = "/mnt/vendor/protect_s/md2"
    FS_ROOT_DIR_MD3 = "/mnt/vendor/nvdata/md3"
    FS_ROOT_DIR1_MD3 = "/mnt/vendor/protect_f/md3"
    FS_ROOT_DIR2_MD3 = "/mnt/vendor/protect_s/md3"
    FS_ROOT_DIR3_MD3 = "/mnt/vendor/nvdata/md3_v"
    FS_ROOT_COMMON = "/mnt/vendor/nvdata/md_cmn"
    FS_ROOT_MDLPM = "/mnt/vendor/mdlpm"
    FS_ROOT_DIR_MD5 = "/mnt/vendor/nvdata/md5"
    FS_ROOT_DIR1_MD5 = "/mnt/vendor/protect_f/md5"
    FS_ROOT_DIR2_MD5 = "/mnt/vendor/protect_s/md5"
    FS_ROOT_DIR_DSP = "/mnt/vendor/firmware"
    FS_ROOT_DIR_DSP_CIP = "/mnt/vendor/custom/etc/firmware"
    MD_ROOT_DIR_DSP = "W:"
    MD_ROOT_DIR = "Z:"
    MD_ROOT_DIR1 = "X:"
    MD_ROOT_DIR2 = "Y:"
    MD_ROOT_DIR3 = "V:"
    MD_ROOT_DIR4 = "U:"
    MD_ROOT_DIR5 = "T:"
    MD_ROOT_DIR6 = "S:"


ROOT_DIR_MD1_RESOLVE = [
    FSPath.FS_ROOT_DIR_MD1,
    FSPath.FS_ROOT_DIR1_MD1,
    FSPath.FS_ROOT_DIR2_MD1,
    FSPath.FS_ROOT_DIR_DSP,
    FSPath.FS_ROOT_COMMON,
    FSPath.FS_ROOT_MDLPM,
    FSPath.FS_ROOT_DIR3_MD1,
    FSPath.FS_ROOT_DIR4_MD1,
]

ROOT_DIR_MD_RESOLVE = [
    FSPath.MD_ROOT_DIR,
    FSPath.MD_ROOT_DIR1,
    FSPath.MD_ROOT_DIR2,
    FSPath.MD_ROOT_DIR_DSP,
    FSPath.MD_ROOT_DIR3,
    FSPath.MD_ROOT_DIR4,
    FSPath.MD_ROOT_DIR5,
    FSPath.MD_ROOT_DIR6,
]


class FSError(IntEnum):
    NO_ERROR = 0
    ERROR_RESERVED = -1
    PARAM_ERROR = -2
    INVALID_FILENAME = -3
    DRIVE_NOT_FOUND = -4
    TOO_MANY_FILES = -5
    NO_MORE_FILES = -6
    WRONG_MEDIA = -7
    INVALID_FILE_SYSTEM = -8
    FILE_NOT_FOUND = -9
    INVALID_FILE_HANDLE = -10
    UNSUPPORTED_DEVICE = -11
    UNSUPPORTED_DRIVER_FUNCTION = -12
    CORRUPTED_PARTITION_TABLE = -13
    TOO_MANY_DRIVES = -14
    INVALID_FILE_POS = -15
    ACCESS_DENIED = -16
    STRING_BUFFER_TOO_SAMLL = -17
    GENERAL_FAILURE = -18
    PATH_NOT_FOUND = -19
    FAT_ALLOC_ERROR = -20
    ROOT_DIR_FULL = -21
    DISK_FULL = -22
    TIMEOUT = -23
    BAD_SECTOR = -24
    DATA_ERROR = -25
    MEDIA_CHANGED = -26
    SECTOR_NOT_FOUND = -27
    ADDRESS_MARK_NOT_FOUND = -28
    DRIVE_NOT_READY = -29
    WRITE_PROTECTION = -30
    DMA_OVERRUN = -31
    CRC_ERROR = -32
    DEVICE_RESOURCE_ERROR = -33
    INVALID_SECTOR_SIZE = -34
    OUT_OF_BUFFERS = -35
    FILE_EXISTS = -36
    LONG_FILE_POS = -37
    FILE_TOO_LARGE = -38
    BAD_DIR_ENTRY = -39
    ATTR_CONFLICT = -40
    CHECKDISK_RETRY = -41
    LACK_OF_PROTECTION_SPACE = -42
    SYSTEM_CRASH = -43
    FAIL_GET_MEM = -44
    READ_ONLY_ERROR = -45
    DEVICE_BUSY = -46
    ABORTED_ERROR = -47
    QUOTA_OVER_DISK_SPACE = -48
    PATH_OVER_LEN_ERROR = -49
    APP_QUOTA_FULL = -50
    VF_MAP_ERROR = -51
    DEVICE_EXPORTED_ERROR = -52
    DISK_FRAGMENT = -53
    DIRCACHE_EXPIRED = -54
    QUOTA_USAGE_WARNING = -55
    MSDC_MOUNT_ERROR = -100
    MSDC_READ_SECTOR_ERROR = -101
    MSDC_WRITE_SECTOR_ERROR = -102
    MSDC_DISCARD_SECTOR_ERROR = -103
    MSDC_PRESENT_NOT_READY = -104
    MSDC_NOT_PRESENT = -105
    EXTERNAL_DEVICE_NOT_PRESENT = -106
    HIGH_LEVEL_FORMAT_ERROR = -107
    FLASH_MOUNT_ERROR = -120
    FLASH_ERASE_BUSY = -121
    NAND_DEVICE_NOT_SUPPORTED = -122
    FLASH_OTP_UNKNOWERR = -123
    FLASH_OTP_OVERSCOPE = -124
    FLASH_OTP_WRITEFAIL = -125
    FDM_VERSION_MISMATCH = -126
    FLASH_OTP_LOCK_ALREADY = -127
    FDM_FORMAT_ERROR = -128
    LOCK_MUTEX_FAIL = -141
    NO_NONBLOCKMODE = -142
    NO_PROTECTIONMODE = -143
    INTERRUPT_BY_SIGNAL = -512


class CDecl:
    def __init__(self):
        self._field_map = {}
        fields = self._validate_fields()
        self.fields = fields

    def __setattr__(self, name, value):
        if hasattr(self, "fields") and name in self._field_map:
            self.set(name, value)
        else:
            super().__setattr__(name, value)

    def __repr__(self):
        fields = []
        for (name, spec) in self.fields:
            value = self.__dict__[name]
            if self._field_map[name]["type"] == int:
                fields.append("%s=0x%x (%s)" % (name, value, spec))
            else:
                fields.append("%s=%s (%s)" % (name, value, spec))

        return "%s<%s>" % (self.__class__.__name__, ", ".join(fields))

    def set(self, name, value):
        if name not in self._field_map:
            raise NameError("Invalid attribute %s" % (name))

        if type(value) != self._field_map[name]["type"]:
            recovered = False

            if self._field_map[name]["type"] == int and hasattr(value, "__int__"):
                value = value.__int__()
                if type(value) != int:
                    raise TypeError(
                        "Failed to cast invalid type %s to int for %s. Need %s"
                        % (type(value), name, self._field_map[name]["type"])
                    )
                else:
                    recovered = True

            if not recovered:
                raise TypeError(
                    "Invalid type %s for %s. Need %s"
                    % (type(value), name, self._field_map[name]["type"])
                )

        self.__dict__[name] = value

    def pack_field(self, name):
        if name not in self._field_map:
            raise ValueError("Field %s does not exist" % (name))

        if self._field_map[name]["type"] == bytes:
            return self.__dict__[name]
        else:
            return struct.pack(self._field_map[name]["spec"], getattr(self, name))

    def _validate_fields(self):
        fields = list(
            filter(lambda x: "_" not in x[0], self.__class__.__dict__.items())
        )

        for (name, spec) in fields:
            default = b"\x00" * struct.calcsize(spec)
            items = struct.unpack(spec, default)

            self._field_map[name] = {}
            self._field_map[name]["spec"] = spec

            # assumes byte string
            if len(items) > 1:
                self.__dict__[name] = default
                self._field_map[name]["type"] = bytes
            else:
                self.__dict__[name] = 0
                self._field_map[name]["type"] = int

        return fields

    def to_bytes(self):
        buf = b""

        for (name, spec) in self.fields:
            buf += self.pack_field(name)

        return buf

    def from_bytes(self, data):
        offset = 0

        for (name, spec) in self.fields:
            values = struct.unpack_from(spec, data, offset=offset)

            if self._field_map[name]["type"] == bytes:
                values = bytes(values)
            else:
                values = values[0]

            self.set(name, values)

            offset += struct.calcsize(spec)


class DOSDirEntry(CDecl):
    FileName = "8b"
    Extension = "3b"
    Attributes = "b"
    NTReserved = "b"
    CreateTimeTenthSecond = "b"
    CreateDateTime = "i"
    LastAccessDate = "H"
    FirstClusterHi = "H"
    DateTime = "i"
    FirstCluster = "H"
    FileSize = "I"
    Cluster = "I"
    Index = "I"
    Stamp = "I"
    Drive = "I"
    SerialNumber = "I"


class DiskInfo(CDecl):
    Label = "24b"
    DriveLetter = "b"
    WriteProtect = "b"
    Reserved = "2b"
    SerialNumber = "I"
    firstPhysicalSector = "I"
    FATType = "I"
    FATCount = "I"
    MaxDirEntries = "I"
    BytesPerSector = "I"
    SectorsPerCluster = "I"
    TotalClusters = "I"
    BadClusters = "I"
    FreeClusters = "I"
    Files = "I"
    FileChains = "I"
    FreeChains = "I"
    LargestFreeChain = "I"


class CMPTRead(CDecl):
    Operation = "I"
    Return0 = "I"
    Return1 = "i"
    OpenFlag = "I"
    FileSize = "I"
    Offset = "I"
    From = "I"
    Ptr = "I"
    Length = "I"
    BytesRead = "I"


class FSDHandle:
    def __init__(self, index):
        self.index = index
        self.fd = -1
        self.md_flag = 0
        self.linux_flag = 0
        self.find_ctx = {}
        self.filename = ""
        self.original_filename = ""

    def __repr__(self):
        return "FSDHandle<filename=%s, orig=%s, idx=%d, fd=%d, find_ctx=%s>" % (
            self.filename,
            self.original_filename,
            self.index,
            self.fd,
            self.find_ctx,
        )


class FSDStreamState:
    def __init__(self):
        self.reset()

    def reset(self):
        self.buffer = b""
        self.more_data = False


class MTKFSD:
    def __init__(self, basedir, log):
        self.log = log
        self._basedir = basedir
        self._handle_map = {}
        self._stream_state = {i: FSDStreamState() for i in range(5)}

    def handle_packet(self, pkt):
        if len(pkt) < 4:
            self.log.error("Invalid packet: not the minimum size")
            return b""

        pkt_size = struct.unpack("<I", pkt[:4])[0]
        pkt = pkt[4:]

        if pkt_size > len(pkt):
            self.log.error("Invalid packet length")
            return b""

        pkt = pkt[:pkt_size]

        off = 4 * 5
        ccci_header = pkt[:off]
        rest = pkt[off:]

        # decode the stream
        data0, data1, channel, reqBuf, op = struct.unpack("5I", ccci_header)

        self.log.debug(
            "CCCI(d0=0x%x)(d1=0x%x)(ch=0x%x)(reqBuf=0x%x)",
            data0,
            data1,
            channel,
            reqBuf,
        )
        self.log.debug("OP=0x%x", op)

        if reqBuf not in self._stream_state:
            self.log.error("Out of range stream buffer %d", reqBuf)
            return b""

        sstate = self._stream_state[reqBuf]

        # Fragment condition
        if (data0 & CCCI_FRAGMENT) != 0:
            sstate.buffer += rest
            sstate.more_data = True
        # no fragment or last fragment
        else:
            if sstate.more_data:
                # end of packet stream
                sstate.buffer += rest
                rest = sstate.buffer
                sstate.reset()

        if sstate.more_data:
            return b""

        # get PACKs (which are just args)
        off = 0
        npacks = struct.unpack_from("I", rest, offset=off)[0]
        off += 4

        packs = []

        for i in range(npacks):
            packlen = struct.unpack_from("I", rest, offset=off)[0]
            off += 4
            pack = rest[off : off + packlen]
            off += (packlen + 0x3) & ~0x3
            packs.append(pack)

        resp_packs = self._handle_op(op, packs)

        resp_buf = b""
        resp_buf += struct.pack("I", len(resp_packs))

        for p in resp_packs:
            resp_buf += struct.pack("I", len(p))
            resp_buf += p + b"\x00" * (len(p) % 4)

        # TODO: fragment outbound packets
        assert len(resp_buf) <= MAX_FS_PKT_BYTE, "Unhandled output packet requirement"

        ccci_header = struct.pack(
            "5I",
            data0 & ~CCCI_FRAGMENT,
            len(resp_buf) + 0x14,
            channel + 1,
            reqBuf,
            op | FS_API_RESP_ID,
        )

        resp_buf = ccci_header + resp_buf

        return resp_buf

    def _handle_op(self, op_int, args):
        ret = 0
        packs = []

        try:
            op = FSCCCIOp(op_int)
        except ValueError:
            self.log.error("Invalid CCCI op 0x%x", op_int)
            return packs

        self.log.debug("Processing %s", op)

        handler_name = "_op_%s" % (op.name)
        if hasattr(self, handler_name):
            returns = getattr(self, handler_name)(args)

            if isinstance(returns, tuple):
                ret, packs = returns

                assert isinstance(packs, list)

                if isinstance(ret, FSError):
                    ret = ret.value

                # encode return value
                packs = [struct.pack("i", ret)] + packs
            elif isinstance(returns, list):
                packs = returns
            else:
                assert 0, "Invalid return pattern"
        else:
            self.log.error("Unhandled FSD operation 0x%x (%s)", op_int, op)
            assert 0

        return packs

    def _rebase_path(self, path):
        return self._basedir + path

    def _decodestr(self, path):
        return path.decode("utf-16").strip("\x00")

    def _convert_path(self, path):
        new_path = None

        path = self._decodestr(path)

        for i, disk in enumerate(ROOT_DIR_MD_RESOLVE):
            disk = disk.value
            if path.startswith(disk):
                new_path = ROOT_DIR_MD1_RESOLVE[i].value + path[len(disk) :]
                break

        if new_path is not None:
            new_path = new_path.replace("\\", "/")

            if ".." in new_path:
                self.log.warning("Path from modem has illegal traversal: %s", new_path)
                return None

        return self._rebase_path(new_path)

    def _get_attrs(self, path):
        attr = 0

        is_ro = self._is_readonly(path)
        if is_ro < 0:
            return is_ro

        if is_ro:
            attr |= FSAttr.FS_ATTR_READ_ONLY.value

        is_dir = self._is_dir(path)
        if is_dir < 0:
            return is_dir

        if is_dir:
            attr |= FSAttr.FS_ATTR_DIR.value

        return attr

    def _is_dir(self, path):
        try:
            return os.path.isdir(path)
        except FileNotFoundError:
            if self.log.level == logging.DEBUG:
                self.log.error("_is_dir: file not found %s", path)
            return FSError.FILE_NOT_FOUND

    def _is_readonly(self, path):
        try:
            sbuf = os.stat(path)
        except FileNotFoundError:
            if self.log.level == logging.DEBUG:
                self.log.error("_is_readonly: file not found %s", path)
            return FSError.FILE_NOT_FOUND

        mode = sbuf.st_mode

        return (mode & (S_IRUSR | S_IRGRP | S_IROTH)) and not (
            mode & (S_IWUSR | S_IWGRP | S_IWOTH | S_IXUSR | S_IXGRP | S_IXOTH)
        )

    def _fs_seek(self, handle_index, offset, from_loc):
        if handle_index not in self._handle_map:
            self.log.error("Seek: invalid handle value %u", handle_index)
            return FSError.INVALID_FILE_HANDLE

        handle = self._handle_map[handle_index]
        linux_from = 0

        if from_loc == FSOpSeek.FS_FILE_BEGIN:
            linux_from = os.SEEK_SET
        elif from_loc == FSOpSeek.FS_FILE_CURRENT:
            linux_from = os.SEEK_CUR
        elif from_loc == FSOpSeek.FS_FILE_END:
            linux_from = os.SEEK_END
        else:
            return FSError.PARAM_ERROR

        try:
            new_position = os.lseek(handle.fd, offset, linux_from)
        except OSError as e:
            self.log.error("Seek: error %s", e)
            # TODO: real error codes
            return FSError.GENERAL_FAILURE

        return new_position

    def _op_SEEK(self, args):
        handle_index = struct.unpack("I", args[0])[0]
        offset = struct.unpack("I", args[1])[0]
        from_loc = struct.unpack("I", args[2])[0]

        ret = self._fs_seek(handle_index, offset, from_loc)

        return ret, []

    def _op_GETDISKINFO(self, args):
        # from the binary it looks like FSD is always returning the struct
        # even with uninitialized memory
        di = DiskInfo()

        # always return failure. call isnt super important for modern FSD
        return FSError.ERROR_RESERVED, [di.to_bytes()]

    def _get_free_handle(self):
        hidx = None

        for i in range(1, FS_FILE_MAX):
            if i not in self._handle_map:
                hidx = i
                break

        return hidx

    def _fs_cmpt_read(self, path_raw, params):
        self.log.debug("CMPT Read %s %s", self._decodestr(path_raw), params)

        params.BytesRead = 0
        ops_done = 0
        handle_index = -1
        data_read = b""

        if params.Operation & FSCompact.OPEN:
            handle_index = self._fs_open(path_raw, params.OpenFlag)
            if handle_index < 0:
                if self.log.level == logging.DEBUG:
                    self.log.error("CMPT Read open failure: %d", handle_index)
                params.Return0 = ops_done
                params.Return1 = handle_index
                return -1, data_read
            else:
                ops_done |= FSCompact.OPEN
        else:
            self.log.error("CMPT Read did not open file first")
            params.Return0 = ops_done
            params.Return1 = FSError.GENERAL_FAILURE
            return -7, data_read

        if params.Operation & FSCompact.GETFILESIZE:
            size = self._fs_getfilesize(handle_index)
            # size is an error
            if size < 0:
                self.log.error("CMPT Read getfilesize failure: %d", size)
                params.Return0 = ops_done
                params.Return1 = size
                self._fs_close(handle_index)
                return -2, data_read
            else:
                ops_done |= FSCompact.GETFILESIZE
                params.FileSize = size

        if params.Operation & FSCompact.SEEK:
            seek_ret = self._fs_seek(handle_index, params.Offset, params.From)

            if seek_ret < 0:
                self.log.error("CMPT Read seek failure: %d", seek_ret)
                params.Return0 = ops_done
                params.Return1 = seek_ret
                self._fs_close(handle_index)
                return -3, data_read
            else:
                ops_done |= FSCompact.SEEK

        if params.Operation & FSCompact.READ:
            read_err, data = self._fs_read(handle_index, params.Length)

            if read_err < 0:
                self.log.error("CMPT Read call failure: %d", read_err)
                params.Return0 = ops_done
                params.Return1 = read_err
                self._fs_close(handle_index)
                return -4, data_read
            else:
                data_read = data
                params.BytesRead = len(data)
                ops_done |= FSCompact.READ

        if params.Operation & FSCompact.CLOSE:
            ret = self._fs_close(handle_index)

            if ret < 0:
                self.log.error("CMPT Read close failure: %d", ret)
                params.Return0 = ops_done
                params.Return1 = ret
                return -5, data_read
            else:
                ops_done |= FSCompact.CLOSE
        else:
            self.log.error("CMPT Read file was not closed")
            self._fs_close(handle_index)
            return -6, data_read

        params.Return0 = ops_done
        params.Return1 = FSError.NO_ERROR

        return FSError.NO_ERROR, data_read

    def _op_CMPT_READ(self, args):
        path_raw = args[0]

        params = CMPTRead()
        params.from_bytes(args[1])

        ret, data_read = self._fs_cmpt_read(path_raw, params)

        return [
            # these are a single pack (unsigned int[2])
            params.pack_field("Return0") + params.pack_field("Return1"),
            params.pack_field("FileSize"),
            params.pack_field("BytesRead"),
            data_read,
        ]

    def _fs_getfilesize(self, handle_index):
        if handle_index not in self._handle_map:
            self.log.error("GetFileSize: invalid handle value %u", handle_index)
            return FSError.INVALID_FILE_HANDLE

        handle = self._handle_map[handle_index]

        sbuf = os.fstat(handle.fd)
        size = sbuf.st_size

        self.log.debug(
            "GetFileSize %s (fd=%d) %d bytes", handle.original_filename, handle.fd, size
        )

        return size

    def _op_GETFILESIZE(self, args):
        handle_index = struct.unpack("I", args[0])[0]

        ret = self._fs_getfilesize(handle_index)

        if ret < 0:
            # technically might be stale / from an old read on error
            file_size = 0
        else:
            file_size = ret
            ret = FSError.NO_ERROR

        return ret, [struct.pack("I", file_size)]

    def _fs_delete(self, path):
        path = self._convert_path(path)

        if path is None:
            self.log.error("MD path not found: %s", path)
            return FSError.PATH_NOT_FOUND

        try:
            os.unlink(path)
            ret = FSError.NO_ERROR
        except FileNotFoundError:
            if self.log.level == logging.DEBUG:
                self.log.error("Delete %s failed: not found", path)
            ret = FSError.FILE_NOT_FOUND

        return ret

    def _op_DELETE(self, args):
        ret = self._fs_delete(args[0])
        return ret, []

    def _fs_open(self, path, flag):
        ret = FSError.GENERAL_FAILURE

        filename = path

        path = self._convert_path(filename)

        if path is None:
            self.log.error("MD path not found: %s", path)
            return FSError.PATH_NOT_FOUND

        linux_flags = 0

        if flag & FSOpOpen.FS_READ_ONLY:
            linux_flags |= os.O_RDONLY
        else:
            linux_flags |= os.O_RDWR

        if flag & FSOpOpen.FS_CREATE:
            linux_flags |= os.O_CREAT | os.O_RDWR

        if flag & FSOpOpen.FS_CREATE_ALWAYS:
            linux_flags |= os.O_CREAT | os.O_RDWR | os.O_TRUNC

        if flag & FSOpOpen.FS_NONBLOCK_MODE:
            linux_flags |= os.O_NONBLOCK

        handle_index = self._get_free_handle()

        if handle_index is None:
            self.log.error("Open %s failed: out of handles", path)
            return FSError.TOO_MANY_FILES

        try:
            fd = os.open(path, linux_flags, mode=0o660)
        except FileNotFoundError:
            if self.log.level == logging.DEBUG:
                self.log.error("Open %s failed: not found", path)
            ret = FSError.FILE_NOT_FOUND
            return ret

        # commit the handle once we are sure there were no errors
        handle = FSDHandle(handle_index)
        self._handle_map[handle_index] = handle

        self.log.debug(
            "Open %s fl=%d l_fl=%d, fd=%d, handle=%d",
            path,
            flag,
            linux_flags,
            fd,
            handle.index,
        )

        handle.fd = fd
        handle.md_flag = flag
        handle.linux_flag = linux_flags
        handle.filename = path
        handle.original_filename = self._decodestr(filename)

        ret = handle.index

        return ret

    def _op_OPEN(self, args):
        flag = struct.unpack("i", args[1])[0]
        return self._fs_open(args[0], flag), []

    def _fs_read(self, handle_index, bytes_to_read):
        if handle_index not in self._handle_map:
            self.log.error("Read: invalid handle value %u", handle_index)
            return FSError.INVALID_FILE_HANDLE, b""

        handle = self._handle_map[handle_index]

        data = os.read(handle.fd, bytes_to_read)

        return FSError.NO_ERROR, data

    def _op_READ(self, args):
        handle_index = struct.unpack("I", args[0])[0]
        bytes_to_read = struct.unpack("i", args[1])[0]

        ret, data = self._fs_read(handle_index, bytes_to_read)
        return ret, [struct.pack("I", len(data)), data]

    def _fs_write(self, handle_index, buf, nbytes):
        if handle_index not in self._handle_map:
            self.log.error("Write: invalid handle value %u", handle_index)
            return FSError.INVALID_FILE_HANDLE, 0

        handle = self._handle_map[handle_index]

        # respect the requested number of bytes to write
        # there is no guarantee that the buffer received and the byte count requested are aligned
        if nbytes > len(buf):
            self.log.warning(
                "Write: requested %d byte write on a %d byte buffer! Truncating",
                nbytes,
                len(buf),
            )
            nbytes = len(buf)

        # slice buf down to size
        buf = buf[:nbytes]

        # TODO: handle_errors
        nbytes_written = os.write(handle.fd, buf)

        return FSError.NO_ERROR, nbytes_written

    def _op_WRITE(self, args):
        handle_index = struct.unpack("I", args[0])[0]
        buf = args[1]
        nbytes = struct.unpack("I", args[2])[0]

        ret, nbytes_written = self._fs_write(handle_index, buf, nbytes)

        return ret, [struct.pack("I", nbytes_written)]

    def _fs_close(self, handle_index):
        if handle_index not in self._handle_map:
            self.log.error("Close: invalid handle value %u", handle_index)
            return FSError.INVALID_FILE_HANDLE

        handle = self._handle_map[handle_index]
        del self._handle_map[handle_index]

        if len(handle.find_ctx):
            self.log.debug(
                "Closedir dir=%s handle=%d", handle.find_ctx["dent"], handle_index
            )
            handle.find_ctx["dent"].close()
        else:
            self.log.debug("Close fd=%d handle=%d", handle.fd, handle_index)
            # ignore FSYNC
            os.close(handle.fd)

        return FSError.NO_ERROR

    def _op_CLOSE(self, args):
        handle_index = struct.unpack("I", args[0])[0]
        return self._fs_close(handle_index), []

    def _op_GETATTRIBUTES(self, args):
        ret = FSError.GENERAL_FAILURE

        path = self._convert_path(args[0])

        if path is None:
            self.log.error("MD path not found: %s", path)
            return FSError.PATH_NOT_FOUND, []

        ret = self._get_attrs(path)
        self.log.debug("GetAttributes %s attr=%d", path, ret)

        return ret, []

    def _fs_findcommon(
        self, prefix, result, dent, filepattern, attribute, attribute_mask, max_length
    ):
        ent = next(dent, None)
        matched_path = None

        r_pattern = r""
        for c in filepattern:
            if c in ["?", "*"]:
                r_pattern += r"." + c
            else:
                r_pattern += re.escape(c)

        r_pattern = re.compile(r_pattern)

        while ent is not None:
            if r_pattern.match(ent.name):
                matched_path = ent.path
                matched_attr = self._get_attrs(matched_path)

                if (matched_attr & attribute) == attribute and (
                    matched_attr & attribute_mask
                ) == 0:
                    self.log.debug("%s: match %s", prefix, ent.name)
                    break
                else:
                    self.log.warning(
                        "%s: attribute mismatch %s, matched_attr=%x, attr=%x, mask=%x",
                        prefix,
                        ent.name,
                        matched_attr,
                        attribute,
                        attribute_mask,
                    )

            ent = next(dent, None)

        if ent is None:
            if self.log.level == logging.DEBUG:
                self.log.error("%s: no files found", prefix)

            if prefix == "FindFirst":
                dent.close()

            result.retval = FSError.NO_MORE_FILES
            return result

        self._fs_linux2dos(matched_path, result.meta)

        if len(ent.name) < max_length:
            result.meta.NTReserved = FSOpFind.FS_LFN_MATCH
        else:
            result.meta.NTReserved = FSOpFind.FS_NOT_MATCH

        # Not 100% sure this is byte accurate
        # * Null terminate?
        # * Slashes in filename?
        # * UTF-16 BOM?
        result.filename = ent.name.encode("utf-16le") + b"\x00\x00"
        result.filename = result.filename[
            : min(len(result.filename), (max_length + 1) * 2)
        ]
        result.maxlen = max_length
        result.retval = FSError.NO_ERROR

        return result

    def _fs_findfirst(self, pattern, attribute, attribute_mask, max_length):
        result = FSFindResult()
        path = self._convert_path(pattern)

        if path is None:
            self.log.error("MD path not found: %s", path)
            result.retval = FSError.PATH_NOT_FOUND
            return result

        filedir = os.path.dirname(path)
        filepattern = os.path.basename(path)

        self.log.debug("FindFirst: open %s", filedir)

        try:
            dent = os.scandir(filedir)
        except FileNotFoundError:
            if self.log.level == logging.DEBUG:
                self.log.error("FindFirst: open error")
            result.retval = FSError.FILE_NOT_FOUND
            return result

        result = self._fs_findcommon(
            "FindFirst",
            result,
            dent,
            filepattern,
            attribute,
            attribute_mask,
            max_length,
        )

        if result.retval != 0:
            return result

        handle_index = self._get_free_handle()

        if handle_index is None:
            self.log.error("FindFirst for %s failed: out of handles", path)
            result.retval = FSError.TOO_MANY_FILES
            return result

        handle = FSDHandle(handle_index)
        self._handle_map[handle_index] = handle

        handle.find_ctx = {
            "dent": dent,
            "attr": attribute,
            "attr_mask": attribute_mask,
            "file_pattern": filepattern,
        }
        handle.filename = path
        handle.original_filename = self._decodestr(pattern)

        result.retval = handle.index

        return result

    def _fs_linux2dos(self, path, dosdir):
        # TODO: handle failures
        sbuf = os.stat(path)

        atime = time.localtime(sbuf.st_atime)
        mtime = time.localtime(sbuf.st_mtime)

        dosdir.Attributes = self._get_attrs(path)

        # XXX: no idea what is happening here. Packet reference shows that mtime is used twice...
        # for (a, t) in [("CreateDateTime", atime), ("DateTime", mtime)]:
        for (a, t) in [("CreateDateTime", mtime), ("DateTime", mtime)]:
            v = (
                (t.tm_sec & 0x1F)
                | ((t.tm_min & 0x3F) << 5)
                | ((t.tm_hour & 0x1F) << 11)
                | ((t.tm_mday & 0x1F) << 16)
                | ((t.tm_mday & 0x0F) << 21)
                | (((t.tm_year - 80 - 1900) & 0x7F) << 25)
            )
            # python returns year + 1900. this isnt documented anywhere
            # Linux's stat(2) call returns the delta years, so fixup

            setattr(dosdir, a, v)

        dosdir.FileSize = sbuf.st_size

        # self.log.debug("DOS: %s %s, atime=%s, mtime=%s",
        # dosdir, dosdir.to_bytes(), atime, mtime)

    def _fs_findnext(self, handle_index, max_length):
        result = FSFindResult()

        if handle_index not in self._handle_map:
            self.log.error("FindNext: invalid handle value %u", handle_index)
            result.retval = FSError.INVALID_FILE_HANDLE
            return result

        handle = self._handle_map[handle_index]

        if len(handle.find_ctx) == 0:
            self.log.error("FindNext: invalid search handle value %u", handle_index)
            result.retval = FSError.INVALID_FILE_HANDLE
            return result

        ctx = handle.find_ctx
        dent = ctx["dent"]
        attribute = ctx["attr"]
        attribute_mask = ctx["attr_mask"]
        filepattern = ctx["file_pattern"]

        result = self._fs_findcommon(
            "FindNext", result, dent, filepattern, attribute, attribute_mask, max_length
        )

        return result

    def _op_FINDNEXT(self, args):
        handle_index = struct.unpack("I", args[0])[0]
        maxlen = struct.unpack("I", args[1])[0]

        result = self._fs_findnext(handle_index, maxlen)

        maxlen = result.maxlen
        fileresult = result.filename if maxlen > 0 else b""

        return result.retval, [result.meta.to_bytes(), fileresult]

    def _op_FINDFIRST(self, args):
        pattern = args[0]
        attr = struct.unpack("b", args[1])[0]
        mask = struct.unpack("b", args[2])[0]
        maxlen = struct.unpack("I", args[3])[0]

        result = self._fs_findfirst(pattern, attr, mask, maxlen)

        maxlen = result.maxlen
        fileresult = result.filename if maxlen > 0 else b""

        return result.retval, [result.meta.to_bytes(), fileresult]

    def _fs_findclose(self, handle_index):
        if handle_index not in self._handle_map:
            self.log.error("FindClose: invalid handle value %u", handle_index)
            return FSError.INVALID_FILE_HANDLE

        handle = self._handle_map[handle_index]

        if len(handle.find_ctx) == 0:
            self.log.error("FindClose: invalid search handle value %u", handle_index)
            return FSError.INVALID_FILE_HANDLE

        return self._fs_close(handle_index)

    def _op_FINDCLOSE(self, args):
        handle_index = struct.unpack("I", args[0])[0]

        ret = self._fs_findclose(handle_index)

        return ret, []

    def _op_RESTORE(self, args):
        filename = args[0]
        path = self._convert_path(filename)

        if path is None:
            self.log.error("MD path not found: %s", path)
            return FSError.PATH_NOT_FOUND, []

        # TODO: what does [redacted] do?
        #
        # This is causing A315GXXU1ATG1_CP16312955_CL19064881_QB32895073_REV00/md1img.img to fail
        #
        # Output from the modem:
        #   "NVRAM ASSERT ERROR NVRAM_LOC_BIN_REGION_RESTORE_FAIL"
        #   assert failed (break): b'common/modem/mml1/mml1_rf/mml1_rf_error_check.c':211
        self.log.warning("Restore: %s stub!", path)

        return FSError.NO_ERROR, []

    def _op_CREATEDIR(self, args):
        dirname = self._convert_path(args[0])

        if not self._is_dir(dirname):
            try:
                os.makedirs(dirname)
            except OSError as e:
                self.log.error("createdir: error %s", e)
                # TODO: real error codes
                return FSError.GENERAL_FAILURE, []
        return FSError.NO_ERROR, []
