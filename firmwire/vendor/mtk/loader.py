## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import firmwire.loader
import firmwire.vendor.mtk.soc
import filetype
import logging
import struct
import lzma
import csv
import sys
import lz4.frame
import re
import pickle

from io import BytesIO
from os import stat

import filetype
from tarfile import TarFile
from avatar2 import *
from pathlib import PurePath

from firmwire.emulator.patterndb import PatternDB, PatternDBEntry
from firmwire.hw.soc import get_soc
from .mtkdb.parse_mdb import readCATD
from .mtkdb.parse_lted import readLTED
from .pattern import PATTERNS
from .machine import MT6878Machine
from .hw import *
from firmwire.vendor.mtk.consts import ROM_BASE_ADDR

MAGIC = 0x58881688
MAGIC2 = 0x58891689

DBG_INFO_NAME = "md1_dbginfo"
DBG_DB_NAME = "md1_mddb"
MAIN_IMG_NAME = "md1rom"

log = logging.getLogger(__name__)


class MDFileException(Exception):
    def __init__(self, message):
        super().__init__(message)


class MTKSection:
    def __init__(self, loader, name, length, maddr, mode, header_start, data_start):
        self.loader = loader
        self.name = name
        self.length = length
        self.maddr = maddr
        self.mode = mode
        self.header_start = header_start
        self.data_start = data_start

    @property
    def data(self):
        with open(self.loader.md1img, "rb") as f:
            f.seek(self.data_start)
            data = f.read(self.length)
        return data

    def to_file(filename):
        with open(self.loader.md1img, "rb") as f:
            f.seek(data_start)
            data = f.read(self.length)
        with open(filename, "wb") as f:
            f.write(data)

    def __repr__(self):
        return f"MTKSection {self.name} with 0x{self.length:x} bytes"


class MTKLoader(firmwire.loader.Loader):
    NAME = "mtk"
    LOADER_ARGS = {
        "nv_data": {
            "type": PurePath,
            "help": "A path to MTK vendor data directory",
            "default": "./mnt",
        },
    }

    @property
    def ARCH(self):
        return MIPS_LE

    @staticmethod
    def is_relevant(path):
        ft = filetype.guess(path)
        return (ft is not None and ft.mime in ["application/x-tar"]) or path.endswith(
            ".img"
        )

    def try_load(self):
        try:
            self.md1img = self.unpack_md1img(self.path)
        except MDFileException as e:
            log.error("%s", e)
            return False

        self.sections = {s.name: s for s in self.iter_section_info()}

        dbg_info = self.parse_debug_info()

        if dbg_info is None:
            return False

        self.symbols = {name: v[0] for name, v in dbg_info.items()}
        self.symbol_sizes = {name: v[1] for name, v in dbg_info.items()}

        if not self.guess_soc_version():
            return False

        if not self.build_memory_map():
            return False

        log.info("Loaded MTK image with %d sections", len(self.sections))

        parsed_lted = None
        if not self.workspace.path("/ltedb.pickle").exists():

            log.info("Parsing MTK debug database...")

            md1_mddb = self.sections.get(DBG_DB_NAME)

            # parsing of trace files is implemented on files, hence we use BytesIO here
            if md1_mddb is not None:
                md1_mddb_segments = readCATD(BytesIO(md1_mddb.data))
                lteds = [x for x in md1_mddb_segments if x[:4] == b"LTED"]

                # MTK machines heavily rely on having debug info. This is fatal
                if len(lteds) == 0:
                    log.warning("Failed to parse MTK debug database or missing 'LTED'")
                else:
                    if len(lteds) > 1:
                        log.warning("More than one LTED entry! Choosing first one")

                    log.info("Parsing LTE DB...")
                    parsed_lted = readLTED(BytesIO(lteds[0]))

                    log.info("Caching DB to workspace...")
                    with open(
                        self.workspace.path("/ltedb.pickle").to_path(), "wb"
                    ) as f:
                        pickle.dump(parsed_lted, f)
        else:
            log.info("Loading cached MTK debug database...")

            with open(self.workspace.path("/ltedb.pickle").to_path(), "rb") as f:
                parsed_lted = pickle.load(f)

        if parsed_lted is None:
            log.warning("Missing LTE trace strings - debug output will suffer")
            self.trace_entries = {}
        else:
            log.info("Loaded database with %d trace entries", len(parsed_lted["trace"]))
            self.trace_entries = parsed_lted["trace"]

        # Check to see if NV data is available
        nv_data_path = self.loader_args["nv_data"]
        if not os.path.isdir(nv_data_path):
            log.error("NV data %s directory is missing", nv_data_path)
            return False

        sub_path = nv_data_path / "vendor" / "nvdata"

        if not os.path.isdir(sub_path):
            log.error(
                "NV data %s directory is available, but missing %s subfolder",
                nv_data_path,
                sub_path,
            )
            return False

        if len(os.listdir(sub_path)) == 0:
            log.warning("NV data directory looks empty. Modem will try to recover and create defaults...")

        log.info("Using NV data from %s", nv_data_path)

        # resolve patterns
        all_data = self.rom_img_data()
        data_base_addr = 0x90000000 + ROM_BASE_ADDR

        try:
            db = PatternDB(self)

            for name, entry in PATTERNS.items():
                pat = PatternDBEntry(name)
                for k, v in entry.items():
                    setattr(pat, k, v)

                db.add_pattern(pat)

            db.find_patterns(all_data, data_base_addr)

            # MTK HACK: copy symbol table to symbols
            for sym in self.symbol_table.symbols:
                self.symbols[sym.name] = sym.address
        except ValueError as e:
            log.exception("Error resolving symbols")
            return False

        return True

    def unpack_md1img(self, infile):
        while True:
            g = filetype.guess(infile)
            if g is not None and g.mime == "application/x-tar":
                tar = TarFile(infile)
                name = None
                for n in tar.getnames():
                    if "md1img" in n:
                        name = n
                if name is None:
                    raise MDFileException("md1img not found!")
                tar.extract(name, set_attrs=False)
                if name.endswith("lz4"):
                    unl4 = lz4.frame.open(name)
                    name = name[:-4]
                    with open(name, "wb") as f:
                        f.write(unl4.read())
                infile = name

            elif g is None and ".img" in infile:
                return infile
            else:
                raise MDFileException(f"Could not handle {infile} of type {g.mime}")

    def _getstr(self, raw):
        out = bytearray()
        while True:
            c = raw.read(1)
            if c == b"\x00":
                break
            out += c
        return out.decode()

    def rom_img_data(self):
        return self.sections[MAIN_IMG_NAME].data

    def parse_debug_info(self):
        if DBG_INFO_NAME not in self.sections:
            log.error("Missing required section %s", DBG_INFO_NAME)
            return None

        log.info("Parsing debug info...")

        debug_compressed = self.sections[DBG_INFO_NAME].data
        decompressor = lzma.LZMADecompressor()
        debug_data = BytesIO(decompressor.decompress(debug_compressed))

        debug_info = {}

        # parse header
        debug_data.seek(0x1C)
        target = self._getstr(debug_data)
        hwplatform = self._getstr(debug_data)
        moly_version = self._getstr(debug_data)
        buildtime = self._getstr(debug_data)

        fn_syms_off = struct.unpack("<I", debug_data.read(4))[0] + 0x10
        file_syms_off = struct.unpack("<I", debug_data.read(4))[0] + 0x10

        while True:
            name = self._getstr(debug_data)
            start = struct.unpack("<I", debug_data.read(4))[0]
            end = struct.unpack("<I", debug_data.read(4))[0]

            while name in debug_info:
                name = name + "_"
            debug_info[name] = (start, end - start)

            if debug_data.tell() >= file_syms_off:
                break
        return debug_info

    def debug_info_to_csv(self, csvfile):
        """
        The CSV format follows the polypyus format
        """
        dbg_info = self.parse_debug_info()
        with open(csvfile, "w") as file:
            fieldnames = ["name", "addr", "size", "mode", "type"]
            writer = csv.DictWriter(file, fieldnames=fieldnames, delimiter=" ")

            writer.writeheader()
            for name, addrs in dbg_info.items():
                writer.writerow(
                    {
                        "name": name,
                        "addr": addrs[0],
                        "size": addrs[1],
                        "mode": "UNKOWN",
                        "type": "FUNC",
                    }
                )

    def debug_info_from_csv(self, csvfile):
        """
        The CSV format follows the polypyus format
        """
        dbg_info = {}
        with open(csvfile, "r") as file:
            fieldnames = ["name", "addr", "size", "mode", "type"]
            reader = csv.DictReader(file, delimiter=" ")
            for row in reader:
                dbg_info[row["name"]] = (row["addr"], row["size"])

        return dbg_info

    def iter_section_info(self):
        off = 0
        file_length = stat(self.md1img).st_size

        with open(self.md1img, "rb") as f:
            while off < file_length:
                f.seek(off)
                header = f.read(0x50)

                # special case for samsung signatures
                if header[:9] == b"SignerVer":
                    return
                contents = struct.unpack("<II32sIIIIIIIIII", header)

                magic = contents[0]
                length = contents[1]
                name = contents[2][
                    : contents[2].find(b"\x00")
                ].decode()  # strip after 0byte
                maddr = contents[3]
                mode = contents[4]
                magic2 = contents[5]
                data_off = contents[6]

                log.info(
                    "Found new file {:s} at 0x{:x}/0x{:x} with length 0x{:x}".format(
                        name, off, maddr, length
                    )
                )

                assert (
                    magic == MAGIC and magic2 == MAGIC2
                )  # either EOF, or we did smthg wrong

                yield MTKSection(self, name, length, maddr, mode, off, off + data_off)

                off = off + data_off + length
                if off % 0x10:
                    off = off - off % 0x10 + 0x10

    def guess_soc_version(self):

        # The DSP is closely tied to the hardware platform and includes a build time
        dsp_data = self.sections["md1dsp"].data

        # Try to find the version with the date first
        found = re.search(
            rb"""
        (?P<date>[0-9]{4}/[0-9]{2}/[0-9]{2}?)  # Date as YYYY/MM/DD (for rough SoC revision)
        (?P<time>[ ][0-9]{2}:[0-9]{2})?   # time in HH:MM format
        .{,100}                 # variable sized inbetween-data
        (?P<SOC>MT[0-9]{4}?) # SOC-ID
        [^\x00]*               # null terminator""",
            dsp_data,
            re.M | re.S | re.X,
        )

        if found is None:
            log.error(
                "Unable to automatically determine the SoC type from the boot image"
            )
            return False

        soc_guess = found.group("SOC").decode()

        # SoC date is a best effort approach
        soc_date = found.group("date").decode() if "date" in found.groupdict() else 0

        self.modem_soc = get_soc(self.NAME, soc_guess)

        if self.modem_soc is None:
            log.error("Guessed SoC '%s' is not supported", soc_guess)
            return False

        # Initialize SoC object
        self.modem_soc = self.modem_soc(soc_date)

        log.info("SoC %s (automatic)", repr(self.modem_soc))

        self._machine_class = MT6878Machine

        return True

    def build_memory_map(self):
        self.build_peripheral_maps()

        ########################
        # Peripheral Memory Map
        ########################

        for peripheral in self.modem_soc.peripherals:
            self.create_soc_peripheral(peripheral)

        return True

    def build_peripheral_maps(self):
        # peripherals
        self.add_memory_range(
            0x1F000000, 0x8000, name="GCR", emulate=GCR_Periph, permissions="rw-"
        )
        self.add_memory_range(
            0x1FC00000, 0x1000, name="MDMCU_MDMCU", permissions="rw-"
        )  # ITC?
        self.add_memory_range(
            0x1FC10000, 0x1000, name="CDMM", emulate=CDMM_Periph, permissions="rw-"
        )
        # 0x1f020000 GIC
        # 0x1f008000 CPC

        # self.add_memory_range(0x1f010000, 0x8000, name='GCRCustom', emulate=GCRCustom_Periph, permissions='rw-')
        self.add_memory_range(
            0x1F010000,
            0x1000,
            name="GCRCustom",
            emulate=GCRCustom_Periph,
            permissions="rw-",
        )
        self.add_memory_range(0x1F014000, 0x1000, name="GCR_MDCIRQ", permissions="rw-")
        self.add_memory_range(0x1F01C000, 0x1000, name="ULSP_PB", permissions="rw-")
        self.add_memory_range(
            0xA0000000,
            0x1000,
            name="MDPERI_MDCFGCTL",
            emulate=MDCFGCTL_Periph,
            permissions="rw-",
        )
        self.add_memory_range(
            0xA0020000, 0x1000, name="MDPERI_MDGDMA", permissions="rw-"
        )
        self.add_memory_range(
            0xA0030000, 0x1000, name="MDPERI_MDGPTM", permissions="rw-"
        )
        self.add_memory_range(
            0xA0060000,
            0x2000,
            name="MDPERI_MDPERISYS_MISC_REG",
            emulate=MDPERISYS_MISC_Periph,
            permissions="rw-",
        )
        # avatar.add_memory_range(0xa0061000, 0x1000, name='MDPERI_MDPERISYS_MISC_REG_cont', emulate=PassthroughPeripheral, permissions='rw-')
        self.add_memory_range(
            0xA0070000,
            0x1000,
            name="MDPERI_MDCIRQ",
            emulate=MDCIRQ_Periph,
            permissions="rw-",
        )
        # TODO: is this all DBGSYS1? maybe..
        self.add_memory_range(
            0xA0080000, 0x10000, name="MDPERI_MD_DBGSYS1", permissions="rw-"
        )
        self.add_memory_range(
            0xA00C0000, 0x1000, name="MDPERI_PTP_THERM_CTRL", permissions="rw-"
        )
        # TODO: F32K_CNT is accessed so much that this is a perf issue (MD_TOPSM)
        # avatar.add_memory_range(0xa00d0000, 0x1000, name='MDPERI_MD_TOPSM', emulate=TOPSM_Periph, permissions='rw-')
        self.add_memory_range(
            0xA00E0000,
            0x1000,
            name="MDPERI_MD_OSTIMER",
            emulate=OSTimer_Periph,
            permissions="rw-",
        )
        self.add_memory_range(
            0xA00F0000, 0x1000, name="MDPERI_MDRGU", permissions="rw-"
        )
        self.add_memory_range(
            0xA0100000, 0x1000, name="MDPERI_MDSM_CORE_PWR_CTRL", permissions="rw-"
        )
        # note that MDPERI_MD_EINT starts at EINT_ADDR_OFFSET = 0x1000, so I added a _GPIOMUX for the base
        self.add_memory_range(
            0xA0110000, 0x2000, name="MDPERI_MD_EINT_GPIOMUX", permissions="rw-"
        )
        self.add_memory_range(
            0xA0130000, 0x1000, name="MDPERI_MD_GLOBAL_CON_DCM", permissions="rw-"
        )
        self.add_memory_range(
            0xA0140000, 0x1000, name="MDPERI_MD_PLLMIXED", permissions="rw-"
        )
        self.add_memory_range(
            0xA0150000,
            0x1000,
            name="MDPERI_MD_CLKSW",
            emulate=CLKSW_Periph,
            permissions="rw-",
        )
        self.add_memory_range(
            0xA01C0000, 0x1000, name="MDPERI_CLK_CTRL", permissions="rw-"
        )
        self.add_memory_range(
            0xA01D2000, 0x1000, name="MDPERI_CORE0_MEM_CONFIG", permissions="rw-"
        )
        self.add_memory_range(
            0xA01D3000, 0x1000, name="MDPERI_CORE1_MEM_CONFIG", permissions="rw-"
        )
        self.add_memory_range(
            0xA01D4000, 0x1000, name="MDPERI_MDCORE_MEM_CONFIG", permissions="rw-"
        )
        self.add_memory_range(
            0xA01D5000, 0x1000, name="MDPERI_MDINFRA_MEM_CONFIG", permissions="rw-"
        )
        self.add_memory_range(
            0xA01D6000, 0x1000, name="MDPERI_MDMEMSLP_CONFIG", permissions="rw-"
        )
        self.add_memory_range(
            0xA01D8000, 0x1000, name="MDPERI_MDPERISYS_MEM_CONFIG", permissions="rw-"
        )
        self.add_memory_range(
            0xA0210000, 0x1000, name="MDMCU_IA_PDA_MON", permissions="rw-"
        )
        self.add_memory_range(
            0xA0300000, 0x1000, name="MDCORESYS_MML2_MCU_MMU_MMU", permissions="rw-"
        )
        self.add_memory_range(
            0xA0301000, 0x1000, name="MDCORESYS_MML2_MCU_MMU_VRB", permissions="rw-"
        )
        self.add_memory_range(
            0xA0302000, 0x1000, name="MDCORESYS_MML2_MCU_MMU", permissions="rw-"
        )
        self.add_memory_range(
            0xA0310000, 0x1000, name="MDMCU_BUSMON", permissions="rw-"
        )
        self.add_memory_range(
            0xA0330000, 0x1000, name="MDMCU_BUS_CONFIG", permissions="rw-"
        )
        self.add_memory_range(
            0xA0350000, 0x1000, name="MDCORESYS_MDMCU_ELM_EMI", permissions="rw-"
        )
        self.add_memory_range(
            0xA0360000, 0x1000, name="MDCORESYS_MISC_REG_ADR_IF", permissions="rw-"
        )
        # this is MCUSYS_MISC_REG + 0x10000
        self.add_memory_range(
            0xA0370000, 0x1000, name="BUSMPU_ERR_REG", permissions="rw-"
        )
        self.add_memory_range(
            0xA04A0000, 0x1000, name="MDINFRA_MDSMICFG", permissions="rw-"
        )
        self.add_memory_range(0xA04F0000, 0x1000, name="MDINFRA_LOG", permissions="rw-")
        self.add_memory_range(
            0xA0520000, 0x1000, name="MDINFRA_MD_INFRA_ELM", permissions="rw-"
        )
        self.add_memory_range(
            0xA0560000, 0x1000, name="MDINFRA_PPPHA", permissions="rw-"
        )
        self.add_memory_range(
            0xA0600000, 0x1000, name="MML2_QUEUE_PROCESSOR", permissions="rw-"
        )
        self.add_memory_range(0xA060B000, 0x1000, name="MML2_CFG", permissions="rw-")
        self.add_memory_range(
            0xA1000000, 0x40000, name="USIP_USIP0_ITCM", permissions="rw-"
        )
        self.add_memory_range(
            0xA1040000, 0x40000, name="USIP_USIP0_DTCM", permissions="rw-"
        )
        self.add_memory_range(
            0xA10A0000, 0x1000, name="USIP_USIP0_power", permissions="rw-"
        )
        self.add_memory_range(
            0xA1100000, 0x40000, name="USIP_USIP1_ITCM", permissions="rw-"
        )
        self.add_memory_range(
            0xA1140000, 0x40000, name="USIP_USIP1_DTCM", permissions="rw-"
        )
        self.add_memory_range(
            0xA11A0000, 0x1000, name="USIP_USIP1_power", permissions="rw-"
        )
        self.add_memory_range(0xA1600000, 0x1000, name="USIP_CONFG", permissions="rw-")
        self.add_memory_range(
            0xA1630000, 0x1000, name="USIP_CROSS_CORE_CTRL", permissions="rw-"
        )
        self.add_memory_range(
            0xA1FF0000,
            0x1000,
            name="MDMCU_MCU_SYNC",
            emulate=MCUSync_Periph,
            permissions="rw-",
        )
        self.add_memory_range(
            0xA6000000,
            0x1000,
            name="MODEML1_AO_MODEML1_TOPSM",
            emulate=MODEML1_TOPSM_Periph,
            permissions="rw-",
        )
        self.add_memory_range(
            0xA6010000, 0x1000, name="MODEML1_AO_MODEML1_DVFS_CTRL", permissions="rw-"
        )
        self.add_memory_range(
            0xA6020000, 0x1000, name="MODEML1_AO_MODEML1_AO_CONFG", permissions="rw-"
        )
        self.add_memory_range(
            0xA6030000, 0x1000, name="MODEML1_AO_TDMA_SLP", permissions="rw-"
        )
        self.add_memory_range(
            0xA6060000, 0x1000, name="MODEML1_AO_FDD_SLP", permissions="rw-"
        )
        self.add_memory_range(
            0xA6080000, 0x1000, name="MODEML1_AO_LTE_SLP", permissions="rw-"
        )
        self.add_memory_range(
            0xA60C0000, 0x1000, name="MODEML1_AO_C2K_1X_TIMER", permissions="rw-"
        )
        self.add_memory_range(
            0xA60E0000, 0x1000, name="MODEML1_AO_C2K_DO_TIMER", permissions="rw-"
        )
        self.add_memory_range(
            0xA60D0000, 0x1000, name="MODEML1_AO_C2K_1X_SLP", permissions="rw-"
        )
        self.add_memory_range(
            0xA60F0000, 0x1000, name="MODEML1_AO_C2K_DO_SLP", permissions="rw-"
        )

        self.add_memory_range(
            0xA6100000,
            0xD000,
            name="BASE_MADDR_MODEML1_AO_WCT_P2P_TX_PARALLEL",
            permissions="rw-",
        )
        self.add_memory_range(
            0xA6110000, 0x1000, name="MODEML1_AO_FESYS_P2P_TX", permissions="rw-"
        )
        self.add_memory_range(
            0xA6120000, 0x1000, name="MODEML1_AO_MDRX_P2P_TX", permissions="rw-"
        )
        self.add_memory_range(
            0xA6140000, 0x1000, name="BASE_MADDR_MODEML1_AO_BSI_MM", permissions="rw-"
        )
        self.add_memory_range(
            0xA6160000, 0x9000, name="MODEML1_AO_BSI_MM_2", permissions="rw-"
        )
        self.add_memory_range(
            0xA6170000, 0x3000, name="MODEML1_AO_BSI_MM_3", permissions="rw-"
        )
        self.add_memory_range(
            0xA6180000, 0x3000, name="BASE_MADDR_MODEML1_AO_BPI_MM", permissions="rw-"
        )
        self.add_memory_range(
            0xA6190000,
            0xE000,
            name="BASE_MADDR_MODEML1_AO_ABBMIX_PKR_P2P_TX",
            permissions="rw-",
        )
        self.add_memory_range(
            0xA61A0000, 0x1000, name="BASE_MADDR_MODEML1_AO_C1X_TTR", permissions="rw-"
        )
        self.add_memory_range(
            0xA61B0000, 0x1000, name="BASE_MADDR_MODEML1_AO_CDO_TTR", permissions="rw-"
        )

        self.add_memory_range(
            0xA6F00000, 0x1000, name="MD2GSYS_MD2G_CONFG", permissions="rw-"
        )
        self.add_memory_range(
            0xA6F20000,
            0x1000,
            name="MD2GSYS_TDMA_BASE",
            emulate=TDMABase_Periph,
            permissions="rw-",
        )
        self.add_memory_range(
            0xA6F40000, 0x1000, name="MD2GSYS_BFE_2ND", permissions="rw-"
        )
        self.add_memory_range(0xA6FE0000, 0x1000, name="MD2GSYS_BFE", permissions="rw-")

        self.add_memory_range(
            0xA7010000, 0x1000, name="RXDFESYS_CONFIG", permissions="rw-"
        )
        self.add_memory_range(
            0xA70C0000, 0x9000, name="RXDFESYS_RXDFE_FC", permissions="rw-"
        )
        self.add_memory_range(
            0xA70D0000, 0x1000, name="RXDFESYS_RXDFE_ATIMER", permissions="rw-"
        )
        self.add_memory_range(
            0xA7430000, 0x1000, name="RXDFESYS_RXDFE_FCCALTC_SRAM", permissions="rw-"
        )
        self.add_memory_range(
            0xAC350000, 0x1000, name="RAKESYS_CIRQ", permissions="rw-"
        )
        self.add_memory_range(
            0xAC351000, 0x1000, name="RAKESYS_PERICTRL", permissions="rw-"
        )
        self.add_memory_range(
            0xAC358000, 0x1000, name="RAKESYS_CMIF", permissions="rw-"
        )
        self.add_memory_range(0xC0005000, 0x1000, name="AP_GPIOMUX", permissions="rw-")
        self.add_memory_range(0xC0006000, 0x1000, name="SPM_PCM", permissions="rw-")
        # pmic_wrap_memory_dump in the current fw binary wants 0x61d entries, TODO: investigate
        # avatar.add_memory_range(0xc000d000, 0x1000, name='APMCU_MISC', emulate=PassthroughPeripheral, permissions='rw-') # aka PMIC_WRAP
        # avatar.add_memory_range(0xc000d000, 0x2000, name='APMCU_MISC', emulate=PMIC_WRAP_Periph, permissions='rw-') # aka PMIC_WRAP -> moved to SOC definition
        self.add_memory_range(0xC000F000, 0x1000, name="SPM_VMODEM", permissions="rw-")
        self.add_memory_range(0xC0012000, 0x1000, name="DVFSRC", permissions="rw-")
        self.add_memory_range(
            0xC0219000, 0x1000, name="AP_EMI_CONFIG", permissions="rw-"
        )
        self.add_memory_range(
            0xC021C800, 0x1000, name="AP_CLDMA_TOP_MD", permissions="rw-"
        )

        self.create_peripheral(AES_TOP0_Periph, 0xC0016000, 0x1000, name="AES_TOP0")
        self.create_peripheral(
            SHM_RUNTIME_Periph, 0x69000000, 0x1000, name="SharedMemoryRUNTIME"
        )
        self.create_peripheral(TOPSM_Periph, 0xA00D0000, 0x1000, name="MDPERI_MD_TOPSM")


firmwire.loader.register_loader(MTKLoader)
