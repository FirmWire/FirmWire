## Copyright (c) 2025, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause

from enum import IntEnum, unique
import struct
import socket
from firmwire.emulator.firmwire import FirmWireEmu

# create_gsmtap_header from https://github.com/fgsect/scat/blob/master/src/scat/util.py
# Struct definitions can be found in libosmocore's include/osmocom/core/gsmtap.h

@unique
class gsmtap_type(IntEnum):
    UM = 0x01
    ABIS = 0x02
    UM_BURST = 0x03
    SIM = 0x04
    GB_LLC = 0x08
    GB_SNDCP = 0x09
    UMTS_RRC = 0x0C
    LTE_RRC = 0x0D
    LTE_MAC = 0x0E
    LTE_MAC_FRAMED = 0x0F
    OSMOCORE_LOG = 0x10
    QC_DIAG = 0x11
    LTE_NAS = 0x12


@unique
class gsmtap_channel(IntEnum):
    UNKNOWN = 0x00
    BCCH = 0x01
    CCCH = 0x02
    RACH = 0x03
    AGCH = 0x04
    PCH = 0x05
    SDCCH = 0x06
    SDCCH4 = 0x07
    SDCCH8 = 0x08
    TCH_F = 0x09
    TCH_H = 0x0A
    PACCH = 0x0B
    CBCH52 = 0x0C
    PDCH = 0x0D
    PTCCH = 0x0E
    CBCH51 = 0x0F


@unique
class gsmtap_umts_rrc_types(IntEnum):
    DL_DCCH = 0
    UL_DCCH = 1
    DL_CCCH = 2
    UL_CCCH = 3
    PCCH = 4
    DL_SHCCH = 5
    UL_SHCCH = 6
    BCCH_FACH = 7
    BCCH_BCH = 8
    MCCH = 9
    MSCH = 10
    HandoverToUTRANCommand = 11
    InterRATHandoverInfo = 12
    SystemInformation_BCH = 13
    System_Information_Container = 14
    UE_RadioAccessCapabilityInfo = 15
    MasterInformationBlock = 16
    SysInfoType1 = 17
    SysInfoType2 = 18
    SysInfoType3 = 19
    SysInfoType4 = 20
    SysInfoType5 = 21
    SysInfoType5bis = 22
    SysInfoType6 = 23
    SysInfoType7 = 24
    SysInfoType8 = 25
    SysInfoType9 = 26
    SysInfoType10 = 27
    SysInfoType11 = 28
    SysInfoType11bis = 29
    SysInfoType12 = 30
    SysInfoType13 = 31
    SysInfoType13_1 = 32
    SysInfoType13_2 = 33
    SysInfoType13_3 = 34
    SysInfoType13_4 = 35
    SysInfoType14 = 36
    SysInfoType15 = 37
    SysInfoType15bis = 38
    SysInfoType15_1 = 39
    SysInfoType15_1bis = 40
    SysInfoType15_2 = 41
    SysInfoType15_2bis = 42
    SysInfoType15_2ter = 43
    SysInfoType15_3 = 44
    SysInfoType15_3bis = 45
    SysInfoType15_4 = 46
    SysInfoType15_5 = 47
    SysInfoType15_6 = 48
    SysInfoType15_7 = 49
    SysInfoType15_8 = 50
    SysInfoType16 = 51
    SysInfoType17 = 52
    SysInfoType18 = 53
    SysInfoType19 = 54
    SysInfoType20 = 55
    SysInfoType21 = 56
    SysInfoType22 = 57
    SysInfoTypeSB1 = 58
    SysInfoTypeSB2 = 59
    ToTargetRNC_Container = 60
    TargetRNC_ToSourceRNC_Container = 61


@unique
class gsmtap_lte_rrc_types(IntEnum):
    DL_CCCH = 0
    DL_DCCH = 1
    UL_CCCH = 2
    UL_DCCH = 3
    BCCH_BCH = 4
    BCCH_DL_SCH = 5
    PCCH = 6
    MCCH = 7
    BCCH_BCH_MBMS = 8
    BCCH_DL_SCH_BR = 9
    BCCH_DL_SCH_MBMS = 10
    SC_MCCH = 11
    SBCCH_SL_BCH = 12
    SBCCH_SL_BCH_V2X = 13
    DL_CCCH_NB = 14
    DL_DCCH_NB = 15
    UL_CCCH_NB = 16
    UL_DCCH_NB = 17
    BCCH_BCH_NB = 18
    BCCH_BCH_TDD_NB = 19
    BCCH_DL_SCH_NB = 20
    PCCH_NB = 21
    SC_MCCH_NB = 22


def create_gsmtap_header(
    version=2,
    payload_type=0,
    timeslot=0,
    arfcn=0,
    signal_dbm=0,
    snr_db=0,
    frame_number=0,
    sub_type=0,
    antenna_nr=0,
    sub_slot=0,
    device_sec=0,
    device_usec=0,
):
    """
    Create a GSMTAP header for the given parameters. To be used with send_gsmtap_packet.
    The two relevant options are payload_type and sub_type, all other parameters can usually be left at their default values.
    
    Args:
        version (int): GSMTAP version, either 2 or 3. Default is 2.
        payload_type (gsmtap_type): The payload type, see gsmtap_type enum. Default is 0.
        timeslot (int): GSM timeslot, default is 0.
        arfcn (int): ARFCN, default is 0.
        signal_dbm (int): Signal strength in dBm, default is 0.
        snr_db (int): Signal to noise ratio, default is 0 (unknown).
        frame_number (int): GSM frame number, default is 0.
        sub_type (int): Subtype, meaning depends on payload_type, see, e.g., gsmtap_lte_rrc_types enum. Default is 0.
        antenna_nr (int): Antenna number, default is 0.
        sub_slot (int): Subslot, default is 0.
        device_sec (int): Seconds part of the timestamp, only for version 3, default is 0.
        device_usec (int): Microseconds part of the timestamp, only for version 3, default is 0.
    """

    gsmtap_v2_hdr_def = "!BBBBHBBLBBBB"
    gsmtap_v3_hdr_def = "!BBBBHBBLBBBBQL"
    gsmtap_hdr = b""

    # Sanity check - Wireshark GSMTAP dissector accepts only 14 bits of ARFCN
    # Only allow in GSM for implicitly marking uplink
    if not (
        payload_type == gsmtap_type.UM
        or payload_type == gsmtap_type.UM_BURST
        or payload_type == gsmtap_type.ABIS
        or payload_type == gsmtap_type.GB_LLC
        or payload_type == gsmtap_type.GB_SNDCP
    ):
        if arfcn < 0 or arfcn > (2**14 - 1):
            arfcn = 0

    if version == 2:
        gsmtap_hdr = struct.pack(
            gsmtap_v2_hdr_def,
            2,  # Version
            4,  # Header Length
            payload_type,  # Type
            timeslot,  # GSM Timeslot
            arfcn,  # ARFCN
            signal_dbm,  # Signal dBm
            snr_db,  # SNR dB
            frame_number,  # Frame Number
            sub_type,  # Subtype
            antenna_nr,  # Antenna Number
            sub_slot,  # Subslot
            0,  # Reserved
        )
    elif version == 3:
        gsmtap_hdr = struct.pack(
            gsmtap_v3_hdr_def,
            3,  # Version
            7,  # Header Length
            payload_type,  # Type
            timeslot,  # GSM Timeslot
            arfcn,  # ARFCN
            signal_dbm,  # Signal dBm
            snr_db,  # SNR dB
            frame_number,  # Frame Number
            sub_type,  # Subtype
            antenna_nr,  # Antenna Number
            sub_slot,  # Subslot
            0,  # Reserved
            device_sec,
            device_usec,
        )
    else:
        assert (version == 2) or (
            version == 3
        ), "GSMTAP version should be either 2 or 3"

    return gsmtap_hdr


def send_gsmtap_packet(emu: FirmWireEmu, gsmtap_hdr: bytes, payload: bytes):
    """
    Send a GSMTAP packet to the configured IP address in the emulator.
    If no IP address is configured, the packet is not sent.

    Args:
        emu (FirmWireEmu): The FirmWire emulator instance.
        gsmtap_hdr (bytes): GSMTAP header, can be initialized via create_gsmtap_header
        payload (bytes): The raw payload to send, e.g., a RRC message.
    """
    ip = emu.get_gsmtap_ip()
    if ip is not None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(gsmtap_hdr + payload, (ip, 4729))
