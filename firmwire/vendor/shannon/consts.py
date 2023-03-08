## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from enum import IntEnum


class LteRrcOps(IntEnum):
    """extracted with the following gidhra script for g973 (requires right symbol name):
    state = getState()
    current_program = state.getCurrentProgram()
    arr = current_program.symbolTable.getLabelOrFunctionSymbols("LTERRC_MSG_HANDLER_ARRAY_4173ba08", None)[0].object

    for i in range(arr.numComponents):
        lte_rrc_msg_entr = arr.getComponent(i)
        str_off = lte_rrc_msg_entr.getComponent(4)
        name = getDataAt(str_off.value)
        if name is None:
            break
        print('{:s} = {:s}'.format(name.value, lte_rrc_msg_entr.getComponent(0).value))
    """

    LTE_CPHY_FREQ_SCAN_CNF = 0x0
    LTE_CPHY_CELL_SEL_CNF = 0x1
    LTE_CPHY_TX_CONFIG_CNF = 0x2
    LTE_CPHY_RX_CONFIG_CNF = 0x3
    LTE_CPHY_TX_SYNC_CONFIG_CNF = 0x4
    LTE_CPHY_DRX_CONFIG_CNF = 0x5
    LTE_CPHY_ACQ_IND = 0x6
    LTE_CPHY_CELL_RESEL_EVAL_IND = 0x7
    LTE_CPHY_CELL_RESEL_CNF = 0x8
    LTE_CPHY_SERV_CELL_SWITCH_CNF = 0x9
    LTE_CPHY_MEAS_CONF_CNF = 0xA
    LTE_CPHY_MEAS_RESULTS = 0xB
    LTE_CPHY_MEAS_CGI_CONF_RES = 0xC
    LTE_CPHY_IN_SYNC_IND = 0xD
    LTE_CPHY_OUT_OF_SYNC_IND = 0xE
    LTE_CPHY_MOB_CMD_TO_IRAT_START_RSP = 0xF
    LTE_CPHY_SUSPEND_CNF = 0x10
    LTE_CPHY_RESUME_CNF = 0x11
    LTE_CPHY_MODEM_STOP_CNF = 0x12
    LTE_CPHY_MODEM_START_CNF = 0x13
    LTE_CPHY_MIB_INFO_IND = 0x14
    LTE_CPHY_RLF_INFO_IND = 0x17
    LTE_CPHY_MCCH_CHANGE_NTF_IND = 0x18
    LTE_CPHY_MBSFN_SIG_STRENGTH_RSP = 0x19
    LTE_CPHY_SCELL_MBSFN_GRANT_RSP = 0x1A
    LTE_CPHY_RRM_CONFIG_CNF = 0x20
    LTE_CPHY_SL_OOC_START_CNF = 0x21
    LTE_CPHY_SL_UE_THRESH_COND_IND = 0x22
    LTE_CPHY_SL_RELAY_CFG_CNF = 0x23
    LTE_CPHY_SL_RELAY_SELECT_CNF = 0x24
    LTE_CPHY_SL_RELAY_RESELECT_IND = 0x25
    LTE_CPHY_SL_RELAY_LOST_IND = 0x26
    LTE_CMAC_RACH_STATUS_IND = 0x28
    LTE_CMAC_RACH_START_CNF = 0x29
    LTE_CMAC_UL_CONFIG_CNF = 0x2A
    LTE_CMAC_DL_CONFIG_CNF = 0x2B
    LTE_CMAC_PUCCH_SRS_RELEASE_IND = 0x2C
    LTE_CMAC_SRS_RELEASE_IND = 0x2D
    LTE_CMAC_UL_RESET_CNF = 0x2E
    LTE_CMAC_DL_RESET_CNF = 0x2F
    LTE_CMAC_MCCH_BOUNDARY_IND = 0x30
    LTE_CMAC_SL_CONFIG_CNF = 0x32
    LTE_CRLC_UL_CONFIG_CNF = 0x34
    LTE_CRLC_DL_CONFIG_CNF = 0x35
    LTE_CRLC_MAX_RETX_IND = 0x36
    LTE_CPDCP_UL_CONFIG_CNF = 0x37
    LTE_CPDCP_DL_CONFIG_CNF = 0x38
    LTE_PDCP_DATA_IND = 0x39
    LTE_PDCP_DATA_CNF = 0x3A
    LTE_PDCP_COUNT_VALUE_RSP = 0x3B
    LTE_CPDCP_UL_SECURITY_CONFIG_CNF = 0x3C
    LTE_CPDCP_DL_SECURITY_CONFIG_CNF = 0x3D
    LTE_CPDCP_INTEGRITY_CHECK_CNF = 0x40
    LTE_PDCP_INTEGRITY_CHECK_FAILED_IND = 0x41
    LTE_PDCP_SECURITY_DATA_IND = 0x42
    LTE_CPDCP_UL_RELEASE_ALL_CNF = 0x43
    LTE_CPDCP_DL_RELEASE_ALL_CNF = 0x44
    LTE_PDCP_DORMANT_IND = 0x49
    LTE_CPDCP_UL_SLCONFIG_CNF = 0x47
    LTE_CPDCP_DL_SLCONFIG_CNF = 0x48
    LTE_RRC_INIT_REQ = 0x4A
    LTE_RRC_EST_REQ = 0x4B
    LTE_RRC_DATA_REQ = 0x4C
    LTE_RRC_PLMN_SEARCH_REQ = 0x4D
    LTE_RRC_PLMN_LIST_REQ = 0x4E
    LTE_RRC_UPDATE_FTAI_LIST_REQ = 0x4F
    LTE_RRC_TERMINATE_REQ = 0x50
    LTE_RRC_UPDATE_UE_ID_REQ = 0x51
    LTE_RRC_UPDATE_EQUIV_PLMN_LIST_REQ = 0x52
    LTE_RRC_UPDATE_BAND_SUPPORT_REQ = 0x53
    LTE_RRC_UPDATE_UECAPA_MCC_BAND_REQ = 0x54
    LTE_RRC_PLMN_SEARCH_ABORT_REQ = 0x55
    LTE_RRC_PLMN_LIST_ABORT_REQ = 0x56
    LTE_RRC_SERVICE_ABORT_REQ = 0x57
    LTE_RRC_REL_REQ = 0x58
    LTE_RRC_UPDATE_SECURITY_CONTEXT_REQ = 0x59
    LTE_RRC_UPDATE_CURR_MODE_REQ = 0x5A
    LTE_RRC_RESUME_RAT_REQ = 0x5B
    LTE_RRC_SUSPEND_RAT_REQ = 0x5C
    LTE_RRC_POWER_DOWN_DRX_REQ = 0x5D
    LTE_CPHY_WAKEUP_IND = 0x61
    LTE_RRC_CMAS_CONFIG_UPDATE_REQ = 0x5E
    LTE_RRC_UPDATE_EMC_CALL_STATUS_IND = 0x60
    LTE_RRC_TIME_AIDING_REQ = 0xB5
    LPP_RRC_LOCATION_INFO_RESULT = 0xA9
    LTE_RRC_UPDATE_DISABLED_PLMN_REQ = 0xB3
    LTE_RRC_CALL_ABORT_NTF = 0x6E
    LTE_RRC_WIFI_STATE_SET_REQ = 0x9F
    LTERRC_NAS_SIGNALING_START_IND = 0xAF
    LTERRC_NAS_SIGNALING_END_IND = 0xB0
    LTERRC_UPDATE_MPLMN_STATUS_IND = 0xB2
    SRIF_LTERRC_START_REQ = 0xBC
    SRIF_LTERRC_RESUME_REQ = 0xBD
    SRIF_LTERRC_PAUSE_REQ = 0xBE
    SRIF_LTERRC_ABORT_REQ = 0xBF
    LTE_CPHY_PROC_PAUSE_IND = 0xB6
    LTE_CPHY_PROC_RELEASE_IND = 0xB8
    LTE_CPHY_OTHER_RAT_BPLMN_IND = 0xB9
    LTE_RRC_DDS_CHANGE_IND = 0xB4
    LTE_RRC_UPDATE_VOLTE_STATUS_IND = 0x5F
    LTE_RRC_RESEL_TO_GSM_RSP = 0x62
    LTE_RRC_REDIRECT_TO_GSM_RSP = 0x63
    LTE_RRC_RESEL_TO_UMTS_RSP = 0x64
    LTE_RRC_REDIRECT_TO_UMTS_RSP = 0x65
    LTE_RRC_REDIRECT_FROM_UMTS_REQ = 0x66
    LTE_RRC_REDIRECT_FROM_GSM_REQ = 0x67
    LTE_RRC_RESEL_FROM_UMTS_REQ = 0x68
    LTE_RRC_RESEL_FROM_GSM_REQ = 0x69
    LTEMM_RRC_UTRAN_CGI_INFO_IND = 0x8E
    LTEMM_RRC_GERAN_CGI_INFO_IND = 0x8F
    LTEMM_RRC_CDMA1X_CGI_INFO_IND = 0x90
    LTEMM_RRC_HRPD_CGI_INFO_IND = 0x91
    LTEMM_RRC_UTRAN_CGI_STOP_IND = 0x92
    LTEMM_RRC_GERAN_CGI_STOP_IND = 0x93
    LTEMM_RRC_CDMA1X_CGI_STOP_IND = 0x94
    LTEMM_RRC_HRPD_CGI_STOP_IND = 0x95
    LTEMM_RRC_UTRAN_CGI_HOLD_IND = 0x96
    LTEMM_RRC_GERAN_CGI_HOLD_IND = 0x97
    LTEMM_RRC_CDMA1X_CGI_HOLD_IND = 0x98
    LTEMM_RRC_HRPD_CGI_HOLD_IND = 0x99
    LTE_CPHY_UTRAN_STOP_CGI_RSP = 0x9A
    LTE_CPHY_GERAN_STOP_CGI_RSP = 0x9B
    LTE_CPHY_CDMA1X_STOP_CGI_RSP = 0x9C
    LTE_CPHY_HRPD_STOP_CGI_RSP = 0x9D
    LTE_RRC_UTRAN_START_CGI_RSP = 0x6A
    LTE_RRC_GERAN_START_CGI_RSP = 0x6B
    LTE_RRC_REDIRECT_FROM_UMTS_ABORT = 0x6C
    LTE_RRC_INITIAL_PLMN_ID_REQ = 0x6F
    LTE_RRC_REDIRECT_FROM_EHRPD_REQ = 0x70
    LTE_RRC_REDIRECT_FROM_1XRTT_REQ = 0x71
    LTE_RRC_RESEL_FROM_EHRPD_REQ = 0x72
    LTE_RRC_RESEL_FROM_1XRTT_REQ = 0x73
    LTE_RRC_RESEL_TO_EHRPD_RSP = 0x74
    LTE_RRC_RESEL_TO_1XRTT_RSP = 0x75
    LTE_RRC_REDIRECT_TO_EHRPD_RSP = 0x76
    LTE_RRC_REDIRECT_TO_1XRTT_RSP = 0x77
    LTE_RRC_EHRPD_START_CGI_RSP = 0x78
    LTE_RRC_1XRTT_START_CGI_RSP = 0x79
    LTE_RRC_MOB_CMD_FROM_IRAT_REQ = 0x7A
    LTE_RRC_MOB_CMD_TO_IRAT_RSP = 0x7C
    LTE_RRC_MOB_CMD_TO_IRAT_ABORT_RSP = 0x7D
    LTE_RRC_UE_CAPA_FROM_IRAT_REQ = 0x7E
    LTE_RRC_UE_CAPA_TO_IRAT_CNF = 0x7F
    EMM_RRC_DEDICATE_PRIORITY_INFO_IND = 0x80
    LTE_RRC_CELL_SEARCH_CONFIG_REQ = 0x81
    LTE_RRC_FH_TEST_REQ = 0xAD
    LTE_RRC_WAKEUP_REQ = 0x6D
    LTE_RRC_UPDATE_CSG_LIST_REQ = 0x82
    LTE_RRC_CSG_SEARCH_REQ = 0x84
    LTE_RRC_CSG_LIST_REQ = 0x83
    LTE_RRC_ABORT_CSG_LIST_REQ = 0x85
    LTE_RRC_ABORT_CSG_SEARCH_REQ = 0x86
    LTE_CPHY_CSG_MEAS_CNF = 0x87
    LTE_CPHY_CSG_STOP_MEAS_CNF = 0x88
    LTE_CPHY_CSG_PROXIMITY_MEAS_CNF = 0x89
    LTE_CPHY_CSG_PROXIMITY_MEAS_RESULTS = 0x8A
    LTE_CPHY_STOP_CSG_PROXIMITY_MEAS_CNF = 0x8B
    EMM_LTERRC_CSG_VISITED_LIST_IND = 0x8C
    EMM_LTERRC_PERIODIC_CSG_SRCH_CNF = 0x8D
    LTE_CPHY_BACKGROUND_START_IND = 0x15
    LTE_CPHY_BACKGROUND_STOP_IND = 0x16
    LTE_CPHY_MOD_BOUNDARY_IND = 0x9E
    LTE_RRC_ACT_HPLMN_UPD_IND = 0xA0
    USAT_EUTRAN_NMR_REQ = 0xAE
    LTE_RRC_UPDATE_MODEM_STATUS_REQ = 0xA3
    LTE_CPHY_DRX_HOLD_START_CNF = 0x1B
    LTE_CPHY_DRX_HOLD_STOP_CNF = 0x1C
    MasterInformationBlock = 0xC351
    SystemInformation = 0xC352
    SystemInformationBlockType1 = 0xC353
    Paging = 0xC354
    RRCConnectionReestablishment = 0xC355
    RRCConnectionReestablishmentReject = 0xC356
    RRCConnectionReject = 0xC357
    RRCConnectionSetup = 0xC358
    CSFBParametersResponseCDMA2000 = 0xC359
    DLInformationTransfer = 0xC35A
    HandoverFromEUTRAPreparationRequest = 0xC35B
    MobilityFromEUTRACommand = 0xC35C
    RRCConnectionReconfiguration = 0xC35D
    RRCConnectionReconfiguration_handover = 0xC35E
    RRCConnectionReconfiguration_InterRatHandover = 0xC35F
    RRCConnectionRelease = 0xC360
    SecurityModeCommand = 0xC361
    UECapabilityEnquiry = 0xC362
    CounterCheck = 0xC363
    MBSFNAreaConfiguration = 0xC366
    LTE_RRC_MODEC_ACT_IND = 0x33
    MBMSCountingRequest = 0xC367
    LTERRC_MBSFN_MESSAGE = 0xA2
    LTERRC_INT_TRANSITION_TO_INIT = 0xC368
    LTERRC_INT_TRANSITION_TO_IDLE = 0xC369
    LTERRC_INT_TRANSITION_TO_SUSP = 0xC36A
    LTERRC_INT_PROC_RECONFIG_COMPLETE = 0xC36B
    LTERRC_INT_LOWLAYER_ALL_CONFIG_CNF = 0xC36C
    LTERRC_INT_RECONFIG_READY = 0xC36D
    LTERRC_INT_REESTABLISHMENT_REQUEST = 0xC36E
    LTERRC_INT_REESTABLISHMENT_FAILURE = 0xC36F
    LTERRC_INT_START_ACCESS_REQ = 0xC370
    LTERRC_INT_CELL_SELECT_CNF_FOR_REEST = 0xC371
    LTERRC_INT_NEED_TO_UPDATE_CONFIG_COMMON = 0xC372
    LTERRC_INT_MOB_CMD_HO_FROM_IRAT = 0xC3A3
    LTERRC_INT_T300_EXPIRY = 0xC373
    LTERRC_INT_T301_EXPIRY = 0xC374
    LTERRC_INT_T302_EXPIRY = 0xC375
    LTERRC_INT_T303_EXPIRY = 0xC376
    LTERRC_INT_T304_IRAT_EXPIRY = 0xC378
    LTERRC_INT_T304_EXPIRY = 0xC377
    LTERRC_INT_T305_EXPIRY = 0xC379
    LTERRC_INT_T310_EXPIRY = 0xC37B
    LTERRC_INT_T311_EXPIRY = 0xC37C
    LTERRC_INT_T312_EXPIRY = 0xC37D
    LTERRC_INT_T320_EXPIRY = 0xC37F
    LTERRC_INT_T321_EXPIRY = 0xC380
    LTERRC_INT_T_RB_SUSPEND_EXPIRY = 0xC383
    LTERRC_INT_T_WAIT_SIB1_EXPIRY = 0xC384
    LTERRC_INT_T_WAIT_SI_EXPIRY = 0xC386
    LTERRC_INT_T_WAIT_SIB2_EXPIRY = 0xC385
    LTERRC_INT_T_WAIT_ETWS_EXPIRY = 0xC387
    LTERRC_INT_T_WAIT_CMAS1_EXPIRY = 0xC388
    LTERRC_INT_T_WAIT_CMAS2_EXPIRY = 0xC389
    LTERRC_INT_T_WAIT_CMAS3_EXPIRY = 0xC38A
    LTERRC_INT_T_WAIT_CMAS4_EXPIRY = 0xC38B
    LTERRC_INT_T_WAIT_CMAS5_EXPIRY = 0xC38C
    LTERRC_INT_T_WAIT_CMAS6_EXPIRY = 0xC38D
    LTERRC_INT_T_REL_DELAY_EXPIRY = 0xC398
    LTERRC_INT_T_SIB_VALIDITY_EXPIRY = 0xC399
    LTERRC_INT_T_CSG_PCI_LIST_VALIDITY_EXPIRY = 0xC39A
    LTERRC_INT_T_BLIND_SCAN_LIMIT_EXPIRY = 0xC39B
    LTERRC_INT_T_UMTS_WAIT_TIME_EXPIRY = 0xC39C
    LTERRC_INT_T_GSM_WAIT_TIME_EXPIRY = 0xC39D
    LTERRC_T_CELL_SEARCH_GUARD_TIME_EXPIRY = 0xC39E
    LTERRC_INT_T_HO_CFG_WAIT_EXPIRY = 0xC39F
    LTERRC_INT_T_WAIT_TO_IRAT_RSP_EXPIRY = 0xC3A1
    LTERRC_INT_T_WAIT_TO_IRAT_ABORT_RSP_EXPIRY = 0xC3A2
    LTERRC_LOCAL_RELEASE_TIMER_EXPIRY = 0xC3B0
    LTERRC_INT_T_EUTRA_VISITED_CSG_EXPIRY = 0xC3A7
    LTERRC_INT_T_UTRA_VISITED_CSG_EXPIRY = 0xC3A8
    LTERRC_INT_T_CSG_RESERVED_RANGE_LIST_EXPIRY = 0xC3A9
    LTERRC_INT_START_AUTO_CSG_MEAS = 0xC3AA
    LTERRC_INT_T_START_AUTO_CSG_SCAN_EXPIRY = 0xC3AB
    LTERRC_INT_T_LOCINFO_VALID_EXPIRY = 0xC3AD
    LTERRC_INT_T_UEINFO_RLF_AVAIL_EXPIRY = 0xC3AE
    LTERRC_INT_T_UEINFO_EFR_AVAIL_EXPIRY = 0xC3AF
    LTERRC_DSDS_SIGNALLING_TIMER_EXPIRY = 0xC3B1
    LTERRC_MPLMN_GLOBAL_GUARD_EXPIRTY = 0xC3B2
    LPP_RRC_ECID_REQ = 0xA4
    LPP_RRC_OTDOA_REQ = 0xA5
    LPP_RRC_ECID_ABORT = 0xA6
    LPP_RRC_OTDOA_ABORT = 0xA7
    LPP_RRC_OTDOA_RESULT_REQ = 0xA8
    LTE_CPHY_ECID_MEAS_RESULT = 0x1D
    LTE_CPHY_OTDOA_MEAS_RESULT = 0x1E
    LTE_CPHY_RSTD_INTER_FREQ_MEAS_REQ = 0x1F
    LoggedMeasurementConfiguration = 0xC365
    LTE_RRM_LOGGED_MEAS_IND = 0xAB
    UEInformationRequest = 0xC364


class LteRRCPkgs:
    """
    just some packages (in order) for rrc connection establishment
    """

    # MIB1 (SFN=13)
    mib1 = (
        b"\x0a\x02\x02\x02\x02\x02\x0a\x01\x01\x01\x01\x01\x08\x00\x45\x00"
        b"\x00\x2f\x12\x34\x00\x00\xff\x11\xab\x87\x7f\x00\x00\x01\x7f\x00"
        b"\x00\x01\x05\x39\x12\x79\x00\x1b\x5e\x93\x02\x04\x0d\x00\x18\x38"
        b"\x00\x00\x00\x00\x00\x00\x04\x00\x00\x00\x60\x34\x00"
    )

    # SIB Type 1
    sib1 = (
        b"\x0a\x02\x02\x02\x02\x02\x0a\x01\x01\x01\x01\x01\x08\x00\x45\x00"
        b"\x00\x42\x12\x34\x00\x00\xff\x11\xab\x74\x7f\x00\x00\x01\x7f\x00"
        b"\x00\x01\x05\x39\x12\x79\x00\x2e\xe2\x0e\x02\x04\x0d\x00\x18\x38"
        b"\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x60\x49\x88\x07\x55\xfc"
        b"\x04\xf1\x00\x28\x23\x54\xc8\x40\x82\x02\x11\x10\x8c\x84\x8d\x00"
    )

    # SIB Type 2
    sib2 = (
        b"\x0a\x02\x02\x02\x02\x02\x0a\x01\x01\x01\x01\x01\x08\x00\x45\x00"
        b"\x00\x4c\x12\x34\x00\x00\xff\x11\xab\x6a\x7f\x00\x00\x01\x7f\x00"
        b"\x00\x01\x05\x39\x12\x79\x00\x38\xdc\x1f\x02\x04\x0d\x00\x18\x38"
        b"\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x00\x59\x3b\x1f\x7f"
        b"\xe4\xa0\xb1\x47\x08\x9a\x80\xd8\x05\x0c\x03\xf0\x6b\xed\x15\x40"
        b"\x64\x03\x00\x6f\x66\x35\xe8\x86\x0c\x00"
    )

    # PDN connectivity request (GSMTAP!, not RRC)
    pdn_conn_req = (
        b"\x0a\x02\x02\x02\x02\x02\x0a\x01\x01\x01\x01\x01\x08\x00\x45\x00"
        b"\x00\x31\x12\x34\x00\x00\xff\x11\xab\x85\x7f\x00\x00\x01\x7f\x00"
        b"\x00\x01\x05\x39\x12\x79\x00\x1d\x1a\xb0\x02\x04\x12\x00\x18\x38"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x01\xd0\x11\xd1"
    )

    # SIB 5
    sib5 = (
        b"\x0a\x02\x02\x02\x02\x02\x0a\x01\x01\x01\x01\x01\x08\x00\x45\x00"
        b"\x00\x3d\x12\x34\x00\x00\xff\x11\xab\x79\x7f\x00\x00\x01\x7f\x00"
        b"\x00\x01\x05\x39\x12\x79\x00\x29\x5b\xa8\x02\x04\x0d\x00\x18\x38"
        b"\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x0c\x4c\x06\x8b\x10"
        b"\x55\x29\xbc\x18\x06\x40\x20\xaa\x52\xb4\x00"
    )

    # SIB 6
    sib6 = (
        b"\x0a\x02\x02\x02\x02\x02\x0a\x01\x01\x01\x01\x01\x08\x00\x45\x00"
        b"\x00\x01\x05\x39\x12\x79\x00\x29\xc8\xa3\x02\x04\x0d\x00\x18\x38"
        b"\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x11\x45\xa6\x9d\x00"
        b"\x02\xca\x53\x51\x12\x00\x05\x94\xa4\xa0\x00"
    )

    # SIB 7
    sib7 = (
        b"\x0a\x02\x02\x02\x02\x02\x0a\x01\x01\x01\x01\x01\x08\x00\x45\x00"
        b"\x00\x4f\x12\x34\x00\x00\xff\x11\xab\x67\x7f\x00\x00\x01\x7f\x00"
        b"\x00\x01\x05\x39\x12\x79\x00\x3b\x1e\x38\x02\x04\x0d\x00\x18\x38"
        b"\x00\x00\x00\x00\x00\x00\x05\x00\x00\x00\x00\x15\xb5\x05\x3a\x27"
        b"\x4f\x54\x15\x2d\xe1\x79\xde\xfe\xc7\xb3\xed\x7b\xbf\x37\xd3\xf6"
        b"\x7d\xff\xa7\xef\xfc\xff\xdf\xfc\x3f\xc9\x00\x00\x00"
    )

    # RRC Connection Request
    rrc_conn_req = (
        b"\x0a\x02\x02\x02\x02\x02\x0a\x01\x01\x01\x01\x01\x08\x00\x45\x00"
        b"\x00\x32\x12\x34\x00\x00\xff\x11\xab\x84\x7f\x00\x00\x01\x7f\x00"
        b"\x00\x01\x05\x39\x12\x79\x00\x1e\x64\xca\x02\x04\x0d\x00\x18\x38"
        b"\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x51\x3e\xe9\x82\x21\x36"
    )

    # RRC Connection Setup
    rrc_cn_setup = (
        b"\x0a\x02\x02\x02\x02\x02\x0a\x01\x01\x01\x01\x01\x08\x00\x45\x00"
        b"\x00\x46\x12\x34\x00\x00\xff\x11\xab\x70\x7f\x00\x00\x01\x7f\x00"
        b"\x00\x01\x05\x39\x12\x79\x00\x32\x36\x41\x02\x04\x0d\x00\x18\x38"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x70\x12\x98\x13\xfd\x94"
        b"\x04\xba\x70\x69\x0a\xcb\x95\x50\x86\x1f\x87\x01\xc3\xb0\x01\x2d"
        b"\x7e\x87\x20\xd8"
    )

    # Attach Request, PDN connectivity request (GSMTAP, not RRC!)
    pdn_attach = (
        b"\x0a\x02\x02\x02\x02\x02\x0a\x01\x01\x01\x01\x01\x08\x00\x45\x00"
        b"\x00\x7c\x12\x34\x00\x00\xff\x11\xab\x3a\x7f\x00\x00\x01\x7f\x00"
        b"\x00\x01\x05\x39\x12\x79\x00\x68\x51\x55\x02\x04\x12\x00\x18\x38"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07\x41\x22\x0b\xf6\x62"
        b"\xf2\x24\x13\x37\x13\xef\xcc\xbb\xaa\x05\xf0\xf0\xc0\xc0\x1d\x00"
        b"\x05\x02\x01\xd0\x11\xd1\x52\x62\xf2\x30\x13\x37\x5c\x08\x02\x31"
        b"\x03\xf5\xe0\x3e\x13\x62\xf2\x30\x13\x37\x11\x03\x57\x58\xb2\x20"
        b"\x0a\x60\x14\x34\xe2\x91\x81\x00\x12\x3e\x80\x40\x08\x00\x02\x1f"
        b"\x00\x04\x02\x60\x04\x5d\x01\x03\xe0\xc1"
    )

    # RRC Connection Setup Complete, Attach Req, PDN connectivity Req
    rrc_conncomp = (
        b"\x0a\x02\x02\x02\x02\x02\x0a\x01\x01\x01\x01\x01\x08\x00\x45\x00"
        b"\x00\x89\x12\x34\x00\x00\xff\x11\xab\x2d\x7f\x00\x00\x01\x7f\x00"
        b"\x00\x01\x05\x39\x12\x79\x00\x75\x93\xd4\x02\x04\x0d\x00\x18\x38"
        b"\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x24\x30\x13\x37\x13\x56"
        b"\x17\xca\xfe\xca\xfe\x13\x07\x41\x22\x0b\xf6\x62\xf2\x24\x13\x37"
        b"\x13\xef\xcc\xbb\xaa\x05\xf0\xf0\xc0\xc0\x1d\x00\x05\x02\x01\xd0"
        b"\x11\xd1\x52\x62\xf2\x30\x13\x37\x5c\x08\x02\x31\x03\xf5\xe0\x3e"
        b"\x13\x62\xf2\x30\x13\x37\x11\x03\x57\x58\xb2\x20\x0a\x60\x14\x34"
        b"\xe2\x91\x81\x00\x12\x3e\x80\x40\x08\x00\x02\x1f\x00\x04\x02\x60"
        b"\x04\x5d\x01\x03\xe0\xc1\x60"
    )