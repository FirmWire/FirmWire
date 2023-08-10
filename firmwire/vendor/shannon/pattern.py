## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging
import time

import firmwire.vendor.shannon.pattern_handlers as handlers

log = logging.getLogger(__name__)

PATTERNS = {
    "boot_mpu_table": {
        "pattern": "00000000 00000000 1c000000"
        + "????????" * 6
        + "01000000 01000000 00000004 20",
        "required": True,
    },
    "boot_setup_memory": {
        "pattern": [
            "00008004 200c0000",
            "00000004 ????0100",  # S335
        ],
        "offset": -0x14,
        "align": 4,
        "post_lookup": handlers.parse_memory_table,
        "required": True,
    },
    "boot_key_check": {
        "pattern": [
            "?? 49 00 22 ?? 48 ?? a3 ?? ?? ?? ?? 80 21 68 46 ?? ?? ?? ?? 10 22 20 a9 68 46 ?? ?? ?? ??"
        ],
        "offset_end": 0x0,
        "soc_match": ["S5000AP"],
        "required": True,
    },
    "OS_fatal_error": {
        "pattern": "70 b5 05 46 ???????? ?? 48 ?? 24",
    },
    "pal_MemAlloc": {
        "pattern" : [
            "2d e9 f0 4f  0d 00  83 b0  99 46  92 46  80 46",
            "2d e9 ff 4f  4f f0  00 05  0e 00  83 b0  9a 46"
            ],
        "post_lookup": handlers.fixup_bios_symbol,
    },
    "pal_MemFree": {
        "pattern": "?? 4b 10 b5 9b 68 13 b1 bd e8 10 40 18 47",
    },
    "pal_MsgSendTo": {
        "pattern": [
            "70 b5 ?+ 04 46 15 46 0e 46 ?? ?? 01 df ?* 88 60 08 46 ?+ ?? 48 ???? ???? 20 46 98 47",  # G973F
            "???????? b0f5fa7f 0446 ??46",  # S337AP
        ]
    },
    "pal_Sleep": {
        "pattern": "30 b5 ?+ 98 ?+  ??98 ??22 ??23 11 46 ?? 94",
        # 30 b5 00 25 83 b0 04 46 2a 46 29 46 01 a8 d9 f6 2a e9 01 98 78 b1 29 46 d9 f6 90 e8 01 98 01 22 00 23 11 46 00 94 d9 f6 36 e9 01 98 d8 f6 5e ee 01 98 d9 f6 28 e9 5c f7 09 d8 00 28 02 d0 02 a8 ff f7 42 fe 03 b0 30 bd
        # 30 b5 04 46 85 b0 df 4b 40 f2 02 30 00 22 00 90 11 46 01 a8 0e f1 54 ee dd f8 04 c0 bc f1 00 0f 1c d0 00 25 01 21 03 ab 2a 46 0c f1 38 00 00 95 65 f4 1a f1 01 98 29 46 8b f1 a8 ed 01 98 01 22 00 23 11 46 00 94 5b f1 58 ed 01 98 8b f1 2e ec cd 49 40 f2 13 32 01 98 8b f1 a0 ed f0 f4 a1 f0 00 28 02 d0 02 a8 ff f7 1a fe 05 b0 30 bd
    },
    "log_printf": {
        "pattern": [
            "0fb4 2de9f047 ???? ??98 d0e90060 c0f34815",
            "0fb4 2de9f0?? ???? ??98 d0e900?? ??f3????",
            "0f b4 10 b5 03 a9 02 98 ff f7 9a ff 10 bc 5d f8 14 fb",
        ],
        "required": True,
    },
    # log_printf_debug
    "log_printf2": {
        "pattern": "0fb4 2de9f04f ???? ??0a 8fb01898 4068",
    },
    "pal_SmSetEvent": {
        "pattern": [
            "10b5 ???? ???????? 04 b2",  # thumb G973F, no NULL check
            "10b5 0068 0028 ???? ???????? 04 b2",  # thumb S337AP, NULL check
        ],
    },
    # OS_Delete_Event_Group is the function (based off string name). It is in the baseband (2017+) otherwise search for string
    # "LTE_RRC_EVENT_GRP_NAME" to find the creation function and explore from there.
    "SYM_EVENT_GROUP_LIST": {
        "pattern": [
            "70 40 2d e9 00 40 a0 e1 ?? ?? 00 eb 00 50 a0 e1 20 00 9f e5 04 10 a0 e1 ?? ?? 00 eb ?? 00 94 e5 00 00 50 e3 30 ff 2f 11 05 00 a0 e1 ?? ?? 00 eb 00 00 a0 e3 70 80 bd e8"
        ],
        "offset_end": 0x0,
        "post_lookup": handlers.dereference,
    },
    "SYM_TASK_LIST": {
        "lookup": handlers.find_task_table,
        "post_lookup": handlers.fixup_set_task_layout,
    },
    "SYM_SCHEDULABLE_TASK_LIST": {"lookup": handlers.find_schedulable_task_table},
    "SYM_CUR_TASK_ID": {"lookup": handlers.find_current_task_ptr},
    "SYM_FN_EXCEPTION_SWITCH": {"lookup": handlers.find_exception_switch},
    "SYM_QUEUE_LIST": {"lookup": handlers.find_queue_table},
    "QUIRK_SXXXAP_DVFS_HACK": {
        "pattern": [
            "??f8???? 00f01f01 ??48 d0 f8 ????  c0 f3 ????  ????????  ????  00 ?? ?* ??f1???? ??82 ??eb??11 0988",
            "????  00 ?? ?* ??f1???? ??82 ??eb??11 0988",  # S335AP alternate
        ],
        "offset_end": 0x0,
        "soc_match": ["S335AP", "S355AP", "S360AP"],
        # Thumb alignment
        "align": 2,
        "required": True,
    },
    # S337AP does a memclr of the SHM area on boot.
    # As SHM is implemented via remote memory, this is slow - this quirck is a workaround
    "QUIRK_S337AP_SHM_HACK": {
        "pattern": [
            "4ff09041 095889b1 6c4900f1 90424ff4 800306 a80097cd e906164f f09041?? ??????67 496748?? ??????03 e0"
        ],
        "offset_end": -6,
        "soc_match": ["S337AP"],
        # Thumb alignment
        "align": 2,
        "required": True,
    },
    "SYM_LTERRC_INT_MOB_CMD_HO_FROM_IRAT_MSG_ID": {
        "lookup": handlers.find_lterrc_int_mob_cmd_ho_from_irat_msgid
    },
    "DSP_SYNC_WORD_0": {
        "pattern": [
            "??21??68 4ff4??72 884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ?* ??b0bde8 f0 ??",
            "??21??68 ??22     884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ?* ??b0bde8 f0 ??", # G930F

        ],
        "post_lookup": handlers.get_dsp_sync0,
        "required": False,
    },
    "DSP_SYNC_WORD_1": {
        "pattern": [
            "4ff4??72 884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ?* ??b0bde8 f0 ??",
            "??????22 884202d1 ??689042 07d0 ??23??a0 cde90003 ??????a0 ?* ??b0bde8 f0 ??", # G930F
        ],
        "offset": 2,
        "offset_end": 3,
        "post_lookup": handlers.get_dsp_sync1,
        "required": False,
    },
}
