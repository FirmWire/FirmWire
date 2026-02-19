## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging
import time

import firmwire.vendor.shannon.pattern_handlers as handlers

log = logging.getLogger(__name__)

PATTERNS_COMMON = {
    "BXLR": {
        "pattern": "70 47",
        "required": True,
        "align": 2
    },
}

PATTERNS_CORTEX_R = {
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
    # S337AP for Moto One does a memclr of the SHM area on boot.
    # As SHM is implemented via remote memory, this is slow - this quirck is a workaround
    "QUIRK_S337AP_SHM_HACK": {
        "pattern": [
            "4ff09041 095889b1 6c4900f1 90424ff4 800306 a80097cd e906164f f09041?? ??????67 496748?? ??????03 e0"
        ],
        "offset_end": -6,
        "soc_match": ["S337AP"],
        # Thumb alignment
        "align": 2,
        "required": False,
    },
    # S337AP for A51 has a boot key, but S337AP for Moto does not, thus this workaround
    # The better solution would probably to split this into two socs and handle the difference in the loader
    "quirk_boot_key_check_a51": {
        "pattern": [
            "?? 49 00 22 ?? 48 ?? a3 ?? ?? ?? ?? 80 21 68 46 ?? ?? ?? ?? 10 22 20 a9 68 46 ?? ?? ?? ??"
        ],
        "offset_end": 0x0,
        "soc_match": ["S337AP"],
        "required": False,
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

PATTERNS_CORTEX_A = {
    "main_mmu_table": {
        "pattern": [
            "01000000 00000000 00000000 0c940100 01000000 00001000", # S5123
            "00000000 00000000 00001000 0c940100 00000040 00000040", # S5123AP
        ],
        "required": True,
    },
    "boot_key_check": {
        "pattern": [
            "0880 ???????? e2a0 ???????? 06f0???? 05f0???? 3aac 8021 2046 ???????? 1aa9 2046 1022", # S5123AP
        ],
        "offset_end": 0x0,
        "soc_match": ["S5123AP"],
        "required": True,
    },
    "set_task_affinity": {
        # Search for == Task(%d) ==
        "pattern": [
            "2de9f047 86b0 ???????? 0446 9846 9146 0e46 0021 0122 0827 c4f2???? 04f10803 2546 daf80000 0590 3c20 07c3 c4e90517 e161 ???????? 2820 3c22 c4f2???? 0023 45f8041f", # S5123AP
            "2de9f043 85b0 0546 9846 9146 0e46 3c20 0021 0122 0827 05f10803 2c46 07c3 c5e90517 e961 ???????? 2820 3c22 c4f2???? 0023 44f8041f",  # oriole
        ],
        "required": True,
    },
    "log_printf": {
        "pattern": [
            "83b0 2de9f0?? ??b0 0df14c0c 0024",  # oriole-sq3a.220705.004
            "83b0 2de9f0?? ??b0 4af29018 0df14c0c 0024",  # G981BXXSKHXEA
            "83b0 2de9f04f ??b0 ???????? 0df14c0c 0024", # S5123AP
        ],
        "required": True,
    },
    "OS_fatal_error": {
        "pattern": [
            "f0b5 81b0 0446 fff7ecea 0546 fff7eaea 49f28036 c4f23046 7179 8842",  # G981BXXSKHXEA
            "f0b5 81b0 0446 00f0???? 0546 00f0???? ???????? c4f2???? 7179 8842", # S5123AP
            "f0b5 81b0 0446 fff7???? 0546 fff7???? ???????? c4f6???? 7179 8842",  # oriole
        ],
    },
    "disableIRQinterrupts": {
        "pattern": "00 00 0f e1 80 00 00 e2 80 00 0c f1 1e ff 2f e1",
        "align": 4,
    },
    "enableIRQinterrupts": {
        "pattern": "80 00 10 e3 ?? 00 00 1a 80 00 08 f1 1e ff 2f e1",
        "align": 4,
    },
    "disableIRQinterrupts_trap": {
        "pattern": "00 00 0f e1 80 00 10 e2 ?+ 80 00 0c f1",
        "align": 4,
    },
    "enableIRQinterrupts_trap": {
        "pattern": "80 00 10 e3 ?? 00 00 1a ?+ 80 00 08 f1 1e ff 2f e1",
        "align": 4,
    },
    "pal_MemAlloc": {
        "pattern": [
            "2de9f04f 85b0 9a46 9146 0c46 8046 29b1 14f00305 18bf c5f10405 11e0",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "2de9f04f 85b0 0c46 9a46 9146 8046 2cb1 14f00305 18bf c5f10405 11e0",  # G981BXXSKHXEA
            "2de9f04f 85b0 ???????? 8046 0c46 9a46 9146 c4f2???? 002c 2868 0490 05d0 14f00307 18bf c7f10407 11e0", # S5123AP
        ],
    },
    "pal_MemFree": {
        "pattern": [
            "2de9f04f 87b0 1546 0491 0646 43f2d6c7 8346 3df246c6 43f2c059 c4f20d59 99f80510 8842",  # G981BXXSKHXEA
            "2de9f04f 89b0 ???????? cde90421 0746 c4f2???? daf80000 0890 ???????? 0646 ???????? ???????? c4f2???? 9bf80510 8842", # S5123AP
            "2de9f04f 87b0 cde90312 8146 ???????? 8246 ???????? ???????? c4f6???? 6979 8842",  # oriole
        ],
    },
    "pal_Sleep": {
        "lookup": handlers.find_pal_sleep,
    },
    "pal_MsgReceiveMbx": {
        "pattern": [
            "10b5 82b0 8c46 0021 1446 002a ccf80010 00d0 2170",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "10b5 82b0 8c46 0021 1446 002c ccf80010 00d0 2170",  # G981BXXSKHXEA
            "70b5 82b0 ???????? 1446 0a46 c4f2???? 3168 0191 0021 002c 1160 00d0 2170",  # S5123AP
            "f0b5 81b0 0e46 0021 1d46 1446 002a 3160 00d0 2170",  # oriole-bp2a.250605.031.a5
        ],
        "soc_match": ["S5123", "S5123AP"],
        "required": True,
    },
    "pal_MsgSendTo": {
        "pattern": [
            "2de9f041 1546 0c46 0646 b0f57a7f ?+ 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # oriole-sq3a.220705.004, oriole-ap2a.240905.003.f1
            "f0b5 81b0 0646 1546 0c46 b6f57a7f ?+ 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # G981BXXSKHXEA
            "2de9???? ??b0 0646 ??46 ??46 b6f57a7f ??db ?+ 2de90f00 bff35f8f 01df bff35f8f bde80f00",  # S5123AP
        ]
    },
    "pal_SmSetEvent": {
        "pattern": [
            "10b5 0068 80b1 57f6c6d1 0446 4ff6ff70 0442 0ad0 45f6b801 20b2",  # G981BXXSKHXEA
            "10b5 0068 80b1 ???????? 0446 4ff6ff70 0442 0ad0 ???????? 20b2",  # S5123AP
            "10b5 0068 80b1 ???????? 0446 4ff6ff70 0442 0ad0 ???????? 20b2",  # oriole
        ],
    },
    "SYM_LTERRC_INT_MOB_CMD_HO_FROM_IRAT_MSG_ID": {
        "lookup": lambda data, offset: 0xc3a5,
    },
    "SYM_QUEUE_LIST": {"lookup": handlers.find_queue_table},             # G991B, oriole
    "SYM_CUR_TASK_PTR": {"lookup": handlers.find_current_task_ptr_a},    # G991B, oriole
    "SYM_TASK_LIST": {                                                   # G991B, oriole
        "lookup": handlers.find_task_table,
        "post_lookup": handlers.fixup_set_task_layout,
    },
    "DSP_SYNC_WORD_0": {
        "pattern": [
            "80b5 82b0 0368 ???????? 4ff48f70 ???????? ???????? cde90010 ??a0 c121 ???????? 02b0 80bd",
            "80b5 82b0 0368 ???????? 4ff49570 4ff4de72 c4f28801 cde90010 03a0 c121 ???????? 02b0 80bd", # S5123AP
        ],
        "offset": 28,
        "post_lookup": handlers.s5123_get_dsp_sync0,
        "required": False,
        "soc_match": ["S5123", "S5123AP"],
    },
    "DSP_SYNC_WORD_1": {
        "pattern": [
            "80b5 82b0 0368 ???????? 4ff48f70 ???????? ???????? cde90010 ??a0 c121 ???????? 02b0 80bd",
            "80b5 82b0 0368 ???????? 4ff49570 4ff4de72 c4f28801 cde90010 03a0 c121 ???????? 02b0 80bd", # S5123AP
        ],
        "offset": 14,
        "post_lookup": handlers.s5123_get_dsp_sync1,
        "required": False,
        "soc_match": ["S5123", "S5123AP"],
    },
    "rf_hwid": {
        "lookup": handlers.find_rf_hwid,
        "soc_match": ["S5123"],
    },
    "board_rf_config": {
        "lookup": handlers.find_board_rf_config,
        "soc_match": ["S5123"],
    },
    "trng_init": {
        "lookup": handlers.find_trng_init,
        "soc_match": ["S5123"],
    },
    "main_task_counter": {
        "lookup": handlers.find_counter,
        "soc_match": ["S5123", "S5123AP"],
    },
}