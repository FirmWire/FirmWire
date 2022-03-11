## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging

log = logging.getLogger(__name__)

PATTERNS = {
    # here we break out of a loop waiting for other cores
    "INC_Initialize_corewait": {
        "pattern": "409a 609b 62ea",
        "offset_end": -2,
        "within": "INC_Initialize",
    },
    # here we overwrite a global to mark all the cores as booted/synced
    "sync1_addr_code": {
        "pattern": "609a 809c 82eb",
        "offset": -2,
        "within": "INC_Initialize",
    },
    # arbitrary-ish point to fix up the nvram table
    "nvram_ltable_init_code": {
        "pattern": "a0e8",  # jrc ra
        "within": "nvram_ltable_construct",
    },
    # here we break out of a loop waiting for other cores
    "corewait_addr_code": {
        "pattern": "11ea 6eea 2367",
        "within": "stack_init_tasks",
        "offset_end": 0,
    },
    # bypass a sanity check
    "L1D_CustomDynamicGetParam_assert": {
        "pattern": "00 f1 00 5c",
        "offset": -2,
        "within": "L1D_CustomDynamicGetParam",
    },
    # assert for failure inside errc_evth_inevt_handler
    # (for the lte-rrc fuzzer)
    # we jump to the end of the function, so we need that too
    "errc_evth_inevt_handler_assert": {
        "pattern": "65 ea",  # break 0x13
        "within": "errc_evth_inevt_handler",
    },
    "errc_evth_inevt_handler_end": {
        "pattern": "???? a0e8",  # restore, jrc ra
        "within": "errc_evth_inevt_handler",
    },
    # pointer to logical_data_item_table (which is a ptr)
    # TODO: alignment?
    "ptr_logical_data_item_table": {
        "pattern": "a0 e8",  # jrc ra
        "within": "nvram_util_get_data_item",
        "offset_end": 0,
    },
    # pointer to sys_comp_config_tbl
    "ptr_sys_comp_config_tbl": {
        "pattern": "a0 e8",  # jrc ra
        "within": "SST_CheckHealthinessQCB",
        "offset_end": 0,
    },
    # place where current task pointer should be set before having it scheduled in
    "TCC_Task_Ready_To_Scheduled_Return": {
        "pattern": "a0 e8",  # jrc ra
        "within": "TCC_Task_Ready_To_Scheduled",
        "offset": -4,  # We need to align to basic block granularity, let's hope this is portable enough
    },
}
