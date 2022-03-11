## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import logging

from . import PassthroughPeripheral

# TAKEN FROM LINUX
"""
struct ccci_runtime_feature {
        u8 feature_id;  /*for debug only*/
        struct ccci_feature_support support_info;
        u8 reserved[2];
        u32 data_len;
        u8 data[0];
};
struct ccci_feature_support {
        u8 support_mask:4;
        u8 version:4;
};
struct ccci_runtime_boot_info {
        u32 boot_channel;
        u32 booting_start_id;
        u32 boot_attributes;
        u32 boot_ready_id;
};

struct ccci_runtime_share_memory {
        u32 addr;
        u32 size;
};
"""


# Linux: arbitrary addresses for us, original sizes
SMEM_USER_RAW_MDCCCI_DBG = 0x69100000
CCCI_EE_SMEM_TOTAL_SIZE = 64 * 1024


class SHM_RUNTIME_Periph(PassthroughPeripheral):
    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        # this is SMEM_USER_RAW_RUNTIME_DATA

        # current target fw uses: 0x20, 0, 1, 9, 0x10, 2, 0x1c, 0xf
        # and via misc: 7, 6, 0xb, 10
        BOOT_INFO = 0
        EXCEPTION_SHARE_MEMORY = 1
        CCIF_SHARE_MEMORY = 2
        MISC_INFO_RTC_32K_LESS = 6
        MISC_INFO_RANDOM_SEED_NUM = 7
        MISC_INFO_SBP_ID = 9
        MISC_INFO_CCCI = 0xA
        MISC_INFO_CLIB_TIME = 0xB
        CCB_SHARE_MEMORY = 0xF
        DHL_RAW_SHARE_MEMORY = 0x10
        AP_CCMNI_MTU = 0x14
        CCISM_SHARE_MEMORY_EXP = 0x1C
        MD_MTEE_SHARE_MEMORY_ENABLE = 0x20

        CCCI_FEATURE_NOT_EXIST = 0
        CCCI_FEATURE_NOT_SUPPORT = 1
        CCCI_FEATURE_MUST_SUPPORT = 2
        CCCI_FEATURE_OPTIONAL_SUPPORT = 3
        CCCI_FEATURE_SUPPORT_BACKWARD_COMPAT = 4

        # ccci_md_prepare_runtime_data
        self.runtime_feature_offset = 0

        for n in range(64):
            if n == BOOT_INFO:
                CCCI_CONTROL_RX = 0
                self.append_runtime_feature(n, CCCI_FEATURE_MUST_SUPPORT, 0, 0x10)
                offset = self.runtime_feature_offset
                self.write_raw(offset + 0x0, 4, CCCI_CONTROL_RX)
                self.write_raw(offset + 0x4, 4, 0)  # TODO: booting_start_id
                self.runtime_feature_offset += 0x10
            elif n == EXCEPTION_SHARE_MEMORY:
                self.append_runtime_feature(n, CCCI_FEATURE_MUST_SUPPORT, 0, 0x8)
                offset = self.runtime_feature_offset
                self.write_raw(offset + 0x0, 4, SMEM_USER_RAW_MDCCCI_DBG)  # addr
                self.write_raw(offset + 0x4, 4, CCCI_EE_SMEM_TOTAL_SIZE)  # size
                self.runtime_feature_offset += 0x8
            elif n == CCIF_SHARE_MEMORY:
                self.append_runtime_feature(n, CCCI_FEATURE_MUST_SUPPORT, 0, 0x8)
                offset = self.runtime_feature_offset
                self.write_raw(offset + 0x0, 4, 0x69200000)  # addr [arbitrary]
                self.write_raw(offset + 0x4, 4, 721 * 1024)  # size, TODO
                self.runtime_feature_offset += 0x8
            elif n == CCISM_SHARE_MEMORY_EXP:
                self.append_runtime_feature(n, CCCI_FEATURE_MUST_SUPPORT, 0, 0x8)
                offset = self.runtime_feature_offset
                self.write_raw(
                    offset + 0x0, 4, 0x69200000 + (721 * 1024)
                )  # addr [arbitrary]
                self.write_raw(offset + 0x4, 4, 121 * 1024)  # size, TODO
                self.runtime_feature_offset += 0x8
            elif n == AP_CCMNI_MTU:
                # required for dpcopro
                self.append_runtime_feature(n, CCCI_FEATURE_MUST_SUPPORT, 0, 0x4)
                offset = self.runtime_feature_offset
                self.write_raw(offset + 0x0, 4, 3584 - 16)  # MTU
                self.runtime_feature_offset += 0x4
            else:
                self.append_runtime_feature(n, CCCI_FEATURE_NOT_EXIST, 0, 0)

    # note: caller is responsible for adding data afterwards
    def append_runtime_feature(self, featureid, supportmask, version, datalen):
        offset = self.runtime_feature_offset
        self.write_raw(offset + 0x0, 1, featureid)
        # TODO: nibble order?
        self.write_raw(offset + 0x1, 1, (version << 4) | supportmask)
        self.write_raw(offset + 0x4, 4, datalen)
        self.runtime_feature_offset = offset + 8
