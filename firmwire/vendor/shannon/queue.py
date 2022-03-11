## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
QUEUE_STRUCT_SIZE = 4 + 4 + 1 + (3) + 4 + 4

QUEUE_NAME_PTR_OFFSET = 0x0
QUEUE_OSTASK_OFFSET = 0x4
QUEUE_QTYPE_OFFSET = 0x8
QUEUE_QID_ALIAS_OR_CALLBACK_OFFSET = 0xC
# is zero by default in all entries
QUEUE_QID_OFFSET_OFFSET = 0x10
