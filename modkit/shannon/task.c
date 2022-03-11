// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include <modkit.h>
#include <common.h>
#include <task.h>

void zero_bss() {
  for (uint8_t * addr = (uint8_t*)&_BSS_START; addr < (uint8_t*)&_BSS_END; addr++) {
    *addr = 0;
  }
}
