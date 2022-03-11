// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include <task.h>
#include <modkit.h>
#include <hello_world.h>

MODKIT_FUNCTION_SYMBOL(void, dhl_print_string, int, int, int, char *)

extern void real_main() {
    while(1) {
        dhl_print_string(2, 0, 0, "hello world\n");
    }
}
