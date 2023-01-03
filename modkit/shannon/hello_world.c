// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include <shannon.h>
#include <task.h>
#include <modkit.h>

const char TASK_NAME[] = "HELLO\0";

void task_main(){
    while(1) {
        uart_puts("Hello World!\r\n");
    }
}
