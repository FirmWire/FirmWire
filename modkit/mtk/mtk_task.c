// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include <mtk_task.h>

static task_struct task_fns = {
    .entry_func = (void *) 0,
    .init_func = (void *) 0,
    .reset_func = (void *) 0
};

int reset() {return 1;}
int init() {return 1;}

int task_main(task_struct **handler_out) {
    task_fns.entry_func = (void*)real_main;

    *handler_out = &task_fns;
    return 1;
}
