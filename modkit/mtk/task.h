// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#ifndef _TASK_H
#define _TASK_H
#include <mtk_task.h>

//extern void real_main() __attribute__ ((noreturn));
extern int task_main(task_struct **);
void zero_bss();

#endif // _TASK_H
