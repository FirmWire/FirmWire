// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#ifndef MTK_TASK_H
#define MTK_TASK_H

typedef struct {
   void * entry_func;
   void * init_func;
   void * reset_func;
} task_struct;

extern void real_main() __attribute__ ((noreturn));

#endif
