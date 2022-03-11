// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#ifndef _AFL_H
#define _AFL_H

#define AFL_MAX_INPUT 4096

// let the linker decide which fuzzer we're using
extern void fuzz_single();
extern int fuzz_single_setup();

char * getWork(unsigned int *sizep);
int startWork(unsigned int start, unsigned int end);
int doneWork(int val);
int startForkserver(int ticks);

#endif // _AFL_H
