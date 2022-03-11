// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include <common.h>
#include <shannon.h>
#include <modkit.h>
#include <afl.h>
#include <task.h>


////////////////////////
// GLOBAL DATA
////////////////////////

static unsigned int bufsz;
char afl_buf[AFL_MAX_INPUT];

////////////////////////
// FUNCTION DEFINITIONS
////////////////////////

static inline unsigned int aflCall(unsigned int a0, unsigned int a1, unsigned int a2)
{

    unsigned int ret;
    register long r0 asm ("r0") = a0;
    register long r1 asm ("r1") = a1;
    register long r2 asm ("r2") = a2;

    //asm(".word 0x0f4c4641"
    asm volatile("svc 0x3f" //.byte 0x3f, 0xdf" // 0x0f4c4641"
            : "=r"(r0)
            : "r"(r0), "r"(r1), "r"(r2)
            );
    ret = r0;

    return ret;
}

static void aflInit(void)
{
    static int aflInit = 0;

    if(aflInit)
        return;

    memset(afl_buf, 0x00, sizeof(afl_buf)); // touch all the bits!
    bufsz = sizeof(afl_buf);
    aflInit = 1;
}

int startForkserver(int ticks)
{
    aflInit();
    // last arg ignored
    return aflCall(1, ticks, 0);
}

char * getWork(unsigned int *sizep)
{
    *sizep = aflCall(2, (unsigned int)afl_buf, bufsz);
    return afl_buf;
}

int startWork(unsigned int start, unsigned int end)
{
    aflInit();
    return aflCall(3, start, end);
}

int doneWork(int val)
{
    aflInit();
    return aflCall(4, (unsigned int)val, 0);
}

void task_main() {
    uart_puts("[+] AFL task starting\n");

    // we're essentially acting like a kernel
    zero_bss();

    // this settles the baseband tasks
    uart_puts("[+] Init sleep\n");
    pal_Sleep(200);

    if (!fuzz_single_setup()) {
      uart_puts("[!] Fuzzer init error\n");
      for (;;) ;
    }
    uart_puts("[+] Fuzzer init complete\n");

    uart_puts("[+] Starting fork server\n");
    startForkserver(1);

    while (1) {
      fuzz_single();
    }

    // tasks can NEVER return from main
}
