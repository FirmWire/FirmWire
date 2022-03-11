// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#define MODKIT_NO_INSTANTIATE

#include <task.h>
#include <modkit.h>
//#include <hello_world.h>
#include "afl.h"

MODKIT_FUNCTION_SYMBOL(void, dhl_print_string, int, int, int, char *)
MODKIT_FUNCTION_SYMBOL(int, kal_get_task_by_moduleID, int)

////////////////////////
// GLOBAL DATA
////////////////////////

static unsigned int bufsz;
char afl_buf[AFL_MAX_INPUT];

////////////////////////
// FUNCTION DEFINITIONS
////////////////////////

unsigned int __attribute__((nomips16)) aflCall(unsigned int a0, unsigned int a1, unsigned int a2) {
    register unsigned int arg0 __asm__("a0") = a0;
    register unsigned int arg1 __asm__("a1") = a1;
    register unsigned int arg2 __asm__("a2") = a2;
    asm volatile(
        ".byte 0x1e\n" // AFLHACK
        ".byte 0x00\n"
        ".byte 0x00\n"
        ".byte 0x70\n" // special2
        : "+r"(arg0), "+r"(arg1), "+r"(arg2)
    );
    return arg0;
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

void uart_puts(char *str) {        
    dhl_print_string(2, 0, 0, str);
}

extern void real_main() {
    uart_puts("[+] AFL task starting\n");

#if 0
    // we're essentially acting like a kernel
    zero_bss();

    // this settles the baseband tasks
    uart_puts("[+] Init sleep\n");
    pal_Sleep(200);
#endif

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
