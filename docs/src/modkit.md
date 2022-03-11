# Modkit

One of the core features of FirmWire is it's modkit, which allows to create and compile own modules and tasks to be injected in the emulated baseband image.
The modkit serves as bases for our [fuzzing](fuzzing.md) modules, as well as the [GuestLink interactive exploration](interactive.md) capabilities.

In a nutshell, mods are C programs, which use the symbols created with [patternDB](pattern_db.md) and the vendor specific loaders to extend the functionality of the existing baseband firmware image.
These C programs need to be pre-compiled by using Makefiles supplied by us. Then, FirmWire can inject these tasks during run time, automatically resolving the symbols and placing the task in an unused memory segment.

## Toolchain & Compilation

To compile tasks, target specific compilation toolchains are required.
For an Ubuntu 20.04 system, we had success with the following toolchains provided by the distribution's packet repository: `gcc-9-mipsel-linux-gnu` for MediaTek based firmware, and `gcc-arm-none-eabi` for Shannon baseband firmware.

After installing the toolchains, the modules can be compiled by browsing to the [modkit](https://github.com/FirmWire/FirmWire/tree/main/modkit) directory and running `make` inside the vendor-specific subdirectories (i.e. `mtk` and `shannon`).

In case you want to extend the modkit and provide your own mod, you will need to adjust the Makefile.
In particular, you need to modify the `MODS` line and provide the path to your mod's source.
To exemplify this, let's assume you want to add `mymod` to the mods available for emulated Shannon modems.

Before modification, the relevant section in the Makefile should look something like this:
```
MODS := gsm_mm gsm_sm gsm_cc lte_rrc glink

gsm_mm_SRC := fuzzers/gsm_mm.c afl.c
gsm_cc_SRC := fuzzers/gsm_cc.c afl.c
gsm_sm_SRC := fuzzers/gsm_sm.c afl.c
lte_rrc_SRC := fuzzers/lte_rrc.c afl.c
glink_SRC := glink.c
```

Assuming you have your source code in `mymod.c`, this part of the Makefile should look as follows after modification:

```
MODS := gsm_mm gsm_sm gsm_cc lte_rrc glink mymod

gsm_mm_SRC := fuzzers/gsm_mm.c afl.c
gsm_cc_SRC := fuzzers/gsm_cc.c afl.c
gsm_sm_SRC := fuzzers/gsm_sm.c afl.c
lte_rrc_SRC := fuzzers/lte_rrc.c afl.c
glink_SRC := glink.c
mymod_SRC := mymod.c
```

After this tiny modifications, your mod should be compiled as well when running `make`!

# Modkit format

To further exemplify how the modkit is used, let's look at a very basic task: The `hello_world` task for MTK basebands.

The source code for this task looks as follows:

```C
#include <task.h>
#include <modkit.h>
#include <hello_world.h>

MODKIT_FUNCTION_SYMBOL(void, dhl_print_string, int, int, int, char *)

extern void real_main() {
    while(1) {
        dhl_print_string(2, 0, 0, "hello world\n");
    }
}
```

There is not a lot of code, isn't it? Let's go through the lines.
The first include import the MediaTek task logic, which is required to make sure our code will be embedded correctly, following the baseband-specific task structure.
Similarly, the second line includes high-level modkit functionalities.
The third line includes `hello_world.h`, whose content are:

```C
#ifndef HELLO_WORLD_H
#define HELLO_WORLD_H

const char TASK_NAME[] = "testtask\0";

#endif
```

The only important line here is the specification of the task name, which is set to `testtask`.

Coming back to `hello_world.c`, the fifth line is where things get interesting: 
```C
MODKIT_FUNCTION_SYMBOL(void, dhl_print_string, int, int, int, char *)
```
This directive is used to advise the modkit to "resolve" a function which is part of the original modem firmware.
The general syntax for it is:
```C
MODKIT_FUNCTION_SYMBOL(return_type, function_name, type_argument1, type_argument2, ..., type_argumentN)
```

After using this directive, the selected function becomes available to the C program, so in this case we can use `dhl_print_string` later in the code, which is used to provide logging output.

The next part of the code defines the `real_main()` function, which is used by the MediaTek modkit to assess where execution should start for this task (in the case of Shannon mods, the corresponding function name would be `task_main`).
This main function does nothing else than using the resolved `dhl_print_string` function to print "Hello World" repeatedly to the console. Neat!

# Running the task

Providing the code for the injected task is only the first step; of course, we also want to run it. Luckily, except running `make`, FirmWire automates the full process of injecting the task. Once build via `make`, we can easily invoke FirmWire with the `-t/--module` flag.

Taken the hello world task from above as example, this would look something like this:

```
$ python3 firmwire.py -t hello_world modem.bin
              ___            __      _                          
-.     .-.   | __|(+) _ _ _ _\ \    / /(+) _ _ ___    .-.     .-
  \   /   \  | _|  | | '_| '  \ \/\/ /  | | '_/ -_)  /   \   /  
   '-'     '-|_|   | |_| |_|_|_\_/\_/   | |_| \___|-'     '-'   
             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~             
                A  baseband  analysis  platform
                   https://github.com/FirmWire
[INFO] firmwire.loader: Reading firmware using ShannonLoader (shannon)
[ERROR] firmwire.vendor.shannon.loader: Modem CP tarfile is missing required modem.bin
[ERROR] firmwire.loader: Loading failed!
[INFO] firmwire.loader: Reading firmware using MTKLoader (mtk)
[INFO] firmwire.vendor.mtk.loader: Found new file md1rom at 0x0/0x0 with length 0x169eca4

[...] (Loading informations)

[INFO] firmwire.vendor.mtk.machine: Resolved dynamic symbol dhl_print_string (0x90287e25) -> 0x9f4000a0 (FUNC)
No Memory range specified at 0x913d66e4
[WARN] firmwire.vendor.mtk.machine: Overwriting an existing task
[INFO] firmwire.vendor.mtk.machine: Injecting Task at 0x9f400000 (stack: 0x9f4010e0)
Injecting contents to 913d66e4: b'7000409f284b3d910001ff00001000003500409f0000000101000000ffffffff'
No Memory range specified at 0x913d66e4
After injecting task

[...] (Lots of Logs)

[49.46536][SSIPC] 0x90e353b7 [SSIPC][ILM_MSG] waiting msg

[49.46661][testtas] 0x9f400033 hello world

[...]
```

As we can see, FirmWire automatically resolved `dhl_print_string` and injected the hello world task, which then later printed it output to the commandline! 

There are also other ways to invoke a mod, namely by using the `--fuzz/--fuzz-triage` or the `--interactive` commandline flag. More about these will be covered in the next Chapters!
