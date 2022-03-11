# Fuzzing

One of FirmWire's core contribution is the capability to fuzz the emulated baseband image using specialized fuzzing tasks.
These tasks are created using our [modkit](modkit.md), and use [triforce-afl](https://github.com/nccgroup/TriforceAFL) hypercalls to communicate with the fuzzer, [AFL++](https://github.com/AFLplusplus/AFLplusplus).

This combination of injected tasks and hypercalls allows for transparent in-modem fuzzing: A fuzz task would get the input from the fuzzer and then send it as *message* to the targeted task. For the targeted task, the input received this way would look like benign input arriving over the usual channels. 

FirmWire comes with some example fuzzing tasks, which were used in the evaluation of our [paper](../../firmwire-ndss22.pdf).
Let's look at one example task, to demonstrate how one would build a harness.

## Example Harness: GSM CC

Below is the high-level overview of our [gsm_cc](https://github.com/FirmWire/FirmWire/blob/main/modkit/shannon/fuzzers/gsm_cc.c) harness for Shannon basebands:

```C
#include <shannon.h>
#include <afl.h>

const char TASK_NAME[] = "AFL_GSM_CC\0";

static uint32_t qid;

int fuzz_single_setup()
{
    ...
}
void fuzz_single()
{
    ...
}
```

First, `shannon.h` is included to provide shannon specific convenience functions (e.g. `uart_puts` and `pal_MemAlloc`).
Then, `afl.h` is included, which provides the main functionality and API for fuzzing. The API is a slightly modified version as the one given by TriforceAFL and provides following four functions:

| Function                                                      | Purpose                                                                                                                                                             |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `char * getWork(unsigned int *sizep)`                         | Returns a buffer with fuzzing input and stores the input size into `sizep`.                                                                                         |
| `int startWork(unsigned int start, unsigned int end)`         | Start a fuzzing execution, while collecting coverage for code residing between `start` and `end`.                                                                   |
| `int doneWork(int val)`                                       | Mark the end of a fuzzing iteration, providing `val` as return code to the fuzzer.                                                                                  |
| `int startForkserver(int ticks, unsigned int persistent_cnt)` | Starts AFL forkserver. `ticks` controls whether qemu ticks should be enabled or not. `persistent_count` is deprecated and now controlled via an environment variable. |

Besides this API, the `afl.h` file also provides the basic skeleton for the fuzzing loop inside a `task_main` function:

```C
void task_main() {
    [...]
    if (!fuzz_single_setup()) {
      uart_puts("[!] Fuzzer init error\n");
      for (;;) ;
    }
    uart_puts("[+] Fuzzer init complete\n");

    uart_puts("[+] Starting fork server\n");
    startForkserver(1, AFL_PERSISTENT_LOOP_CTX);

    while (1) {
      fuzz_single();
    }
```

As we can see, this logic requires two additional functions: `fuzz_single_setup` and `fuzz_single`, which both need to be provided by our harness.
The first function is responsible for all task-specific setup. In the case of `gsm_cc`, this means (1) resolving the queueID for CC, (2) creating a `qitem_cc` memory chunk containing the correct msgGroup ID to initiate task initialization, and (3) sending the memory chunk as message to the according queue.

The full code for these three steps looks as below:

```C
int fuzz_single_setup()
{
    qid = queuename2id("CC");

    struct qitem_cc * init = pal_MemAlloc(4, sizeof(struct qitem_cc), __FILE__, __LINE__);

    init->header.op = 0;
    init->header.size = 1;
    // 0x2a01 CC_INIT_REQ
    init->header.msgGroup = 0x2a01;
    pal_MsgSendTo(qid, init, 2);

    return 1;
}
```

When it comes to `fuzz_single`, this function is executed once per fuzzing iteration and is meant to forward the input from the fuzzer to the dedicated target task.

In case of `gsm_cc`, this includes the following steps:
1) Create a memory chunk for the `qitem_cc` (just as above).
2) Get fuzzing input from the fuzzer using `getWork()`.
3) Validate that the input size is within valid boundaries.
4) Set up the `qitem_cc` to have the correct MessageGroup for RADIO_MSG types, as the contents for these are attacker controlled.
5) Moving the received input into `qitem_cc`.
6) Trigger the collection of coverage by calling `startWork`.
7) Sending the set up message to the target tasks. This will invoke the scheduler and the fuzztask is only scheduled back in after the message was processed.
8) Call `doneWork` to signalize the fuzzer that the input was processed, and the next iteration can start.

In code, this looks as follows:
```C
void fuzz_single()
{
    uint32_t input_size;
    uint16_t size;

    uart_puts("[+] Allocating Qitem\n");
    struct qitem_cc * item = pal_MemAlloc(4, sizeof(struct qitem_cc) + AFL_MAX_INPUT, __FILE__, __LINE__);

    if (!item) {
      uart_puts("ALLOC FAILED");
      return;
    }

    uart_puts("[+] Getting Work\n");
    char * buf = getWork(&input_size);
    size = (uint16_t) input_size;
    // GSM radio messages are usually limited in size
    size = size > 512 ? 512 : size;

    uart_puts("[+] Received n bytes: ");
    uart_dump_hex((uint8_t *) &size, 4); // Print some for testing

    if (size < 3) {
      startWork(0, 0xffffffff); // memory range to collect coverage
      doneWork(0);
      return;
    }

    uart_puts("[+] Filling the qitem\n");
    item->header.op1 = 0xaa;
    item->header.op2 = 0x20;

    // Only target the RADIO_MSG msg types that get sent to the MM task
    item->header.msgGroup = 0x2a3c;

    item->header.size = size;

    memcpy(item->payload, buf, size);

    uart_puts("[+] FIRE\n");
    startWork(0, 0xffffffff); // memory range to collect coverage

    pal_MsgSendTo(qid, item, 2);
    doneWork(0);
}
```

Further examples on how to write fuzzing harnesses can be found by inspecting the source code of our other harnesses.
Our [lte_rrc](https://github.com/FirmWire/FirmWire/blob/main/modkit/shannon/fuzzers/lte_rrc.c) fuzzer demonstrates for instance how a fuzzer would look like when the targeted task requires (a) an event to trigger message processing and (b) the input delivered in a separated memory chunk (rather than inlined in the qitem).

## Controlling the fuzzing process

Writing the fuzzing harness is only the first step; the second is to actually start the fuzzer.
FirmWire requires, at its minimum, two additional commandline flags to facilitate fuzzing: `--fuzz` and `--fuzz-input`.
The first one will cause FirmWire to be started in fuzzing mode. This disables console output, debugging hooks, and similar to achieve maximum performance during fuzzing.
The latter flag advises FirmWire where it can find the current fuzzing input, and this is usually provided by AFL itself.
A full commandline for starting fuzzing, on the example of `gsm_cc` would look like this:
```
$ afl-fuzz -i in -o out -U -- ./firmwire.py --restore-snapshot fuzz_base --fuzz gsm_cc --fuzz-input @@ modem.bin
```

Assuming you have some seed inputs in the `in` directory, this commandline should bring you directly to the AFL++ window.
Note how we used a snapshot here? As the boot time of the modem is quite long, AFL++ would timeout without these snapshot.
If you would like to fuzz without using the snapshot, we recommend to set the `AFL_FORKSRV_INIT_TMOUT` environment variable to a high value.

## Persistent Mode


## Replaying Inputs


Happy Fuzzing