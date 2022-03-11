// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include <shannon.h>
#include <afl.h>

const char TASK_NAME[] = "AFL_GSM_CC\0";

static uint32_t qid;

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
