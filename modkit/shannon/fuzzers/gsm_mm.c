// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include <shannon.h>
#include <afl.h>

const char TASK_NAME[] = "AFL_GSM_MM\0";

static uint32_t qid;

struct qitem_mm_init_req {
  uint8_t unk[0x14];
} PACKED;

int fuzz_single_setup()
{
    qid = queuename2id("MM");

    struct qitem_mm * init = pal_MemAlloc(4, sizeof(struct qitem_mm) + sizeof(struct qitem_mm_init_req),
        __FILE__, __LINE__);

    init->header.op = 0;
    init->header.op2 = 0x1e; // dst message entity (unk)
    init->header.size = sizeof(struct qitem_mm_init_req); // min length
    // 0x29a3 MMC2G3G_INIT_REQ
    init->header.msgGroup = 0x29a3;

    memset(init->payload, 0, init->header.size);

    pal_MsgSendTo(qid, init, 2);

    return 1;
}

void fuzz_single()
{

    uint32_t input_size;
    uint16_t size;

    uart_puts("[+] Allocating Qitem\n");
    struct qitem_mm * item = pal_MemAlloc(4, sizeof(struct qitem_mm) + AFL_MAX_INPUT, __FILE__, __LINE__);

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
    item->header.op1 = 0xaa; // src entity unk
    item->header.op2 = qid;

    // Only target the RADIO_MSG msg types that get sent to the MM task
    if (buf[0] & 1)
      item->header.msgGroup = 0x295d;
    else
      item->header.msgGroup = 0x2922;

    item->header.size = size-1;

    memcpy(item->payload, buf+1, size-1);

    uart_puts("[+] FIRE\n");
    startWork(0, 0xffffffff); // memory range to collect coverage

    pal_MsgSendTo(qid, item, 2);
    doneWork(0);
}
