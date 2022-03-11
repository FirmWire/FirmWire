// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include <shannon.h>
#include <afl.h>

const char TASK_NAME[] = "AFL_GSM_SM\0";
static uint32_t qid;

int fuzz_single_setup()
{
    if (qid == 0)
      qid = queuename2id("SM");

    struct qitem_sm * init = pal_MemAlloc(4, sizeof(struct qitem_sm), __FILE__, __LINE__);

    init->header.op = 0;
    init->header.size = 1;
    // 0x3407 SMREG_INIT_REQ
    init->header.msgGroup = 0x3407;
    pal_MsgSendTo(qid, init, 2);

    return 1;
}

#define SPLIT_AMOUNT 2
#define SPLIT_CHAR '@'

void fuzz_single_multi(char * buf, size_t size);

/*void fuzz_single()
{
    uint32_t input_size;
    int split = 0;
    char * buf = getWork(&input_size);
    char * packet_start = buf;
    char * packet_end = buf + input_size;

    startWork(0, 0xffffffff); // memory range to collect coverage

    // find packets to split
    for (; buf < packet_end; buf++) {
      char c = *buf;

      if (c != SPLIT_CHAR)
        split = 0;
      else {
        split++;

        if (split == SPLIT_AMOUNT) {
          split = 0;
          fuzz_single_multi(packet_start, packet_start-buf-SPLIT_AMOUNT);
          packet_start = buf+1;
        }
      }
    }

    if (packet_start != packet_end)
      fuzz_single_multi(packet_start, packet_end-packet_start);

    doneWork(0);
}

void fuzz_single_multi(char * buf, size_t size)
{
    uart_puts("[+] Allocating Qitem\n");
    struct qitem_sm * item = pal_MemAlloc(4, sizeof(struct qitem_sm), __FILE__, __LINE__);
    char * pdu = pal_MemAlloc(4, AFL_MAX_INPUT, __FILE__, __LINE__);

    if (!item || !pdu) {
      uart_puts("ALLOC FAILED");
      return;
    }

    item->pdu = pdu;

    // GSM radio messages are usually limited in size
    size = size > 512 ? 512 : size;

    uart_puts("[+] Received n bytes: ");
    uart_dump_hex((uint8_t *) &size, 4); // Print some for testing

    if (size < 3) {
      return;
    }

    uart_puts("[+] Filling the qitem\n");
    item->header.op = 0;

    // Only target the RADIO_MSG msgs
    item->header.msgGroup = 0x3414;
    item->header.size = size;

    memcpy(item->pdu, buf, size);

    uart_puts("[+] FIRE\n");

    pal_MsgSendTo(qid, item, 2);
}*/

void fuzz_single()
{
    uint32_t input_size;
    uint16_t size;

    uart_puts("[+] Allocating Qitem\n");
    struct qitem_sm * item = pal_MemAlloc(4, sizeof(struct qitem_sm), __FILE__, __LINE__);
    char * pdu = pal_MemAlloc(4, AFL_MAX_INPUT, __FILE__, __LINE__);

    if (!item || !pdu) {
      uart_puts("ALLOC FAILED");
      return;
    }

    item->pdu = pdu;

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
    item->header.op = 0;

    // Only target the RADIO_MSG msgs
    item->header.msgGroup = 0x3414;
    item->header.size = size;

    memcpy(item->pdu, buf, size);

    uart_puts("[+] FIRE\n");
    startWork(0, 0xffffffff); // memory range to collect coverage

    pal_MsgSendTo(qid, item, 2);
    doneWork(0);
}
