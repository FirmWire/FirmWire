// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include <shannon.h>
#include <task.h>
#include <afl.h>
#include <macros.h>

const char TASK_NAME[] = "INTERACTIVE\0";

#define TX_FIFO_SIZE 0x400
#define RX_FIFO_SIZE 0x400

struct glink_peripheral {
  uint32_t access;
  uint32_t tx_head;
  uint32_t tx_tail;
  uint32_t rx_head;
  uint32_t rx_tail;
  uint8_t tx_fifo[TX_FIFO_SIZE];
  uint8_t rx_fifo[RX_FIFO_SIZE];
} PACKED;

struct glink_cmd_header {
  uint8_t cmd;
  uint8_t len;
  // next field is variable amount of octets
};

#define GLINK_MAX_SIZE (TX_FIFO_SIZE - sizeof(struct glink_cmd_header))

#define QUEUE_NAME_SZ 64

struct glink_queue_buf {
  char srcName[QUEUE_NAME_SZ]; // if srcName[0] == '\0': set op independently
  char dstName[QUEUE_NAME_SZ];
  uint32_t op; // used if srcName[0] == '\0'
  uint16_t group;
  uint8_t payload[];
} __attribute__((packed));

struct glink_set_event {
  uint8_t eventFlags;
  char eventName[9];
} __attribute__((packed));

struct glink_call_func {
  uint32_t function;
  uint32_t arg_count;
  uint32_t args[];
} __attribute__((packed));

enum GLINK_CMD_TYPE {
  /* Incirect queue entry (payload in buf) */
  GLINK_SEND_QUEUE_INDIR = 0,
  /* Direct queue entry (payload in struct) */
  GLINK_SEND_QUEUE,
  /* Set a GLINK Event */
  GLINK_SET_EVENT,
  /* creates a pal_memalloced chunk */
  GLINK_ALLOC_BLOCK,
  /* Call an arbitrary guest function with any args */
  GLINK_CALL_FUNC,
};


size_t glink_dequeue(uint8_t * buf, size_t amount)
{
  struct glink_peripheral * glink = (struct glink_peripheral*)0xec000000;

  // XXX: all of these reads are double-fetching and could cause race conditions with host
  // There are no memory barriers for doing this with pyperipherals, so memory consistency will be an issue

  // queue is empty
  if (glink->tx_head == glink->tx_tail)
    return 0;

  size_t bytes_available = 0;

  // enqueue to head, dequeue from tail

  // we have wrapped around and need two copy operations
  if (glink->tx_head < glink->tx_tail) {
    bytes_available = (TX_FIFO_SIZE - glink->tx_tail) + glink->tx_head;
  } else {
    bytes_available = glink->tx_head - glink->tx_tail;
  }

  if (bytes_available == 0)
    return 0;

  if (bytes_available > amount)
    bytes_available = amount;

  if (glink->tx_head < glink->tx_tail && TX_FIFO_SIZE - glink->tx_tail < bytes_available) {
    /* the read wraps around */
    size_t first_read = TX_FIFO_SIZE - glink->tx_tail;
    size_t second_read = bytes_available - first_read;

    memcpy(buf, glink->tx_fifo + glink->tx_tail, first_read);
    memcpy(buf+first_read, glink->tx_fifo, second_read);
  } else {
    memcpy(buf, glink->tx_fifo + glink->tx_tail, bytes_available);
  }

  glink->tx_tail = (glink->tx_tail + bytes_available) % TX_FIFO_SIZE;

  return bytes_available;
}

int glink_process_cmd()
{
  struct glink_cmd_header header;

  // TODO: unhardcode this!
  struct glink_peripheral * glink = (struct glink_peripheral*)0xec000000;
  size_t size = glink_dequeue((uint8_t *)&header, sizeof(header));

  if (size != sizeof(header)) {
    if (!size) {
      uart_puts("No new header to read\n");
    } else {
      uart_puts("glink header received is too small! Bug in fifo :(\n");
    }
    return -1;
  }

  uint8_t glink_payload[GLINK_MAX_SIZE];

  // Note: This can never happen as len is u8
  if (header.len > GLINK_MAX_SIZE) {
    uart_puts("Illegal header received - len too big\n");
    return -1;
  }

  size = glink_dequeue(glink_payload, header.len);

  if (size != header.len) {
    uart_puts("glink payload received is too small! Bug in Fifo :(\n");
    return -1;
  }

  switch(header.cmd) {
    case GLINK_SEND_QUEUE_INDIR: {

      uart_puts("GLINK SEND_QUEUE_INDIRECT\n");

      struct glink_queue_buf *msg = (struct glink_queue_buf *)glink_payload;

      // PDU is indirect
      size_t pdu_size = size - sizeof(struct glink_queue_buf);
      struct qitem_gmm * qitem = pal_MemAlloc(2, sizeof(struct qitem_gmm), __FILE__, __LINE__);
      char *pdu = pal_MemAlloc(2, pdu_size, __FILE__, __LINE__);

      int dstId = queuename2id(msg->dstName);
      if ( msg->srcName[0] ) {
          /*  We are not using the manually set op field */
          int srcId = queuename2id(msg->srcName);

          if (srcId == -1 || dstId == -1) {
            uart_puts(msg->srcName);
            uart_puts("GLINK unable to resolve QID name\n");
            return -1;
          }

          qitem->header.op1 = srcId;
          qitem->header.op2 = dstId;
      }
      else {
          qitem->header.op = msg->op;
      }
      qitem->header.msgGroup = msg->group;
      qitem->header.size = pdu_size;
      qitem->pdu = pdu;

      memcpy(pdu, glink_payload + sizeof(struct glink_queue_buf), pdu_size);

      pal_MsgSendTo(dstId, qitem, 2);
      break;

    } case GLINK_SEND_QUEUE: {
      uart_puts("GLINK SEND_QUEUE\n");

      struct glink_queue_buf *msg = (struct glink_queue_buf *)glink_payload;

      // PDU is inline
      size_t pdu_size = size - sizeof(struct glink_queue_buf);
      struct qitem_mm * qitem = pal_MemAlloc(2, sizeof(struct qitem_mm) + pdu_size, __FILE__, __LINE__);

      int dstId = queuename2id(msg->dstName);
      if ( msg->srcName[0] ) {
          /*  We are not using the manually set op field */
          int srcId = queuename2id(msg->srcName);

          if (srcId == -1 || dstId == -1) {
            uart_puts("GLINK unable to resolve QID name\n");
            return -1;
          }

          qitem->header.op1 = srcId;
          qitem->header.op2 = dstId;
      }
      else {
          qitem->header.op = msg->op;
      }
      qitem->header.msgGroup = msg->group;
      qitem->header.size = pdu_size;

      memcpy(qitem->payload, glink_payload + sizeof(struct glink_queue_buf), pdu_size);

      pal_MsgSendTo(dstId, qitem, 2);
      break;

    }
    case GLINK_SET_EVENT: {
      struct glink_set_event *msg = (struct glink_set_event *)glink_payload;

      uart_puts("GLINK SET_EVENT ");
      uart_puts(msg->eventName);
      uart_puts("\n");

      struct pal_event_group *evt = eventname2addr(msg->eventName);

      if (!evt) {
        uart_puts("GLINK invalid event name ");
        uart_puts(msg->eventName);
        uart_puts("\n");
        return -1;
      }

      pal_SmSetEvent(&evt, msg->eventFlags);
      break;
    }
    case GLINK_ALLOC_BLOCK: {
      if (header.len != 4) {
          uart_puts("GLINK alloc block in wrong format");
          break;
      }
      uart_puts("GLINK allocates a block: ");
      uint32_t size = *(uint32_t *) glink_payload;
      uart_dump_hex( (uint8_t *)&size, 4);
      void * ptr = pal_MemAlloc(2, size, __FILE__, __LINE__);

      glink->access = (uint32_t) ptr;

      break;
    }
    case GLINK_CALL_FUNC: {
      struct glink_call_func *msg = (struct glink_call_func *)glink_payload;
      uint32_t ret = 0;

      uart_puts("[+] Calling function\n");

#define VARCALL_WORD uint32_t
#define VARCALL(fn, c, ...) ((VARCALL_WORD(*)(PRIMITIVE_CAT(REPL, c)(VARCALL_WORD)))fn)(__VA_ARGS__)
#define A(c) msg->args[c]
      uint32_t fn = msg->function;

      switch (msg->arg_count) {
        case 0: ret = VARCALL(fn, 0); break;
        case 1: ret = VARCALL(fn, 1, A(0)); break;
        case 2: ret = VARCALL(fn, 2, A(0), A(1)); break;
        case 3: ret = VARCALL(fn, 3, A(0), A(1), A(2)); break;
        case 4: ret = VARCALL(fn, 4, A(0), A(1), A(2), A(3)); break;
        case 5: ret = VARCALL(fn, 5, A(0), A(1), A(2), A(3), A(4)); break;
        case 6: ret = VARCALL(fn, 6, A(0), A(1), A(2), A(3), A(4), A(5)); break;
        default:
          uart_puts("GLINK ERROR unhandled arg count\n");
          break;
      }

      glink->access = ret;
      break;
    }
    default:
      uart_puts("GLINK ERROR unhandled CMD\n");
      return -1;
  }

  return 0;
}

void task_main() {
  uart_puts("INTERACTIVE: starting\n");

  zero_bss();

  while (1) {
    uart_puts("INTERACTIVE: enter\n");

    int ret = glink_process_cmd();

    if (ret == -1) {
      uart_puts("INTERACTIVE: sleep\n");
      pal_Sleep(500);
    }
  }
}
