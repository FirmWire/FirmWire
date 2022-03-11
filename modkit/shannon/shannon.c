// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include "shannon.h"

volatile unsigned char * const UART_IO_OUTPUT = (unsigned char *)0x84000000;

int32_t queuename2id(const char * name) {
  struct pal_queue * queue = SYM_QUEUE_LIST;
  uint32_t qid = 0;

  // we dont know the exact size of the queue list as this is in the binary (sizeof)
  // Just keep searching forward until we see a name pointer that seems suspect (NULL
  // or just invalid)
  while ((uint32_t)queue->name >= 0x40000000 && (uint32_t)queue->name <= 0x50000000) {
    if (strcmp(queue->name, name) == 0)
      return qid;

    queue++, qid++;
  }

  uart_puts("ERROR: Unable to resolve queue id ");
  uart_puts((char *)name);
  uart_putc('\n');

  return -1;
}

// the event id is the offset in the SYM_EVENT_GROUP_LIST
struct pal_event_group *eventid2addr(int32_t event_id) {
  struct pal_event_group *event = *SYM_EVENT_GROUP_LIST;
  int32_t i = 0;

  while (event) {
    if (event_id == i) {
      return event;
    }
    event = event->next;
    i++;
  }

  return NULL;
}



struct pal_event_group *eventname2addr(const char *name) {
  struct pal_event_group *event = *SYM_EVENT_GROUP_LIST;

  while (event) {
    if (strncmp(event->name, name, sizeof(event->name)-1) == 0)
      return event;

    event = event->next;
  }

  return NULL;
}

void uart_dump_hex(uint8_t * str, unsigned int sz) {
#if ENABLE_DEBUG_OUTPUT
  for (unsigned int i = 0; i < sz; i++) {
    char b = str[i];
    char h = (b >> 4) & 0xf;
    char l = b & 0xf;

    uart_putc(h >= 10 ? 'a' + (h-10) : '0' + h);
    uart_putc(l >= 10 ? 'a' + (l-10) : '0' + l);
    uart_putc(' ');
  }

  uart_putc('\n');
#endif
}

void uart_putc(char c) {
#if ENABLE_DEBUG_OUTPUT
    *UART_IO_OUTPUT = c;
#endif
}

void uart_puts(char * str) {
#if ENABLE_DEBUG_OUTPUT
  while (*str) {
    uart_putc(*str);
    str++;
  }
#endif
}

void set_tim1(uint32_t value){
    volatile int *tim1_base = (int*)0x82008100;
    *(tim1_base+1) = 0x00;
    *tim1_base = value;
    *(tim1_base+1) = 0x01;
}
