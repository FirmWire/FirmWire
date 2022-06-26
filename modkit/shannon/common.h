// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#ifndef _COMMON_H
#define _COMMON_H

#define COMPILE_TEST_CODE 0
#define ENABLE_DEBUG_OUTPUT 0

#define NULL 0
#define PACKED __attribute__((packed))

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef uint32_t size_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long uintptr_t;

void * memset(void * dst, int s, unsigned int count);
void * memcpy (void *dst, const void *src, unsigned int n);
char * strcpy(char * dst, char *src);
int strcmp(const char * s1, const char * s2);
int strncmp(const char * s1, const char * s2, size_t n);

/* Swap the bytes around */
static inline uint16_t _swap16(uint16_t to_swap) {
  return ((to_swap<<8)&0xff00) | // move byte 0 to byte 1
          ((to_swap>>8)&0xff); // 1 to 0
}

/* Swap the bytes around */
static inline uint32_t _swap32(uint32_t to_swap) {
  return ((to_swap>>24)&0xff) | // move byte 3 to byte 0
          ((to_swap<<8)&0xff0000) | // move byte 1 to byte 2
          ((to_swap>>8)&0xff00) | // move byte 2 to byte 1
          ((to_swap<<24)&0xff000000); // byte 0 to byte 3
}

static inline uint32_t ntohl(uint32_t net) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return _swap32(net);
#elif __BYTE__ORDER__ == __ORDER_BIG_ENDIAN__
  return net;
#else
  #error Unsupported Byte Order (or compiler)
#endif
}

static inline uint32_t htonl(uint32_t host) {
  return ntohl(host);
}

static inline uint16_t ntohs(uint16_t net) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  return _swap16(net);
#elif __BYTE__ORDER__ == __ORDER_BIG_ENDIAN__
  return net;
#else
  #error Unsupported Byte Order (or compiler)
#endif
}

static inline uint16_t htons(uint16_t host) {
  return ntohs(host);
}

#endif
