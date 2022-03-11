// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#ifndef _COMMON_H
#define _COMMON_H

#define COMPILE_TEST_CODE 0
#define ENABLE_DEBUG_OUTPUT 1

#define NULL 0
#define PACKED __attribute__((packed))

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef char int8_t;
typedef short int16_t;
typedef int int32_t;
typedef uint32_t size_t;

void * memset(void * dst, int s, unsigned int count);
void * memcpy (void *dst, const void *src, unsigned int n);
char * strcpy(char * dst, char *src);
int strcmp(const char * s1, const char * s2);
int strncmp(const char * s1, const char * s2, size_t n);

#endif
