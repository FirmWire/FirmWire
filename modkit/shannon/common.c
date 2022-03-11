// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#include "common.h"

/*  Convienence function copied from dietlibc */
void * memset(void * dst, int s, unsigned int count)
{
    register char * a = dst;
    count++;	/* this actually creates smaller code than using count-- */
    while (--count) {
      *a++ = s;
    }
    return dst;
}

void * memcpy (void *dst, const void *src, unsigned int n)
{
    void           *res = dst;
    unsigned char  *c1, *c2;
    c1 = (unsigned char *) dst;
    c2 = (unsigned char *) src;
    while (n--) *c1++ = *c2++;
    return (res);
}

char * strcpy(char * dst, char *src)
{
  while (*src) {
    *dst++ = *src++;
  }
  return dst;
}

int strcmp(const char * s1, const char * s2)
{
  while (*s1 && *s1 == *s2) {
    s1++, s2++;
  }
  return (*s1 - *s2);
}

int strncmp(const char * s1, const char * s2, size_t n)
{
  size_t i = 0;

  while (*s1 && *s1 == *s2 && i < n)
    s1++, s2++, i++;
  return (*s1 - *s2);
}
