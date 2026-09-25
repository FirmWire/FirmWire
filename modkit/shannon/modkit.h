// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#ifndef _MODKIT_H
#define _MODKIT_H

#define MODKIT_SYMBOL_UNRESOLVED 0xaaaaaaaa
#define MODKIT_SYMBOL_RESOLVED(name) ((unsigned int)(name) != MODKIT_SYMBOL_UNRESOLVED)

extern const volatile unsigned char _BSS_START;
extern const volatile unsigned char _BSS_END;
extern const volatile unsigned char _TASK_START;
extern const volatile unsigned char _TASK_END;

#ifdef MODKIT_INSTANTIATE

// Magic to have an obvious symbol name in the exports but allow for a nice name
// when calling functions in the modkit. If a symbol isnt resolved, then the modem
// should crash when calling an invalid address. ALSO the bss is cleared on task boot
// so, by initializing these, they are guaranteed storage. This could be fixed by
// having the dynamic loader zero the bss instead of the task
#define MODKIT_FUNCTION_SYMBOL(ret, name, ...) \
  ret (*__SYMREQ_FUNC_ ## name)(__VA_ARGS__) = (ret (*)(__VA_ARGS__))0xaaaaaaaa; \
  static ret (*name)(__VA_ARGS__) __attribute__ ((weakref, alias ("__SYMREQ_FUNC_" # name)));

#define MODKIT_DATA_SYMBOL(ty, name) \
  ty __SYMREQ_DATA_ ## name = (ty)0xaaaaaaaa; \
  static ty name __attribute__ ((weakref, alias ("__SYMREQ_DATA_" # name)));

// A C++ instance (`this`) pointer. Unlike DATA and FUNC symbols these are heap
// allocated by the target, so FirmWire cannot fill them in from a static symbol
// table: on a cold boot the value only becomes known once the constructor has
// run, which is after task injection. Always test with MODKIT_SYMBOL_RESOLVED
// before using one.
#define MODKIT_INSTANCE_SYMBOL(ty, name) \
  ty __SYMREQ_INST_ ## name = (ty)MODKIT_SYMBOL_UNRESOLVED; \
  static ty name __attribute__ ((weakref, alias ("__SYMREQ_INST_" # name)));

#else

#define MODKIT_FUNCTION_SYMBOL(ret, name, ...) \
  static ret (*name)(__VA_ARGS__) __attribute__ ((weakref, alias ("__SYMREQ_FUNC_" # name)));

#define MODKIT_DATA_SYMBOL(ty, name) \
  static ty name __attribute__ ((weakref, alias ("__SYMREQ_DATA_" # name)));

#define MODKIT_INSTANCE_SYMBOL(ty, name) \
  static ty name __attribute__ ((weakref, alias ("__SYMREQ_INST_" # name)));

#endif


#endif // _MODKIT_H
