// Copyright (c) 2022, Team FirmWire
// SPDX-License-Identifier: BSD-3-Clause
#ifndef _MACROS_H
#define _MACROS_H

#define CAT(a, ...) PRIMITIVE_CAT(a, __VA_ARGS__)
#define PRIMITIVE_CAT(a, ...) a ## __VA_ARGS__

#define COMMA() ,
#define EMPTY() 
#define DEFER(id) id EMPTY()

#define REP0(X)
#define REP1(X) X
#define REP2(X) REP1(X) X
#define REP3(X) REP2(X) X
#define REP4(X) REP3(X) X
#define REP5(X) REP4(X) X
#define REP6(X) REP5(X) X
#define REP7(X) REP6(X) X
#define REP8(X) REP7(X) X
#define REP9(X) REP8(X) X
#define REP10(X) REP9(X) X

#define REPL0(X)
#define REPL1(X) X
#define REPL2(X) REPL1(X)COMMA() X
#define REPL3(X) REPL2(X)COMMA() X
#define REPL4(X) REPL3(X)COMMA() X
#define REPL5(X) REPL4(X)COMMA() X
#define REPL6(X) REPL5(X)COMMA() X
#define REPL7(X) REPL6(X)COMMA() X
#define REPL8(X) REPL7(X)COMMA() X
#define REPL9(X) REPL8(X)COMMA() X
#define REPL10(X) REPL9(X)COMMA() X

#endif // _MACROS_H
