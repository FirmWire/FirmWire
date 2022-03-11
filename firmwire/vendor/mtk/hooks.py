## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct
import logging

log = logging.getLogger(__name__)


def host_printf(self, env, stringptr, params):
    pidx = 0
    fstring_orig = self.read_phy_string(stringptr)
    fstring = fstring_orig
    n = 0
    while True:
        if n >= len(fstring) - 1:
            break
        if fstring[n : n + 1] == b"%":
            while fstring[n + 1 : n + 2] in [
                b"0",
                b"1",
                b"2",
                b"3",
                b"4",
                b"5",
                b"6",
                b"7",
                b"8",
                b"9",
            ]:
                fstring = fstring[: n + 1] + fstring[n + 2 :]
            if fstring[n + 1 : n + 2] == b"%":
                fstring = fstring[:n] + fstring[n + 1 :]
                n = n + 1
                continue
            elif fstring[n + 1 : n + 2] == b"s":
                instring = self.read_phy_string(params[pidx])
                # print("DHL: read " + repr(instring))
                pidx = pidx + 1
                fstring = fstring[:n] + instring + fstring[n + 2 :]
                n = n + len(instring) + 1
                continue
            elif fstring[n + 1 : n + 2] == b"d":
                intstring = str(params[pidx])
                pidx = pidx + 1
                fstring = fstring[:n] + intstring.encode() + fstring[n + 2 :]
                n = n + len(intstring) + 1
                continue
            elif fstring[n + 1 : n + 2] == b"u":
                intstring = str(params[pidx])
                pidx = pidx + 1
                fstring = fstring[:n] + intstring.encode() + fstring[n + 2 :]
                n = n + len(intstring) + 1
                continue
            elif fstring[n + 1 : n + 2] == b"x":
                intstring = b"%x" % params[pidx]
                pidx = pidx + 1
                fstring = fstring[:n] + intstring + fstring[n + 2 :]
                n = n + len(intstring) + 1
                continue
            else:
                self.guest_logger.log_emit(
                    "FORMAT ERROR: %s (error_sym=%s)",
                    fstring_orig,
                    fstring[n + 1 : n + 2],
                    task_name=self._current_task_name,
                )
                return

        n = n + 1

    ra = self.qemu.pypanda.arch.get_reg(env, "ra")
    self.guest_logger.log_emit(
        fstring.decode(), task_name=self._current_task_name, address=ra
    )


def parseTraceString(self, fmt, argtype, params):
    # print("%r %r %r" % (fmt, argtype, params))
    # we replace each % with a parameter
    argsLeft = 0

    newString = ""
    for c in fmt:
        if c != "%":
            newString = newString + c
            continue
        if argsLeft == 0:
            argsLeft = 1
            currArgType = argtype[0]
            argtype = argtype[1:]
            if currArgType & 0x80:
                argsLeft = currArgType - 0x80
                currArgType = argtype[0]
                argtype = argtype[1:]

        if currArgType == ord("c"):
            newString = newString + ("%x" % (params[0] & 0xFF))
        elif currArgType == ord("h"):
            newString = newString + ("%x" % (params[0] & 0xFFFF))
        elif currArgType == ord("d"):
            newString = newString + ("%x" % params[0])
        elif currArgType == ord("s"):
            try:
                newString = newString + self.read_phy_string(params[0]).decode()
            except UnicodeDecodeError:
                newString += "[DECODE ERROR: unicode]"
        else:
            newString += "[DECODE ERROR: ** bad arg type %r" % bytes([currArgType])

        params = params[1:]
        argsLeft = argsLeft - 1

    return newString


def stack_params(self, env, howmany=4):
    sp = self.qemu.pypanda.arch.get_reg(env, "sp")
    sp = sp + 0x10
    params = []
    for n in range(howmany):
        readval = self.qemu.pypanda.physical_memory_read(sp + n * 4, 4)
        readval = struct.unpack("<I", readval)[0]
        params.append(readval)
    return params


def dhl_print_hook(self, env, tb, param3):
    stringptr = self.qemu.pypanda.arch.get_reg(env, "a3")
    params = stack_params(self, env)
    host_printf(self, env, stringptr, params)

    return True


# for hooking dhl_internal_trace_impl
def dhl_trace_hook(self, env, tb, param3):
    params = stack_params(
        self, env, 20
    )  # TODO: be smarter than just grabbing fixed number?
    ra = self.qemu.pypanda.arch.get_reg(env, "ra")
    cls = self.qemu.pypanda.arch.get_reg(env, "a0")
    userflag = self.qemu.pypanda.arch.get_reg(env, "a1")
    accesslevel = self.qemu.pypanda.arch.get_reg(env, "a2")
    msgidx = self.qemu.pypanda.arch.get_reg(env, "a3")
    moduleid = params[0]
    argtype = params[1]
    argtype = self.read_phy_string(argtype)
    params = params[2:]
    trace_entry = self.loader.trace_entries.get(msgidx)
    if trace_entry is not None:
        s = parseTraceString(self, trace_entry[1], argtype, params)
        self.guest_logger.log_emit(
            "%s [%s]", s, trace_entry[0], task_name=self._current_task_name, address=ra
        )


def prompt_trace_hook(self, env, tb, param3):
    stringptr = self.qemu.pypanda.arch.get_reg(env, "a1")
    p1 = self.qemu.pypanda.arch.get_reg(env, "a2")
    p2 = self.qemu.pypanda.arch.get_reg(env, "a3")
    params = [p1, p2] + stack_params(self, env)
    host_printf(self, env, stringptr, params)
    return True


def sys_trace_hook(self, env, tb, param3):
    stringptr = self.qemu.pypanda.arch.get_reg(env, "a0")
    p1 = self.qemu.pypanda.arch.get_reg(env, "a1")
    p2 = self.qemu.pypanda.arch.get_reg(env, "a2")
    p3 = self.qemu.pypanda.arch.get_reg(env, "a3")
    params = [p1, p2, p3] + stack_params(self, env)
    host_printf(self, env, stringptr, params)
    return True


# STATUS NU_Set_Events(NU_EVENT_GROUP *group, UNSIGNED event_flags, OPTION operation);
def NU_Set_Events_hook(self, env, tb, hook):
    group = self.qemu.pypanda.arch.get_reg(env, "a0")
    event_flags = self.qemu.pypanda.arch.get_reg(env, "a1")
    operation = self.qemu.pypanda.arch.get_reg(env, "a2")
    log.info(
        f"[NU_Set_Events_hook] group: {group:#010x}, event_flags: {event_flags:x}, operation: {operation:x}"
    )
    return True


def TCC_Task_Ready_To_Scheduled_Return(self, env, tb, hook):
    task = self.qemu.pypanda.arch.get_reg(env, "s1")
    if task != 0:
        self._current_task_name = self.read_phy_string(task + 0x10).decode()
