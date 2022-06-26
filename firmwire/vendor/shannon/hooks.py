## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import re
import os
import struct
import logging
import binascii
import collections

from avatar2 import *
from .queue import QUEUE_STRUCT_SIZE, QUEUE_NAME_PTR_OFFSET

from firmwire.util.panda import read_cstring_panda

log = logging.getLogger(__name__)

##########################################################
## HOOKS BEGIN
##########################################################


def log_fatal_error_file_line(self):
    return False


# http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.ddi0458c/CHDJHAGA.html
# NA - no access, RO - read only, RW - read write, RESV - reserved
# U_* - unpriviledged, P_* - priviledged
AP_NAME = ["NA", "P_RW", "P_RW/U_RO", "RW", "RESV", "P_RO/U_NA", "RO", "RESV"]
VARARG_SENTINEL = 0xFECDBA98
VARARG_DUMP_CSTRING = 0xFFFFFFFF


def set_mpu_slot_modem(self, cpustate, tb, hook):
    sp = cpustate.env_ptr.regs[13]
    slot = cpustate.env_ptr.regs[0]
    base = cpustate.env_ptr.regs[1]
    size = cpustate.env_ptr.regs[2]
    r3 = cpustate.env_ptr.regs[3]

    arg4_arg9 = panda.virtual_memory_read(cpustate, sp, 4 * 6)
    arg4_arg9 = struct.unpack("6I", arg4_arg9)

    size_bytes = (size >> 1) & 0b11111
    assert size_bytes >= 7
    size_bytes = 2 ** (8 + size_bytes - 7)

    enable = arg4_arg9[-1]
    access_control = sum([r3] + list(arg4_arg9[:-1]))

    XN = (access_control >> 12) & 1
    AP = (access_control >> 8) & 0b111
    B = (access_control) & 1
    C = (access_control >> 1) & 1
    S = (access_control >> 2) & 1
    TEX = (access_control >> 3) & 0b111

    args = [
        slot,
        bool(enable),
        base,
        base + size_bytes,
        XN,
        AP_NAME[AP],
        access_control,
    ]

    log.info("MPU RGN=%-2d ENABLE=%s [%08x - %08x] XN=%d AP=%s (0x%x)", *args)

    return False


def OS_log(self):
    return False


def OS_enter_idle(self, cpustate, tb, hook):
    r0 = cpustate.env_ptr.regs[0]

    log_emit(self, cpustate, "OS_enter_idle(%d)", r0)


"""
Enables per-basic block stepping and debugging output
"""


def panda_step_debug(self):
    @panda.cb_before_block_exec(enabled=True)
    def bbe(cpustate, tb):
        pc = panda.current_pc(cpustate)
        sym = self.symbol_table.lookup(pc)
        offset = pc - sym.address

        while True:
            log.info("========================> %s", sym.format(offset))
            dump_state(panda, cpustate)
            # sleep seems required otherwise BlockingIOError is common
            time.sleep(0.05)


def hw_MCU_Sleep(self, cpustate, tb, hook):
    log_emit(self, cpustate, "hw_MCU_Sleep")


def OS_Schedule_Task(self, cpustate, tb, hook):
    r0 = cpustate.env_ptr.regs[0]

    name = self.get_sch_task_name_by_id(r0)

    log_emit(self, cpustate, "OS_Schedule_Task(%s (%d))", name, r0)


def boot_after_uart_setup(self):
    print(
        self.qemu.call(
            0x400009BC, args=[b"HelloWorld\n"], playground=0x1000000, step=True
        )
    )
    self.qemu.cont(blocking=False)


def OS_handle_irq(self, cpustate, tb, hook):
    # to be extedted called from 0x42393f50:
    # 42393f50 50 f8 26 40     ldr.w      r4,[r0=>OSSyscallArray,r6,lsl #0x2]

    r0 = cpustate.env_ptr.regs[0]
    r6 = cpustate.env_ptr.regs[6]
    lr = cpustate.env_ptr.regs[14]
    handler = panda.virtual_memory_read(cpustate, r0 + 4 * r6, 0x4)
    log.info("%08x: OS_handle_interrupt(irq=%08x, handler=%08x)", lr, r6, handler)


def OS_enable_irq(self, cpustate, tb):

    # addr 0x42380242

    r0 = cpustate.env_ptr.regs[1]
    lr = cpustate.env_ptr.regs[14]

    log.info("%08x: Enabled IRQ %d", r0, lr)


def OS_create_task(self, cpustate, tb, hook):
    r1 = cpustate.env_ptr.regs[1]
    r3 = cpustate.env_ptr.regs[3]
    sp = cpustate.env_ptr.regs[13]
    lr = cpustate.env_ptr.regs[14]

    task_name = panda.virtual_memory_read(cpustate, r1, 0x8)
    arg4_arg7 = panda.virtual_memory_read(cpustate, sp, 4 * 4)
    arg4_arg7 = struct.unpack("IIII", arg4_arg7)

    start_function = arg4_arg7[2]
    log.info(
        "%08x: OS_create_task(%s, stack=%08x, cb=%08x)",
        lr,
        task_name,
        r3,
        start_function,
    )
    return False


FORMAT_SPECIFIER = re.compile("%?%[#]?[0-9lh.]*[a-zA-Z]")


def vsprintf(self, cpustate, fmt, argv, dump=False):
    argv_resolved = []

    res = FORMAT_SPECIFIER.findall(fmt)

    res = [
        x for x in res if "%%" not in x
    ]  # MM: hotfix to deal with "%%%%" in messages

    for i, r in enumerate(res):
        if r[0] == "%" and r[1] == "%":
            continue

        try:
            arg = argv[i]
        except IndexError:
            return "FORMAT INDEX ERROR: %s %s %s" % (fmt, res, argv)

        if r[-1] == "s":
            arg = read_cstring_panda(panda, arg)
        elif r[-1] == "C":
            fmt = fmt.replace(r, r[:-1] + "c")
        elif r[-1] == "p":
            fmt = fmt.replace(r, "0x%08x")

        argv_resolved += [arg]

    try:
        formatted = fmt % tuple(argv_resolved[: len(res)])
    except (TypeError, ValueError) as e:
        formatted = "FORMAT ERROR: [%s] [%s] [%s]" % (str(fmt), str(res), str(argv))

    if dump:
        dump_commands = argv[len(argv_resolved) :]

        if len(dump_commands) > 0 and dump_commands[0] == VARARG_DUMP_CSTRING:
            dump_commands = dump_commands[1:]

        # need at least an address and size
        if len(dump_commands) < 2:
            return formatted

        # blank string for join separator between formatted message and dumps
        dump_command_results = [""]

        for i in range(len(dump_commands) // 2):
            addr = dump_commands[i * 2]
            size = dump_commands[i * 2 + 1]
            if size == VARARG_DUMP_CSTRING:
                s = read_cstring_panda(panda, addr)
            else:
                s = panda.virtual_memory_read(cpustate, addr, size)
                s = binascii.hexlify(s).decode()

            dump_command_results += [s]

        formatted += " -- ".join(dump_command_results)

    return formatted


def _read_trace_cstring(self, cpustate, address):
    s = _read_trace_data(self, cpustate, address, 0x100)
    return s[: s.find(b"\x00")].decode("ascii", "ignore")


def _read_trace_data(self, cpustate, address, size):
    offset = address - self.trace_data_offset

    # fallback to other memory ranges
    if offset < 0 or offset > len(self.trace_data):
        return panda.virtual_memory_read(cpustate, address, size)

    if offset + size > len(self.trace_data):
        size = len(self.trace_data) - offset

    return self.trace_data[offset : offset + size]


def _vsprintf_get_va_list(cpustate):
    sp = cpustate.env_ptr.regs[13]

    # _cdecl calling convention passes the rest of the args on the stack after R3
    # 7 stack args appears to be the max! (as seen from the log_printf function)
    stack_args = panda.virtual_memory_read(cpustate, sp, 4 * 7)
    stack_args = list(struct.unpack("7I", stack_args))
    argv = [
        cpustate.env_ptr.regs[1],
        cpustate.env_ptr.regs[2],
        cpustate.env_ptr.regs[3],
    ] + stack_args

    max_idx = 0
    for arg in argv:

        if arg == VARARG_SENTINEL:
            break

        max_idx += 1

    return argv[:max_idx]


def _log_printf_common(self, cpustate, tb, dump):
    pc = panda.current_pc(cpustate)
    r0 = cpustate.env_ptr.regs[0]
    logcontext = panda.virtual_memory_read(cpustate, r0, 8)

    logcontext = struct.unpack("II", logcontext)
    trace_entry = _read_trace_data(self, cpustate, logcontext[0], 4 * 7)
    trace_entry = struct.unpack("IIIIIII", trace_entry)

    fmt = _read_trace_cstring(self, cpustate, trace_entry[4])
    filename = _read_trace_cstring(self, cpustate, trace_entry[6])

    argv = _vsprintf_get_va_list(cpustate)
    formatted = vsprintf(self, cpustate, fmt, argv, dump=dump)

    loglevel = logcontext[1] & 0b11111
    log_emit(
        self, cpustate, "%s: [%s] - %s", bin(loglevel), filename, formatted.rstrip()
    )

    return False


def log_printf(self, cpustate, tb, hook):
    return _log_printf_common(self, cpustate, tb, False)


def log_printf_debug(self, cpustate, tb, hook):
    return _log_printf_common(self, cpustate, tb, True)


def log_emit(self, cpustate, fmt, *args):
    caller = cpustate.env_ptr.regs[14]
    name = self.get_current_task_name(cpustate)

    self.guest_logger.log_emit(fmt, *args, task_name=name, address=caller)


def log_printf_stage(self, cpustate, tb, hook):
    cplog_buffer_p = cpustate.env_ptr.regs[0]
    trace_entry_stage_p = cpustate.env_ptr.regs[1]
    flags = cpustate.env_ptr.regs[2]
    fmt_p = cpustate.env_ptr.regs[3]

    cplog_buffer = panda.virtual_memory_read(cpustate, cplog_buffer_p, 4 * 4)
    cplog_buffer = struct.unpack("IIII", cplog_buffer)
    cplog_buffer_name = read_cstring_panda(panda, cplog_buffer[0])

    trace_entry_stage = panda.virtual_memory_read(cpustate, trace_entry_stage_p, 4 * 4)
    trace_entry_stage = struct.unpack("IIII", trace_entry_stage)
    filename = read_cstring_panda(panda, trace_entry_stage[3])

    fmt = read_cstring_panda(panda, fmt_p)
    argv = _vsprintf_get_va_list(cpustate)
    formatted = vsprintf(self, cpustate, fmt, argv)

    log_emit(
        self, cpustate, "[%s][%s] - %s", cplog_buffer_name, filename, formatted.rstrip()
    )

    return False


def OS_event(self, cpustate, tb, hook):
    event_group = cpustate.env_ptr.regs[0]
    event_group_name_p = cpustate.env_ptr.regs[1]

    event_group_name = read_cstring_panda(panda, event_group_name_p)

    log.info("OS_Create_Event_Group(0x%08x, %s)", event_group, event_group_name)

    return True


# keyed by thread id (which we treat as task ID)
target_invocation_stack = {}


class PALMsg:
    def __init__(self, shannon, src, dst, size, msgId, data):
        self.src = src
        self.dst = dst
        self.size = size
        self.msgId = msgId
        self.data = data
        self.srcName = shannon.pal_queueid2name(self.src)
        self.dstName = shannon.pal_queueid2name(self.dst)

    def __repr__(self):
        return "PALMsg<0x%04x, %s (%x) -> %s (%x), %d bytes>" % (
            self.msgId,
            self.srcName,
            self.src,
            self.dstName,
            self.dst,
            self.size,
        )


PALMsg_pattern = "<HHHH"
MSG_HEADER_SIZE = struct.calcsize(PALMsg_pattern)


def read_msg(self, addr):
    src, dst, size, mid = struct.unpack(
        PALMsg_pattern, panda.physical_memory_read(addr, MSG_HEADER_SIZE)
    )

    dataPtr = addr + MSG_HEADER_SIZE
    data = panda.physical_memory_read(dataPtr, size)
    return PALMsg(self, src, dst, size, mid, data)


def pal_MsgReceiveMbx(self, cpustate, tb, hook):
    fromLoc = cpustate.env_ptr.regs[14]
    qid = cpustate.env_ptr.regs[0]
    ppItem = cpustate.env_ptr.regs[1]
    pItemClass = cpustate.env_ptr.regs[2]
    flags = cpustate.env_ptr.regs[3]

    ctx = {
        "caller": cpustate.env_ptr.regs[14],
        "args": [qid, ppItem, pItemClass, flags],
    }

    ctx_id = self.get_current_task_id()
    assert ctx_id != None

    if ctx_id not in target_invocation_stack:
        target_invocation_stack[ctx_id] = []

    target_invocation_stack[ctx_id].append(ctx)

    name = self.pal_queueid2name(qid)
    log_emit(self, cpustate, "pal_MsgReceiveMbx(%s (%d)) - ENTER", name, qid)


def pal_MsgReceiveMbx_ret(self, cpustate, tb, hook):
    ctx_id = self.get_current_task_id()
    assert ctx_id != None

    # TODO: save context stack on snapshot
    if (
        ctx_id not in target_invocation_stack
        or len(target_invocation_stack[ctx_id]) == 0
    ):
        log_emit(self, cpustate, "pal_MsgReceiveMbx(???) - NO CONTEXT")
        return

    ctx = target_invocation_stack[ctx_id].pop()

    qid = ctx["args"][0]
    ppItem = ctx["args"][1]

    # We can't get item type because its assigned to a pointer at the last TB,
    # so grab it from the stack instead
    sp = cpustate.env_ptr.regs[13]
    itemType = struct.unpack("<I", panda.physical_memory_read(sp + 0x0, 4))[0]

    name = self.pal_queueid2name(qid)

    if itemType == 2:
        pItem = struct.unpack("<I", panda.physical_memory_read(ppItem, 4))[0]
        msg = read_msg(self, pItem)
        self.pal_log_recv_msg(self.get_current_task_name(cpustate), name, msg)
        log_emit(
            self, cpustate, "pal_MsgReceiveMbx(%s (%d)) - %s", name, qid, repr(msg)
        )
    elif itemType == 3:
        log_emit(
            self, cpustate, "pal_MsgReceiveMbx(%s (%d)) - TIMER 0x%x", name, qid, ppItem
        )
    else:
        log_emit(
            self,
            cpustate,
            "pal_MsgReceiveMbx(%s (%d)) - UNKNOWN TYPE 0x%x",
            name,
            qid,
            itemType,
        )


def pal_MsgSendTo(self, cpustate, tb, hook):
    qid = cpustate.env_ptr.regs[0]
    msgAddr = cpustate.env_ptr.regs[1]
    itemType = cpustate.env_ptr.regs[2]

    name = self.pal_queueid2name(qid)

    if itemType == 2:
        msg = read_msg(self, msgAddr)
        self.pal_log_send_msg(self.get_current_task_name(cpustate), name, msg)
        log_emit(self, cpustate, "pal_MsgSendTo(%s (%d)) - %s", name, qid, repr(msg))
    elif itemType == 3:
        log_emit(
            self, cpustate, "pal_MsgSendTo(%s (%d)) - TIMER 0x%x", name, qid, msgAddr
        )
    else:
        log_emit(
            self,
            cpustate,
            "pal_MsgSendTo(%s (%d)) - UNKNOWN TYPE 0x%x",
            name,
            qid,
            itemType,
        )


def pal_QueueCreate(self, cpustate, tb, hook):
    queue_name_p = cpustate.env_ptr.regs[2]
    queue_name = read_cstring_panda(panda, queue_name_p)

    log.info("pal_QueueCreate(%s)", queue_name)

    return True


def log_format_unk(self, cpustate, tb, hook):
    fmt = cpustate.env_ptr.regs[0]

    fmt = read_cstring_panda(panda, fmt)
    argv = _vsprintf_get_va_list(cpustate)

    formatted = vsprintf(self, cpustate, fmt, argv)
    log_emit(self, cpustate, "%s", formatted.rstrip())

    return True


def pal_Sleep(self, cpustate, tb, hook):
    sleep_time = cpustate.env_ptr.regs[0]
    log_emit(self, cpustate, "pal_Sleep(%d)", sleep_time)


def NV_STUFF(self, cpustate, tb, hook):
    log.info("NV_STUFF this will take a while (time so far %.2f)", self.time_running())
    return True


###############################


def handle_RESET(self, cpustate, tb, hook):
    log.info("RESET CALLED")


def OS_fatal_error(self, cpustate, tb, hook):
    lr = cpustate.env_ptr.regs[14]
    r0 = cpustate.env_ptr.regs[0]

    osfatalerror = panda.virtual_memory_read(cpustate, r0, 4 * 3)
    osfatalerror = struct.unpack("3I", osfatalerror)

    iLine, szFile, szError = osfatalerror

    szFile = read_cstring_panda(panda, szFile)
    szError = read_cstring_panda(panda, szError)

    log.error(
        "FATAL ERROR (%s): from 0x%08x [%s:%d - %s]",
        self.get_current_task_name(cpustate),
        lr,
        szFile,
        iLine,
        szError,
    )


def handle_UDI(self, cpustate, tb, hook):
    lr = cpustate.env_ptr.regs[14]
    log.error(
        "EXCEPTION: UNDEFINED INSTRUCTION (%s) - Faulting PC: 0x%08x",
        self.get_current_task_name(cpustate),
        lr,
    )
    return False


def handle_SWI(self, cpustate, tb, hook):
    return False


def handle_PREFETCH(self, cpustate, tb, hook):
    lr = cpustate.env_ptr.regs[14]
    log.error(
        "EXCEPTION: PREFETCH ABORT (%s) - Faulting PC: 0x%08x",
        self.get_current_task_name(cpustate),
        lr,
    )

    return False


def handle_DA(self, cpustate, tb, hook):
    lr = cpustate.env_ptr.regs[14]
    pc = panda.current_pc(cpustate)
    log.error(
        "EXCEPTION: DATA ABORT (%s) - Faulting PC: 0x%08x",
        self.get_current_task_name(cpustate),
        lr,
    )

    return False


def handle_NA(self, cpustate, tb, hook):
    return False


def handle_IRQ(self, cpustate, tb, hook):
    return False


def handle_FIQ(self, cpustate, tb, hook):
    return False


##########################################################
## HOOKS END
##########################################################

# NOTE: there a lot of hooks that need patterns. They are hardcoded for the CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar image
# They are all just informative - emulation will still work for other firmware
mappings = [
    {
        "name": "OS_handle_interrupt",
        # TODO: pattern
        "address": 0x42393EEE,
        "handler": OS_handle_irq,
    },
    {
        "name": "OS_fatal_error",
        "symbol": "OS_fatal_error",
        "handler": OS_fatal_error,
    },
    {
        "name": "log_format_unk",
        # TODO: pattern
        "address": 0x40C22608,
        "handler": log_format_unk,
    },
    {
        "name": "log_printf",
        "symbol": "log_printf",
        "handler": log_printf,
    },
    {
        "name": "log_printf2",
        "symbol": "log_printf2",
        "handler": log_printf,
    },
    {
        "name": "log_printf_stage",
        # TODO: pattern
        "address": 0x40CB8F5C,
        "handler": log_printf_stage,
    },
    {
        "name": "log_early_clk",
        # TODO: pattern
        "address": 0x4054C9DE,
        "handler": log_format_unk,
    },
    {
        "name": "OS_create_task",
        # TODO: pattern
        "address": 0x416F90F0,
        "handler": OS_create_task,
    },
    {
        "name": "OS_enter_idle",
        # TODO: pattern
        "address": 0x4054C88E,
        "handler": OS_enter_idle,
    },
    {
        "name": "hw_MCU_Sleep",
        # TODO: pattern
        "address": 0x40D4F9E0,
        "handler": hw_MCU_Sleep,
    },
    {
        "name": "OS_Schedule_Task",
        # TODO: pattern
        "address": 0x416F8D24,
        "handler": OS_Schedule_Task,
    },
    {
        "name": "OS_Create_Event_Group",
        # TODO: pattern
        "address": 0x4054D4FC,
        "handler": OS_event,
    },
    {
        "name": "pal_QueueCreate",
        # TODO: pattern
        "address": 0x405B2464,
        "handler": pal_QueueCreate,
    },
    {
        "name": "pal_Sleep",
        "symbol": "pal_Sleep",
        "handler": pal_Sleep,
    },
    {
        "name": "set_mpu_slot_modem",
        # TODO: pattern
        "address": 0x41739484,
        "handler": set_mpu_slot_modem,
    },
    {
        "name": "OS_DispatchIRQ",
        # TODO: pattern
        "address": 0x42393F4E,
        "handler": OS_handle_irq,
    },
    {
        "name": "pal_MsgReceiveMbx",
        # TODO: pattern
        "address": 0x411560A2,
        "handler": pal_MsgReceiveMbx,
    },
    {
        "name": "pal_MsgReceiveMbx_ret",
        # TODO: pattern
        "address": 0x4115610E,
        "handler": pal_MsgReceiveMbx_ret,
    },
    {
        "name": "pal_MsgSendTo",
        "symbol": "pal_MsgSendTo",
        "handler": pal_MsgSendTo,
    },
    {
        "name": "NV_STUFF",
        # TODO: pattern
        "address": 0x40CAAE84,
        "handler": NV_STUFF,
    },
]

# Add hooks to exception handlers at various locations
handlers = [handle_RESET, handle_UDI, handle_SWI, handle_PREFETCH, handle_DA]

for base_address in [0x00000000]:
    for i, handler in enumerate(handlers):
        mappings += [
            {"name": str(handler), "address": base_address + i * 4, "handler": handler}
        ]
