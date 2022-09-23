## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import sys
import struct
import logging
import binascii
import enum

from avatar2 import *

from typing import Union, Optional

from .peripheral import FirmWirePeripheral
from .fifo import CircularFIFO

log = logging.getLogger(__name__)


class GLINK_CMD_TYPE(enum.IntEnum):
    GLINK_SEND_QUEUE_INDIR = 0
    GLINK_SEND_QUEUE = 1
    GLINK_SET_EVENT = 2
    GLINK_ALLOC_BLOCK = 3
    GLINK_CALL_FUNC = 4


"""
struct glink_peripheral {
  uint32_t access;
  uint32_t tx_head;
  uint32_t tx_tail;
  uint32_t rx_head;
  uint32_t rx_tail;
  uint8_t tx_fifo[TX_FIFO_SIZE];
  uint8_t rx_fifo[RX_FIFO_SIZE];
} PACKED;
"""

INT32SIZE = 4
FIXED_NAME_LEN = 9  # 8 chars + \0
QUEUE_NAME_SZ = 64  # 63 chars  + \0


class GLinkPeripheral(FirmWirePeripheral):
    def hw_read(self, offset, size):
        off_state = [0]

        def next_off(size):
            current = off_state[0]
            ret = offset >= current and offset < (current + size)
            current = current + size
            off_state[0] = current
            return ret

        offset_name = None

        if next_off(INT32SIZE):
            value = self.access
            offset_name = "access"
        elif next_off(INT32SIZE):
            value = self.fmt_tx_buff.head
            offset_name = "tx_head"
        elif next_off(INT32SIZE):
            value = self.fmt_tx_buff.tail
            offset_name = "tx_tail"
        elif next_off(INT32SIZE):
            value = self.fmt_rx_buff.head
        elif next_off(INT32SIZE):
            value = self.fmt_rx_buff.tail

        else:
            found = False
            for i, fifo in enumerate([self.fmt_tx_buff, self.fmt_rx_buff]):
                if fifo.within(offset):
                    found = True
                    fo = fifo.rebase(offset)
                    value = fifo.read_raw(fo, size)
                    offset_name = "%s_READ[%x]" % (fifo.name, fo)
                    break

            if not found:
                value = 0
                offset_name = "%x" % offset

        if offset_name is None:
            offset_name = "unknown"

        self.log_read(value, size, offset_name)
        return value

    # TX = from host to guest
    # RX = from guest to host
    def hw_write(self, offset, size, value):
        offset_name = None
        if offset == 0x0:
            log.info("ACCESS %d", value)
            self.access = value
            self.access_log.append(value)

        elif offset == 0x4:
            self.fmt_tx_buff.head = value
        elif offset == 0x8:
            self.fmt_tx_buff.tail = value
        elif offset == 0xC:
            self.fmt_rx_buff.head = value
            # TODO: dequeue elsewhere for handling
            self.fmt_rx_buff.dequeue()
        elif offset == 0x10:
            self.fmt_rx_buff.tail = value
        else:
            found = False
            for i, fifo in enumerate([self.fmt_tx_buff, self.fmt_rx_buff]):
                if fifo.within(offset):
                    found = True
                    fo = fifo.rebase(offset)
                    fifo.write_raw(fo, size, value)
                    offset_name = "%s_WRITE[%x]" % (fifo.name, fo)
                    break

            if not found:
                value = 0
                offset_name = "%x" % offset

        if offset_name is None:
            offset_name = "unknown"

        self.log_write(value, size, offset_name)

        return True

    def send_cmd(self, cmd):
        self.fmt_tx_buff.queue(cmd)

    def glink_header(self, cmd_type: GLINK_CMD_TYPE, len: int) -> bytes:
        """
        construct a header for:
        uint8_t cmd;
        uint8_t len;
        """
        return struct.pack("<BB", cmd_type, len)

    def name2fixedlen(self, name: Union[bytes, str], fixed_len: int) -> bytes:
        """
        Returns the constant-sized 8 byte string from qid
        """
        if len(name) > fixed_len - 1:
            log.warn("truncating name to 8 chars")
        if isinstance(name, str):
            name = name.encode()
        return name[: fixed_len - 1].ljust(fixed_len, b"\0")

    def construct_queue_header(
        self,
        src_qid_name: Union[bytes, str],
        dst_qid_name: Union[bytes, str],
        msg_group: int,
        op: Optional[int] = None,
    ) -> bytes:
        if op is not None:
            assert len(src_qid_name) == 0  # requirement: opped message have no srcqueue
        else:
            op = 0

        return (
            self.name2fixedlen(src_qid_name, QUEUE_NAME_SZ)
            + self.name2fixedlen(dst_qid_name, QUEUE_NAME_SZ)
            + struct.pack("<IH", op, msg_group)
        )

    def send_queue_indir(
        self,
        src_qid_name: Union[bytes, str],
        dst_qid_name: Union[bytes, str],
        msg_group: int,
        payload: bytes,
    ) -> bool:
        """
        Sends a new indirect queue entry (buf not in page)
        """
        return self.send_queue(True, src_qid_name, dst_qid_name, msg_group, payload)

    def send_queue_dir(
        self,
        src_qid_name: Union[bytes, str],
        dst_qid_name: Union[bytes, str],
        msg_group: int,
        payload: bytes,
    ) -> bool:
        """
        Sends a new direct queue entry (buf in page)
        """
        return self.send_queue(False, src_qid_name, dst_qid_name, msg_group, payload)

    def send_queue(
        self,
        indirect_buf: bool,
        src_qid_name: Union[bytes, str],
        dst_qid_name: Union[bytes, str],
        msg_group: int,
        payload: bytes,
    ) -> bool:
        """
        Sends a new cmd
        """
        if indirect_buf:
            cmd_type = GLINK_CMD_TYPE.GLINK_SEND_QUEUE_INDIR
        else:
            cmd_type = GLINK_CMD_TYPE.GLINK_SEND_QUEUE
        msg = (
            self.construct_queue_header(src_qid_name, dst_qid_name, msg_group) + payload
        )
        header = self.glink_header(cmd_type, len(msg))
        return self.send_cmd(header + msg)

    def send_queue_op(
        self,
        indirect_buf: bool,
        dst_qid_name: Union[bytes, str],
        op: int,
        msg_group: int,
        payload: bytes,
    ) -> bool:
        """
        Sends a new cmd which uses the op field with specified value
        """
        if indirect_buf:
            cmd_type = GLINK_CMD_TYPE.GLINK_SEND_QUEUE_INDIR
        else:
            cmd_type = GLINK_CMD_TYPE.GLINK_SEND_QUEUE
        msg = self.construct_queue_header("", dst_qid_name, msg_group, op=op) + payload
        header = self.glink_header(cmd_type, len(msg))
        return self.send_cmd(header + msg)

    def set_event(self, event_name: Union[bytes, str], flags: int = 4):
        """
        Set/send an event
        """
        return self.send_cmd(
            self.glink_header(GLINK_CMD_TYPE.GLINK_SET_EVENT, FIXED_NAME_LEN)
            + struct.pack("<B", flags)
            + self.name2fixedlen(event_name, FIXED_NAME_LEN)
        )

    def send_rrc(self, payload: bytes, opcode: int) -> bool:
        # Different src queues may have different effects
        # See https://github.com/grant-h/ShannonBaseband/blob/master/firmware/extdata/G973FXXU3ASG8/pal_queues.h
        self.send_queue_indir("LTERRC_RLC", "LTERRC", opcode, payload)
        self.set_event("LTE_RRC_")

    def create_block(self, size: int) -> int:
        """ """
        cmd_type = GLINK_CMD_TYPE.GLINK_ALLOC_BLOCK
        header = self.glink_header(cmd_type, 4)
        msg = struct.pack("<I", size)
        self.send_cmd(header + msg)

    def start_fuzzz(self):
        """ """
        cmd_type = GLINK_CMD_TYPE.GLINK_START_FUZZ
        header = self.glink_header(cmd_type, 0)
        # msg = struct.pack('<I', size)
        self.send_cmd(header)

    def call_function(self, fn, args=[]):
        """ """
        assert type(fn) == int

        packed_args = []
        for i in range(len(args)):
            if type(args[i]) == int:
                packed_args += [struct.pack("<I", args[i])]
            else:
                raise TypeError("Only int function call arguments supported")

        cmd_type = GLINK_CMD_TYPE.GLINK_CALL_FUNC

        # function pointer
        # number of word-size arguments being passed
        # arguments (word aligned)
        cmd_args = (
            struct.pack("<I", fn)
            + struct.pack("<I", len(packed_args))
            + b"".join(packed_args)
        )
        header = self.glink_header(cmd_type, len(cmd_args))

        self.send_cmd(header + cmd_args)

    @property
    def cmd_types(self):
        """
        Shorrthand to access the CMD_TYPES enum
        """
        return GLINK_CMD_TYPE

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size, **kwargs)

        self.access = 0
        self.access_log = []

        # TX/RX relative to AP
        self.fmt_tx_buff = CircularFIFO("cmd_tx_buff", 0x14, 0x400)  # CP recv
        self.fmt_rx_buff = CircularFIFO("cmd_rx_buff", 0x414, 0x400)  # CP send

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
