## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct

from . import LoggingPeripheral


class PhyIpcPeripheralCortexA(LoggingPeripheral):
    """Models the (un-emulated) PHY/L1 DSP consuming the CP->PHY async IPC ring.

    The CP queues a command into a 16-deep ring (per channel) via
    PHY_IPC_C2P_Sender, marking each slot "pending" (actFlag = 0x01020304), then
    rings this write-only doorbell to interrupt the PHY. On real hardware the PHY
    consumes the slots, clears each actFlag back to FLAG_CLEAR (0) and advances
    the consumer index. FirmWire does not emulate the PHY, so the ring is never
    drained; after 16 sends on a channel the producer laps the consumer and the
    sender fires `Dev Assert (actFlag == FLAG_CLEAR)` (PHY_IPC_C2P_Sender.c:63 /
    L1_Exit.c:253), killing the run.

    On any doorbell write we model instantaneous PHY consumption: for every
    channel, clear all slot actFlags and set rdIdx := wrIdx.

    Ring layout, relative to `ring_base` (= the value FUN_4128b7ec returns, i.e.
    &SCATTERED_FROM_...; resolved per-image via the SYM_PHY_IPC_C2P_RING_BASE
    pattern). The field offsets are compile-time constants, stable across builds
    of this baseband generation:

        slots  @ +0x11d68   NUM_SLOTS * SLOT_SIZE bytes, actFlag = first word
        rdIdx  @ +0x12268   u16 per channel  (consumer / PHY)
        wrIdx  @ +0x12272   u16 per channel  (producer / CP)

    with channel stride CHAN_STRIDE.
    """

    SLOTS_OFF = 0x11D68
    RDIDX_OFF = 0x12268
    WRIDX_OFF = 0x12272
    CHAN_STRIDE = 0x100
    SLOT_SIZE = 0x10
    NUM_SLOTS = 16
    NUM_CHANNELS = 5

    def __init__(self, name, address, size, **kwargs):
        # Resolved after pattern matching (see machine.py); None disables drain.
        self.ring_base = None
        super().__init__(name, address, size, **kwargs)

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write

    def hw_write(self, offset, size, value):
        if self.ring_base is not None:
            self._drain_rings()
        return super().hw_write(offset, size, value)

    def _drain_rings(self):
        base = self.ring_base
        zero = struct.pack("<I", 0)
        for ch in range(self.NUM_CHANNELS):
            ch_off = ch * self.CHAN_STRIDE
            for slot in range(self.NUM_SLOTS):
                self.machine.physical_memory_write(
                    base + self.SLOTS_OFF + ch_off + slot * self.SLOT_SIZE, zero
                )
            # consumer catches up to the producer (queue drained)
            wr = self.machine.panda.physical_memory_read(
                base + self.WRIDX_OFF + ch * 2, 2
            )
            self.machine.physical_memory_write(base + self.RDIDX_OFF + ch * 2, wr)
