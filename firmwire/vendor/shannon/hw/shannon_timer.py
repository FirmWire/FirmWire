## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
from avatar2 import *

from . import LoggingPeripheral
from time import sleep
from threading import Thread, Event, Lock

import logging


class ShannonTCU(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x40:
            offset_name = "TCU_PRESCALAR"
            value = self.prescalar
        else:
            value = 0
            offset_name = ""
            value = super(ShannonTCU, self).hw_read(offset, size)

        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):
        if offset == 0x40:
            offset_name = "TCU_PRESCALAR"
            self.prescalar = value
        else:
            return super(ShannonTCU, self).hw_write(offset, size, value)

        self.log_write(value, size, offset_name)

        return value

    def __init__(self, name, address, size, **kwargs):
        super(ShannonTCU, self).__init__(name, address, size, **kwargs)

        self.prescalar = 23
        self.read_handler[0:size] = self.hw_read

        self.write_handler[0:size] = self.hw_write


class ShannonUptimer(LoggingPeripheral):
    def hw_read(self, offset, size):
        if offset == 0x34:
            self.read_count += 1
            if self.read_count > 4:
                value = 0
            else:
                value = 0xFFFFFFFC
        else:
            value = 0
        return value

    def hw_write(self, offset, size, value):
        return super().hw_write(offset, size, value)

    def __init__(self, name, address, size, **kwargs):
        super().__init__(name, address, size)
        self.read_count = 0

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write


IS_ENA = 1 << 0
RELOAD = 1 << 1


class ShannonTimer(LoggingPeripheral):
    """
    Assumed Layout:
        0x00: SET_VA: (WO?)
        0x04: CFG (RW)
        0x08: ??
        0x0C: Scalar?
        0x10: IRQ_ENA?
        0x14:
        0x20: IRQ_ENA
        0x34: CUR_VAL



    CFG_OFFSETS:
        31--------------------------------2-1-0
          |                              | |R|E|
        E: TimerEnable
        R: AutoReload ? (If set, reload value after dec to 0)

        0xfffffffc - Allow to write value
        0xfffffffd - Run + Countdown
        0xffffffff - Run + Countup
    """

    def hw_read(self, offset, size):

        if offset == 0x00:
            offset_name = "TIM_SET_VAL"
            value = self.load_value
        elif offset == 0x04:
            offset_name = "TIM_CFG"
            value = self.config
        elif offset == 0x14:  # Write_only
            assert False
        elif offset == 0x20:  # Write_only
            assert False
        elif offset == 0x34:
            offset_name = "TIM_VALUE"
            value = self.counter

        else:
            value = 0
            offset_name = f"TIM_OFF_{offset}"
            value = super(ShannonTimer, self).hw_read(offset, size)

        self.log_read(value, size, offset_name)

        return value

    def hw_write(self, offset, size, value):

        if offset == 0x00:
            offset_name = "TIM_SET_VAL"
            self.load_value = value
            self.thread_lock.acquire()
            self.counter = value
            self.thread_lock.release()
        elif offset == 0x04:
            offset_name = "TIM_CFG"
            self.config = value
            # import IPython; IPython.embed()

            if self.config & IS_ENA:
                self.thread = Thread(
                    name=f"{self.name}_thread", target=self.timer_thread
                )
                self.thread.setDaemon(True)
                self.thread._shutdown = Event()
                self.thread.start()
            else:
                if self.thread is not None:
                    # This may have performance impact on frequent timer enable/disable
                    while self.thread.is_alive():
                        sleep(self.tick_time)
                    self.thread = None

        elif offset == 0x10:
            offset_name = "TIM_SET_DEC"
            assert value == 0 or value == 1
            self.decr_mode = value

        elif offset == 0x14:
            offset_name = "TIM_IRQ_ENA"
            self.irq_ena = value
            if value == 0x00:
                self.avatar.shannon.inject_irq(self.irq_num, 0)

        elif offset == 0x34:
            assert False
            offset_name = "TIM_VALUE"
            self.value = value
        else:
            offset_name = f"TIM_OFF_{offset}"

        self.log_write(value, size, offset_name)

        return True

    def timer_thread(self):
        # We use the host clock for advancing the timer.
        # While not accurate, it's enough for our purposes
        while self.config & IS_ENA:
            sleep(self.tick_time)
            self.thread_lock.acquire()
            if self.decr_mode == 0x1:
                self.counter -= self.tick_step
            else:
                self.counter += self.tick_step

            if self.counter <= 0 or self.counter >= 0xFFFFFFFF:
                if self.config & RELOAD:
                    self.counter = self.load_value
                else:
                    self.counter = 0
                if self.irq_ena and self.config & IS_ENA:
                    import logging

                    l = logging.getLogger()
                    # l.critical(f"Trigger IRQ for {self.name}")
                    self.avatar.shannon.inject_irq(self.irq_num, 1)
            self.thread_lock.release()

    def shutdown(self):
        self.config = self.config & 0xFFFFFFFD

    def __init__(self, name, address, size, tick_time=0.001, tick_step=0x100, **kwargs):
        super(ShannonTimer, self).__init__(name, address, size, **kwargs)

        self.irq_num = kwargs.get("irq")
        self.avatar = kwargs.get("avatar")
        self.tick_time = tick_time
        self.tick_step = tick_step

        self.thread = None
        self.thread_lock = Lock()

        self.load_value = 0x030BFFFD  # 0x00
        self.config = 0xFFFFFFFF  # 0x04
        self.irq_ena = 0x00000000  # 0x14
        self.counter = self.load_value  # 0x34
        self.decr_mode = 0x00

        self.read_handler[0:size] = self.hw_read
        self.write_handler[0:size] = self.hw_write
