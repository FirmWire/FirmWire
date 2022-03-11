## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import struct

from .queue import QUEUE_STRUCT_SIZE, QUEUE_NAME_PTR_OFFSET
from .task import Task
from firmwire.util.panda import read_cstring_panda


class ShannonOSI:
    def get_task_name_by_id(self, task_id):
        task_arr = self.symbol_table.lookup("SYM_TASK_LIST").address

        if task_arr is None:
            return None

        task_struct = self._read_task(task_arr, task_id)

        if task_struct.name_ptr == 0:
            return None

        task_struct.name = read_cstring_panda(self.panda, task_struct.name_ptr)
        return task_struct

    def get_current_task_id(self):
        sym = self.symbol_table.lookup("SYM_CUR_TASK_ID", single=True)

        if sym is None:
            return None

        return struct.unpack("I", self.panda.physical_memory_read(sym.address, 4))[0]

    def get_current_task_name(self, cpustate):
        tid = self.get_current_task_id()

        if tid is None:
            return "ERROR_MISSING_SYM"

        name = self.get_sch_task_name_by_id(tid)

        if name == "ERR_NO_TASK":
            return "NO_TASK"
        else:
            return name

    def get_sch_task_name_by_id(self, task_id):
        sched_task_table = self.symbol_table.lookup("SYM_SCHEDULABLE_TASK_LIST")

        if task_id < 0 or task_id > 0x420:
            task_name = "ERR_INVALID_TASK_ID(%d)" % task_id
        elif task_id == 0x420:
            task_name = "ERR_NO_TASK"
        elif sched_task_table == None:
            task_name = "ERR_UNRESOLVABLE_TASK_NAME(%d)" % task_id
        else:
            task_struct_p = self.panda.physical_memory_read(
                sched_task_table.address + task_id * 4, 4
            )
            task_struct_p = struct.unpack("I", task_struct_p)[0]

            task_magic = self.panda.physical_memory_read(
                task_struct_p + self.task_layout.SUBTASK_MAGIC_OFFSET, 4
            )

            if task_magic[::-1] != b"TASK":
                return "ERR_INVALID_TASK_MAGIC(%d)" % (task_id)

            task_struct_upper_p = self.panda.physical_memory_read(
                task_struct_p + self.task_layout.SUBTASK_TASK_P_OFFSET, 4
            )
            task_struct_upper_p = struct.unpack("I", task_struct_upper_p)[0]

            if task_struct_upper_p != 0:
                task = self._read_task(task_struct_upper_p)
                task_name = read_cstring_panda(self.panda, task.name_ptr)
            else:
                # truncate to the size of the task name
                # This is not the ideal name, but its good enough
                task_name = read_cstring_panda(
                    self.panda, task_struct_p + self.task_layout.SUBTASK_NAME_OFFSET
                )[: self.task_layout.SUBTASK_NAME_SIZE]

            if len(task_name) == 0:
                task_name = "TASK_NAME_BLANK(%d)" % task_id

        return task_name

    def _read_task(self, address, idx=0):
        offset = address + idx * self.task_layout.SIZE()
        task_struct_data = self.panda.physical_memory_read(
            offset, self.task_layout.SIZE()
        )

        return Task(offset, self.task_layout, raw_bytes=task_struct_data)

    def get_queues(self):
        return self._get_object_array(
            "SYM_QUEUE_LIST",
            self.pal_queueid2name,
            lambda name: name.startswith("ERR_"),
        )

    def get_tasks(self):
        return self._get_object_array(
            "SYM_TASK_LIST", self.get_task_name_by_id, lambda name: name is None
        )

    def _get_object_array(self, symbol, fn, stop_fn):
        sym = self.symbol_table.lookup(symbol, single=True)

        if sym is None:
            return []

        items = []

        idx = 0
        while True:
            obj = fn(idx)

            if stop_fn(obj):
                break

            items += [obj]
            idx += 1

        return items

    def pal_queueid2name(self, qid):
        sym = self.symbol_table.lookup("SYM_QUEUE_LIST", single=True)

        if sym is None:
            return "ERR_MISSING_SYM"

        queue_struct = self.panda.physical_memory_read(
            sym.address + qid * QUEUE_STRUCT_SIZE, QUEUE_STRUCT_SIZE
        )
        (name_p,) = struct.unpack(
            "I", queue_struct[QUEUE_NAME_PTR_OFFSET : QUEUE_NAME_PTR_OFFSET + 4]
        )

        if name_p == 0:
            return "ERR_OUT_OF_BOUNDS"

        return read_cstring_panda(self.panda, name_p)
