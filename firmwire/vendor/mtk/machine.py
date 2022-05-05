## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import os
import sys
import struct
import fcntl
import logging
import time

from avatar2 import *

from firmwire.vendor.mtk.hw import *
from firmwire.vendor.mtk.consts import *
from firmwire.vendor.mtk.modkit import TaskMod
from firmwire.vendor.mtk.hooks import (
    TCC_Task_Ready_To_Scheduled_Return,
    dhl_print_hook,
    dhl_trace_hook,
    prompt_trace_hook,
    sys_trace_hook,
    NU_Set_Events_hook,
)
from firmwire.vendor.mtk.mtk_task import MtkTask, TASK_STRUCT_SIZE

from firmwire.util.port import find_free_port
from firmwire.emulator.firmwire import FirmWireEmu

log = logging.getLogger(__name__)


class MT6878Machine(FirmWireEmu):
    def __init__(self):
        super().__init__()

        self.instance_name = "MtkEMU"

        self._fuzzing = False
        self._current_task_name = None

        self.ports = {}

    def initialize(self, loader, args):
        if not super().initialize(loader):
            return False

        img_path = loader.path

        module = None
        for path in [args.injected_task, args.fuzz, args.fuzz_triage]:
            if path is None:
                continue

            module = self.modkit.find_module(path)

            if module is None:
                log.error(
                    "Unable to find module %s with search paths %s. Was it built?",
                    path,
                    [str(x) for x in self.modkit.get_search_paths()],
                )
                return None

        # Fast exit should only be enabled when fuzzing under AFL, not triaging
        if args.fuzz:
            os.environ["AFL_FAST_EXIT"] = "1"

        avatar = self.avatar

        self.ports["qemu_gdb"] = 3333
        self.ports["qemu_qmp"] = 3334

        # Allocate ports
        if args.consecutive_ports:
            log.info(
                f"Using {len(self.ports.keys())} consecutive ports, starting with {args.consecutive_ports}"
            )
            for port_id, name in enumerate(self.ports):
                self.ports[name] = args.consecutive_ports + port_id

        # used for unique temporary directories and shared memory queues for avatar
        self.instance_name = "MtkEMU" + str(self.ports["qemu_qmp"])

        additional_args = ["-cpu", "24Kc"]  # FIXME: horrible hack on qemu side
        additional_args += [
            "-drive",
            "if=none,id=drive0,file=%s,format=qcow2"
            % self.snapshot_manager.snapshot_qcow_path,
        ]

        # TODO: move to loader
        self.symbols = self.loader.symbols
        symbols_addr_to_name = {v: k for k, v in self.symbols.items()}

        symbols = self.symbols

        # this chunk is based heavily on shannon_emu's code
        if args.fuzz_input is not None or args.fuzz_crashlog_replay is not None:
            if args.fuzz_input is not None:
                log.info(f"Inputs will be provided via {args.fuzz_input}")
                os.environ["AFL_INPUT_FILE"] = args.fuzz_input

            if args.fuzz_crashlog_replay is not None:
                log.info(f"Replaying inputs from {args.fuzz_crashlog_replay}")
                os.environ["AFL_INPUT_REPLAY_FILE"] = args.fuzz_crashlog_replay

            if args.fuzz_crashlog_dir is not None:
                os.environ["AFL_PERSISTENT_CRASH_LOG_DIR"] = args.fuzz_crashlog_dir

            panic_addresses = [
                symbols["ex_reboot"],
                symbols["stack_system_error"],
                symbols["general_ex_handler"],
                symbols["general_ex_vector"],
                symbols["INT_EnterExceptionForOtherCore"],
                symbols["ERC_System_Error"],
            ]
            panic_addresses.append(symbols["_rst_swWdReset_aux"])
            for n in range(len(panic_addresses)):
                panic_addresses.append(panic_addresses[n] + 1)

            panic_addresses_fmt = ",".join([hex(x) for x in panic_addresses])

            log.info("AFL panic address set [%s]", panic_addresses_fmt)
            os.environ["AFL_PANIC_ADDR"] = panic_addresses_fmt

        qemu = avatar.add_target(
            PyPandaTarget,
            name=self.instance_name,
            entry_address=ROM_BASE_ADDR,
            gdb_executable="gdb-multiarch",
            # additional_args=['-smp', 'threads=2', '-cpu', '24Kc'], # TODO which cpu
            # additional_args=['-cpu', '24Kc'],
            additional_args=additional_args,
            gdb_port=self.ports["qemu_gdb"],
            qmp_port=self.ports["qemu_qmp"],
            # gdb_verbose=True,
            # log_items=['in_asm', 'int', 'exec', 'cpu', 'op', 'mmu', 'unimp'],
            log_file="/dev/stdout",
        )

        avatar.add_memory_range(
            ROM_BASE_ADDR, 0x2000000, name="ROM_LO", alias_at=0x90000000
        )
        # magical aliasing will happen in hacked panda
        avatar.add_memory_range(0x02000000, 0xE000000, name="RAM", alias_at=0x92000000)
        # 0x70000 -> 0x90070000 type mapping
        # avatar.add_memory_range(0x90000000, 0x2000000, name='ROM_HI',
        #                        file=modem_raw_img, file_offset=modem_raw_offset)

        # avatar.add_memory_range(0xbfc00000, 0x1000, name='init',
        #                       file='./init.bin')
        # avatar.add_memory_range(0x1f000000, 0x01000000, name='bootstack')
        # avatar.add_memory_range(0x1f000000, 0x01000000, name='RAM_1f00')

        # TODO: what is this exactly
        # L2CACHE_LOCK_DATA
        avatar.add_memory_range(0x951C0000, 0x8000, name="RAM_951c")
        # L2CACHE_LOCK_ZI
        # avatar.add_memory_range(0x951c6c00, 0x1140, name='RAM')

        # TODO: fairly random range, huge?
        avatar.add_memory_range(0x61300000, 0x5000000, name="RAM_6130")

        # TODO: lengths are wrong
        avatar.add_memory_range(0x9F000000, 0x800000, name="ISPRAM0")
        avatar.add_memory_range(0x9F100000, 0x800000, name="DSPRAM0")

        # MD writes exception info here
        avatar.add_memory_range(
            SMEM_USER_RAW_MDCCCI_DBG, CCCI_EE_SMEM_TOTAL_SIZE, name="RAW_MDCCCI_DBG"
        )

        self.apply_memory_map(self.loader.memory_map)

        # For Fuzzing Task Setup
        self.playground = self.avatar.add_memory_range(
            0x9F900000, 0x10000, name="PLAYGROUND_RWX_REGION", permissions="rwx"
        )
        # import IPython; IPython.embed()
        assert self.playground is not None

        if args.fuzz:
            log.info("Fuzzing mode active (no debug output)")
            self._fuzzing = True

        if args.fuzz_persistent:
            loops = args.fuzz_persistent

            # NOTE: you MUST set this before avatar.init_targets !
            os.environ["AFL_ENABLE_PERSISTENT_MODE"] = str(loops)
            log.info("Fuzzing in persistent mode with %d iterations ", loops)

        # hijack PANDA's signal handling. we know better
        def fake_signal_handler(*args, **kwargs):
            # print("HIJACKED ", repr(args), repr(kwargs))
            pass

        # VERY noisy
        self.guest_logger.add_ban_string("CCCI_FS")
        self.guest_logger.add_ban_string("CCCIFS")

        from pandare import Panda

        Panda.setup_internal_signal_handler = fake_signal_handler
        Panda._setup_internal_signal_handler = fake_signal_handler

        self.qemu = qemu
        avatar.init_targets()
        self.panda = qemu.pypanda
        # qemu.pypanda.disable_tb_chaining()

        if args.fuzz_triage:
            coverage_dir = self.workspace.path("/coverage")
            coverage_dir.mkdir()

            coverage_fn = coverage_dir.join(
                "coverage_" + os.path.basename(args.fuzz_input) + ".csv"
            )

            # TIP: if you want to see ALL basic blocks, including duplicates, pass {"full" : True}
            # Useful for spotting hot loops
            qemu.pypanda.load_plugin(
                "coverage", args={"filename": coverage_fn.to_path()}
            )
            log.info(
                "Triage mode active. Logging code coveage to %s", coverage_fn.to_path()
            )

        # coverage_fn = 'coverage.csv'
        # qemu.pypanda.load_plugin('coverage', args={"filename": coverage_fn})

        self.qemu.pypanda.physical_memory_write(
            ROM_BASE_ADDR, self.loader.rom_img_data()
        )

        self.add_debug_hooks()

        # Custom, non-function symbols

        # this is in stack_init_tasks, the first wait
        corewait_addr_code = symbols["corewait_addr_code"]  # 0x909869a6

        ptr_to_ltable = symbols["ptr_logical_data_item_table"]  # 0x638ebe68
        ptr_to_ltable = qemu.pypanda.physical_memory_read(ptr_to_ltable, 4)
        ptr_to_ltable = struct.unpack("<I", ptr_to_ltable)[0]

        ptr = symbols["ptr_sys_comp_config_tbl"]
        ptr = qemu.pypanda.physical_memory_read(ptr, 4)
        ptr = struct.unpack("<I", ptr)[0]
        symbols["sys_comp_config_tbl"] = ptr

        # Breakpoints for core sync loop

        def nvram_bp(x):
            tmp_ptr = qemu.pypanda.physical_memory_read(ptr_to_ltable, 4)
            ltable_addr = struct.unpack("<I", tmp_ptr)[0]
            # remove the flags from the nvram lock entry, which is encrypted
            for x in range(20):
                if x > 5:
                    assert False
                table_entry_size = 4 * 4 + 4 * 2 + 5 + 4 + 3
                table_entry_data = qemu.pypanda.physical_memory_read(
                    ltable_addr + x * table_entry_size, table_entry_size
                )
                table_entry = struct.unpack("<HHIIIHH5s4sIBBB", table_entry_data)
                if table_entry[0] == 0xF006:
                    # this is the NVRAM_LOCK entry
                    flags = table_entry[5]
                    assert flags & 0x2000  # FAULT_ASSERT
                    assert flags & 0x20  # MSP (tied to chip id)
                    flags = flags ^ 0x2020
                    qemu.pypanda.physical_memory_write(
                        ltable_addr + x * table_entry_size + 3 * 4 + 2 * 2,
                        struct.pack("<H", flags),
                    )
                    table_entry_data = qemu.pypanda.physical_memory_read(
                        ltable_addr + x * table_entry_size, table_entry_size
                    )
                    table_entry = struct.unpack("<HHIIIHH5s4sIBBB", table_entry_data)
                    assert table_entry[5] == flags
                    break

        nvram_ltable_init_code = symbols[
            "nvram_ltable_init_code"
        ]  # 0x90be97a0 # at the END of ltable init, convenient place to modify ltable?
        self.set_breakpoint(
            nvram_ltable_init_code, nvram_bp, temporary=True, continue_after=True
        )

        l1d_custom_dynamic_get_param_assert = symbols[
            "L1D_CustomDynamicGetParam_assert"
        ]

        def l1d_custom_assert_fix_stage2_bp(x):
            x.set_breakpoint(
                l1d_custom_dynamic_get_param_assert,
                l1d_custom_assert_fix_stage1_bp,
                temporary=True,
                continue_after=True,
            )

        def l1d_custom_assert_fix_stage1_bp(x):
            qemu.write_register("a0", 0)
            x.set_breakpoint(
                l1d_custom_dynamic_get_param_assert - 2,
                l1d_custom_assert_fix_stage2_bp,
                temporary=True,
                continue_after=True,
            )

        self.set_breakpoint(
            l1d_custom_dynamic_get_param_assert,
            l1d_custom_assert_fix_stage1_bp,
            temporary=True,
            continue_after=True,
        )

        # For printing trace entries, we hook dhl_internal_trace_impl, which gets only called if the trace check returns 0
        # For performance reasons, we implement this via a patch, rather than a breakpoint.
        if not self._fuzzing:
            newcode_ret0 = b"\x00\x6a" + b"\xa0\xe8\x00\x65"
            patchAddr = symbols["tst_trace_check_ps_filter_off"]
            qemu.pypanda.physical_memory_write(patchAddr, newcode_ret0)
        """    
        def tst_trace_check_ps_filter_off_bp(_):
            qemu.write_register('a0', 0)
            qemu.write_register('pc', qemu.read_register('ra'))
        if not self._fuzzing:
            self.set_breakpoint(symbols['tst_trace_check_ps_filter_off'], tst_trace_check_ps_filter_off_bp, continue_after=True)
        """

        breakpoints = {}

        # All hardcoded addresses for md1rom_A415FXXU1BUA1_2021-25-02_new (new A41 image)
        register_setting_hooks = [
            # mcu/common/interface/service/prbm/prbm.h -> prbm_config_t.prb_alloc_align check for 2
            # (corewait_addr_code-2, 'v0', 0),
            # dpcopro stuff
            # (0x90c9d482, 'v1', 0),
            # (0x9029e34a, 'v0', 0xff),
            # (0x9029e358, 'v1', 0),
            # waiting for other cores in INC_Initialize
            (symbols["INC_Initialize_corewait"], "v1", 0)
        ]

        def gen_setreg_bp(addr, reg_name, reg_val):
            def setreg_bp(self):
                print("reg set @ %08x (%s to %x)" % (addr, reg_name, reg_val))
                # time.sleep(1)
                qemu.write_register(reg_name, reg_val)
                # TODO: remove breakpoint!
                # qemu.remove_breakpoint(breakpoints[addr & ~1])

            return setreg_bp

        def corewait_stage2_bp(x):
            self.set_breakpoint(
                corewait_addr_code - 2,
                corewait_stage1_bp,
                temporary=True,
                continue_after=True,
            )

        def corewait_stage1_bp(x):
            qemu.write_register("v0", 0)
            self.set_breakpoint(
                corewait_addr_code,
                corewait_stage2_bp,
                temporary=True,
                continue_after=True,
            )

        self.set_breakpoint(
            corewait_addr_code - 2,
            corewait_stage1_bp,
            temporary=True,
            continue_after=True,
        )

        for addr, reg_name, reg_val in register_setting_hooks:
            self.set_breakpoint(
                addr & ~1,
                gen_setreg_bp(addr & ~1, reg_name, reg_val),
                temporary=True,
                continue_after=True,
            )

        def set_vpe_count(x):
            log.info("Quirk: Setting VPE count")

            # this is the address of the #VPEs synced
            # write to symbol inct_all_vpes_sync_count
            v0 = qemu.read_register("v0")
            qemu.pypanda.physical_memory_write(v0, struct.pack("<I", 4))

        # this is where we want to set the # of VPEs synced (since we only run 1)
        self.set_breakpoint(
            symbols["sync1_addr_code"],
            set_vpe_count,
            temporary=True,
            continue_after=True,
        )

        # Writing to PC does not seem to work in a panda hook. Working with breakpoints here
        skip_functions = frozenset(
            [
                symbols["SST_Secure_Algo"] + 1,  # FIXME: hack for a10s??
                symbols["SEJ_AES_HW_Kdf_Internal"] + 1,
                symbols["nvram_sec_check"] + 1,
                symbols["PMIC_Read_All"] + 1,
                symbols["MML1_RF_Wait_us"] + 1,
                # TODO: mutexes do not seem to be set up here
                symbols["ccismc_submit_ior"] + 1,  # symbols['enqueue_gpd']+1
            ]
        )

        def skip_function_bp(x):
            ra = qemu.read_register("ra")
            qemu.write_register("pc", ra)

        for addr in skip_functions:
            self.set_breakpoint(addr & ~1, skip_function_bp, continue_after=True)

        def exit_hook(self, env, tb, hook):
            print(
                f"[*] Hit manuall specified exit addr {tb.pc:#010x} -> {symbols_addr_to_name.get(tb.pc, 'unknown function')} (see exit_functions)"
            )
            self.qemu.pypanda.arch.dump_state(self.qemu.pypanda.get_cpu())
            # self.qemu.stop()
            # time.sleep(5)

        exit_functions = frozenset(
            [
                ### General error functions which we do not expect to hit
                # If we hit those, we would like to know about them
                symbols["ex_reboot"] + 1,
                symbols["stack_system_error"] + 1,
                symbols["general_ex_handler"],
                symbols["general_ex_vector"],
                symbols["INT_EnterExceptionForOtherCore"] + 1,
                symbols["ERC_System_Error"] + 1,
                ### Looping and Task initialization Progress Tracking
                # IdleTask while(1) loop after DCM_Service_Handler is done
                # 0x90e59f70+1,
                # IdleTask1 while(1) loop after DCM_Service_Handler_Slave is done
                # 0x90e59fc6+1,
                # mm_task_main just before calling msg_receive_extq
                # 0x90b73876+1,
                # -> hit! (with activated MM task)
                # cc_task_main just before calling msg_receive_extq
                # 0x90147a86+1,
                # -> hit! (with activated CC task)
                # sms_task_main just before calling msg_receive_extq
                # 0x90e253fa+1,
                # -> hit! (with activated SMS task)
                ### Temporary progress tracking for message sending
                # CC task after msg_receive_extq
                # 0x90147a8c+1,
                ### Temporary progress tracking for task init
                # symbols['nvram_write_bitmap_into_file'] + 1,
                # symbols['custom_default_mode_config'] + 1,
                # 0x90bef07a+1, <- this and all the above go through
                ### Useful places doing low-level init which we need to reach
                # symbols['stack_init_tasks']+1# , symbols['stack_init_comp_info']+1# , symbols['stack_init']+1
                # symbols['mainp']+1,
            ]
        )
        if not self._fuzzing:
            for addr in exit_functions:
                self.add_panda_hook(addr & ~1, exit_hook)

        def read_phy_string_2(self, offset):
            sstr = bytes()
            while True:
                c = self.qemu.pypanda.physical_memory_read(offset, 1)
                if c == b"\x00":
                    return sstr
                sstr = sstr + c
                offset = offset + 1

        # global task_names
        task_names = []
        task_tbl_base = symbols["sys_comp_config_tbl"]
        task_table = qemu.pypanda.physical_memory_read(
            task_tbl_base, 0x20 * self.modem_soc.KAL_TOTAL_TASKS
        )
        task_id_by_name = {}

        for n in range(self.modem_soc.KAL_TOTAL_TASKS):
            (
                name_ptr,
                qname_ptr,
                priority,
                stack_size,
                create_func,
                int_ram_stack,
                ext_qsize,
                int_qsize,
                boot_mode,
                affin_attr,
                affin_dyn,
                a,
                b,
                affin_group,
            ) = struct.unpack("<IIIIIBBBBBBBBI", task_table[n * 0x20 : (n + 1) * 0x20])
            # patch everything to run on core 1
            taskname = read_phy_string_2(self, name_ptr)
            task_names.append(taskname.decode())
            if len(taskname) and n != 0:  # FIXME: bleh
                task_id_by_name[taskname.decode()] = n - 1
            if taskname in [b"DPCOPRO", b"LHIFCORE"]:
                # disable annoying tasks
                # (without this, a21 boot fails)
                qemu.pypanda.physical_memory_write(
                    task_tbl_base + (0x20 * n) + 16, b"\xf0\xf0\xf0\xf0"
                )
                pass
            if create_func != 0xF0F0F0F0 and len(taskname):
                print("task: " + taskname.decode() + " has affin " + str(affin_attr))
            if taskname[1:] == b"IDLE":
                # but not the per-core idle tasks
                continue
            # qemu.pypanda.physical_memory_write(0x90f4fb50 + (0x20 * n) + 24, b'\x01')

        # Before task information is first read, adjust affinities such that all tasks are bound to core 0
        def set_task_affinities_hook(self, env, tb, hook):
            INFO_STRUCT_SIZE = 0x20
            OFFSET_comp_affinity_attribute = 24
            tbl_base = symbols["sys_comp_config_tbl"]

            task_name_by_id = {v: k for k, v in task_id_by_name.items()}

            for i in range(self.modem_soc.KAL_TOTAL_TASKS - 1):
                taskinfo_start = tbl_base + (i + 1) * INFO_STRUCT_SIZE

                task_name = task_name_by_id.get(i)
                if task_name is None:
                    log.info(f"Activating unknown task with ID {i} via affinity hook")
                    aff = self.modem_soc.AFFINITY_ONLY_CPU_0
                elif task_name in TASKNAMES_DEACTIVATED:
                    log.info(f"Deactivating {task_name} via affinity hook")
                    aff = self.modem_soc.AFFINITY_ONLY_CPU_1
                else:
                    log.info(f"Activating {task_name} via affinity hook")
                    aff = self.modem_soc.AFFINITY_ONLY_CPU_0
                qemu.pypanda.physical_memory_write(
                    taskinfo_start + OFFSET_comp_affinity_attribute, aff
                )

        self.add_panda_hook(symbols["stack_init_comp_info"], set_task_affinities_hook)

        if module is not None:
            task = TaskMod.FromFile(module.elf_path, module.bin_path)

            inject_ok = self.inject_task(task, task_id_by_name["0IDLE"])
            assert inject_ok
            print("After injecting task")

        # def dbg_hook(self, env, tb, hook):
        #    global called_init_hooks
        #    called_init_hooks.append(self.qemu.pypanda.arch.get_reg(env, 'v0')&~1)
        #    # import IPython; IPython.embed()
        # self.add_panda_hook(0x90989c48, dbg_hook)

        # any errors in errc_evth_inevt_handler and friends end up here
        # add a breakpoint so we can skip the assert
        def skip_assert_bp(x):
            print("*** skipping assert")
            qemu.write_register("pc", symbols["errc_evth_inevt_handler_end"] + 1)

        self.set_breakpoint(
            symbols["errc_evth_inevt_handler_assert"],
            skip_assert_bp,
            continue_after=True,
        )

        if not self._fuzzing:
            self.add_panda_hook(symbols["dhl_internal_trace_impl"], dhl_trace_hook)
            self.add_panda_hook(symbols["dhl_print"], dhl_print_hook)
            self.add_panda_hook(symbols["dhl_print_string"], dhl_print_hook)
            self.add_panda_hook(symbols["kal_prompt_trace"], prompt_trace_hook)
            self.add_panda_hook(symbols["tst_sys_trace"], sys_trace_hook)
            self.add_panda_hook(symbols["tst_sysfatal_trace"], sys_trace_hook)
            self.add_panda_hook(symbols["NU_Set_Events"], NU_Set_Events_hook)
            self.add_panda_hook(
                symbols["TCC_Task_Ready_To_Scheduled_Return"],
                TCC_Task_Ready_To_Scheduled_Return,
            )

            """
            def buffer_print_hook(self, env, tb, hook):
                a0 = self.qemu.pypanda.arch.get_reg(env, 'a0')
                print("free_ctrl_buffer_ext: buffer is %08x" % a0)
            self.add_panda_hook(symbols['free_ctrl_buffer_ext'], buffer_print_hook)
            """

            """def geminisusp_hook(self, env, tb, hook):
                v0 = self.qemu.pypanda.arch.get_reg(env, 'v0')
                print("gemini susp returned %d" % v0)
            self.add_panda_hook(0x90519d34, geminisusp_hook)"""

        fcntl.fcntl(sys.stdout.fileno(), fcntl.F_SETFL, 0)  # remove non-block

        # @qemu.pypanda.ppp("callstack_instr", "on_call")
        # def on_call(cpu, func):
        #    print(f"Call to 0x{func:x}")

        # @qemu.pypanda.cb_before_block_exec
        def on_before_block_exec(cpu, tb):
            if tb.pc in symbols_addr_to_name:
                caller = self.qemu.pypanda.arch.get_reg(cpu, "ra")
                print(f"FN: {symbols_addr_to_name[tb.pc]} from %x" % caller)
            # else:
            #    print(f"BB exec 0x{tb.pc:x}")

        if False:  # TODO: proper debug hook for function logging
            self.qemu.pypanda.cb_before_block_exec(on_before_block_exec)

        # @qemu.pypanda.cb_before_block_translate
        # def on_before_block_translate(cpu, addr):
        #    print(f"BB translate 0x{addr:x}")

        self.panda.athread.warned = True

        return True

    def read_phy_string(self, offset):
        sstr = bytes()
        while True:
            c = self.qemu.pypanda.physical_memory_read(offset, 1)
            if c == b"\x00":
                return sstr
            sstr = sstr + c
            offset = offset + 1

    def add_debug_hooks(self):
        def handleassert(cpustate, string_ptr, lineno):
            filename = b""
            while True:
                c = self.qemu.pypanda.physical_memory_read(
                    string_ptr + len(filename), 1
                )
                if c == b"\x00":
                    break
                filename = filename + c
            self.qemu.pypanda.arch.dump_state(cpustate)
            print("PC: 0x%x" % self.qemu.pypanda.arch.get_pc(cpustate))
            print("assert failed (break): " + repr(filename) + ":" + str(lineno))
            # self.qemu.stop()

        def preexception(cpustate, idx):
            # print(cpustate)
            print(f"Exception no: {idx}")
            if idx == 18:  # qemu's mips break
                # assume it's an assert for now
                string_ptr = self.qemu.pypanda.arch.get_reg(cpustate, "a0")
                lineno = self.qemu.pypanda.arch.get_reg(cpustate, "a1")
                handleassert(cpustate, string_ptr, lineno)
                return idx
            if idx == 28:  # unmapped read
                self.qemu.pypanda.arch.dump_state(cpustate)
                print("PC: 0x%x" % self.qemu.pypanda.arch.get_pc(cpustate))
                print("#### Crashed because of an unmapped access ####")
                # self.qemu.stop()
                # import IPython; IPython.embed()

            return idx

        if not self._fuzzing:
            self.qemu.register_callback("before_handle_exception", preexception)

        def handle_mmio_after_read(
            cpustate, arg1=None, arg2=None, arg3=None, arg4=None
        ):
            print(
                f"handle_mmio_after_read: {self.qemu.pypanda.current_pc(cpustate):#010x}"
            )
            # import IPython; IPython.embed()

        # self.qemu.register_callback('mmio_after_read', handle_mmio_after_read)

        def handle_mmio_before_write(
            cpustate, arg1=None, arg2=None, arg3=None, arg4=None
        ):
            print(
                f"handle_mmio_before_write: {self.qemu.pypanda.current_pc(cpustate):#010x}"
            )
            # import IPython; IPython.embed()

        # self.qemu.register_callback('mmio_before_write', handle_mmio_before_write)

        # @self.qemu.pypanda.ppp("callstack_instr", "on_call")
        # def on_call(cpu, func):
        #    print(f"Call to 0x{func:x}")
        # self.qemu.register_callback('callstack_instr', on_call)

    # Override breakpointing to account for compressed functions
    def set_breakpoint(self, address, handler, temporary=False, **kwargs):
        if address & 1:
            new_address = address & ~1
            log.warning(
                "Cannot set breakpoints on odd addresses in MIPS16e mode. Adjusting %08x -> %08x",
                address,
                new_address,
            )
            address = new_address

        return super().set_breakpoint(address, handler, temporary=temporary, **kwargs)

    def restore_snapshot(self, snapshot_name):
        # MTK snapshot restoring is MESSED UP!
        # This is some whacky stuff to make restores work. I
        # I suspect that our MTK machine introduced a bug into panda and some global state isn't being captured

        log.warning("MTK snapshot quirk: First restore...")
        super().restore_snapshot(snapshot_name)

        log.warning("MTK snapshot quirk: First execution...")
        self.qemu.cont(blocking=False)

        for i in range(5):
            log.warning("MTK snapshot quirk: waiting for target to crash...")
            time.sleep(1)

        log.warning("MTK snapshot quirk: Stopping target...")
        self.qemu.stop(blocking=True)

        log.warning("MTK snapshot quirk: Second restore...")
        super().restore_snapshot(snapshot_name)

        log.warning("MTK snapshot quirk: finished...")

    def inject_task(self, task, idx, prio=None):
        """
        injects a task info in sys_comp_config_tbl at given idx or by name
        """

        assert type(task) == TaskMod
        log.info(f"Creating task for ID {idx}")

        if task.address != 0:
            log.error("Mods must be position independent code (-fPIE)!")
            return False

        task = task.rebase(self.playground.address)

        # inject code
        self.qemu.write_memory(task.address, len(task.data), task.data, raw=True)

        # perform dynamic linking to baseband symbols and functions
        for sym_name, kw in task.symbols.items():
            # sym = self.symbol_table.lookup(sym_name, single=True)
            # FIXME: mips16 vs mips32 |1 bit
            # TODO: use symbol_table
            if sym_name not in self.symbols:
                log.error(
                    "Unable to resolve requested dynamic modkit symbol %s", sym_name
                )
                return False

            sym_type = kw["type"]
            # kw["symbol"] = sym

            write_address = kw["write_address"]

            addr = self.symbols[sym_name]
            if sym_type == "FUNC":
                # XXX: this assumes all requested symbols are mips16e functions!!!
                addr |= 1

            # TODO: symbol size checking
            log.info(
                "Resolved dynamic symbol %s (0x%08x) -> 0x%08x (%s)",
                sym_name,
                addr,
                write_address,
                sym_type,
            )
            self.qemu.wm(write_address, 4, struct.pack("<I", addr), raw=True)

        # resolve a free place in OSTASK_ARR
        task_comp_info_arr = self.symbols["sys_comp_config_tbl"]

        task_struct_addr = task_comp_info_arr + (idx + 1) * TASK_STRUCT_SIZE

        task_struct_data = self.qemu.rm(task_struct_addr, TASK_STRUCT_SIZE, raw=True)

        task_struct = MtkTask(raw_bytes=task_struct_data)

        if any(b != 0 for b in task_struct_data):
            log.warning("Overwriting an existing task")

        task_struct.name_ptr = task.name_addr
        task_struct.main_fn = task.main_addr
        task_struct.stacksize = task.stack_size
        if prio is not None:
            task_struct.sched_prio = prio

        log.info(
            "Injecting Task at 0x{:x} (stack: 0x{:x})".format(
                task.address, task.stack_base
            )
        )
        from binascii import hexlify

        print(
            f"Injecting contents to {task_struct_addr:x}: {hexlify(task_struct.data)}"
        )
        self.qemu.wm(
            task_struct_addr, len(task_struct.data), task_struct.data, raw=True
        )

        return task.address
