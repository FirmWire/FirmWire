#!/usr/bin/env python3
## Copyright (c) 2022, Team FirmWire
## SPDX-License-Identifier: BSD-3-Clause
import argparse
import sys
import os
import re
import logging

import firmwire
from firmwire.util.param import ParamValidator
from firmwire.util.misc import arg_snapshot, download_url
from firmwire.emulator.init import MachineInitParams
from _version import __version__

log = logging.getLogger("firmwire")

def get_args():
    print(r"              ___            __      _                          ")
    print(r"-.     .-.   | __|(+) _ _ _ _\ \    / /(+) _ _ ___    .-.     .-")
    print(r"  \   /   \  | _|  | | '_| '  \ \/\/ /  | | '_/ -_)  /   \   /  ")
    print(r"   '-'     '-|_|   | |_| |_|_|_\_/\_/   | |_| \___|-'     '-'   ")
    print(r"             ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~   v%s" % (__version__))
    print(r"                A  baseband  analysis  platform")
    print("                   https://github.com/FirmWire")
    print("")

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "modem_file", type=str, default=None, help="Modem file to emulate"
    )
    parser.add_argument(
        "-w",
        "--workspace",
        type=str,
        default=None,
        help="FirmWire workspace path. Default is adjacent to the modem file itself. Use the value 'SCRATCH' for an ephemeral workspace",
    )
    parser.add_argument("-S", "--stop", action="store_true", help="Stop CPU at startup")
    parser.add_argument(
        "-s",
        "--gdb-server",
        type=int,
        nargs="?",
        const=1234,
        help="Start GDB server on TCP port. Default is 1234. NOTE: this is a minimal GDB stub.",
    )
    parser.add_argument(
        "--snapshot-at",
        type=arg_snapshot,
        help="Snapshot when an address is reached (e.g. --snapshot-at 0x1234,snapshot_name). Snapshots are saved in the current workspace.",
    )
    parser.add_argument(
        "--console",
        action="store_true",
        help="After booting, spawn an IPython remote kernel that can be "
        "connected to from another terminal using `jupyter console --existing`. It's recommended you pair this with --stop",
    )
    parser.add_argument(
        "-t",
        "--module",
        **MachineInitParams.param_arg_spec("injected-task"),
        dest="injected_task",
        help="Module to inject into baseband memory",
    )

    parser.add_argument(
        "--restore-snapshot", type=str, help="Restore a snapshot by name"
    )
    parser.add_argument(
        "--consecutive-ports",
        **MachineInitParams.param_arg_spec("--consecutive-ports"),
        help=f"Choose consecutive ports for the any listening sockets (e.g. QEMU's GDB & QMP), starting with the port provided.",
    )

    fuzzopts = parser.add_argument_group("fuzzing options")

    fuzzopts.add_argument(
        "--fuzz",
        **MachineInitParams.param_arg_spec("--fuzz"),
        help="Inject and invoke the passed AFL fuzz task module (headless)."
    )
    fuzzopts.add_argument(
        "--fuzz-triage",
        **MachineInitParams.param_arg_spec("--fuzz-triage"),
        help="Invoke the fuzzer, but without an AFL front end. Enables debug hooks and saves code coverage as a CSV in the workspace (${workspace}/coverage/coverage_${fuzz_input}.csv).",
    )
    fuzzopts.add_argument(
        "--fuzz-input",
        **MachineInitParams.param_arg_spec("--fuzz-input"),
        help="Path the fuzzer test case (use @@ with AFL) or just the path to a single test file.",
    )
    fuzzopts.add_argument(
        "--fuzz-persistent",
        **MachineInitParams.param_arg_spec("--fuzz-persistent"),
        help="Enable persistent fuzzing with a loop count as the argument.",
    )
    fuzzopts.add_argument(
        "--fuzz-crashlog-dir",
        **MachineInitParams.param_arg_spec("--fuzz-crashlog-dir"),
        help='Save input-file sequences that led to a crash during persistent mode fuzzing, effectively enabling "stateful" fuzzing. The log file starts with a MD5 hash of the last input (the one causing the crash). Binary format: ([u32:length][u8[]:testbytes])+',
    )

    fuzzopts.add_argument(
        "--fuzz-crashlog-replay",
        **MachineInitParams.param_arg_spec("--fuzz-crashlog-dir"),
        help="Replay a persistent-mode crash log written with --fuzz-crashlog-dir.",
    )

    ### Loader args

    def fix_up_params(name, params):
        if params["required"]:
            params["required"] = False

            if params["help"] is None:
                params["help"] = "REQUIRED BY LOADER"
            else:
                params["help"] += " (REQUIRED BY LOADER)"

    loader_specific_args = {}
    for loader in sorted(firmwire.get_loaders(), key=lambda x: x.NAME):
        group = parser.add_argument_group(loader.NAME + " loader arguments")
        # create a namespaced parser that isolates loader-specific parameters
        loader_specific_args[loader.NAME] = ParamValidator(
            arg_name_prefix=(loader.NAME + "-loader-")
        ).build_params(loader.LOADER_ARGS)
        loader_specific_args[loader.NAME].copy_params_to_parser(
            group, param_hook=fix_up_params
        )

    ##############################
    ## Dev-focused options
    ## (may change or disappear)
    ##############################

    devopts = parser.add_argument_group("developer options")
    devopts.add_argument(
        "--debug", action="store_true", help="Enable FirmWire debugging"
    )
    devopts.add_argument(
        "--debug-peripheral",
        nargs="+",
        action="append",
        help="Enable debug logging for specified peripheral by names. Multiple peripherals can be selected. Pass 'ALL' to enable debugging for all peripherals.",
    )
    devopts.add_argument(
        "--avatar-debug", action="store_true", help="Enable debug logging for Avatar2"
    )
    devopts.add_argument(
        "--avatar-debug-memory",
        action="store_true",
        help="Enable Avatar2 remote memory debugging (useful when peripherals throw exceptions)",
    )
    devopts.add_argument(
        "--unassigned-access-log",
        action="store_true",
        help="Print log messages when memory accesses to unmapped memory occur.",
    )
    devopts.add_argument(
        "--raw-asm-logging",
        action="store_true",
        **MachineInitParams.param_arg_spec("--raw-asm-logging"),
        help="Print assembly basic blocks as QEMU executes them. Useful for spotting infinite loops.",
    )
    devopts.add_argument(
        "--trace-bb-translation",
        action="store_true",
        help="Print the address of each new basic block, useful to see BBs reached during fuzzing.",
    )
    parser.add_argument(
        "--full-coverage",
        action="store_true",
        help="Enable *full* coverage collection (logs every executed basic block)",
    )

    ### Parse
    args = parser.parse_args()

    params = MachineInitParams()

    for k, v in vars(args).items():
        if params.has(k) and v is not None:
            params.set(k, v)

    params.validate(arg_parser=parser)

    for name, validator in loader_specific_args.items():
        loader_specific_args[name] = validator.extract_relevant_params(args)

    return args, loader_specific_args, params


def main() -> int:
    args, loader_specific_args, init_params = get_args()

    firmwire.util.logging.setup_logging(
        debug=args.debug,
        enable_colors=sys.stdout.isatty(),
        show_package=True,
        avatar_debug=args.avatar_debug,
    )

    modem_file = args.modem_file

    if modem_file.startswith("http"):
        filename = download_url(modem_file)

        if filename is None:
            return 1

        modem_file = filename

    if not os.access(modem_file, os.R_OK) or not os.path.isfile(modem_file):
        log.error("Missing modem file: %s", modem_file)
        return 1

    if args.workspace:
        if args.workspace == "SCRATCH":
            workspace = firmwire.ScratchWorkspace()
        else:
            workspace = firmwire.Workspace(args.workspace)
    else:
        workspace = firmwire.Workspace(modem_file + "_workspace")

    workspace.create()

    loader = firmwire.loader.load_any(
        modem_file,
        workspace,
        keep_trying=True,
        loader_specific_args=loader_specific_args,
    )

    if loader is None:
        log.error("Failed to load firmware")
        return 1

    machine = loader.get_machine()
    machine.modkit.append_search_path("./modkit/%s/build" % (loader.NAME))
    machine.modkit.append_search_path("./")

    log.info("FirmWire initializing %s", type(machine).__name__)

    if not machine.initialize(loader, init_params):
        log.error("Machine failed to initialize")
        return 1

    log.info("Machine initialization time took %.2f seconds", machine.time_running())

    if args.restore_snapshot:
        machine.restore_snapshot(args.restore_snapshot)

    # MUST come after initialization (needs a valid QEMU instance)
    if args.snapshot_at:
        machine.snapshot_state_at_address(
            args.snapshot_at[0],
            args.snapshot_at[1],
            reason="Snapshot at command line",
            once=True,
        )

    # machine logging
    if machine.qemu.protocols.remote_memory:
        if args.avatar_debug_memory:
            machine.qemu.protocols.remote_memory.log.setLevel(logging.DEBUG)
        else:
            machine.qemu.protocols.remote_memory.log.setLevel(logging.WARNING)

    if args.debug_peripheral:
        # flatten list of lists
        for name in [item for sublist in args.debug_peripheral for item in sublist]:
            try:
                if name == "ALL":
                    for per_name, _ in machine.get_peripherals().items():
                        machine.set_peripheral_log_level(per_name, logging.DEBUG)
                else:
                    machine.set_peripheral_log_level(name, logging.DEBUG)
            except KeyError:
                log.error("Unknown peripheral '%s'", name)
                return 1

    if args.unassigned_access_log:
        machine.register_unassigned_access_callbacks()

    if args.trace_bb_translation:
        machine.register_basic_block_trace()

    if args.gdb_server:
        machine.spawn_gdb_server(args.gdb_server)

    if loader.NAME == "shannon":
        # With shannon we can inject tasks overwriting the old one, even after snapshot restores for quick dev
        # NOTE: if you inject a task AFTER the task boot up phase it WILL NOT ever run. You will need
        # to use GLINK to dynamically register a task. GLINK would need have been loaded from the start in that case
        injection_modules = [args.fuzz, args.fuzz_triage]
        if type(args.injected_task) != type(None):
            if ',' in args.injected_task:
                args.injected_task = args.injected_task.split(',')
                injection_modules.extend(list(args.injected_task))
            else:
                injection_modules.append(args.injected_task)
        for module_name in injection_modules:
            if module_name is None:
                continue
            if not machine.load_and_inject_task(module_name):
                print("loaded task: " + module_name)

        machine.print_task_list()

    log.info("Starting emulator %s", machine.instance_name)
    machine.start(start_suspended=args.stop, console=args.console)


if __name__ == "__main__":
    sys.exit(main())

