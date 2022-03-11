# Command Line Interface Reference

This part of our documentation works as quick-reference to all the `firmwire.py` and `firmwire_dev.py` CLI arguments, and provides links about where they are covered.

## firmwire.py arguments

| Argument                                      | Covered in                                | Description                                                                                                      |
| --------------------------------------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `modem_file`                                  | [Getting Started](getting_started.md)     | The modem file FirmWire shall create an emulation environment for. Only mandatory argument(!)                    |
| `--consecutive-ports CONSECUTIVE_PORTS`       | [Getting Started](getting_started.md)     | Choose consecutive ports for the any listening sockets (e.g. QEMU's GDB & QMP), starting with the port provided. |
| `-h/--help`                                   | [CLI reference](cli_reference.md)         | Show help for for different cli flags on commandline                                                             |
| `-w/--workspace WORKSPACE`                    | [Workspaces](workspaces.md)               | Path to the workspace to use                                                                                     |
| `--snapshot-at SNAPSHOT_AT`                   | [Workspaces](workspaces.md)               | Address and name for taking a snapshot. (Syntax: address,name)                                                   |
| `--restore-snapshot SNAPSHOT_NAME`            | [Workspaces](workspaces.md)               | Name of snapshot to be restored                                                                                  |
| `-t/--module INJECTED_TASK`                   | [Modkit](modkit.md)                       | Module / Task to be injected to the baseband modem                                                               |
| `-S/--stop`                                   | [Interactive exploration](interactive.md) | Stop CPU after initializing the Machine. Useful for interactive exploration.                                     |
| `--interactive`                               | [Interactive exploration](interactive.md) | Inject GLINK into the baseband for interactive exploration                                                       |
| `--ipython-kernel`                            | [Interactive exploration](interactive.md) | Spawn an ipython remote kernel that can be connected to from another terminal using `jupyter console --existing` |
| `--fuzz FUZZ`                                 | [Fuzzing](fuzzing.md)                     | Inject and invoke the passed AFL fuzz task module (headless).                                                    |
| `--fuzz-input FUZZ_INPUT`                     | [Fuzzing](fuzzing.md)                     | Path the AFL test case (@@ should be sufficient) or just the path to a single test file.                         |
| `--fuzz-triage FUZZ_TRIAGE`                   | [Fuzzing](fuzzing.md)                     | Invoke the fuzzer, but without an AFL front end. Enables debug hooks and saves code coverage.                    |
| `--fuzz-persistent FUZZ_PERSISTENT`           | [Fuzzing](fuzzing.md)                     | Enable persistent fuzzing with a loop count as the argument.                                                     |
| `--fuzz-crashlog-dir FUZZ_CRASHLOG_DIR`       | [Fuzzing](fuzzing.md)                     | Folder to which logs of all testcases (length testcase) for a crashing run in persistent mode                    |
| `--fuzz-crashlog-replay FUZZ_CRASHLOG_REPLAY` | [Fuzzing](fuzzing.md)                     | Replay a persistent-mode crash trace written with fuzz-crashcase-dir.                                            |
| `--fuzz-state-addr-file FUZZ_STATE_ADDR_FILE` | [Fuzzing](fuzzing.md)                     | Textfile containing the hex-addresses of state-variables                                                         |
| `--full-coverage`                             | [Fuzzing](fuzzing.md)                     | Enable *full* coverage collection (logs every executed basic block)                                              |
| `--shannon-loader-nv_data NV_DATA`            | TBD                                       | (Shannon only) Specify the NV_DATA to be used                                                                    |




## firmwire_dev.py arguments

Note: These arguments are mostly useful for development and debugging. As of now, they are part of `firmwire.py`, but will be moved to a custom `firmwire_dev.py` interface to clearly distinguish developer and user features in a future iteration of FirmWire.

| Argument                  | Covered in | Description                                                                               |
| ------------------------- | ---------- | ----------------------------------------------------------------------------------------- |
| `--debug`                 | TBD        | Enable FirmWire debugging                                                                 |
| `--debug-peripheral`      | TBD        | Enable debugging for specified peripheralas                                               |
| `--avatar-debug`          | TBD        | Enable debug logging for Avatar2                                                          |
| `--avatar-debug-memory`   | TBD        | Enable Avatar2 remote memory debugging (useful when Peripherals crash)                    |
| `--unassigned_access_log` | TBD        | Print log messages when memory accesses to undefined memory occur                         |
| `--raw-asm-logging`       | TBD        | Print assembly basic blocks as QEMU executes them. Useful for determining infinite loops. |
| `--trace-bb-translation`  | TBD        | Print the address of each new Basic Block, useful to eval BBs reached during fuzzing.     |