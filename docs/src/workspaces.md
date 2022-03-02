# Workspaces

FirmWire uses workspaces tied to the specific firmware file under analysis.
These workspaces contain a variety of useful files, most notably logs emitted by the avatar2-orchestration, the configurable machine definition, and a qcow2-image used for FirmWire's snapshotting mechanism, as well as vendor-specific files and directories.

By default, FirmWire creates a workspace at the very same directory where the modem file is located at, but this behavior can be overriden via the `-w/--workspace` command line flag.

## Snapshots

One of FirmWire's convenience features is snapshotting, which is implemented on top of QEMU. Besides storing the emulation machine state in QEMU's `qcow2` image format, FirmWire also saves the state of used python peripherals in auxiliary `.snapinfo` files. 

To take a snapshot use the `--snapshot-at` commandline argument or call the `snapshot()` method during [interactive](interactive.md) exploration.
Presume you want to take a snapshot with the name `my_first_snapshot` at address `0x464d5752`.
For taking the snapshot from commandline, simply run `./firmwire.py --snapshot-at 0x464d5752,my_first_snapshot modem_file`.
When using interactive exploration, you will have directly access to the python `machine` object via `self`. Make sure to stop execution at the desired address (for instance by setting a breakpoint), and then execute: `self.snapshot("my_first_snapshot")`. 
Alternatively, if you don't want to manually steer execution, you can also use `self.snapshot_state_at_address(0x464d5752, "my_first_snapshot")`.