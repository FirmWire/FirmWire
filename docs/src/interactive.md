# Interactive Exploration

FirmWire has multiple ways to facilitate interactive exploration of the emulated baseband firmware.
The reason for such exploration are various, ranging from aiding static reverse engineering over observing the baseband's behavior when receiving custom messages to root-cause analysis for crashing inputs.

## GDB

The most classic way to interact with the emulated baseband is via GDB.
Simply start FirmWire with the `-s/--gdb-server` flag while specifying a port number to start a gdb server!
Then, you can start up your local gdb build (we recommend `gdb-multiarch` for Ubuntu 20.04) and connect to the emulated baseband by executing from within gdb:

```
target remote :PORT
```

Alternatively, when using gdb together with [gef](https://gef.readthedocs.io/), we suggest to run the following for better usability instead:
```
gef-remote --qemu-mode 127.0.0.1:PORT
```

Once connected, you should be able to set breakpoints, inspect and modify memory, as well as steering execution just as usual.
Under the hood, FirmWire spawns a gdb server provided by the corresponding [avatar2 plugin](https://github.com/avatartwo/avatar2/blob/main/avatar2/plugins/gdbserver.py). This allows to transparently access both the memory provided by avatar-backed memory ranges (as in the case of  python peripherals), and emulated memory provided by PANDA.

What's more, via gdb's `monitor` command you have directly access to the Python context of avatar2 gdb server, and allows you to execute simple Python statements. You even can access the global avatar object from gdb by executing:
```
monitor self.avatar
```

However, if you are really eager to control FirmWire's, and the emulated baseband's, execution state from Python, we recommend using IPython as described below.

## Console

FirmWire offers a second convenient way for controlling execution: a IPython/jupyter console interface. To invoke it, run FirmWire with the `--console` flag:
```
$ python3 firmwire.py modem.bin --console
```

Then, after initial FirmWire startup, you can connect to the console from the second terminal:

```
$ jupyter-console --existing
```

In here, you have full access to FirmWire's API, and your main interface to interact with the emulated baseband is its `machine` abstraction, which is directly accessible via `self`.

While explaining the full API and available functions would be to extensive for this guide, below are the most important objects and methods provided by firmwire's machine object.

| Object                   | Description                                                                                                 |
| ------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `self.avatar`              | The avatar object, providing information about memory ranges and python peripherals                         |
| `self.loader`              | The vendor specific loader, providing information about the loaded firmware image.                          |
| `self.loader.symbol_table` | The symbols extracted by the loader, using [patternDB](pattern_db.md) and auxiliary information.            |
| `self.modkit`              | Handle to FirmWire's [modkit](modkit.md)                                                                    |
| `self.panda`               | Handle to libpanda, the PANDA library with python bindings                                                  |
| `self.qemu`                | Direct handle to avatar's PyPanda target, the avatar wrapper around libpanda. Follows avatar2's target API. |

To steer execution and inspecting memory, the `self.qemu` object will most likely be your bread and butter.
It provides functions such as `cont()`, `stop()`, `set_breakpoint()`, `read_memory()` or `write_memory()` - more information can be found over in handbook for [avatar2]().

Besides these objects and capabilities provided by the PANDA and avatar2 frameworks, the FirmWire also provide a couple of additional methods to make exploration easier:

| Method/Signature                        | Description                                                                                          |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| `self.get_tasks()`                      | Retrieves the RTOS tasks automatically identified by FirmWire in its abstract Python representation. |
| `self.get_peripheral(name)`             | Retrieve a handle to the Python peripheral with specified name.                                      |
| `self.restore_snapshot(snapshot_name)`  | Restores [Snapshot](workspaces.md) with given name.                                                  |
| `self.run_for(t)`                       | If the machine is stopped, continue execution for `t` seconds.                                       |
| `self.snapshot(snapshot_name)`          | Create snapshot of current execution state with given name.                                          |
| `self.set_breakpoint(address, handler)` | Set a breakpoint at specified address and execute the code provided in `handler` when hit.           |

For Shannon basebands, the interactive capabilities are further extended by the special GuestLink peripheral.

## GuestLink (Shannon only)

The GuestLink is a combination of custom task injected into the baseband and python peripheral, allowing for _interaction_ with the emulated baseband.
