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

The GuestLink is a combination of custom task injected into the baseband and python peripheral, allowing for _interaction_ with the emulated baseband. To make use of it, start FirmWire both with activated console and injected `glink` task:

```
./firmwire.py -t glink --console ./modem.bin
```

Now, after connecting to the console as described above, you can get a handle to the glink peripheral:

```
In [1]: gl = self.get_peripheral('glink')
```

This GLink peripheral can be controlled from Python and uses a MMIO range to communicated with the GLink task.
More specifically, the MMIO range is organized as follows:
 
```C
struct glink_peripheral {
  uint32_t access;
  uint32_t tx_head;
  uint32_t tx_tail;
  uint32_t rx_head;
  uint32_t rx_tail;
  uint8_t tx_fifo[TX_FIFO_SIZE];
  uint8_t rx_fifo[RX_FIFO_SIZE];
} ;
```

The `access` field is used to communicate return values from the GLink task back to the Python peripheral, while the rest are data structures for input and output FIFO buffers.
These buffers use a simple packet-based data format for communication:

```C
struct glink_cmd_header {
  uint8_t cmd;
  uint8_t len;
  // next field is variable amount of octets
};
```

Currently, GuestLinks implementation only allows for commands from Python to the emulated baseband. The available commands are:

| CMD                    | PythonAPI                                                              | Description                                                                                                                                                                       |
| ---------------------- | ---------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GLINK_SEND_QUEUE_INDIR | `gl.send_queue(True, src_qid_name, dst_qid_name, msg_group, payload)`  | Sends specified message to baseband internal queue. Payload is provided as allocated memory chunk, to be free'd by the baseband.                                                  |
| GLINK_SEND_QUEUE       | `gl.send_queue(False, src_qid_name, dst_qid_name, msg_group, payload)` | Sends specified message to baseband internal queue. Payload is inlined with the msg_struct.                                                                                       |
| GLINK_SET_EVENT        | `gl.set_event(event)`                                                  | Sets the baseband internal event. `event` can either be int (event number) or bytes (event name).                                                                                 |
| GLINK_ALLOC_BLOCK      | `gl.create_block(size)`                                                | Allocate a chunk of memory of given `size`. The address of the chunk can later be retrieved via `gl.access`.                                                                      |
| GLINK_CALL_FUNC        | `gl.call_function(fn, args)`                                           | Call function `fn` with args specified in `args`. `fn` must be of type int, and `args` a list of `ints`. The return code of the function can later be retrieved from `gl.access`. |


### GuestLink Tips & Tricks

#### Asynchronous behavior:
When using any of the commands, keep in mind that GLink acts fully asynchronously, i.e., when calling a function from Python, the according command is only written to the shared MMIO region. The GLink task in the baseband then has to parse and process the command before the result is available.

For better understanding, we provide a typical guestlink usage example below, allocating a block of size 0x100, and storing the result into chunk_addr:

```Python
In [1]: self.qemu.stop()
In [2]: gl = self.get_peripheral('glink')
In [3]: gl.create_block(0x100)
In [4]: self.run_for(0.5)
In [5]: chunk_addr = gl.access
In [6]: hex(chunk_addr)
Out[6]: '0x44f0293c'
```

#### GuestLink & Snapshots:
When using GLink in combination with snapshots, it is important to note that a reference to the guest link peripheral does not propagate across snapshots. That means, after restoring a snapshot, a new reference to the GLink peripheral has to be required via `get_peripheral`, as shown below:

```Python
In [1]: gl = self.get_peripheral('glink')
In [2]: gl
Out[2]: <firmwire.hw.glink.GLinkPeripheral at 0x7f720c4f59d0>
In [3]: self.restore_snapshot("glink_demo")
In [3]: gl = self.get_peripheral('glink')
In [4]: gl 
Out[4]: <firmwire.hw.glink.GLinkPeripheral at 0x7f7219792850>`
```