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

## IPython


## GuestLink 
