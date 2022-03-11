# Quick Start

Have you installed FirmWire and are all eager to emulate your modem FirmWire? Very good!
All you have to run after [installation](installation.md) is:
```
$ ./firmwire.py modem.bin
```

This will automatically attempt to create an emulation environment for the selected modem file and kick off emulation!
Currently, FirmWire supports a subset of MediaTek MTK and Samsung Shannon firmware images.

Please note that FirmWire requires a couple different tcp ports for its operation. If you have any restrictions on which ports can be used, please use the `--consecutive-ports` flag to specify which ports can be used.
For instance, if ports 10000-10005 are free to use on your system, invoke firmwire as follows:
```
$ ./firmwire.py --consecutive-ports 100000 modem.bin
```