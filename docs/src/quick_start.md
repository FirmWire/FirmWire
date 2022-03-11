# Quick Start

Have you installed FirmWire and are all eager to emulate your modem FirmWire? Very good!
All you have to run after [installation](installation.md) is:

```
$ ./firmwire.py modem.bin
```

This will automatically recognize the firmware, unpack it, and select a loader and machine to run it.
You can also load firmware from a URL to get started:

```
$ ./firmwire.py https://github.com/grant-h/ShannonFirmware/raw/master/modem_files/CP_G973FXXU3ASG8_CP13372649_CL16487963_QB24948473_REV01_user_low_ship.tar.md5.lz4
```

Currently, FirmWire supports a subset of MediaTek MTK and Samsung Shannon firmware images.

Please note that FirmWire requires a couple different TCP ports for its operation. If you have any restrictions on which ports can be used, please use the `--consecutive-ports` flag to specify which ports can be used.
For instance, if ports 10000-10005 are free to use on your system, invoke FirmWire as follows:
```
$ ./firmwire.py --consecutive-ports 10000 modem.bin
```

## Supported Images

### MediaTek

* Samsung A10s (MT6262)
* Samsung A41 (MT6768)

### Shannon

* Most images for Galaxy S7, S7e (S335)
* Moto One Vision (S337)
* Galaxy S8, S8+ (S355)
* Galaxy S9 (S360)
* Galaxy S10, S10e (S5000)

## Using Ghidra

We have custom patches to Ghidra which are required if you are analyzing **MediaTek firmware**. See
[https://github.com/FirmWire/ghidra](https://github.com/FirmWire/ghidra) for setup instructions.
For **Shannon firmware** see [https://github.com/grant-h/ShannonBaseband#getting-started-with-shannon-firmware](https://github.com/grant-h/ShannonBaseband#getting-started-with-shannon-firmware).
You will need the ShannonLoader, which can be installed on to the custom Ghidra for MediaTek (or just use the upstream Ghidra).

## Known Issues

* MediaTek snapshotting is hacky. CCCI FSD has file system state that needs to be specially saved
* After snapshotting, segfaults in Panda may occur. Just restore from snapshot to resume
* Ctrl+C during console mode doesn't work. Use Ctrl+\
