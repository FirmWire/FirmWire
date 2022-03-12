# Installation

The recommended way of using FirmWire is by using the supplied [Dockerfile](https://github.com/FirmWire/FirmWire/blob/main/Dockerfile). To build the docker file, execute the following commands:

```
git clone https://github.com/FirmWire/FirmWire.git
cd FirmWire
git clone https://github.com/FirmWire/panda.git

# This will take some time
docker build -t firmwire .
```

Afterwards, you can obtain an interactive shell to a docker environment with FirmWire installed by executing:
```
docker run --rm -it -v $(pwd):/firmwire firmwire
```
From here, you can directly go to check out our [quick start](quick_start.md) documentation to emulate your first modem!

## Visual Studio Code

Alternatively to using docker from your commandline, you can also create a FirmWire environment using VScode, by using the `devcontainer` and `docker` extensions.
After cloning FirmWire and FirmWire's version of Panda, just open the corresponding directory in code and execute:
`> Remote-Containers: Add Development Container Configuration Files`
Then, select `From Dockerfile`, which should automatically create a `.devcontainer` file. Afterwards, follow code's prompt to `Reopen in container`.

This will build the docker container and provide you an interactive shell inside the docker environment, with files transparently forwarded to the host directories. This is the favorite development setup for some of the FirmWire developers!


## Manual Installation

The manual installation of FirmWire is a bit more tedious. Besides installing FirmWire and its requirement, you also need to:
1) Manually build Panda
2) Install PyPanda
3) Manually build the FirmWire [mods](modkit.md) 

For information on how to carry out these individual steps, please refer to the [Dockerfile](https://github.com/FirmWire/FirmWire/blob/main/Dockerfile).
