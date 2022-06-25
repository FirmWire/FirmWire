FROM ubuntu:20.04
LABEL "about"="FirmWire base img"

ARG DEBIAN_FRONTEND=noninteractive
ENV AFL_SKIP_CPUFREQ=1
ENV IS_DOCKER="1"

RUN apt-get update && apt-get upgrade -y && \
    apt-get -y install --no-install-suggests --no-install-recommends \
    automake \
    bison flex \
    build-essential \
    chrpath \
    git zip zsh openssh-client \
    clang clang-tools \
    python3 python3-dev python3-setuptools \
    libglib2.0-dev gcc-arm-none-eabi \
    libtool libtool-bin \
    wget curl vim \
    apt-utils apt-transport-https ca-certificates gnupg dialog \
    libpixman-1-dev \
    virtualenv python3-ipython \
    python3 python3-pip libc++-dev libcurl4-openssl-dev libelf-dev libffi-dev libdwarf-dev libelf-dev libwiretap-dev wireshark-dev python3-pycparser \
    protobuf-compiler protobuf-c-compiler python3-protobuf libprotoc-dev libprotobuf-dev libprotobuf-c-dev libjsoncpp-dev \
    gdb-multiarch python3-pip qemu-utils libcapstone-dev \
  && apt-get update \
  && apt-get install -y gcc-9-mipsel-linux-gnu gcc-9-multilib \
  && update-alternatives --install /usr/bin/mipsel-linux-gnu-gcc mipsel-linux-gnu-gcc /usr/bin/mipsel-linux-gnu-gcc-9 10 \
  && pip3 install https://foss.heptapod.net/pypy/cffi/-/archive/branch/default/cffi-branch-default.tar.gz
# Ubuntu is unable to install the gcc-multilib metapackage with any cross compiler due to /usr/include/asm conflicts
# See: https://bugs.launchpad.net/ubuntu/+source/gcc-defaults/+bug/1300211
# pypanda needs the latest cffi, because $reasons

  
# Install panda, and deps for Shannon Panda
WORKDIR /firmwire_deps
RUN rm -rf panda \
  && git clone --depth=1 https://github.com/FirmWire/panda.git \
  && cd panda \
  && git checkout main \
  && rm -rf build \
  && mkdir build \
  && cd build \
  && ../configure --disable-werror --target-list=arm-softmmu,mipsel-softmmu \
    --cc=gcc-9 \
    --cxx=g++-9 \
    --disable-sdl \
    --disable-user \
    --disable-linux-user \
    --disable-pyperipheral3 \
    --disable-bsd-user \
    --disable-vte \
    --disable-curses \
    --disable-vnc \
    --disable-vnc-sasl \
    --disable-vnc-jpeg \
    --disable-vnc-png \
    --disable-cocoa \
    --disable-virtfs \
    --disable-xen \
    --disable-xen-pci-passthrough \
    --disable-brlapi \
    --disable-curl \
    --disable-bluez \
    --disable-kvm \
    --disable-hax \
    --disable-rdma \
    --disable-vde \
    --disable-netmap \
    --disable-linux-aio \
    --disable-cap-ng \
    --disable-attr \
    --disable-vhost-net \
    --disable-spice \
    --disable-rbd \
    --disable-gtk \
    --disable-gnutls \
    --disable-gcrypt \
    --disable-libiscsi \
    --disable-libnfs \
    --disable-smartcard \
    --disable-libusb \
    --disable-usb-redir \
    --disable-lzo \
    --disable-snappy \
    --disable-bzip2 \
    --disable-seccomp \
    --disable-coroutine-pool \
    --disable-glusterfs \
    --disable-tpm \
    --disable-libssh2 \
    --disable-numa \
    --disable-tcmalloc \
    --disable-jemalloc \
    --disable-replication \
    --disable-vhost-vsock \
    --disable-opengl \
    --disable-virglrenderer \
  && make -j `nproc` \
  && cd /firmwire_deps/panda/panda/python/core/ \
  && python3 setup.py install

COPY requirements.txt /firmwire/requirements.txt
RUN pip3 install -r /firmwire/requirements.txt

WORKDIR /firmwire
CMD [ "/bin/bash" ]
