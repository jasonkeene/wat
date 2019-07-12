#!/bin/bash

set -Eeuo pipefail

# add build deps
apt-get update
apt-get install --yes bison cmake flex g++ git libelf-dev zlib1g-dev \
    libfl-dev systemtap-sdt-dev llvm-7-dev llvm-7-runtime libclang-7-dev \
    clang-7 build-essential python libedit-dev luajit luajit-5.1-dev

# clone src
mkdir /build
git clone --recursive https://github.com/iovisor/bcc /build/bcc
git clone --recursive https://github.com/iovisor/bpftrace /build/bpftrace

# build bcc
mkdir -p /build/bcc/build
pushd /build/bcc/build 2> /dev/null
    cmake -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Debug ..
    make
    make install
popd 2> /dev/null

# build bpftrace
mkdir -p /build/bpftrace/build
pushd /build/bpftrace/build 2> /dev/null
    cmake -DCMAKE_BUILD_TYPE=Debug ..
    make
    make install
popd 2> /dev/null

# install go
pushd /build 2> /dev/null
    wget -O go1.12.6.linux-amd64.tar.gz https://dl.google.com/go/go1.12.6.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.12.6.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.profile
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.profile
popd 2> /dev/null
