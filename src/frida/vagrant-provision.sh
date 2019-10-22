#!/bin/bash

set -Eeuo pipefail

# add build deps
apt-get update
apt-get install --yes build-essential python python-pip

# install frida
pip install frida-tools

# install go
mkdir -p /build
pushd /build 2> /dev/null
    wget -O go1.12.6.linux-amd64.tar.gz https://dl.google.com/go/go1.12.6.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.12.6.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/vagrant/.profile
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.profile
popd 2> /dev/null
