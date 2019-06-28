#!/bin/bash

set -Eeuo pipefail

hugo
pushd public 2> /dev/null
    docker build \
        -f ../Dockerfile \
        -t jasonkeene/wat:latest \
        .
popd 2> /dev/null
