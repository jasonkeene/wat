#!/bin/bash

set -Eeuo pipefail

rm -r public
hugo
pushd public 2> /dev/null
    docker build \
        -f ../Dockerfile \
        -t jasonkeene/wat:latest \
        .
popd 2> /dev/null
