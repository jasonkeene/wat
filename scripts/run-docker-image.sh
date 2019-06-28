#!/bin/bash

set -Eeuo pipefail

docker run -it --rm -p 8080:80 jasonkeene/wat:latest
