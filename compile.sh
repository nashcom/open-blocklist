#!/bin/bash
############################################################################
# Copyright Nash!Com, Daniel Nashed 2026  - APACHE 2.0 see LICENSE
############################################################################

docker run --rm -v "$PWD/src":/src -v "$PWD/bin":/bin -w /src golang:alpine go build -trimpath -ldflags="-s -w -X main.gBuildPlatform=alpine" -o /bin/open-blocklist
