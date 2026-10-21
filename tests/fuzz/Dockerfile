# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

# The environments of the fuzz targets (see README.md), not part of the image
# and not run by the normal build:
#   docker build --target c -t dionaea-fuzz-c tests/fuzz
#   docker build --target python -t dionaea-fuzz-py tests/fuzz

# C: the distribution of the image with clang and its libFuzzer
FROM ubuntu:26.04 AS c

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      clang \
      cmake \
      libclang-rt-dev \
      libev-dev \
      libglib2.0-dev \
      libssl-dev \
      libudns-dev \
      llvm \
      make \
      pkg-config && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src


# Python: atheris 3.0.0 runs on Python 3.6 to 3.12, not on the 3.14 of the
# image, so the Python targets run on 3.12; bson is the one of the image
# (pymongo 4.16)
FROM python:3.12-slim-trixie AS python

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends clang g++ libclang-rt-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN CC=clang CXX=clang++ CLANG_BIN=clang pip install --no-cache-dir atheris==3.0.0 pymongo==4.16.0

WORKDIR /src
