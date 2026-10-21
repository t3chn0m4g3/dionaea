# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

# Install layout as in the T-Pot image: prefix /opt/dionaea, configuration in
# /opt/dionaea/etc/dionaea, data in /opt/dionaea/var, runs as uid/gid 2000.

FROM ubuntu:26.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      cmake \
      cython3 \
      libcurl4-openssl-dev \
      libev-dev \
      libglib2.0-dev \
      libnetfilter-queue-dev \
      libpcap-dev \
      libssl-dev \
      libudns-dev \
      pkg-config \
      python3 \
      python3-dev \
      python3-setuptools

COPY . /src

RUN mkdir -p /src/build && \
    cd /src/build && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/opt/dionaea -DCMAKE_BUILD_TYPE=RelWithDebInfo .. && \
    make -j"$(nproc)" && \
    make install


# Unit tests of the bundled libemu (third_party/libemu), not part of the image:
#   docker build --target libemu-test .
#   docker build --target libemu-test \
#     --build-arg LIBEMU_TEST_CFLAGS="-fsanitize=address,undefined -fno-sanitize=shift,signed-integer-overflow -fno-omit-frame-pointer" .
FROM builder AS libemu-test

ARG LIBEMU_TEST_CFLAGS=""

RUN mkdir -p /src/build-test && \
    cd /src/build-test && \
    cmake -DDIONAEA_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="${LIBEMU_TEST_CFLAGS}" .. && \
    make -j"$(nproc)" test_libemu test_synthetic_pe test_mul test_rotate test_w32_hooks && \
    ctest -R '^(libemu|synthetic_pe|mul|rotate|w32_hooks)$' --output-on-failure


# Unit tests of the stream processing (tests/processor: bistream limits, streamdumper, processor
# jobs and threadpool admission, emu detection windows and file hooks, the JSON of a profile, curl
# sessions, listen of the core, the buffering of the log files, the log lines of failed downloads and
# the summaries of the warnings of every connection),
# not part of the image:
#   docker build --target processor-test .
#   docker build --target processor-test \
#     --build-arg PROCESSOR_TEST_CFLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer" .
#   docker build --target processor-test \
#     --build-arg PROCESSOR_TEST_CFLAGS="-fsanitize=thread -O1 -g -fno-omit-frame-pointer" .
FROM builder AS processor-test

ARG PROCESSOR_TEST_CFLAGS=""

# a locale of one byte per character for the JSON of a profile and the streamdumper
# (test_profile.c, test_streamdumper.c)
RUN apt-get install -y --no-install-recommends locales && \
    localedef -i en_US -f ISO-8859-1 en_US.ISO-8859-1

RUN mkdir -p /src/build-processor-test && \
    cd /src/build-processor-test && \
    cmake -DDIONAEA_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="${PROCESSOR_TEST_CFLAGS}" .. && \
    make -j"$(nproc)" test_bistream test_processor test_streamdumper test_detect test_emu_hooks test_profile \
      test_curl_session test_connection_listen test_log test_download_log test_log_summary && \
    ctest -R '^(bistream|processor|streamdumper|detect|emu_hooks|profile|curl_session|connection_listen|log|download_log|log_summary)$' \
      --output-on-failure


FROM ubuntu:26.04

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      libcap2-bin \
      libcurl4t64 \
      libev4t64 \
      libglib2.0-0t64 \
      libnetfilter-queue1 \
      libpcap0.8t64 \
      libpython3.14 \
      libudns0t64 \
      python3 \
      python3-boto3 \
      python3-bson \
      python3-yaml && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/*

COPY --from=builder /opt/dionaea /opt/dionaea

RUN addgroup --gid 2000 dionaea && \
    adduser --system --no-create-home --shell /bin/bash --uid 2000 --disabled-password --disabled-login --gid 2000 dionaea && \
    setcap cap_net_bind_service=+ep /opt/dionaea/sbin/dionaea && \
    chown -R dionaea:dionaea /opt/dionaea/var

STOPSIGNAL SIGINT
USER dionaea:dionaea
CMD ["/opt/dionaea/sbin/dionaea", "-u", "dionaea", "-g", "dionaea", "-c", "/opt/dionaea/etc/dionaea/dionaea.cfg"]
