# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

# Client container of the functional tests: pytest, impacket, PyMySQL, pyftpdlib, paho-mqtt and
# nmap on the same Docker network as the dionaea container under test.
#
# Built the same every time: python:3.14-slim (3.14.8, Debian 13.7) by the digest of its
# index (amd64 and arm64), the Debian packages from snapshot.debian.org of the day of that
# image (its debian.sources name it) with their versions, the Python packages from the
# requirements files with their hashes (lock.sh makes them). A base image whose sources the sed
# does not find ends the build.
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN sed -i \
      -e 's|^URIs: http://deb.debian.org/debian-security$|URIs: http://snapshot.debian.org/archive/debian-security/20261005T000000Z|' \
      -e 's|^URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/20261005T000000Z|' \
      /etc/apt/sources.list.d/debian.sources && \
    grep -q '^URIs: http://snapshot.debian.org/archive/debian/20261005T000000Z$' /etc/apt/sources.list.d/debian.sources && \
    grep -q '^URIs: http://snapshot.debian.org/archive/debian-security/20261005T000000Z$' /etc/apt/sources.list.d/debian.sources && \
    ! grep -q 'deb.debian.org' /etc/apt/sources.list.d/debian.sources && \
    apt-get -o Acquire::Check-Valid-Until=false update && \
    apt-get install -y --no-install-recommends nmap=7.95+dfsg-3 nmap-common=7.95+dfsg-3 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements-build.txt requirements.txt /tmp/
RUN pip install --require-hashes --no-deps --only-binary :all: -r /tmp/requirements-build.txt && \
    pip install --require-hashes --no-deps --no-build-isolation --only-binary :all: --no-binary pyftpdlib \
      -r /tmp/requirements.txt && \
    rm /tmp/requirements-build.txt /tmp/requirements.txt

WORKDIR /tests
