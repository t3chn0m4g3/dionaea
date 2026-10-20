#!/bin/sh
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# coldstop.sh IMAGE DATADIR [repro.py options]: the cold stop on a bind mount
# (Docker Desktop: virtiofs) without the shim. DATADIR is filled once with
# 188,108 dumps of 11,420 bytes (2 GB, kept for the next run), the dentries
# and inodes of the Docker VM are dropped (a cold folder), dionaea starts and
# is stopped with docker stop -t 10 after 60 s, during its first count.
# See README.md.
set -eu
unset CDPATH
[ $# -ge 2 ] || { echo "usage: $0 IMAGE DATADIR [repro.py options]" >&2; exit 2; }
HERE="$(cd -- "$(dirname -- "$0")" && pwd)"
image="$1"; data="$2"; shift 2
exec python3 "$HERE/repro.py" --image "$image" --data-bind "$data" --no-shim --drop-caches \
  --prefill 188108 --size 11420 --stop-early 60 "$@"
