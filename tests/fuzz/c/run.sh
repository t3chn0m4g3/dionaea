#!/bin/sh
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

# Run one C fuzz target of build.sh (see ../README.md):
#   run.sh TARGET [SECONDS] [OUT] [libFuzzer options]
# TARGET is bistream, processor, profile or shellcode; SECONDS the time of the
# run (default 1800). The corpus grows in OUT/corpus/TARGET (the seeds of
# tests/fuzz/corpus/TARGET are copied in), failing inputs go to
# OUT/artifacts/TARGET. One fuzzing process (-fork=1); a failing input does not
# end the run.
set -eu

TARGET=$1
SECONDS_=${2:-1800}
OUT=${3:-/out}
[ $# -gt 3 ] && shift 3 || shift $#
SRC=${SRC:-/src}

mkdir -p "$OUT/corpus/$TARGET" "$OUT/artifacts/$TARGET"
for seed in "$SRC/tests/fuzz/corpus/$TARGET"/*; do
	[ -e "$OUT/corpus/$TARGET/$(basename "$seed")" ] || cp "$seed" "$OUT/corpus/$TARGET/"
done

MAX_LEN=4096
[ "$TARGET" = shellcode ] && MAX_LEN=65535

cd "$OUT/artifacts/$TARGET"
exec "$OUT/fuzz_$TARGET" -fork=1 -ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 \
	-max_total_time="$SECONDS_" -rss_limit_mb=2048 -timeout=5 -max_len="$MAX_LEN" \
	-artifact_prefix="$OUT/artifacts/$TARGET/" "$@" "$OUT/corpus/$TARGET"
