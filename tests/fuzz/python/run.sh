#!/bin/sh
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

# Run one Python fuzz target (see ../README.md):
#   run.sh TARGET [SECONDS] [OUT] [libFuzzer options]
# TARGET is smb, mqtt, mongo, http_multipart or emu_scripts; SECONDS the time
# of the run (default 1800). The corpus grows in OUT/corpus/TARGET (the seeds
# of tests/fuzz/corpus/TARGET are copied in); every error is written once per
# place to OUT/failures/TARGET (the input and its traceback) and the run goes
# on; inputs over -timeout go to OUT/artifacts/TARGET.
set -eu

TARGET=$1
SECONDS_=${2:-1800}
OUT=${3:-/out}
[ $# -gt 3 ] && shift 3 || shift $#
SRC=${SRC:-/src}
HERE="$SRC/tests/fuzz/python"

mkdir -p "$OUT/corpus/$TARGET" "$OUT/artifacts/$TARGET" "$OUT/failures/$TARGET"
for seed in "$SRC/tests/fuzz/corpus/$TARGET"/*; do
	[ -e "$OUT/corpus/$TARGET/$(basename "$seed")" ] || cp "$seed" "$OUT/corpus/$TARGET/"
done
DICT=""
[ -f "$HERE/$TARGET.dict" ] && DICT="-dict=$HERE/$TARGET.dict"

cd "$OUT/artifacts/$TARGET"
FUZZ_FAILURES="$OUT/failures/$TARGET" exec python3 "$HERE/fuzz_$TARGET.py" \
	-max_total_time="$SECONDS_" -rss_limit_mb=2048 -timeout=5 -max_len=65536 \
	-artifact_prefix="$OUT/artifacts/$TARGET/" $DICT "$@" "$OUT/corpus/$TARGET"
