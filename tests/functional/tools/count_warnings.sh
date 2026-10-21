#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# count_warnings.sh ERRORS_LOG MINUTES: the warnings of a dionaea-errors.log per message, the
# most frequent first, as "COUNT domain: message" (numbers as N, addresses as ADDR) on stdout.
#
# A summary warning ("<what>: N <unit> in the last minute, the last: <text>", log_summary.c,
# logtext.LogSummary) counts by the text before its number, whatever its last text is: it may be
# there once per started minute of the run (MINUTES) and once more. Any other message may be
# there MAX_SAME_WARNING (5) times. A message above its bound goes to stderr as well, and the
# exit status is 1; 0 otherwise. A line of the log file: "[date time] domain[ file:line]-level: message".

set -Eeuo pipefail

log="$1"
minutes="$2"
MAX_SAME_WARNING=5

{ grep -E '^\[[0-9]{8} [0-9:]{8}\] [^ ]+( [^ ]+)?-warning: ' "${log}" || true; } \
  | sed -E 's/^\[[^]]*\] ([^ ]+)( [^ ]+)?-warning: /\1: /; s/0x[0-9a-fA-F]+/ADDR/g; s/\.incoming\/[^ :]+/.incoming\/FILE/g; s/(^|[^A-Za-z0-9_])[0-9]+/\1N/g' \
  | sed -E 's/^(.*: N [^:,]+ in the last minute), the last: .*$/\1/' \
  | sort | uniq -c | sort -rn \
  | awk -v summary_max="$(( minutes + 1 ))" -v max="${MAX_SAME_WARNING}" '
      {
        print
        bound = ($0 ~ / in the last minute$/) ? summary_max : max
        if( $1 > bound ) { print > "/dev/stderr"; over = 1 }
      }
      END { exit over }'
