#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# After all tests dionaea has to be idle: CPU of its processes over 10 s
# below HC_CPU_LIMIT (20 %). A busy loop (accept() errors, stdin) shows here.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }
hc_check_cpu 10 "idle after the tests"
