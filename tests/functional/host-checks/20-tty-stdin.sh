#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# Interactive Python shell on a terminal. Runs only with a terminal:
#   DIONAEA_TTY=1 tests/functional/run.sh
#   DIONAEA_TTY=1 DIONAEA_TTY_CLOSE=eof tests/functional/run.sh
#
# A line typed on the terminal is run by the shell (and must not crash
# dionaea), then stdin is closed: by a hangup of the terminal (TIOCVHANGUP,
# default, as when the other side of the terminal goes away) or by ^D
# (DIONAEA_TTY_CLOSE=eof). stdin stays readable after that; dionaea has to
# stop watching it instead of spinning. Input goes in with TIOCSTI from a
# privileged docker exec (CAP_SYS_ADMIN).

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

if [[ "$(docker inspect -f '{{.Config.Tty}}' "${DIONAEA_CONTAINER}")" != "true" ]]; then
  hc_say "skipped: no terminal (run with DIONAEA_TTY=1)"
  exit 0
fi
mode="${DIONAEA_TTY_CLOSE:-hangup}"
pid="$(hc_main_pid)"

# hc_tty hangup | hc_tty type TEXT: hang up dionaea's terminal or type TEXT
# on it (backslash escapes as in Python, e.g. \n, \x04)
hc_tty() {
  hc_exec_root python3 -c '
import fcntl, os, sys, termios
fd = os.open("/proc/%s/fd/0" % sys.argv[1], os.O_RDWR | os.O_NOCTTY)
if sys.argv[2] == "hangup":
    fcntl.ioctl(fd, 0x5437)  # TIOCVHANGUP
else:
    for b in sys.argv[3].encode().decode("unicode_escape").encode("latin-1"):
        fcntl.ioctl(fd, termios.TIOCSTI, bytes([b]))
' "${pid}" "$@"
}

rc=0
hc_tty type 'print(6 * 7 * 1000 + 42)\n'
if hc_wait_log "${DIONAEA_CONTAINER}" "42042" 10; then
  hc_say "the Python shell ran a line typed on the terminal"
else
  hc_fail "the Python shell did not answer a line typed on the terminal"
  rc=1
fi
hc_running || { hc_fail "dionaea died after a line on the terminal"; exit 1; }

case "${mode}" in
  hangup) hc_tty hangup ;;
  eof) hc_tty type '\x04' ;;
  *) hc_fail "DIONAEA_TTY_CLOSE must be hangup or eof, not ${mode}"; exit 1 ;;
esac
hc_say "stdin closed (${mode})"
sleep 2
hc_running || { hc_fail "dionaea died after stdin was closed (${mode})"; exit 1; }
hc_check_cpu 10 "stdin closed (${mode})" || rc=1
exit ${rc}
