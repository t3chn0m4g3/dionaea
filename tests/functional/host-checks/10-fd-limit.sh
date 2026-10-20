#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# accept() under EMFILE. Runs only with a low fd limit:
#   DIONAEA_RUN_ARGS="--ulimit nofile=128" tests/functional/run.sh
#
# dionaea closes accepted connections whose fd is above 70 % of the limit it
# read at the start, so idle connections alone never reach the limit. The
# check lowers the soft limit of the running process to the fds in use plus
# 8 (prlimit), so accept() fails with EMFILE, as when something else holds
# the fds. Then 200 idle connections each to 445 (tcp) and 443 (tls):
#   - while they are held, dionaea must not spin (CPU below the limit)
#   - after they are closed, a new connection to 21 gets the 220 banner
#   - after dionaea stopped, dionaea-errors.log has the EMFILE line of
#     accept() for every port (run.sh checks it, hc_expect_log)
# The check fails if the lowered limit cannot lead to EMFILE (above the 70 %
# guard).

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

FD_TEST_MAX_LIMIT=256
PORTS="${DIONAEA_FD_TEST_PORTS:-445,443}"

pid="$(hc_main_pid)"
read -r soft hard < <(hc_exec_root awk '/^Max open files/ {print $4, $5}' "/proc/${pid}/limits")
if [[ "${soft}" == "unlimited" || "${soft}" -gt ${FD_TEST_MAX_LIMIT} ]]; then
  hc_say "skipped: fd limit ${soft} (run with DIONAEA_RUN_ARGS=\"--ulimit nofile=128\")"
  exit 0
fi

used="$(hc_exec_root sh -c "ls /proc/${pid}/fd | wc -l")"
low=$(( used + 8 ))
# dionaea closes an accepted fd above 70 % of the limit it read at the start
# (= soft here). EMFILE needs every fd below the lowered limit to be kept,
# i.e. the highest one (low - 1) must not be above that guard.
guard=$(( soft * 70 / 100 ))
if (( low - 1 > guard )); then
  hc_fail "EMFILE cannot be reached: ${used} fds in use, lowered limit ${low} is above the 70 % guard (${guard}) of the limit ${soft}"
  exit 1
fi
hc_exec_root prlimit --pid "${pid}" --nofile="${low}:${hard}"
hc_say "fd limit ${soft} (guard ${guard}), ${used} fds in use, soft limit lowered to ${low}"

client="${DIONAEA_CONTAINER}-fd"
cleanup_fd() {
  docker rm -f "${client}" >/dev/null 2>&1 || true
  hc_exec_root prlimit --pid "${pid}" --nofile="${soft}:${hard}" >/dev/null 2>&1 || true
}
trap cleanup_fd EXIT

docker run -d --name "${client}" --network "${DIONAEA_NETWORK}" \
  -v "${DIONAEA_TESTS_DIR}:/tests:ro" "${DIONAEA_CLIENT_IMAGE}" \
  python /tests/scenarios/idle_connections.py --host "${DIONAEA_CONTAINER}" \
    --ports "${PORTS}" --count 200 --hold 15 --banner-port 21 --banner-timeout 30 >/dev/null

rc=0
if ! hc_wait_log "${client}" "holding" 60; then
  docker logs "${client}" >&2 || true
  hc_fail "the client did not open its connections"
  exit 1
fi
docker logs "${client}" 2>&1 | sed 's/^/    client: /'
hc_check_cpu 10 "${PORTS} at EMFILE, connections held" || rc=1

status="$(docker wait "${client}")"
docker logs "${client}" 2>&1 | sed -n '/^closed/,$p' | sed 's/^/    client: /'
if [[ "${status}" != "0" ]]; then
  hc_fail "no FTP banner after the connections were closed (client exit ${status})"
  rc=1
fi

hc_exec_root prlimit --pid "${pid}" --nofile="${soft}:${hard}" || hc_fail "could not restore the fd limit"

# EMFILE really happened: one backoff warning per port, checked by run.sh
# once dionaea has written its logs
IFS=',' read -r -a port_list <<< "${PORTS}"
for port in "${port_list[@]}"; do
  hc_expect_log dionaea-errors.log "accept\(\) failed on [^ ]+:${port} \(Too many open files\)"
done
hc_running || { hc_fail "dionaea is not running"; exit 1; }
hc_check_cpu 10 "after the connections were closed" || rc=1
exit ${rc}
