#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# Clients that leave while dionaea still answers (scenarios/early_close.py):
# HTTPS and HTTP requests closed after the first bytes, half of them with a
# reset, and MQTT packets across two reads. dionaea must log no Traceback for
# them (the container log has the Python errors at once, dionaea.log only after
# the stop) and must still answer HTTPS and MQTT afterwards. dionaea runs at 0.3 CPU meanwhile (docker update),
# as on a loaded sensor: the client must be able to leave while one handler of
# dionaea is still sending (unthrottled it hits the case a few times in 1,600
# requests, throttled dozens of times).

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

client="${DIONAEA_CONTAINER}-early-close"
trap 'docker rm -f "${client}" >/dev/null 2>&1 || true' EXIT

tracebacks() {
  docker logs "${DIONAEA_CONTAINER}" 2>&1 | grep -c 'Traceback' || true
}

before="$(tracebacks)"
rc=0
cpus="$(docker inspect -f '{{.HostConfig.NanoCpus}}' "${DIONAEA_CONTAINER}")"
restore_cpus() {
  # --cpus 0 does not lift a limit: without one before, allow all CPUs
  if [[ "${cpus}" -gt 0 ]]; then
    docker update --cpus "$(awk -v n="${cpus}" 'BEGIN { printf "%.3f", n / 1e9 }')" "${DIONAEA_CONTAINER}" >/dev/null
  else
    docker update --cpus "$(docker info --format '{{.NCPU}}')" "${DIONAEA_CONTAINER}" >/dev/null
  fi
}
trap 'restore_cpus; docker rm -f "${client}" >/dev/null 2>&1 || true' EXIT
docker update --cpus 0.3 "${DIONAEA_CONTAINER}" >/dev/null
docker run --name "${client}" --network "${DIONAEA_NETWORK}" \
  -v "${DIONAEA_TESTS_DIR}:/tests:ro" "${DIONAEA_CLIENT_IMAGE}" \
  python /tests/scenarios/early_close.py --host "${DIONAEA_CONTAINER}" --count "${EARLY_CLOSE_COUNT:-400}" \
  2>&1 | sed 's/^/    client: /' || rc=1
restore_cpus
status="$(docker inspect -f '{{.State.ExitCode}}' "${client}" 2>/dev/null || echo 1)"
if [[ "${status}" != "0" ]]; then
  hc_fail "dionaea did not answer afterwards (client exit ${status})"
  rc=1
fi
sleep 2
after="$(tracebacks)"
if [[ "${after}" -gt "${before}" ]]; then
  docker logs "${DIONAEA_CONTAINER}" 2>&1 | grep -A12 'Traceback' | tail -n 40 | sed 's/^/    /' >&2
  hc_fail "$((after - before)) Traceback(s) in the container log for clients that left early"
  rc=1
else
  hc_say "no Traceback for clients that left early"
fi
hc_running || { hc_fail "dionaea is not running"; exit 1; }
exit ${rc}
