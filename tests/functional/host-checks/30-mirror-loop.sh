#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# Mirror service (port 42) without loops. A client container (private
# address) listens on port 42 and holds connections to dionaea's port 42.
# dionaea must not connect back (no connection of the dionaea container with
# the remote port 42, seen in /proc/net/tcp and tcp6 inside the container:
# the image has no ss) and must stay
# below the CPU limit.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

client="${DIONAEA_CONTAINER}-mirror"
trap 'docker rm -f "${client}" >/dev/null 2>&1 || true' EXIT

docker run -d --name "${client}" --network "${DIONAEA_NETWORK}" \
  -v "${DIONAEA_TESTS_DIR}:/tests:ro" "${DIONAEA_CLIENT_IMAGE}" \
  python /tests/scenarios/mirror_client.py --host "${DIONAEA_CONTAINER}" \
    --port 42 --count 5 --hold 12 >/dev/null

if ! hc_wait_log "${client}" "holding" 30; then
  docker logs "${client}" >&2 || true
  hc_fail "the client did not open its connections"
  exit 1
fi
sleep 2

rc=0
# connections of dionaea (all its processes share the network namespace)
# with the remote port 42 (002A): established, or a connect still going
conns() {
  hc_exec_root awk 'FNR > 1 && $3 ~ /:002A$/ && $4 != "0A" {print $2, $3, $4}' /proc/net/tcp /proc/net/tcp6
}
out="$(conns)"
if [[ -n "${out}" ]]; then
  printf '%s\n' "${out}" | sed 's/^/    /' >&2
  hc_fail "dionaea has outgoing connection(s) to port 42 (mirror connect-back)"
  rc=1
else
  hc_say "no outgoing connection of dionaea to port 42"
fi
hc_check_cpu 5 "mirror port 42, connections held" || rc=1

status="$(docker wait "${client}")"
docker logs "${client}" 2>&1 | sed 's/^/    client: /'
if [[ "${status}" != "0" ]]; then
  hc_fail "dionaea connected back to the client or mirrored data (client exit ${status})"
  rc=1
fi
hc_running || { hc_fail "dionaea is not running"; exit 1; }
hc_check_cpu 5 "after the mirror connections were closed" || rc=1
exit ${rc}
