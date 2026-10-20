#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# Mirror service (port 42) for a client with a public address: the path that
# 30-mirror-loop.sh and test_mirror.py can not reach (their client has a
# private address, which the mirror refuses). A second dionaea and a client run
# on a network of their own with a public subnet (HC_PUBLIC_SUBNET, default
# 11.77.0.0/24), created --internal: nothing on it reaches outside the host.
# scenarios/mirror_public_client.py checks that dionaea connects back to the
# client and passes the data both ways, that a second connection from the same
# source gets no second mirror, and that the source gets one again once the
# first has ended. Afterwards the log of the second dionaea must have no
# Traceback.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

subnet="${HC_PUBLIC_SUBNET:-11.77.0.0/24}"
network="${DIONAEA_CONTAINER}-public"
inst="${DIONAEA_CONTAINER}-mirror-public"
client="${inst}-client"
root="${DIONAEA_TMP_ROOT}/mirror-public"
image="$(docker inspect -f '{{.Config.Image}}' "${DIONAEA_CONTAINER}")"

cleanup_public() {
  docker rm -f "${client}" >/dev/null 2>&1 || true
  docker rm -f "${inst}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
}
trap cleanup_public EXIT

docker network create --internal --subnet "${subnet}" "${network}" >/dev/null \
  || { hc_fail "no network with the public subnet ${subnet} (HC_PUBLIC_SUBNET)"; exit 1; }

mkdir -p "${root}/etc" "${root}/var-log" \
  "${root}/var-dionaea/binaries" "${root}/var-dionaea/bistreams" "${root}/var-dionaea/rtp" \
  "${root}"/var-dionaea/roots/{ftp,tftp,www,upnp}
cp -R "${DIONAEA_TESTS_DIR}/config/." "${root}/etc/"
chmod -R a+rwX "${root}/var-log" "${root}/var-dionaea"
chmod -R a+rX "${root}/etc"

docker run -d --name "${inst}" --network "${network}" \
  --read-only --user 2000:2000 \
  --tmpfs /tmp:uid=2000,gid=2000,size=16m \
  -v "${root}/etc:/opt/dionaea/etc/dionaea:ro" \
  -v "${root}/var-dionaea:/opt/dionaea/var/dionaea" \
  -v "${root}/var-log:/opt/dionaea/var/log" \
  "${image}" >/dev/null
hc_say "second dionaea ${inst} on ${subnet}"

docker run --rm --network "${network}" "${DIONAEA_CLIENT_IMAGE}" python -c '
import socket, sys, time
deadline = time.monotonic() + 60
while True:
    try:
        socket.create_connection((sys.argv[1], 42), timeout=2).close()
        break
    except OSError:
        if time.monotonic() > deadline:
            sys.exit("no mirror service within 60 s")
        time.sleep(0.5)
' "${inst}" || { hc_fail "the second dionaea does not answer on port 42"; exit 1; }

rc=0
docker run --name "${client}" --network "${network}" -v "${DIONAEA_TESTS_DIR}:/tests:ro" \
  "${DIONAEA_CLIENT_IMAGE}" python /tests/scenarios/mirror_public_client.py --host "${inst}" --port 42 \
  2>&1 | sed 's/^/    client: /' || true
status="$(docker inspect -f '{{.State.ExitCode}}' "${client}" 2>/dev/null || echo unknown)"
if [[ "${status}" != "0" ]]; then
  hc_fail "the mirror of a public client does not work as it should (client exit ${status})"
  rc=1
else
  hc_say "a public client is mirrored, once per source"
fi

docker stop -t 30 "${inst}" >/dev/null
log="${root}/var-dionaea/dionaea.log"
if [[ ! -f "${log}" ]]; then
  hc_fail "the second dionaea wrote no dionaea.log"
  rc=1
elif grep -nE 'Traceback|LoaderError|Error loading module|Unable to start service' "${log}" >&2; then
  hc_fail "errors in dionaea.log of the second dionaea (see above)"
  rc=1
fi
exit ${rc}
