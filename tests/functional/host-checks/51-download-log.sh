#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# The log lines of downloads that do not complete. A target the download target
# filter refuses is one info line ("download target refused by the filter:
# <url>") and nothing in dionaea-errors.log; a download that fails is one info
# line with its reason, and at most one warning a minute sums the failures up
# ("downloads: <N> failed in the last minute, the last: <url> (<reason>)").
#
# A second dionaea, whose download policy allows the network of the test, gets
# scenarios/download_offers.py: for 65 s HTTP and FTP downloads from 127.0.0.1
# (refused) and from a closed port of the client container (allowed, they fail),
# and three TFTP downloads from 127.0.0.1 in shellcode. After a minute more (the
# summary of the last failures) it is stopped, and the same script checks its
# dionaea-errors.log and dionaea.log. It takes about 2.5 minutes.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

inst="${DIONAEA_CONTAINER}-dl"
root="${DIONAEA_TMP_ROOT}/download-log"
image="$(docker inspect -f '{{.Config.Image}}' "${DIONAEA_CONTAINER}")"

cleanup_dl() {
  docker rm -f "${inst}" >/dev/null 2>&1 || true
}
trap cleanup_dl EXIT

mkdir -p "${root}/etc" "${root}/var-log" "${root}/out" \
  "${root}/var-dionaea/binaries" "${root}/var-dionaea/bistreams" "${root}/var-dionaea/rtp" \
  "${root}"/var-dionaea/roots/{ftp,tftp,www,upnp}
cp -R "${DIONAEA_TESTS_DIR}/config/." "${root}/etc/"
subnet="$(docker network inspect --format '{{(index .IPAM.Config 0).Subnet}}' "${DIONAEA_NETWORK}")"
printf '%s\n' '- name: download_policy' '  config:' "    allowed_networks: [\"${subnet}\"]" \
  > "${root}/etc/ihandlers/download_policy.yaml"
chmod -R a+rwX "${root}/var-log" "${root}/var-dionaea" "${root}/out"
chmod -R a+rX "${root}/etc"

docker run -d --name "${inst}" --network "${DIONAEA_NETWORK}" \
  --read-only --user 2000:2000 \
  --tmpfs /tmp:uid=2000,gid=2000,size=16m \
  -v "${root}/etc:/opt/dionaea/etc/dionaea:ro" \
  -v "${root}/var-dionaea:/opt/dionaea/var/dionaea" \
  -v "${root}/var-log:/opt/dionaea/var/log" \
  "${image}" >/dev/null
hc_say "second dionaea ${inst}"

docker run --rm --network "${DIONAEA_NETWORK}" "${DIONAEA_CLIENT_IMAGE}" python -c '
import socket, sys, time
deadline = time.monotonic() + 60
for port in (21, 3306, 445):
    while True:
        try:
            socket.create_connection((sys.argv[1], port), timeout=2).close()
            break
        except OSError:
            if time.monotonic() > deadline:
                sys.exit("no answer on port %d within 60 s" % port)
            time.sleep(0.5)
' "${inst}" || { hc_fail "the second dionaea does not answer"; exit 1; }

docker run --rm --network "${DIONAEA_NETWORK}" -v "${DIONAEA_TESTS_DIR}:/tests:ro" -v "${root}/out:/out" \
  "${DIONAEA_CLIENT_IMAGE}" python /tests/scenarios/download_offers.py offer --host "${inst}" \
  --seconds 65 --out /out/offers.json || { hc_fail "the download offers failed"; exit 1; }
hc_say "waiting 62 s for the summary of the last failures"
sleep 62
docker stop -t 30 "${inst}" >/dev/null

errors="${root}/var-dionaea/dionaea-errors.log"
log="${root}/var-dionaea/dionaea.log"
if [[ ! -f "${errors}" || ! -f "${log}" ]]; then
  hc_fail "the second dionaea wrote no dionaea-errors.log or dionaea.log"
  exit 1
fi
rc=0
docker run --rm -v "${DIONAEA_TESTS_DIR}:/tests:ro" -v "${root}/out:/out:ro" \
  -v "${root}/var-dionaea:/logs:ro" "${DIONAEA_CLIENT_IMAGE}" \
  python /tests/scenarios/download_offers.py check --offers /out/offers.json \
  --errors /logs/dionaea-errors.log --log /logs/dionaea.log || rc=1
if grep -nE 'Traceback|LoaderError|Error loading module|Unable to start service' "${log}" >&2; then
  hc_fail "errors in dionaea.log of the second dionaea (see above)"
  rc=1
fi
exit "${rc}"
