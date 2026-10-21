#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# The size cap of the store handler (max_size) needs its own configuration, so
# the check starts a second dionaea with ``max_size: 1`` (MiB) in
# ihandlers/store.yaml on the same network and runs test_store_cap_instance.py
# against it (it also runs the printer service, whose PCL jobs go through the store). After dionaea was stopped (its log files are written then) the
# check expects the info line of every refused sample in dionaea.log, once per md5
# even if the sample was uploaded again.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

cap="${DIONAEA_CONTAINER}-cap"
client="${cap}-client"
root="${DIONAEA_TMP_ROOT}/cap"
image="$(docker inspect -f '{{.Config.Image}}' "${DIONAEA_CONTAINER}")"

cleanup_cap() {
  docker rm -f "${client}" >/dev/null 2>&1 || true
  docker rm -f "${cap}" >/dev/null 2>&1 || true
}
trap cleanup_cap EXIT

mkdir -p "${root}/etc" "${root}/out" "${root}/var-log" \
  "${root}/var-dionaea/binaries" "${root}/var-dionaea/bistreams" "${root}/var-dionaea/rtp" \
  "${root}"/var-dionaea/roots/{ftp,tftp,www,upnp,printer}
cp -R "${DIONAEA_TESTS_DIR}/config/." "${root}/etc/"
cat > "${root}/etc/ihandlers/store.yaml" <<'YAML'
- name: store
  config:
    max_size: 1
YAML
# the printer service (port 9100) is not in the T-Pot config: its PCL jobs have to go through the store too
cat > "${root}/etc/services/printer.yaml" <<'YAML'
- name: printer
  config:
    root: "/opt/dionaea/var/dionaea/roots/printer"
YAML
chmod -R a+rwX "${root}/var-log" "${root}/var-dionaea" "${root}/out"
chmod -R a+rX "${root}/etc"

docker run -d --name "${cap}" --network "${DIONAEA_NETWORK}" \
  --read-only --user 2000:2000 \
  --tmpfs /tmp:uid=2000,gid=2000,size=16m \
  -v "${root}/etc:/opt/dionaea/etc/dionaea:ro" \
  -v "${root}/var-dionaea:/opt/dionaea/var/dionaea" \
  -v "${root}/var-log:/opt/dionaea/var/log" \
  "${image}" >/dev/null
hc_say "second dionaea ${cap} with max_size 1"

rc=0
docker run --rm --name "${client}" --network "${DIONAEA_NETWORK}" \
  -v "${DIONAEA_TESTS_DIR}:/tests:ro" \
  -v "${root}/var-dionaea:/dionaea/data:ro" \
  -v "${root}/var-log:/dionaea/log:ro" \
  -v "${root}/out:/out" \
  -e DIONAEA_HOST="${cap}" \
  -e DIONAEA_DATA_DIR=/dionaea/data \
  -e DIONAEA_LOG_DIR=/dionaea/log \
  -e DIONAEA_CAP_INSTANCE=1 \
  -e DIONAEA_CAP_OUT=/out \
  -e DIONAEA_START_TIMEOUT="${DIONAEA_START_TIMEOUT:-60}" \
  "${DIONAEA_CLIENT_IMAGE}" \
  python -m pytest -p no:cacheprovider -ra test_store_cap_instance.py || rc=1

# it must still run after the refused samples
if [[ "$(docker inspect -f '{{.State.Running}}' "${cap}" 2>/dev/null)" != "true" ]]; then
  hc_fail "the second dionaea is not running after the tests"
  rc=1
fi

docker stop -t 30 "${cap}" >/dev/null
log="${root}/var-dionaea/dionaea.log"
if [[ ! -f "${log}" ]]; then
  hc_fail "dionaea.log of the second dionaea is missing"
  exit 1
fi
if grep -nE 'Traceback|LoaderError|Error loading module|Unable to start service' "${log}" >&2; then
  hc_fail "errors in dionaea.log of the second dionaea (see above)"
  rc=1
fi
if ! grep -q 'limited to 1 MiB' "${log}"; then
  hc_fail "dionaea.log has no line about the limit of 1 MiB"
  rc=1
fi
if [[ ! -s "${root}/out/cap-refused" ]]; then
  hc_fail "no refused sample was recorded by the tests"
  rc=1
else
  while read -r md5; do
    [[ -n "${md5}" ]] || continue
    count="$(grep -c "Not storing ${md5} " "${log}" || true)"
    if [[ "${count}" == "1" ]]; then
      hc_say "dionaea.log has the line for ${md5}"
    else
      hc_fail "dionaea.log has ${count} lines for the refused sample ${md5} (expected one)"
      rc=1
    fi
  done < "${root}/out/cap-refused"
fi
if [[ ${rc} -ne 0 ]]; then
  echo "---- dionaea.log of the second dionaea (last 40 lines) ----" >&2
  tail -n 40 "${log}" | cut -c1-300 >&2
fi
exit ${rc}
