#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# A service that asks for a transport the core does not have: the core has tcp, udp and
# tls, DTLS was removed. A second dionaea starts with the blackhole service on port 4434 of
# protocol tcp and port 4433 of protocol dtls. That service does not start: 4434 does not
# accept a connection on any address of the container, IPv4 and (when the container has it)
# IPv6 (no listener is left that the service could not stop), dionaea-errors.log has one warning that names it and the
# transport and no Traceback, and the other services answer (port 21).

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

inst="${DIONAEA_CONTAINER}-transport"
root="${DIONAEA_TMP_ROOT}/transport"
image="$(docker inspect -f '{{.Config.Image}}' "${DIONAEA_CONTAINER}")"

cleanup_transport() {
  docker rm -f "${inst}" >/dev/null 2>&1 || true
}
trap cleanup_transport EXIT

mkdir -p "${root}/etc" "${root}/var-log" \
  "${root}/var-dionaea/binaries" "${root}/var-dionaea/bistreams" "${root}/var-dionaea/rtp" \
  "${root}"/var-dionaea/roots/{ftp,tftp,www,upnp}
cp -R "${DIONAEA_TESTS_DIR}/config/." "${root}/etc/"
cat > "${root}/etc/services/blackhole.yaml" <<'YAML'
- name: blackhole
  config:
    services:
      - port: 4434
        protocol: tcp
      - port: 4433
        protocol: dtls
YAML
chmod -R a+rwX "${root}/var-log" "${root}/var-dionaea"
chmod -R a+rX "${root}/etc"

docker run -d --name "${inst}" --network "${DIONAEA_NETWORK}" \
  --read-only --user 2000:2000 \
  --tmpfs /tmp:uid=2000,gid=2000,size=16m \
  -v "${root}/etc:/opt/dionaea/etc/dionaea:ro" \
  -v "${root}/var-dionaea:/opt/dionaea/var/dionaea" \
  -v "${root}/var-log:/opt/dionaea/var/log" \
  "${image}" >/dev/null
hc_say "second dionaea ${inst} with a blackhole port of protocol dtls"

rc=0
if ! docker exec "${inst}" python3 -c '
import socket, sys, time
deadline = time.monotonic() + 60
while time.monotonic() < deadline:
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect(("127.0.0.1", 21))
        sys.exit(0)
    except OSError:
        time.sleep(0.2)
    finally:
        s.close()
sys.exit("port 21 did not answer within 60 s")
'; then
  hc_fail "the other services of the second dionaea do not answer"
  rc=1
fi
# port 4434 of the blackhole service on no address: IPv4, and IPv6 when the container has it
addresses="127.0.0.1 $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' "${inst}")"
# (a file of /proc has the size 0: test -s never holds)
if docker exec "${inst}" sh -c 'grep -q . /proc/net/if_inet6'; then
  addresses="${addresses} ::1 $(docker inspect -f '{{range .NetworkSettings.Networks}}{{.GlobalIPv6Address}} {{end}}' "${inst}")"
else
  hc_say "the container has no IPv6, only IPv4 is probed"
fi
for address in ${addresses}; do
  if docker exec "${inst}" python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET6 if ":" in sys.argv[1] else socket.AF_INET)
s.settimeout(2)
try:
    s.connect((sys.argv[1], 4434))
except OSError:
    sys.exit(1)
sys.exit(0)
' "${address}"; then
    hc_fail "port 4434 of the blackhole service accepts a connection on ${address}"
    rc=1
  fi
done
if [[ "$(docker inspect -f '{{.State.Running}}' "${inst}" 2>/dev/null)" != "true" ]]; then
  hc_fail "the second dionaea is not running"
  rc=1
fi
docker stop -t 30 "${inst}" >/dev/null

errors="${root}/var-dionaea/dionaea-errors.log"
line="-warning: Unable to start service blackhole: unknown transport 'dtls', the core has tcp, udp and tls"
n="$(grep -cF -- "${line}" "${errors}" 2>/dev/null || true)"
if [[ "${n}" != "1" ]]; then
  hc_fail "dionaea-errors.log has ${n:-0} line(s) '${line}', expected 1"
  rc=1
fi
if grep -nE 'Traceback|LoaderError|Error loading module' "${errors}" >&2; then
  hc_fail "dionaea-errors.log has a traceback"
  rc=1
fi
if (( rc != 0 )); then
  tail -n 20 "${errors}" 2>/dev/null | sed 's/^/    | /' >&2 || true
else
  hc_say "the blackhole service did not start (4434 closed), one line, the other services answer"
fi
exit "${rc}"
