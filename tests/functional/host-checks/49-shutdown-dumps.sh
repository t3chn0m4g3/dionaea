#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# The dumps of the connections that are open when dionaea stops are complete. dionaea
# never frees these connections at its end, so their dumps ended without the closing
# "')]" and were no Python literal (ast.literal_eval failed). The shutdown of the
# streamdumper closes them now, as at the end of a connection.
#
# A second dionaea (the limits of T-Pot in [processor.streamdumper]) gets connections
# that stay open: FTP (banner, then a command without its line end), HTTP (half a
# request), SMB (a NetBIOS session request), and is stopped while a client container
# holds them. Every file of bistreams/ must parse, the open FTP connections among them.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

inst="${DIONAEA_CONTAINER}-dumps"
holder="${DIONAEA_CONTAINER}-dumps-client"
root="${DIONAEA_TMP_ROOT}/dumps"
image="$(docker inspect -f '{{.Config.Image}}' "${DIONAEA_CONTAINER}")"
count=8

cleanup_dumps() {
  docker rm -f "${holder}" "${inst}" >/dev/null 2>&1 || true
}
trap cleanup_dumps EXIT

mkdir -p "${root}/etc" "${root}/var-log" \
  "${root}/var-dionaea/binaries" "${root}/var-dionaea/bistreams" "${root}/var-dionaea/rtp" \
  "${root}"/var-dionaea/roots/{ftp,tftp,www,upnp}
cp -R "${DIONAEA_TESTS_DIR}/config/." "${root}/etc/"
# the limits of T-Pot go below config.path of [processor.streamdumper]
awk '{ print } /^config\.path=.*bistreams/ { print "config.max_size=2048"; print "config.max_files=200000" }' \
  "${DIONAEA_TESTS_DIR}/config/dionaea.cfg" > "${root}/etc/dionaea.cfg"
grep -qx "config.max_files=200000" "${root}/etc/dionaea.cfg" || { hc_fail "the limits are not in dionaea.cfg"; exit 1; }
chmod -R a+rwX "${root}/var-log" "${root}/var-dionaea"
chmod -R a+rX "${root}/etc"

docker run -d --name "${inst}" --network "${DIONAEA_NETWORK}" \
  --read-only --user 2000:2000 \
  --tmpfs /tmp:uid=2000,gid=2000,size=16m \
  -v "${root}/etc:/opt/dionaea/etc/dionaea:ro" \
  -v "${root}/var-dionaea:/opt/dionaea/var/dionaea" \
  -v "${root}/var-log:/opt/dionaea/var/log" \
  "${image}" >/dev/null
hc_say "second dionaea ${inst}"

# the client holds the connections until it is removed; "held" on stdout once they are open
docker run -d --name "${holder}" --network "${DIONAEA_NETWORK}" "${DIONAEA_CLIENT_IMAGE}" python -u -c '
import socket, sys, time
host, count = sys.argv[1], int(sys.argv[2])
deadline = time.monotonic() + 60
while True:
    try:
        socket.create_connection((host, 21), timeout=2).close()
        break
    except OSError:
        if time.monotonic() > deadline:
            sys.exit("no FTP within 60 s")
        time.sleep(0.5)
held = []
for i in range(count):
    c = socket.create_connection((host, 21), timeout=10)
    if not c.recv(1024).startswith(b"220"):
        sys.exit("no FTP banner")
    c.sendall(b"USER open-%d" % i)          # no line end: dionaea waits for the rest
    held.append(c)
    h = socket.create_connection((host, 81), timeout=10)
    h.sendall(b"GET /open-%d HTTP/1.1\r\nHost: x\r\n" % i)   # half a request
    held.append(h)
    s = socket.create_connection((host, 445), timeout=10)
    s.sendall(b"\x81\x00\x00\x44" + b" " * 68)   # a NetBIOS session request
    held.append(s)
time.sleep(2)   # dionaea has dumped what came
print("held", flush=True)
time.sleep(600)
' "${inst}" "${count}" >/dev/null
for _ in $(seq 1 120); do
  if docker logs "${holder}" 2>/dev/null | grep -q '^held$'; then
    break
  fi
  if [[ "$(docker inspect -f '{{.State.Running}}' "${holder}" 2>/dev/null)" != "true" ]]; then
    hc_fail "the client that holds the connections ended: $(docker logs "${holder}" 2>&1 | tail -n 3)"
    exit 1
  fi
  sleep 0.5
done
docker logs "${holder}" 2>/dev/null | grep -q '^held$' || { hc_fail "the connections were not open within 60 s"; exit 1; }

# the connections are open while dionaea stops
rc=0
docker stop -t 30 "${inst}" >/dev/null
status="$(docker inspect -f '{{.State.ExitCode}}' "${inst}")"
if [[ "${status}" != "0" && "${status}" != "255" ]]; then
  hc_fail "the second dionaea exited with ${status}"
  rc=1
fi
docker rm -f "${holder}" >/dev/null 2>&1 || true

docker run --rm -v "${root}/var-dionaea/bistreams:/b:ro" "${DIONAEA_CLIENT_IMAGE}" python -c '
import ast, os, sys
count = int(sys.argv[1])
bad, ftp_open, total = [], 0, 0
for folder, _, names in os.walk("/b"):
    for name in names:
        path = os.path.join(folder, name)
        total += 1
        text = open(path, encoding="ascii").read()
        try:
            stream = ast.literal_eval(text[len("stream = "):]) if text.startswith("stream = ") else None
        except (SyntaxError, ValueError):
            stream = None
        if stream is None:
            bad.append("%s: %r" % (name, text[-40:]))
            continue
        if any(d == "in" and data.startswith(b"USER open-") for d, data in stream):
            ftp_open += 1
for line in bad[:5]:
    print("not a literal:", line, file=sys.stderr)
print("%d dumps, %d of the open FTP connections, %d do not parse" % (total, ftp_open, len(bad)))
sys.exit(1 if bad or ftp_open < count else 0)
' "${count}" || { hc_fail "dumps of connections open at the stop are incomplete (see above)"; rc=1; }

log="${root}/var-dionaea/dionaea.log"
if grep -nE 'Traceback|LoaderError|Error loading module|Unable to start service' "${log}" >&2; then
  hc_fail "errors in dionaea.log of the second dionaea (see above)"
  rc=1
fi
[[ ${rc} -eq 0 ]] && hc_say "every dump parses, also those of the ${count} FTP connections open at the stop"
exit ${rc}
