#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# The rows of the last second survive a stop. log_sqlite commits once a second;
# when dionaea stops, the event loop ends, the python imports flush (module api
# flush: dionaea.ihandlers.flush() commits log_sqlite) and only then dionaea
# waits for its threadpool, whose waiting processor jobs are dropped. A stop
# timeout during that wait (10 s in Docker) no longer loses the rows written
# since the last commit.
#
# A second dionaea gets 40 FTP connections, each one up to its banner (its row
# of connections is written, not yet committed), and is stopped right after the
# last one. All 40 rows have to be in dionaea.sqlite, and dionaea.log has the
# flush of dionaea.ihandlers before the stop of the imports.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

inst="${DIONAEA_CONTAINER}-flush"
root="${DIONAEA_TMP_ROOT}/flush"
image="$(docker inspect -f '{{.Config.Image}}' "${DIONAEA_CONTAINER}")"
count=40

cleanup_flush() {
  docker rm -f "${inst}" >/dev/null 2>&1 || true
}
trap cleanup_flush EXIT

mkdir -p "${root}/etc" "${root}/var-log" \
  "${root}/var-dionaea/binaries" "${root}/var-dionaea/bistreams" "${root}/var-dionaea/rtp" \
  "${root}"/var-dionaea/roots/{ftp,tftp,www,upnp}
cp -R "${DIONAEA_TESTS_DIR}/config/." "${root}/etc/"
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

rc=0
docker run --rm --network "${DIONAEA_NETWORK}" "${DIONAEA_CLIENT_IMAGE}" python -c '
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
time.sleep(2)   # the commit of the probe connection is done
for _ in range(count):
    with socket.create_connection((host, 21), timeout=10) as c:
        if not c.recv(1024).startswith(b"220"):
            sys.exit("no FTP banner")
' "${inst}" "${count}" || { hc_fail "the FTP connections failed"; exit 1; }
# at once: the rows of the last second are not committed yet
docker stop -t 30 "${inst}" >/dev/null

rows="$(docker run --rm -v "${root}/var-log:/r" "${DIONAEA_CLIENT_IMAGE}" python -c '
import sqlite3
db = sqlite3.connect("/r/dionaea.sqlite")
print(db.execute("SELECT COUNT(*) FROM connections WHERE local_port = 21").fetchone()[0])
')"
# the probe connection of the client is one more
if [[ "${rows}" -ge $(( count + 1 )) ]]; then
  hc_say "dionaea.sqlite has ${rows} FTP connections after the stop (${count} + 1 made)"
else
  hc_fail "dionaea.sqlite has ${rows} FTP connections after the stop, $(( count + 1 )) were made"
  rc=1
fi

log="${root}/var-dionaea/dionaea.log"
flush_line="$(grep -n 'flush dionaea.ihandlers' "${log}" | head -n 1 | cut -d: -f1 || true)"
stop_line="$(grep -n 'stop dionaea.ihandlers' "${log}" | head -n 1 | cut -d: -f1 || true)"
if [[ -n "${flush_line}" && -n "${stop_line}" && "${flush_line}" -lt "${stop_line}" ]]; then
  hc_say "dionaea.log: flush of dionaea.ihandlers before the stop of the imports"
else
  hc_fail "dionaea.log: no flush of dionaea.ihandlers before its stop (flush line ${flush_line:-none}, stop line ${stop_line:-none})"
  rc=1
fi
if grep -nE 'Traceback|LoaderError|Error loading module|Unable to start service' "${log}" >&2; then
  hc_fail "errors in dionaea.log of the second dionaea (see above)"
  rc=1
fi
exit ${rc}
