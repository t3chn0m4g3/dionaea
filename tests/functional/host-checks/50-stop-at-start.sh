#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# A stop right after the start. dionaea is PID 1 of its container: a signal that comes
# before it handles it is ignored (PID 1 has no default action), Docker kills it at the
# end of the stop timeout and the buffered log files are lost. The handlers are installed
# before the services listen, and the python module keeps the one of SIGINT, so a stop as
# soon as the first port answers ends dionaea at once, with exit code 0 and its log files
# written.
#
# A second dionaea starts, once for the stop signal of the image (SIGINT, what docker stop
# sends) and once for SIGTERM; a process in its container connects to the ports of the
# services every 2 ms and sends the signal to PID 1 when the first one answers (as docker
# stop does, without the delay of the docker CLI). dionaea has to end within 30 s with
# exit code 0, and dionaea.log has to have the lines of the stop.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

inst="${DIONAEA_CONTAINER}-stop-at-start"
root="${DIONAEA_TMP_ROOT}/stop-at-start"
image="$(docker inspect -f '{{.Config.Image}}' "${DIONAEA_CONTAINER}")"

cleanup_stop_at_start() {
  docker rm -f "${inst}" >/dev/null 2>&1 || true
}
trap cleanup_stop_at_start EXIT

mkdir -p "${root}/etc"
cp -R "${DIONAEA_TESTS_DIR}/config/." "${root}/etc/"
chmod -R a+rX "${root}/etc"

# the stop signal of the image (SIGINT, docker stop) and SIGTERM
stop_signal="$(docker image inspect -f '{{.Config.StopSignal}}' "${image}")"
signals=("${stop_signal:-SIGTERM}")
[[ "${signals[0]}" == "SIGTERM" ]] || signals+=(SIGTERM)

rc=0
for sig in "${signals[@]}"; do
  # the folders of this signal
  run="${root}/${sig}"
  mkdir -p "${run}/var-log" "${run}/var-dionaea/binaries" "${run}/var-dionaea/bistreams" \
    "${run}/var-dionaea/rtp" "${run}"/var-dionaea/roots/{ftp,tftp,www,upnp}
  chmod -R a+rwX "${run}/var-log" "${run}/var-dionaea"
  docker rm -f "${inst}" >/dev/null 2>&1 || true
  docker run -d --name "${inst}" --network "${DIONAEA_NETWORK}" \
    --read-only --user 2000:2000 \
    --tmpfs /tmp:uid=2000,gid=2000,size=16m \
    -v "${root}/etc:/opt/dionaea/etc/dionaea:ro" \
    -v "${run}/var-dionaea:/opt/dionaea/var/dionaea" \
    -v "${run}/var-log:/opt/dionaea/var/log" \
    "${image}" >/dev/null
  hc_say "second dionaea ${inst} (${sig})"

  # the first port that answers, then the signal to PID 1 at once
  if ! port="$(docker exec "${inst}" python3 -c '
import os, signal, socket, sys, time
sig = getattr(signal, sys.argv[1])
ports = (21, 42, 80, 135, 443, 445, 1433, 1723, 1883, 3306, 27017)
deadline = time.monotonic() + 60
while time.monotonic() < deadline:
    for port in ports:
        s = socket.socket()
        s.settimeout(0.05)
        try:
            s.connect(("127.0.0.1", port))
        except OSError:
            continue
        finally:
            s.close()
        os.kill(1, sig)
        print(port)
        sys.exit(0)
    time.sleep(0.002)
sys.exit("no port answered within 60 s")
' "${sig}")"; then
    hc_fail "no port of the second dionaea answered (${sig})"
    rc=1
    continue
  fi
  hc_say "port ${port} answered, ${sig} sent to dionaea"

  state=""
  for (( i = 0; i < 60; i++ )); do
    state="$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "${inst}")"
    [[ "${state}" == exited* ]] && break
    sleep 0.5
  done
  if [[ "${state}" != exited* ]]; then
    hc_fail "dionaea still runs 30 s after a ${sig} right after the start (${state})"
    rc=1
    continue
  fi
  failed=0
  if [[ "${state}" != "exited 0" ]]; then
    hc_fail "dionaea ended with ${state#exited } after a ${sig} right after the start (expected 0)"
    failed=1
  fi

  log="${run}/var-dionaea/dionaea.log"
  # the callback of the signal, and the stop of the python import dionaea.log, one of the last lines
  callback="sigterm_cb"
  [[ "${sig}" == "SIGINT" ]] && callback="sigint_cb"
  for pattern in "${callback} loop " "-info: stop dionaea\\.log 0x"; do
    if ! grep -qE -- "${pattern}" "${log}" 2>/dev/null; then
      hc_fail "dionaea.log has no line matching '${pattern}' (the lines of the stop, ${sig})"
      failed=1
    fi
  done
  if (( failed != 0 )); then
    tail -n 5 "${log}" 2>/dev/null | sed 's/^/    | /' >&2 || true
    rc=1
    continue
  fi
  hc_say "${sig}: dionaea ended with exit code 0, dionaea.log has the lines of the stop"
done
exit "${rc}"
