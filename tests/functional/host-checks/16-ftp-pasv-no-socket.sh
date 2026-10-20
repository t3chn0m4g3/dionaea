#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# A PASV whose socket cannot be made gets one 425 and nothing else.
#
# For TCP the core makes the socket in listen(), not in bind(). When socket()
# fails (EMFILE) the core calls the error callback of the data connection (which
# answers 425) and frees it; ftp_PASV then sends no 227 and keeps no listener.
#
# A client logs in on port 21 first (its control connection has its fd). The
# check then lowers the soft fd limit of the running process below the fds it
# has open (prlimit, as 15-tftp-no-socket.sh), the client sends PASV and reads
# what comes for 3 s, the limit is restored, and the client sends PASV again:
#   - the first PASV gets exactly one reply, 425, and no 227
#   - the second gets a 227 with a port, PWD still works
#   - no Traceback in the container log meanwhile

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

pid="$(hc_main_pid)"
read -r soft hard < <(hc_exec_root awk '/^Max open files/ {print $4, $5}' "/proc/${pid}/limits")
client="${DIONAEA_CONTAINER}-pasv-nosock"
flags="${DIONAEA_TMP_ROOT}/pasv-nosock"
mkdir -p "${flags}"
chmod 0777 "${flags}"
cleanup_pasv() {
  docker rm -f "${client}" >/dev/null 2>&1 || true
  hc_exec_root prlimit --pid "${pid}" --nofile="${soft}:${hard}" >/dev/null 2>&1 || true
}
trap cleanup_pasv EXIT

# steps of the client: login -> ready; go -> PASV, 3 s of replies -> first; go2 -> PASV, PWD -> second
docker run -d --name "${client}" --network "${DIONAEA_NETWORK}" -v "${flags}:/x" "${DIONAEA_CLIENT_IMAGE}" python -u -c '
import json, os, socket, sys, time
host = sys.argv[1]

def wait(name):
    deadline = time.monotonic() + 60
    while not os.path.exists("/x/" + name):
        if time.monotonic() > deadline:
            sys.exit("no %s within 60 s" % name)
        time.sleep(0.1)

def put(name, value):
    # whole or not at all: the check waits for the name
    with open("/x/." + name, "w") as f:
        f.write(json.dumps(value))
    os.rename("/x/." + name, "/x/" + name)

def lines(sock, seconds):
    sock.settimeout(0.2)
    data, end = b"", time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        data += chunk
    return [l.decode(errors="replace") for l in data.split(b"\r\n") if l]

c = socket.create_connection((host, 21), timeout=10)
c.sendall(b"USER pasv\r\nPASS nosock\r\n")
login = lines(c, 2)
put("ready", login)
wait("go")
c.sendall(b"PASV\r\n")
put("first", lines(c, 3))
wait("go2")
c.sendall(b"PASV\r\nPWD\r\n")
put("second", lines(c, 3))
' "${DIONAEA_CONTAINER}" >/dev/null

wait_flag() {
  local i
  for (( i = 0; i < 300; i++ )); do
    [[ -f "${flags}/$1" ]] && return 0
    sleep 0.2
  done
  hc_fail "no $1 from the client: $(docker logs "${client}" 2>&1 | tail -n 3)"
  return 1
}

rc=0
wait_flag ready || exit 1
hc_say "login: $(cat "${flags}/ready")"
lowest="$(hc_exec_root sh -c "ls /proc/${pid}/fd" | sort -n | awk 'BEGIN {n = 0} $1 == n {n++} END {print n}')"
low=$(( lowest < 16 ? lowest : 16 ))
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
hc_exec_root prlimit --pid "${pid}" --nofile="${low}:${hard}"
hc_say "fd limit ${soft}, soft limit lowered to ${low}"
touch "${flags}/go"
wait_flag first || rc=1
hc_exec_root prlimit --pid "${pid}" --nofile="${soft}:${hard}"
hc_say "fd limit restored to ${soft}"
touch "${flags}/go2"
wait_flag second || rc=1
[[ ${rc} -eq 0 ]] || exit 1

first="$(cat "${flags}/first")"
second="$(cat "${flags}/second")"
hc_say "PASV without fds: ${first}"
hc_say "PASV, PWD afterwards: ${second}"
if ! docker run --rm "${DIONAEA_CLIENT_IMAGE}" python -c '
import json, sys
first, second = json.loads(sys.argv[1]), json.loads(sys.argv[2])
ok = len(first) == 1 and first[0].startswith("425 ") and not any(l.startswith("227") for l in first)
ok = ok and len(second) == 2 and second[0].startswith("227 ") and not second[0].endswith(",0,0).")
ok = ok and second[1].startswith("257 ")
sys.exit(0 if ok else 1)
' "${first}" "${second}"; then
  hc_fail "PASV without a socket: want one 425 and no 227, then 227 and 257"
  rc=1
fi
if docker logs --since "${since}" "${DIONAEA_CONTAINER}" 2>&1 | grep -q 'Traceback'; then
  docker logs --since "${since}" "${DIONAEA_CONTAINER}" 2>&1 | grep -A8 'Traceback' | head -n 40 >&2
  hc_fail "Traceback in the container log after the PASV without a socket"
  rc=1
else
  hc_say "no Traceback in the container log"
fi
hc_running || { hc_fail "dionaea is not running"; exit 1; }
exit ${rc}
