#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# A TFTP session whose socket cannot be made gives its place back.
#
# Every read request claims one of the 64 places of the TFTP sessions (4 per
# source address) before its handler makes a UDP socket. When socket() fails
# (EMFILE, ENFILE, ENOBUFS) the core calls the error callback and frees the
# connection; no disconnect follows, so the error callback gives the place back.
#
# The check lowers the soft fd limit of the running process below the fds it
# has open (prlimit), so the next socket() fails with EMFILE, and sends 8 read
# requests from one client (one source address). Then it restores the limit:
#   - a read request of the same client gets DATA (its places are back)
#   - no Traceback in the container log meanwhile
#   - after dionaea stopped, dionaea-errors.log has the EMFILE line of
#     socket() (run.sh checks it, hc_expect_log)

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

pid="$(hc_main_pid)"
read -r soft hard < <(hc_exec_root awk '/^Max open files/ {print $4, $5}' "/proc/${pid}/limits")
client="${DIONAEA_CONTAINER}-tftp-nosock"
cleanup_nosock() {
  docker rm -f "${client}" >/dev/null 2>&1 || true
  hc_exec_root prlimit --pid "${pid}" --nofile="${soft}:${hard}" >/dev/null 2>&1 || true
}
trap cleanup_nosock EXIT

# one client container for all requests: one source address
docker run -d --name "${client}" --network "${DIONAEA_NETWORK}" "${DIONAEA_CLIENT_IMAGE}" \
  sleep 300 >/dev/null

REQUESTS='
import socket, struct, sys
host, count, expect = sys.argv[1], int(sys.argv[2]), sys.argv[3]
rrq = struct.pack("!H", 1) + b"functional-test.txt\x00octet\x00"
replies = []
for _ in range(count):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    s.sendto(rrq, (host, 69))
    try:
        data, _ = s.recvfrom(2048)
        opcode = struct.unpack("!H", data[:2])[0]
        replies.append("DATA" if opcode == 3 else "ERROR %r" % data[4:-1].decode("ascii", "replace"))
    except socket.timeout:
        replies.append("none")
    s.close()
print(" ".join(r.replace(" ", "_") for r in replies))
if expect == "data" and replies[-1] != "DATA":
    sys.exit(1)
'

# socket() needs an fd below the soft limit. The limit goes to at most 16, below the
# fds dionaea keeps for good (logs, the loop, the listeners): an fd that is closed in
# the meantime (the journal of dionaea.sqlite) must not make a hole below it.
lowest="$(hc_exec_root sh -c "ls /proc/${pid}/fd" | sort -n | awk 'BEGIN {n = 0} $1 == n {n++} END {print n}')"
low=$(( lowest < 16 ? lowest : 16 ))
since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
hc_exec_root prlimit --pid "${pid}" --nofile="${low}:${hard}"
hc_say "fd limit ${soft}, fds 0 to $(( lowest - 1 )) in use, soft limit lowered to ${low}"
rc=0
out="$(docker exec "${client}" python -c "${REQUESTS}" "${DIONAEA_CONTAINER}" 8 any 2>&1)" || true
hc_say "8 read requests without fds: ${out}"
hc_exec_root prlimit --pid "${pid}" --nofile="${soft}:${hard}"
hc_say "fd limit restored to ${soft}"

if out="$(docker exec "${client}" python -c "${REQUESTS}" "${DIONAEA_CONTAINER}" 1 data 2>&1)"; then
  hc_say "read request of the same source afterwards: ${out}"
else
  hc_fail "the source got no session after its sockets failed (places kept): ${out}"
  rc=1
fi

# the Tracebacks are in the container log (dionaea.log has the first line of a record)
if docker logs --since "${since}" "${DIONAEA_CONTAINER}" 2>&1 | grep -q 'Traceback'; then
  docker logs --since "${since}" "${DIONAEA_CONTAINER}" 2>&1 | grep -A8 'Traceback' | head -n 40 >&2
  hc_fail "Traceback in the container log while the sockets failed"
  rc=1
else
  hc_say "no Traceback in the container log"
fi
hc_expect_log dionaea-errors.log "socket\(\) failed for con .*\(Too many open files\)"
hc_running || { hc_fail "dionaea is not running"; exit 1; }
exit ${rc}
