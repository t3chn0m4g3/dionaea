#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# The binding in a running dionaea: dionaea.core.timer (logsql commits with it
# once a second) and the connection wrappers of incidents.
#
# A second dionaea on the same network imports probes/binding_probe.py, which makes
# one-shot and repeating timers, stops some inside their own callback, drops the
# reference of one and lets one raise, then reads incident.con 200 times. The check
# expects from binding-probe.json: every timer called as often as it should be, the two
# exceptions logged with their Traceback (and no other Traceback in the container log),
# the reads of incident.con without objects in reference cycles (at most 20 for all
# 200), a closed connection as the value of an incident gives ReferenceError, and
# dionaea still running and answering afterwards.
# An ihandler of the probe raises with a message of a client's kind (an escape sequence,
# 1000 characters, 60 line breaks): dionaea-errors.log has its Traceback with printable
# lines of at most 256 characters, at most 40 of them. Its stop() raises with no handler
# of logging left: that record is in dionaea-errors.log the same way, and nothing of it
# reaches the container log raw (the escape sequence of its text).
# The errors log of the second dionaea takes critical (as config/dionaea.cfg; added if
# it lacks it): the two records of the timer at Python's error level are in it, with
# their Traceback.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

probe="${DIONAEA_CONTAINER}-binding"
root="${DIONAEA_TMP_ROOT}/binding"
image="$(docker inspect -f '{{.Config.Image}}' "${DIONAEA_CONTAINER}")"

cleanup_binding() {
  docker rm -f "${probe}" >/dev/null 2>&1 || true
}
trap cleanup_binding EXIT

mkdir -p "${root}/etc" "${root}/var-log" \
  "${root}/var-dionaea/binaries" "${root}/var-dionaea/bistreams" "${root}/var-dionaea/rtp" \
  "${root}"/var-dionaea/roots/{ftp,tftp,www,upnp}
cp -R "${DIONAEA_TESTS_DIR}/config/." "${root}/etc/"
sed -i.orig 's/^imports=\(.*\)$/imports=\1,binding_probe/' "${root}/etc/dionaea.cfg"
grep -q '^imports=.*,binding_probe$' "${root}/etc/dionaea.cfg" || { hc_fail "could not add binding_probe to imports"; exit 1; }
rm -f "${root}/etc/dionaea.cfg.orig"
if ! grep -q '^errors\.levels=.*critical' "${root}/etc/dionaea.cfg"; then
  sed -i.orig 's/^errors\.levels=\(.*\)$/errors.levels=\1,critical/' "${root}/etc/dionaea.cfg"
  rm -f "${root}/etc/dionaea.cfg.orig"
fi
grep -q '^errors\.levels=.*critical' "${root}/etc/dionaea.cfg" || { hc_fail "could not add critical to errors.levels"; exit 1; }
chmod -R a+rwX "${root}/var-log" "${root}/var-dionaea"
chmod -R a+rX "${root}/etc"

docker run -d --name "${probe}" --network "${DIONAEA_NETWORK}" \
  --read-only --user 2000:2000 \
  --tmpfs /tmp:uid=2000,gid=2000,size=16m \
  -v "${root}/etc:/opt/dionaea/etc/dionaea:ro" \
  -v "${root}/var-dionaea:/opt/dionaea/var/dionaea" \
  -v "${root}/var-log:/opt/dionaea/var/log" \
  -v "${DIONAEA_TESTS_DIR}/probes/binding_probe.py:/opt/dionaea/lib/dionaea/python/binding_probe.py:ro" \
  "${image}" >/dev/null
hc_say "second dionaea ${probe} with probes/binding_probe.py"

result="${root}/var-log/binding-probe.json"
for _ in $(seq 1 60); do
  [[ -s "${result}" ]] && break
  sleep 0.5
done
rc=0
if [[ ! -s "${result}" ]]; then
  hc_fail "no binding-probe.json after 30 s"
  docker logs "${probe}" 2>&1 | tail -n 30 >&2
  exit 1
fi
hc_say "binding-probe.json: $(cat "${result}")"
sleep 1   # nothing may fire any more

docker run --rm --network "${DIONAEA_NETWORK}" -v "${root}/var-log:/r:ro" "${DIONAEA_CLIENT_IMAGE}" python -c '
import json, socket, sys
r = json.load(open("/r/binding-probe.json"))
want = {"one_shot": 1, "unreferenced": 1, "self_stop_repeat": 3, "self_stop_once": 1, "raises": 4, "stopped_early": 0}
if r.get("raised") != 1 or "raise_error" in r:
    sys.exit("the raising ihandler: called %s times, %s" % (r.get("raised"), r.get("raise_error")))
bad = {k: (r["calls"].get(k), v) for k, v in want.items() if r["calls"].get(k) != v}
errors = [(e["exception"], e["message"]) for e in r["errors"]]
if bad:
    sys.exit("calls (got, expected): %s" % bad)
if errors != [("ValueError", "timer probe 1"), ("ValueError", "timer probe 2")]:
    sys.exit("logged errors: %s" % errors)
if r.get("wrapper_gets") != 200 or r.get("wrapper_garbage", 1 << 30) > 20:
    sys.exit("incident.con: %s reads left %s objects in reference cycles (%s us a read; %s)" % (
        r.get("wrapper_gets"), r.get("wrapper_garbage"), r.get("wrapper_us"), r.get("wrapper_error")))
if r.get("released_value") != "ReferenceError":
    sys.exit("a closed connection as the value of an incident: %s (expected ReferenceError)" % r.get("released_value"))
c = socket.create_connection((sys.argv[1], 21), timeout=10)
if not c.recv(1024).startswith(b"220"):
    sys.exit("no FTP banner")
print("timers as expected; incident.con: %d reads, %d objects in cycles, %s us a read; "
      "a closed connection is no incident value; FTP answers" % (
    r["wrapper_gets"], r["wrapper_garbage"], r["wrapper_us"]))
' "${probe}" | sed 's/^/    /' || { hc_fail "the binding did not behave"; rc=1; }

if [[ "$(docker inspect -f '{{.State.Running}}' "${probe}" 2>/dev/null)" != "true" ]]; then
  hc_fail "the second dionaea is not running after the probe"
  rc=1
fi

docker stop -t 30 "${probe}" >/dev/null
log="${root}/var-dionaea/dionaea.log"
if [[ ! -f "${log}" ]]; then
  hc_fail "dionaea.log of the second dionaea is missing"
  exit 1
fi
# the Tracebacks are in the container log (dionaea.log has the first line of a record)
console="${root}/container.log"
docker logs "${probe}" > "${console}" 2>&1 || true
tracebacks="$(grep -c 'Traceback' "${console}" || true)"
probe_errors="$(grep -c 'ValueError: timer probe' "${console}" || true)"
if [[ "${tracebacks}" != "4" || "${probe_errors}" != "2" ]]; then
  hc_fail "container log: ${tracebacks} Tracebacks, ${probe_errors} of the timer probe (expected 4 and 2)"
  grep -n -A6 'Traceback' "${console}" | head -n 40 >&2 || true
  rc=1
else
  hc_say "container log: the 4 exceptions of the probe with their Traceback, no other"
fi
if grep -q $'\x1b\[2J' "${console}"; then
  hc_fail "the container log has the text of the exception at the stop as it was"
  rc=1
fi
# the exceptions of the ihandler and of the stop in dionaea-errors.log: records of printable lines
errors="${root}/var-dionaea/dionaea-errors.log"
docker run --rm -v "${root}/var-dionaea:/r:ro" "${DIONAEA_CLIENT_IMAGE}" python -c '
import re, sys
raw = open("/r/dionaea-errors.log", "rb").read()
lines = raw.split(b"\n")
bad = [n for n, line in enumerate(lines, 1) if any(b < 0x20 or b > 0x7e for b in line)]
if bad:
    sys.exit("dionaea-errors.log: %d lines with bytes outside 0x20..0x7e, e.g. line %d: %r" % (
        len(bad), bad[0], lines[bad[0] - 1][:120]))
text = [line.decode() for line in lines]
if text and text[-1] == "":
    text.pop()   # after the last line break of the file
# a line of the log file starts with its prefix; the lines after it in the same record do not
records = []
for line in text:
    if re.match(r"^\[\d{8} \d\d:\d\d:\d\d\] ", line):
        records.append([line])
    elif records:
        records[-1].append(line)
timer = [r for r in records if "There was an error in a timer callback" in r[0]]
if len(timer) != 2 or not all("Traceback (most recent call last):" in r and
                              any(line.startswith("ValueError: timer probe") for line in r) for r in timer):
    sys.exit("dionaea-errors.log has %d records of the timer at error, with their Traceback: %r" % (
        len(timer), [r[:2] for r in timer]))
print("the 2 errors of the timer (Python error, glib critical) are in dionaea-errors.log")
records = [r for r in records if "There was an error in the Python code" in r[0]]
for what, head, last in (("the ihandler", "ValueError: binding probe?[31m", "end of the binding probe"),
                         ("the stop", "ValueError: binding probe at stop?[2J", "end of the stop")):
    found = [r for r in records if any(line.startswith(head) for line in r)]
    if len(found) != 1:
        sys.exit("dionaea-errors.log has %d records of the exception of %s" % (len(found), what))
    record = found[0]
    want = head + ("z" if what == "the ihandler" else "s") * (256 - len(head)) + "..."
    if want not in record or record[-1] != last:
        sys.exit("the record of %s: %r" % (what, [line[:80] for line in record]))
    if len(record) > 1 + 40 or max(len(line) for line in record[1:]) > 259:
        sys.exit("the record of %s has %d lines, the longest %d characters" % (
            what, len(record), max(len(line) for line in record[1:])))
    print("the exception of %s: %d lines in dionaea-errors.log, all printable" % (what, len(record)))
' | sed 's/^/    /' || { hc_fail "the exceptions of the probe in ${errors##*/}"; rc=1; }
if [[ "$(grep -c 'There was an error in a timer callback' "${console}" || true)" != "2" ]]; then
  hc_fail "the container log does not have the 2 errors of the timer callback"
  rc=1
fi
if grep -nE 'LoaderError|Error loading module|Unable to start service' "${log}" >&2; then
  hc_fail "errors in dionaea.log of the second dionaea (see above)"
  rc=1
fi
exit ${rc}
