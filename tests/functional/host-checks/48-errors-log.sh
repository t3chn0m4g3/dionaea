#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# dionaea-errors.log (warning and error, the only log of T-Pot) gets no line for a
# request of every day: an FTP command, a missing TFTP file,
# the database of a MySQL login, a refused SQL statement, an SMB message over the
# limit, a partial DCERPC request, a reset port scan, the read on the socket of a UDP
# session that closed itself.
#
# A second dionaea gets scenarios/routine_requests.py and is stopped (the logs are
# written then). Its dionaea-errors.log must have none of these lines; dionaea.log
# (info and above) must still have the ones that moved to info.
#
# The errors log of the sample configuration (conf/dionaea.cfg.cmake) takes critical as well:
# a record of Python's logging at error is a glib critical.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

sample="${DIONAEA_TESTS_DIR}/../../conf/dionaea.cfg.cmake"
sample_levels="$(sed -n 's/^errors\.levels=//p' "${sample}")"
case ",${sample_levels}," in
  *,warning,*) ;;
  *) hc_fail "errors.levels of ${sample##*/} has no warning: ${sample_levels}"; exit 1 ;;
esac
for level in error critical; do
  case ",${sample_levels}," in
    *",${level},"*) ;;
    *) hc_fail "errors.levels of ${sample##*/} has no ${level}: ${sample_levels}"; exit 1 ;;
  esac
done
hc_say "errors.levels of ${sample##*/}: ${sample_levels}"

inst="${DIONAEA_CONTAINER}-quiet"
root="${DIONAEA_TMP_ROOT}/quiet"
image="$(docker inspect -f '{{.Config.Image}}' "${DIONAEA_CONTAINER}")"

cleanup_quiet() {
  docker rm -f "${inst}" >/dev/null 2>&1 || true
}
trap cleanup_quiet EXIT

mkdir -p "${root}/etc" "${root}/var-log" \
  "${root}/var-dionaea/binaries" "${root}/var-dionaea/bistreams" "${root}/var-dionaea/rtp" \
  "${root}"/var-dionaea/roots/{ftp,tftp,www,upnp}
cp -R "${DIONAEA_TESTS_DIR}/config/." "${root}/etc/"
echo "a file of the FTP root" > "${root}/var-dionaea/roots/ftp/functional-list.txt"
echo "a file of the TFTP root" > "${root}/var-dionaea/roots/tftp/functional.txt"
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

docker run --rm --network "${DIONAEA_NETWORK}" "${DIONAEA_CLIENT_IMAGE}" python -c '
import socket, sys, time
deadline = time.monotonic() + 60
while True:
    try:
        socket.create_connection((sys.argv[1], 21), timeout=2).close()
        break
    except OSError:
        if time.monotonic() > deadline:
            sys.exit("no FTP within 60 s")
        time.sleep(0.5)
' "${inst}" || { hc_fail "the second dionaea does not answer"; exit 1; }

routine_out="$(docker run --rm --network "${DIONAEA_NETWORK}" -v "${DIONAEA_TESTS_DIR}:/tests:ro" \
  "${DIONAEA_CLIENT_IMAGE}" python /tests/scenarios/routine_requests.py --host "${inst}")" \
  || { printf '%s\n' "${routine_out}" >&2; hc_fail "the routine requests failed"; exit 1; }
# the client ports of the connections that reset after their request (reset_after_request)
reset_ports="$(printf '%s\n' "${routine_out}" | awk '/^reset after request from port / {print $NF}')"
docker stop -t 30 "${inst}" >/dev/null

rc=0
errors="${root}/var-dionaea/dionaea-errors.log"
log="${root}/var-dionaea/dionaea.log"
if [[ ! -f "${errors}" ]]; then
  hc_fail "the second dionaea wrote no dionaea-errors.log"
  exit 1
fi
# lines of a request of every day: none may be in dionaea-errors.log
routine=(
  "ftp.py:[0-9]+-warning: cmd '"
  "-warning: no dtp on "
  "-warning: DATABASE opening "
  "-warning: open db "
  "-warning: SQL ERROR"
  "-warning: Requested file "
  "-warning: Insecure path"
  "-warning: Unsupported mode"
  "-warning: SMB message exceeds limit"
  "-warning: p.haslayer\\(Raw\\)"
  "-warning: epmapper - not enough data"
  "-warning: no attack data for "
  "-warning: no attackid for "
  "-warning: getpeername failed \\(Transport endpoint is not connected\\)"
  "-warning: accepting connection failed"
  "-warning: connection error -1 Bad file descriptor"
  "-warning: Potential FTP Bounce Scan detected"
  "-warning: recv failed .*\\((Connection reset by peer|Broken pipe)\\)"
)
for pattern in "${routine[@]}"; do
  n="$(grep -cE -- "${pattern}" "${errors}" || true)"
  if [[ "${n}" -gt 0 ]]; then
    hc_fail "dionaea-errors.log has ${n} lines of '${pattern}', e.g.: $(grep -m1 -E -- "${pattern}" "${errors}" | cut -c1-160)"
    rc=1
  fi
done
# what moved to info is still in dionaea.log
for pattern in "-info: Requested file .* does not exist" "-info: Insecure path" "-info: Unsupported mode" \
               "-info: SQL ERROR" "-info: SMB message exceeds limit" "-info: no dtp on " \
               "-info: Potential FTP Bounce Scan detected"; do
  if ! grep -qE -- "${pattern}" "${log}"; then
    hc_fail "dionaea.log has no line of '${pattern}'"
    rc=1
  fi
done
# the reset after a request was read, and logged at info: a line of one of those ports (a port scan
# that resets makes a line of the same text, from other ports)
if [[ -z "${reset_ports}" ]]; then
  hc_fail "the routine requests made no connection that resets after its request"
  rc=1
else
  matched=0
  for port in ${reset_ports}; do
    if grep -qE -- "-info: recv failed .*\((Connection reset by peer|Broken pipe)\), connection [0-9a-fA-F.:]+:${port}\$" "${log}"; then
      matched=$(( matched + 1 ))
    fi
  done
  if [[ "${matched}" -eq 0 ]]; then
    hc_fail "dionaea.log has no recv failed line at info of the $(wc -w <<< "${reset_ports}" | tr -d ' ') connections that reset after their request"
    rc=1
  else
    hc_say "${matched} of $(wc -w <<< "${reset_ports}" | tr -d ' ') resets after a request are in dionaea.log at info"
  fi
fi
if grep -nE 'Traceback|LoaderError|Error loading module|Unable to start service' "${log}" >&2; then
  hc_fail "errors in dionaea.log of the second dionaea (see above)"
  rc=1
fi
if [[ ${rc} -eq 0 ]]; then
  hc_say "dionaea-errors.log: $(wc -l < "${errors}" | tr -d ' ') lines, none of a routine request"
fi
exit ${rc}
