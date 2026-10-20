#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# The limits of the streamdumper (config.max_files, config.max_size) need their own
# configuration, so the check starts a second dionaea on the same network, once
# with config.max_files=40 and twice with config.max_size=0.25 (MiB) in
# [processor.streamdumper], and runs test_bistream_cap_instance.py against it: a
# burst of HTTP connections stays within the limit, every connection is answered,
# (max_files) a folder emptied from outside is noticed by the next count, and
# (long) one FTP connection that goes on sending past max_size: its dump stops
# at the limit as a valid dump, the connection is still answered.
# After dionaea was stopped (its log files are written then) the check expects a
# clean exit, the line of the limit and the warnings about refused and stopped
# dumps in dionaea.log, at most one per minute each and without the data of the
# connections.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

cap="${DIONAEA_CONTAINER}-bistream-cap"
client="${cap}-client"
image="$(docker inspect -f '{{.Config.Image}}' "${DIONAEA_CONTAINER}")"

cleanup_cap() {
  docker rm -f "${client}" >/dev/null 2>&1 || true
  docker rm -f "${cap}" >/dev/null 2>&1 || true
}
trap cleanup_cap EXIT

rc=0
# hc_count_warnings LABEL LOG TEXT MIN MINUTES WHAT: MIN to MINUTES + 1 lines with TEXT, without data
hc_count_warnings() {
  local label="$1" log="$2" text="$3" min="$4" minutes="$5" what="$6" n
  n="$(grep -c "${text}" "${log}" || true)"
  if [[ "${n}" -lt "${min}" || "${n}" -gt $(( minutes + 1 )) ]]; then
    hc_fail "dionaea.log has ${n} warnings about ${what} dumps in ${minutes} minute(s) (expected ${min} to $(( minutes + 1 )))"
    return 1
  fi
  hc_say "${label}: ${n} warning(s) about ${what} dumps in ${minutes} minute(s)"
  grep -m1 "${text}" "${log}" | cut -c1-300 | while read -r line; do hc_say "${line}"; done
  # the warning names totals and limits, never the data of a connection
  if grep "${text}" "${log}" | grep -qE 'AAAA|X-Pad|bistream-cap-|NOOP'; then
    hc_fail "a warning about ${what} dumps carries data of a connection"
    return 1
  fi
}

for mode in files size long; do
  root="${DIONAEA_TMP_ROOT}/bistream-cap-${mode}"
  case "${mode}" in
    files) option="config.max_files=40"; limit_line="limited to max_size unlimited and max_files 40"
           refused_min=1; stopped_min=0 ;;
    size) option="config.max_size=0.25"; limit_line="limited to max_size 0.25 MiB and max_files unlimited"
          refused_min=1; stopped_min=0 ;;
    long) option="config.max_size=0.25"; limit_line="limited to max_size 0.25 MiB and max_files unlimited"
          refused_min=1; stopped_min=1 ;;
  esac
  mkdir -p "${root}/etc" "${root}/out" "${root}/var-log" \
    "${root}/var-dionaea/binaries" "${root}/var-dionaea/bistreams" "${root}/var-dionaea/rtp" \
    "${root}"/var-dionaea/roots/{ftp,tftp,www,upnp}
  cp -R "${DIONAEA_TESTS_DIR}/config/." "${root}/etc/"
  # the option goes below config.path of [processor.streamdumper]
  awk -v option="${option}" '{ print } /^config\.path=.*bistreams/ { print option }' \
    "${DIONAEA_TESTS_DIR}/config/dionaea.cfg" > "${root}/etc/dionaea.cfg"
  grep -qx "${option}" "${root}/etc/dionaea.cfg" || { hc_fail "${option} is not in dionaea.cfg"; exit 1; }
  chmod -R a+rwX "${root}/var-log" "${root}/var-dionaea" "${root}/out"
  chmod -R a+rX "${root}/etc"

  docker run -d --name "${cap}" --network "${DIONAEA_NETWORK}" \
    --read-only --user 2000:2000 \
    --tmpfs /tmp:uid=2000,gid=2000,size=16m \
    -v "${root}/etc:/opt/dionaea/etc/dionaea:ro" \
    -v "${root}/var-dionaea:/opt/dionaea/var/dionaea" \
    -v "${root}/var-log:/opt/dionaea/var/log" \
    "${image}" >/dev/null
  hc_say "second dionaea ${cap} with ${option}"
  started="$(date +%s)"

  docker run --rm --name "${client}" --network "${DIONAEA_NETWORK}" \
    -v "${DIONAEA_TESTS_DIR}:/tests:ro" \
    -v "${root}/var-dionaea:/dionaea/data" \
    -v "${root}/var-log:/dionaea/log:ro" \
    -v "${root}/out:/out" \
    -e DIONAEA_HOST="${cap}" \
    -e DIONAEA_DATA_DIR=/dionaea/data \
    -e DIONAEA_LOG_DIR=/dionaea/log \
    -e DIONAEA_CAP_INSTANCE=1 \
    -e DIONAEA_BISTREAM_CAP="${mode}" \
    -e DIONAEA_CAP_OUT=/out \
    -e DIONAEA_START_TIMEOUT="${DIONAEA_START_TIMEOUT:-60}" \
    "${DIONAEA_CLIENT_IMAGE}" \
    python -m pytest -p no:cacheprovider -ra test_bistream_cap_instance.py || rc=1

  if [[ "$(docker inspect -f '{{.State.Running}}' "${cap}" 2>/dev/null)" != "true" ]]; then
    hc_fail "the second dionaea (${option}) is not running after the tests"
    rc=1
  fi
  docker stop -t 30 "${cap}" >/dev/null
  minutes=$(( ($(date +%s) - started) / 60 + 1 ))
  # the counting thread ends before the logs close: the exit of a stop (255 after
  # SIGINT, see run.sh, or 0), no crash, no kill after the timeout
  status="$(docker inspect -f '{{.State.ExitCode}}' "${cap}" 2>/dev/null || echo unknown)"
  if [[ "${status}" != "0" && "${status}" != "255" ]]; then
    hc_fail "the second dionaea (${option}) exited with ${status}"
    rc=1
  fi
  if [[ -f "${root}/out/bistream-cap-${mode}" ]]; then
    while read -r line; do hc_say "${mode}: ${line}"; done < "${root}/out/bistream-cap-${mode}"
  fi

  log="${root}/var-dionaea/dionaea.log"
  if [[ ! -f "${log}" ]]; then
    hc_fail "dionaea.log of the second dionaea (${option}) is missing"
    rc=1
  else
    if grep -nE 'Traceback|LoaderError|Error loading module|Unable to start service' "${log}" >&2; then
      hc_fail "errors in dionaea.log of the second dionaea (${option}, see above)"
      rc=1
    fi
    if ! grep -qF "${limit_line}" "${log}"; then
      hc_fail "dionaea.log has no line '${limit_line}'"
      rc=1
    fi
    hc_count_warnings "${mode}" "${log}" 'Not dumping the streams of' "${refused_min}" "${minutes}" refused || rc=1
    hc_count_warnings "${mode}" "${log}" 'Stopped dumping the streams of' "${stopped_min}" "${minutes}" stopped || rc=1
  fi
  if [[ ${rc} -ne 0 && -f "${log}" ]]; then
    echo "---- dionaea.log of the second dionaea (${option}, last 40 lines) ----" >&2
    tail -n 40 "${log}" | cut -c1-300 >&2
  fi
  docker rm -f "${cap}" >/dev/null 2>&1 || true
done
exit ${rc}
