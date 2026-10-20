#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# The limits from the environment: DIONAEA_STREAMDUMPER_MAX_SIZE (MiB),
# DIONAEA_STREAMDUMPER_MAX_FILES and DIONAEA_STORE_MAX_SIZE (MiB) replace the
# values of dionaea.cfg and store.yaml. The check starts a second dionaea on the
# same network four times:
#
#   env      no limits in the config, the three variables set (max_files 40,
#            max_size 2048, store 1): the limits of the variables hold
#   size     config.max_size=2048 in dionaea.cfg, DIONAEA_STREAMDUMPER_MAX_SIZE=1:
#            the burst of HTTP connections stays within 1 MiB
#   invalid  config.max_files=40 in dionaea.cfg and max_size: 1 in store.yaml,
#            the three variables set to values that are refused: one warning per
#            variable, the limits of the config hold
#   unset    the config of "invalid", no variable: the limits of the config hold
#
# Each time but "size" the burst of test_bistream_cap_instance.py (max_files 40) and
# test_store_cap_instance.py (1 MiB) run against it, at "size" the burst of
# test_bistream_cap_instance.py for max_size. After dionaea was stopped
# (its log files are written then) dionaea.log must have the three lines at the
# start in their documented format, each with the value and its source.

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${HERE}/lib.sh"

hc_running || { hc_fail "dionaea is not running"; exit 1; }

inst="${DIONAEA_CONTAINER}-limits-env"
client="${inst}-client"
image="$(docker inspect -f '{{.Config.Image}}' "${DIONAEA_CONTAINER}")"

cleanup_inst() {
  docker rm -f "${client}" >/dev/null 2>&1 || true
  docker rm -f "${inst}" >/dev/null 2>&1 || true
}
trap cleanup_inst EXIT

# hc_log_has LOG LINE: LINE is a whole message of dionaea.log (after "-info: " / "-warning: ")
hc_log_has() {
  local log="$1" line="$2"
  if grep -qF -- "${line}" "${log}"; then
    hc_say "dionaea.log: ${line}"
  else
    hc_fail "dionaea.log has no line '${line}'"
    return 1
  fi
}

# hc_log_count LOG TEXT N: N lines of dionaea.log have TEXT
hc_log_count() {
  local log="$1" text="$2" want="$3" n
  n="$(grep -cF -- "${text}" "${log}" || true)"
  if [[ "${n}" != "${want}" ]]; then
    hc_fail "dionaea.log has ${n} lines with '${text}' (expected ${want})"
    return 1
  fi
}

rc=0
for mode in env size invalid unset; do
  root="${DIONAEA_TMP_ROOT}/limits-env-${mode}"
  mkdir -p "${root}/etc" "${root}/out" "${root}/var-log" \
    "${root}/var-dionaea/binaries" "${root}/var-dionaea/bistreams" "${root}/var-dionaea/rtp" \
    "${root}"/var-dionaea/roots/{ftp,tftp,www,upnp,printer}
  cp -R "${DIONAEA_TESTS_DIR}/config/." "${root}/etc/"
  # the printer service (port 9100), as in 40-store-cap.sh: test_store_cap_instance.py uses it
  cat > "${root}/etc/services/printer.yaml" <<'YAML'
- name: printer
  config:
    root: "/opt/dionaea/var/dionaea/roots/printer"
YAML
  env_args=()
  cap=files
  tests_list=("test_bistream_cap_instance.py -k test_a_burst_stops_at_max_files" test_store_cap_instance.py)
  case "${mode}" in
    env)
      env_args=(-e DIONAEA_STREAMDUMPER_MAX_SIZE=2048 -e DIONAEA_STREAMDUMPER_MAX_FILES=40
                -e DIONAEA_STORE_MAX_SIZE=1)
      lines=("streamdumper: max_size 2048 MiB (from DIONAEA_STREAMDUMPER_MAX_SIZE)"
             "streamdumper: max_files 40 (from DIONAEA_STREAMDUMPER_MAX_FILES)"
             "store: max_size 1 MiB (from DIONAEA_STORE_MAX_SIZE)")
      ignored=()
      ;;
    size)
      awk '{ print } /^config\.path=.*bistreams/ { print "config.max_size=2048" }' \
        "${DIONAEA_TESTS_DIR}/config/dionaea.cfg" > "${root}/etc/dionaea.cfg"
      grep -qx "config.max_size=2048" "${root}/etc/dionaea.cfg" || { hc_fail "config.max_size=2048 is not in dionaea.cfg"; exit 1; }
      env_args=(-e DIONAEA_STREAMDUMPER_MAX_SIZE=1)
      cap=size
      tests_list=("test_bistream_cap_instance.py -k test_a_burst_stays_within_max_size")
      lines=("streamdumper: max_size 1 MiB (from DIONAEA_STREAMDUMPER_MAX_SIZE)"
             "streamdumper: max_files 0 (from dionaea.cfg)"
             "store: max_size 0 MiB (from store.yaml)")
      ignored=()
      ;;
    invalid|unset)
      awk '{ print } /^config\.path=.*bistreams/ { print "config.max_files=40" }' \
        "${DIONAEA_TESTS_DIR}/config/dionaea.cfg" > "${root}/etc/dionaea.cfg"
      grep -qx "config.max_files=40" "${root}/etc/dionaea.cfg" || { hc_fail "config.max_files=40 is not in dionaea.cfg"; exit 1; }
      cat > "${root}/etc/ihandlers/store.yaml" <<'YAML'
- name: store
  config:
    max_size: 1
YAML
      lines=("streamdumper: max_size 0 MiB (from dionaea.cfg)"
             "streamdumper: max_files 40 (from dionaea.cfg)"
             "store: max_size 1 MiB (from store.yaml)")
      ignored=()
      if [[ "${mode}" == "invalid" ]]; then
        env_args=(-e "DIONAEA_STREAMDUMPER_MAX_SIZE=-5" -e "DIONAEA_STREAMDUMPER_MAX_FILES=40 files"
                  -e "DIONAEA_STORE_MAX_SIZE=1.5")
        ignored=("Ignoring DIONAEA_STREAMDUMPER_MAX_SIZE='-5': a whole number of MiB >= 0 (decimal digits) is expected, the value of dionaea.cfg holds"
                 "Ignoring DIONAEA_STREAMDUMPER_MAX_FILES='40 files': a whole number >= 0 (decimal digits) is expected, the value of dionaea.cfg holds"
                 "Ignoring DIONAEA_STORE_MAX_SIZE='1.5': a whole number of MiB >= 0 (decimal digits) is expected, the value of store.yaml holds")
      fi
      ;;
  esac
  chmod -R a+rwX "${root}/var-log" "${root}/var-dionaea" "${root}/out"
  chmod -R a+rX "${root}/etc"

  docker run -d --name "${inst}" --network "${DIONAEA_NETWORK}" \
    --read-only --user 2000:2000 \
    --tmpfs /tmp:uid=2000,gid=2000,size=16m \
    -v "${root}/etc:/opt/dionaea/etc/dionaea:ro" \
    -v "${root}/var-dionaea:/opt/dionaea/var/dionaea" \
    -v "${root}/var-log:/opt/dionaea/var/log" \
    ${env_args[@]+"${env_args[@]}"} \
    "${image}" >/dev/null
  hc_say "second dionaea ${inst} (${mode})"

  for tests in "${tests_list[@]}"; do
    # shellcheck disable=SC2086
    docker run --rm --name "${client}" --network "${DIONAEA_NETWORK}" \
      -v "${DIONAEA_TESTS_DIR}:/tests:ro" \
      -v "${root}/var-dionaea:/dionaea/data" \
      -v "${root}/var-log:/dionaea/log:ro" \
      -v "${root}/out:/out" \
      -e DIONAEA_HOST="${inst}" \
      -e DIONAEA_DATA_DIR=/dionaea/data \
      -e DIONAEA_LOG_DIR=/dionaea/log \
      -e DIONAEA_CAP_INSTANCE=1 \
      -e DIONAEA_BISTREAM_CAP="${cap}" \
      -e DIONAEA_BISTREAM_CAP_MAX_SIZE=1048576 \
      -e DIONAEA_CAP_OUT=/out \
      -e DIONAEA_START_TIMEOUT="${DIONAEA_START_TIMEOUT:-60}" \
      "${DIONAEA_CLIENT_IMAGE}" \
      python -m pytest -p no:cacheprovider -ra ${tests} || { hc_fail "${mode}: ${tests}"; rc=1; }
  done

  if [[ "$(docker inspect -f '{{.State.Running}}' "${inst}" 2>/dev/null)" != "true" ]]; then
    hc_fail "the second dionaea (${mode}) is not running after the tests"
    rc=1
  fi
  docker stop -t 30 "${inst}" >/dev/null

  log="${root}/var-dionaea/dionaea.log"
  if [[ ! -f "${log}" ]]; then
    hc_fail "dionaea.log of the second dionaea (${mode}) is missing"
    rc=1
  else
    if grep -nE 'Traceback|LoaderError|Error loading module|Unable to start service' "${log}" >&2; then
      hc_fail "errors in dionaea.log of the second dionaea (${mode}, see above)"
      rc=1
    fi
    for line in "${lines[@]}"; do
      hc_log_has "${log}" "${line}" || rc=1
    done
    # one line per limit, no other value
    hc_log_count "${log}" "streamdumper: max_size " 1 || rc=1
    hc_log_count "${log}" "streamdumper: max_files " 1 || rc=1
    hc_log_count "${log}" "store: max_size " 1 || rc=1
    for line in ${ignored[@]+"${ignored[@]}"}; do
      hc_log_has "${log}" "${line}" || rc=1
    done
    hc_log_count "${log}" "Ignoring DIONAEA_" "${#ignored[@]}" || rc=1
  fi
  if [[ ${rc} -ne 0 && -f "${log}" ]]; then
    echo "---- dionaea.log of the second dionaea (${mode}, last 40 lines) ----" >&2
    tail -n 40 "${log}" | cut -c1-300 >&2
  fi
  docker rm -f "${inst}" >/dev/null 2>&1 || true
done
exit ${rc}
