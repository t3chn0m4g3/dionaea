# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# Helpers of the host checks (sourced, not run: not executable).
# run.sh passes DIONAEA_CONTAINER, DIONAEA_NETWORK, DIONAEA_CLIENT_IMAGE,
# DIONAEA_TESTS_DIR and DIONAEA_TMP_ROOT.

# CPU limit (percent of one core) for an idle dionaea
HC_CPU_LIMIT="${HC_CPU_LIMIT:-20}"

hc_say() { printf '    %s\n' "$*"; }
hc_fail() { printf '    FAIL: %s\n' "$*" >&2; }

hc_running() {
  [[ "$(docker inspect -f '{{.State.Running}}' "${DIONAEA_CONTAINER}" 2>/dev/null)" == "true" ]]
}

# root with all capabilities: dionaea has file capabilities, so its
# /proc/<pid>/fd and its limits are closed to its own user
hc_exec_root() {
  docker exec --privileged -u 0 "${DIONAEA_CONTAINER}" "$@"
}

# pids of the dionaea processes (main process and its privileged helper)
# (exit 0: the test of the last entry of /proc decides the status of the loop otherwise, and a
# pipeline that fails under pipefail ends a host check without a word)
hc_pids() {
  docker exec "${DIONAEA_CONTAINER}" sh -c \
    'for p in /proc/[0-9]*; do [ "$(cat "$p/comm" 2>/dev/null)" = dionaea ] && echo "${p#/proc/}"; done; exit 0' | sort -n
}

# the main dionaea process: the one with the lowest pid (awk reads all of it: head could end
# the pipe before sort wrote its last line, SIGPIPE fails the pipeline under pipefail).
# Without one it fails with a message: pid="$(hc_main_pid)" then ends the check under set -e,
# where an empty pid let the next read of /proc/<pid>/... end it without a word.
hc_main_pid() {
  local pid
  pid="$(hc_pids | awk 'NR == 1')"
  if [[ -z "${pid}" ]]; then
    hc_fail "no dionaea process in ${DIONAEA_CONTAINER}"
    return 1
  fi
  echo "${pid}"
}

# hc_cpu_percent SECONDS: CPU time of all dionaea processes over SECONDS
# seconds, in percent of one core (utime + stime of /proc/<pid>/stat)
hc_cpu_percent() {
  local seconds="$1" pids hz before after script
  pids="$(hc_pids | tr '\n' ' ')"
  if [[ -z "${pids// /}" ]]; then
    echo "-1"
    return 0
  fi
  hz="$(docker exec "${DIONAEA_CONTAINER}" getconf CLK_TCK)"
  script='t=0; for p in '"${pids}"'; do set -- $(cut -d" " -f14,15 /proc/$p/stat 2>/dev/null || echo "0 0"); t=$((t + $1 + $2)); done; echo $t'
  before="$(docker exec "${DIONAEA_CONTAINER}" sh -c "${script}")"
  sleep "${seconds}"
  after="$(docker exec "${DIONAEA_CONTAINER}" sh -c "${script}")"
  echo $(( (after - before) * 100 / (hz * seconds) ))
}

# hc_check_cpu SECONDS WHAT: fail if dionaea uses HC_CPU_LIMIT % or more
hc_check_cpu() {
  local seconds="$1" what="$2" cpu
  cpu="$(hc_cpu_percent "${seconds}")"
  if [[ "${cpu}" -lt 0 ]]; then
    hc_fail "${what}: no dionaea process found"
    return 1
  fi
  if [[ "${cpu}" -ge "${HC_CPU_LIMIT}" ]]; then
    hc_fail "${what}: dionaea used ${cpu}% CPU over ${seconds}s (limit ${HC_CPU_LIMIT}%)"
    return 1
  fi
  hc_say "${what}: ${cpu}% CPU over ${seconds}s (limit ${HC_CPU_LIMIT}%)"
}

# hc_expect_log FILE ERE: run.sh checks after stopping dionaea (when the
# buffered log files are written) that FILE of var-dionaea has a line
# matching the extended regular expression ERE
hc_expect_log() {
  printf '%s\t%s\n' "$1" "$2" >> "${DIONAEA_TMP_ROOT}/out/expect-log"
}

# hc_wait_log CONTAINER TEXT TIMEOUT: wait until the container log has TEXT
hc_wait_log() {
  local container="$1" text="$2" timeout="$3" i
  for (( i = 0; i < timeout * 2; i++ )); do
    if docker logs "${container}" 2>&1 | tr -d '\r' | grep -qF -- "${text}"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}
