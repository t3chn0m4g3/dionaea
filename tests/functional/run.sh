#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# Functional tests: dionaea with the T-Pot config on its own Docker network,
# pytest in a client container on the same network. See README.md.

set -Eeuo pipefail

unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${HERE}/../.." && pwd)"

usage() {
  cat <<EOT
Usage: $0 [pytest arguments]

Environment:
  DIONAEA_IMAGE       Test this image, do not build the Dockerfile of the checkout.
  DIONAEA_RUN_ARGS    Extra arguments for "docker run" of the dionaea container,
                      e.g. "--ulimit nofile=128": only --ulimit nofile=N and
                      -v FILE:TARGET:ro into the modules or the configuration of
                      dionaea (tests/load/runargs.py), anything else is exit 2.
  DIONAEA_TTY=1       Run dionaea with "-t -i" (as with stdin_open / tty in compose);
                      host-checks/20-tty-stdin.sh then types on the terminal and
                      closes it (DIONAEA_TTY_CLOSE=hangup, the default, or eof).
  KEEP_ARTIFACTS=1    Keep the temporary folder with config, data and logs.
  DIONAEA_RECORD_FIXTURE=<name>
                      Record the log format of the reference session into
                      fixtures/<name> instead of comparing it (tools/record_fixture.sh).
  DIONAEA_START_TIMEOUT  Seconds to wait for dionaea to answer (default 60).

Folders (host side) in the temporary folder: etc/ var-dionaea/ var-log/ out/
EOT
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

# DIONAEA_RUN_ARGS through the allow-list of the load tools, before anything starts: the
# arguments come after the options of the run, and docker takes the last value of an option
run_args=()
if [[ -n "${DIONAEA_RUN_ARGS:-}" ]]; then
  command -v python3 >/dev/null 2>&1 || { echo "python3 not found (it checks DIONAEA_RUN_ARGS)" >&2; exit 3; }
  # exit 2 of runargs.py: refused (it says why); anything else: the check itself failed
  # (python3 answers a missing script with exit 2 too, so that is checked before)
  run_args_rc=0
  if [[ -f "${REPO_ROOT}/tests/load/runargs.py" ]]; then
    run_args_lines="$(python3 "${REPO_ROOT}/tests/load/runargs.py")" || run_args_rc=$?
  else
    run_args_rc=127
  fi
  if [[ ${run_args_rc} -eq 2 ]]; then
    exit 2
  elif [[ ${run_args_rc} -ne 0 ]]; then
    echo "DIONAEA_RUN_ARGS could not be checked: python3 tests/load/runargs.py exited with ${run_args_rc}" >&2
    exit 3
  fi
  while IFS= read -r arg; do
    [[ -n "${arg}" ]] && run_args+=("${arg}")
  done <<< "${run_args_lines}"
fi

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 3; }
docker info >/dev/null 2>&1 || { echo "Docker daemon not accessible" >&2; exit 3; }

RUN_ID="$$"
NETWORK="dionaea-func-${RUN_ID}"
DIONAEA_CONTAINER="dionaea-func-${RUN_ID}"
CLIENT_IMAGE="dionaea-func-client:local"
BUILT_IMAGE="dionaea-func:${RUN_ID}"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/dionaea-func.XXXXXX")"
OUT_DIR="${TMP_ROOT}/out"
mkdir -p "${OUT_DIR}"
CLIENT_CONTAINER="${DIONAEA_CONTAINER}-client"
RC=1

say() { printf '==> %s\n' "$*"; }

# Files written by uid 2000 in the bind mounts can be unremovable for the
# calling user, so remove them from a container.
cleanup() {
  set +e
  local have_container=0
  if docker inspect "${DIONAEA_CONTAINER}" >/dev/null 2>&1; then
    have_container=1
  fi
  if [[ ${RC} -ne 0 ]]; then
    if [[ ${have_container} -eq 1 ]]; then
      # stopping flushes the buffered log files
      docker stop -t 10 "${DIONAEA_CONTAINER}" >/dev/null 2>&1
      echo "---- dionaea container log (last 60 lines) ----" >&2
      docker logs --tail 60 "${DIONAEA_CONTAINER}" >&2 2>&1
    fi
    if [[ -f "${TMP_ROOT}/var-dionaea/dionaea.log" ]]; then
      echo "---- dionaea.log (last 40 lines) ----" >&2
      tail -n 40 "${TMP_ROOT}/var-dionaea/dionaea.log" | cut -c1-300 >&2 2>&1
    fi
    if [[ -f "${TMP_ROOT}/var-dionaea/dionaea-errors.log" ]]; then
      echo "---- dionaea-errors.log (last 40 lines) ----" >&2
      tail -n 40 "${TMP_ROOT}/var-dionaea/dionaea-errors.log" >&2 2>&1
    fi
  fi
  if [[ ${have_container} -eq 1 ]]; then
    docker logs "${DIONAEA_CONTAINER}" > "${OUT_DIR}/dionaea.container.log" 2>&1
  fi
  docker rm -f "${CLIENT_CONTAINER}" >/dev/null 2>&1
  docker rm -f "${DIONAEA_CONTAINER}" >/dev/null 2>&1
  docker network rm "${NETWORK}" >/dev/null 2>&1
  if [[ "${DIONAEA_IMAGE:-}" == "" ]]; then
    docker rmi "${BUILT_IMAGE}" >/dev/null 2>&1
  fi
  if [[ "${KEEP_ARTIFACTS:-0}" == "1" ]]; then
    echo "Artifacts kept in ${TMP_ROOT}" >&2
  else
    docker run --rm -v "${TMP_ROOT}:/clean" --entrypoint sh "${CLIENT_IMAGE}" \
      -c 'rm -rf /clean/* /clean/.[!.]*' >/dev/null 2>&1
    rm -rf "${TMP_ROOT}"
  fi
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# dionaea image
if [[ -n "${DIONAEA_IMAGE:-}" ]]; then
  IMAGE="${DIONAEA_IMAGE}"
  docker image inspect "${IMAGE}" >/dev/null 2>&1 || docker pull "${IMAGE}"
  say "Using image ${IMAGE}"
else
  IMAGE="${BUILT_IMAGE}"
  say "Building ${IMAGE} from ${REPO_ROOT}/Dockerfile"
  docker build -t "${IMAGE}" -f "${REPO_ROOT}/Dockerfile" "${REPO_ROOT}"
fi

# client image
say "Building the client image"
docker build -q -t "${CLIENT_IMAGE}" "${HERE}/client" >/dev/null

# data folders and config
mkdir -p "${OUT_DIR}" \
  "${TMP_ROOT}/etc" \
  "${TMP_ROOT}/var-log" \
  "${TMP_ROOT}/var-dionaea/binaries" \
  "${TMP_ROOT}/var-dionaea/bistreams" \
  "${TMP_ROOT}/var-dionaea/rtp" \
  "${TMP_ROOT}"/var-dionaea/roots/{ftp,tftp,www,upnp}
# files the tests read over TFTP and FTP (test_tftp.py, test_ftp.py)
printf 'tftp functional test file\n' > "${TMP_ROOT}/var-dionaea/roots/tftp/functional-test.txt"
printf 'ftp functional test file\n' > "${TMP_ROOT}/var-dionaea/roots/ftp/functional-list.txt"
cp -R "${HERE}/config/." "${TMP_ROOT}/etc/"
chmod -R a+rwX "${TMP_ROOT}/var-log" "${TMP_ROOT}/var-dionaea"
chmod -R a+rX "${TMP_ROOT}/etc"

docker network create "${NETWORK}" >/dev/null
# These download fixtures deliberately use private addresses on an isolated
# disposable network; production configurations retain an empty allowlist.
TEST_DOWNLOAD_SUBNET=$(docker network inspect --format '{{(index .IPAM.Config 0).Subnet}}' "${NETWORK}")
printf '%s\n' '- name: download_policy' '  config:' "    allowed_networks: [\"${TEST_DOWNLOAD_SUBNET}\"]" > "${TMP_ROOT}/etc/ihandlers/download_policy.yaml"

# dionaea, as in T-Pot: uid/gid 2000, read-only root filesystem with a tmpfs on /tmp
# (16 MiB), the roots of the services (roots/ftp, tftp, www, upnp) mounted read-only
tty_args=()
if [[ "${DIONAEA_TTY:-0}" == "1" ]]; then
  tty_args=(-t -i)
fi
docker run -d --name "${DIONAEA_CONTAINER}" --network "${NETWORK}" \
  --read-only --user 2000:2000 \
  --tmpfs /tmp:uid=2000,gid=2000,size=16m \
  -v "${TMP_ROOT}/etc:/opt/dionaea/etc/dionaea:ro" \
  -v "${TMP_ROOT}/var-dionaea:/opt/dionaea/var/dionaea" \
  -v "${TMP_ROOT}/var-log:/opt/dionaea/var/log" \
  -v "${TMP_ROOT}/var-dionaea/roots/ftp:/opt/dionaea/var/dionaea/roots/ftp:ro" \
  -v "${TMP_ROOT}/var-dionaea/roots/tftp:/opt/dionaea/var/dionaea/roots/tftp:ro" \
  -v "${TMP_ROOT}/var-dionaea/roots/www:/opt/dionaea/var/dionaea/roots/www:ro" \
  -v "${TMP_ROOT}/var-dionaea/roots/upnp:/opt/dionaea/var/dionaea/roots/upnp:ro" \
  ${tty_args[@]+"${tty_args[@]}"} ${run_args[@]+"${run_args[@]}"} \
  "${IMAGE}" >/dev/null
say "dionaea started as ${DIONAEA_CONTAINER}"

# the roots of the services are read-only in the container (test_ftp_readonly_root.py)
for service in ftp tftp www upnp; do
  rw="$(docker inspect -f "{{range .Mounts}}{{if eq .Destination \"/opt/dionaea/var/dionaea/roots/${service}\"}}{{.RW}}{{end}}{{end}}" "${DIONAEA_CONTAINER}")"
  if [[ "${rw}" != "false" ]]; then
    echo "roots/${service} is not mounted read-only (RW=${rw:-none})" >&2
    exit 1
  fi
done

# /tmp is a tmpfs dionaea can write, as in T-Pot: the files of the emulation (CreateFile,
# _lcreat, tempdownload_new() in src/util.c) are made there, the root filesystem is read-only
if ! docker exec "${DIONAEA_CONTAINER}" sh -c \
    'grep -q "^[^ ]* /tmp tmpfs " /proc/mounts && f=$(mktemp /tmp/emu-XXXXXX) && rm -f "$f"'; then
  echo "/tmp is no tmpfs that uid 2000 can write" >&2
  exit 1
fi

# fail fast if dionaea exits right after the start (e.g. a broken image)
for _ in 1 2 3 4 5; do
  sleep 1
  if [[ "$(docker inspect -f '{{.State.Running}}' "${DIONAEA_CONTAINER}" 2>/dev/null)" != "true" ]]; then
    echo "dionaea container exited right after the start" >&2
    exit 1
  fi
done

# DIONAEA_RECORD_FIXTURE=<name>: test_log_format.py writes fixtures/<name> (tools/record_fixture.sh)
record_args=()
if [[ -n "${DIONAEA_RECORD_FIXTURE:-}" ]]; then
  mkdir -p "${HERE}/fixtures"
  record_args=(
    -v "${HERE}/fixtures:/tests/fixtures"
    -e "DIONAEA_RECORD_FIXTURE=${DIONAEA_RECORD_FIXTURE}"
    -e "DIONAEA_RECORD_IMAGE=${IMAGE}"
    -e "DIONAEA_RECORD_IMAGE_ID=$(docker image inspect -f '{{.Id}}' "${IMAGE}" 2>/dev/null || echo unknown)"
  )
fi

# tests
say "Running pytest in the client container"
set +e
docker run --rm --name "${CLIENT_CONTAINER}" --network "${NETWORK}" \
  -v "${HERE}:/tests:ro" \
  -v "${TMP_ROOT}/var-dionaea:/dionaea/data:ro" \
  -v "${TMP_ROOT}/var-log:/dionaea/log:ro" \
  -v "${REPO_ROOT}/modules/python/dionaea:/src/dionaea:ro" \
  -e DIONAEA_PY_SRC=/src/dionaea \
  -e DIONAEA_HOST="${DIONAEA_CONTAINER}" \
  -e DIONAEA_DATA_DIR=/dionaea/data \
  -e DIONAEA_LOG_DIR=/dionaea/log \
  -e DIONAEA_START_TIMEOUT="${DIONAEA_START_TIMEOUT:-60}" \
  ${record_args[@]+"${record_args[@]}"} \
  "${CLIENT_IMAGE}" \
  python -m pytest -p no:cacheprovider -ra "$@"
RC=$?
set -e

# the container must still run after the tests
if [[ "$(docker inspect -f '{{.State.Running}}' "${DIONAEA_CONTAINER}" 2>/dev/null)" != "true" ]]; then
  echo "dionaea container is not running after the tests" >&2
  RC=1
fi

# host side checks (e.g. /proc of the dionaea process), in the order of
# their names: executable host-checks/*.sh get DIONAEA_CONTAINER,
# DIONAEA_NETWORK, DIONAEA_CLIENT_IMAGE, DIONAEA_TESTS_DIR and DIONAEA_TMP_ROOT
if [[ ${RC} -eq 0 && -d "${HERE}/host-checks" ]]; then
  for check in "${HERE}"/host-checks/*.sh; do
    [[ -x "${check}" ]] || continue
    say "Host check ${check##*/}"
    DIONAEA_CONTAINER="${DIONAEA_CONTAINER}" \
    DIONAEA_NETWORK="${NETWORK}" \
    DIONAEA_CLIENT_IMAGE="${CLIENT_IMAGE}" \
    DIONAEA_TESTS_DIR="${HERE}" \
    DIONAEA_TMP_ROOT="${TMP_ROOT}" \
      "${check}" || RC=1
  done
fi

# Stop dionaea the way T-Pot does (SIGINT), so its buffered logs are written,
# then check them: every module and service has to load without an error.
if [[ ${RC} -eq 0 ]]; then
  say "Stopping dionaea and checking its logs"
  docker stop -t 30 "${DIONAEA_CONTAINER}" >/dev/null
  # dionaea exits with status 255 after SIGINT (as the 24.04.1 image), so the
  # status is not checked
  for log in dionaea.log dionaea-errors.log; do
    if [[ ! -f "${TMP_ROOT}/var-dionaea/${log}" ]]; then
      echo "${log} is missing" >&2
      RC=1
    elif grep -nE 'Traceback|LoaderError|Error loading module|Unable to start service' "${TMP_ROOT}/var-dionaea/${log}" >&2; then
      echo "${log}: errors while loading modules or services (see above)" >&2
      RC=1
    fi
  done
  if ! grep -q 'Starting services' "${TMP_ROOT}/var-dionaea/dionaea.log" 2>/dev/null; then
    echo "dionaea.log has no 'Starting services' line" >&2
    RC=1
  fi
  # lines the host checks expect in the logs (hc_expect_log): FILE<TAB>ERE
  if [[ -f "${OUT_DIR}/expect-log" ]]; then
    while IFS=$'\t' read -r log pattern; do
      [[ -n "${log}" ]] || continue
      if grep -qE -- "${pattern}" "${TMP_ROOT}/var-dionaea/${log}" 2>/dev/null; then
        say "${log} has a line matching /${pattern}/"
      else
        echo "${log}: no line matches /${pattern}/ (expected by a host check)" >&2
        RC=1
      fi
    done < "${OUT_DIR}/expect-log"
  fi
fi

[[ ${RC} -eq 0 ]] && say "Functional tests passed" || say "Functional tests FAILED"
exit ${RC}
