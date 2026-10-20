#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# Makes requirements.txt and requirements-build.txt of the client image from requirements.in, the
# same every time: uv pip compile of the files on PyPI before LOCK_DATE (--exclude-newer), for every
# platform (--universal) with the hashes of every file. A new lock: change requirements.in or
# LOCK_DATE, run this script, build the client image and run the tests.
#
#   tests/functional/client/lock.sh

set -Eeuo pipefail
unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
LOCK_DATE="2026-10-11T00:00:00Z"
COMPILE=(uv pip compile --universal --generate-hashes --python-version 3.14 --no-header --no-annotate
         --exclude-newer "${LOCK_DATE}")

# the tags of the header are data for the files it makes, not tags of this file
# REUSE-IgnoreStart
header() {
  printf '%s\n' "# This file is part of the dionaea honeypot" "#" "# SPDX-FileCopyrightText: none" "#" \
    "# SPDX-License-Identifier: CC0-1.0" "#" "$@"
}
# REUSE-IgnoreEnd

{
  header "# Made by lock.sh from requirements.in (files on PyPI before ${LOCK_DATE}), do not edit."
  "${COMPILE[@]}" "${HERE}/requirements.in"
} > "${HERE}/requirements.txt.new"
{
  header "# setuptools to build pyftpdlib (pip install --no-build-isolation), made by lock.sh (files on" \
    "# PyPI before ${LOCK_DATE}), do not edit."
  echo setuptools | "${COMPILE[@]}" --only-binary :all: -
} > "${HERE}/requirements-build.txt.new"
mv "${HERE}/requirements.txt.new" "${HERE}/requirements.txt"
mv "${HERE}/requirements-build.txt.new" "${HERE}/requirements-build.txt"
