#!/usr/bin/env bash
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0
#
# Records the log format (fixtures/log_0.11.1.json) of the release before 0.12:
# runs the reference session (logformat.py) against the image of T-Pot 24.04.1,
# which is dionaea 0.11.x, and writes the shape of the entries of dionaea.json
# and the columns of dionaea.sqlite into the fixture.
#
#   tests/functional/tools/record_fixture.sh [image] [fixture name]

set -Eeuo pipefail

unset CDPATH
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

IMAGE="${1:-ghcr.io/telekom-security/dionaea:24.04.1}"
NAME="${2:-log_0.11.1.json}"

DIONAEA_IMAGE="${IMAGE}" DIONAEA_RECORD_FIXTURE="${NAME}" \
  "${HERE}/../run.sh" -k test_record_log_fixture
echo "Written: ${HERE}/../fixtures/${NAME}"
