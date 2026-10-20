# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The log formats of this release against the reference of 0.11.1.

fixtures/log_0.11.1.json holds the shape of the entries of dionaea.json
(event type -> key -> value types), the timestamp format and the columns of
the tables of dionaea.sqlite that the reference session (logformat.py)
caused in the image of T-Pot 24.04.1. Missing keys, other value types, another
timestamp format and missing or retyped columns fail, new keys do not.

With DIONAEA_RECORD_FIXTURE=<name> the session is not compared but written
to fixtures/<name> (tools/record_fixture.sh).
"""

import json
import os
import time
from pathlib import Path

import pytest

import helpers
import logformat

FIXTURE = Path(__file__).parent / "fixtures" / "log_0.11.1.json"


@pytest.fixture
def session_ports(dionaea_host, json_log):
    """The source ports of the connections of the reference session (after the session ran)."""
    ports = logformat.run_session(dionaea_host)
    assert ports, "the reference session made no connection"
    return ports


def _read(json_log):
    return lambda: helpers.read_json_events(json_log)


@pytest.mark.skipif(not os.environ.get("DIONAEA_RECORD_FIXTURE"), reason="only with DIONAEA_RECORD_FIXTURE=<name>")
def test_record_log_fixture(session_ports, json_log, query_db):
    ports = session_ports
    # an entry is written when its connection is closed
    logformat.wait_for_ports(_read(json_log), ports)
    time.sleep(3)
    events = logformat.events_of_ports(helpers.read_json_events(json_log), ports)
    fixture = logformat.build_fixture(
        events,
        logformat.sqlite_columns(query_db),
        os.environ.get("DIONAEA_RECORD_IMAGE", "unknown"),
        os.environ.get("DIONAEA_RECORD_IMAGE_ID", "unknown"),
    )
    target = Path("/tests/fixtures") / os.environ["DIONAEA_RECORD_FIXTURE"]
    target.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n")


@pytest.mark.skipif(bool(os.environ.get("DIONAEA_RECORD_FIXTURE")), reason="recording")
def test_log_format_matches_0_11_1(session_ports, json_log, query_db):
    ports = session_ports
    fixture = json.loads(FIXTURE.read_text())
    events = logformat.wait_for_events(_read(json_log), ports, logformat.expected_types(fixture))
    problems = logformat.compare(fixture, events, logformat.sqlite_columns(query_db))
    assert not problems, "log format differs from 0.11.1:\n  " + "\n  ".join(problems)
