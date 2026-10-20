# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The comparison of the log formats (logformat.compare) finds what it has to find."""

import copy

import logformat

EVENT = {
    "connection": {"protocol": "ftpd", "transport": "tcp", "type": "accept"},
    "dst_ip": "10.0.0.2",
    "dst_port": 21,
    "src_hostname": "",
    "src_ip": "10.0.0.3",
    "src_port": 40000,
    "timestamp": "2026-10-10T12:00:00.123456",
    "credentials": {"username": ["a"], "password": ["b"]},
}
TABLES = {"downloads": {"download": "INTEGER", "download_url": "TEXT"}}


def _fixture():
    return logformat.build_fixture([EVENT], TABLES, "image", "id")


def test_same_format_is_fine():
    assert logformat.compare(_fixture(), [copy.deepcopy(EVENT)], TABLES) == []


def test_new_keys_tables_and_columns_are_fine():
    event = copy.deepcopy(EVENT)
    event["new_key"] = {"a": 1}
    other = copy.deepcopy(EVENT)
    other["connection"]["protocol"] = "smbd"
    tables = {"downloads": dict(TABLES["downloads"], extra="TEXT"), "new_table": {"a": "TEXT"}}
    assert logformat.compare(_fixture(), [event, other], tables) == []


def test_missing_key_is_found():
    event = copy.deepcopy(EVENT)
    del event["credentials"]["password"]
    problems = logformat.compare(_fixture(), [event], TABLES)
    assert any("credentials.password" in p and "missing" in p for p in problems), problems


def test_retyped_key_is_found():
    event = copy.deepcopy(EVENT)
    event["src_port"] = "40000"
    problems = logformat.compare(_fixture(), [event], TABLES)
    assert any("src_port" in p for p in problems), problems


def test_missing_event_type_is_found():
    other = copy.deepcopy(EVENT)
    other["connection"]["protocol"] = "smbd"
    problems = logformat.compare(_fixture(), [other], TABLES)
    assert any("ftpd/accept is missing" in p for p in problems), problems


def test_timestamp_format_is_checked():
    for timestamp in ("2026-10-10T12:00:00.123456+00:00", "2026-10-10 12:00:00.123456", "2026-10-10T12:00:00.123"):
        event = copy.deepcopy(EVENT)
        event["timestamp"] = timestamp
        problems = logformat.compare(_fixture(), [event], TABLES)
        assert any("timestamp" in p for p in problems), (timestamp, problems)


def test_timestamp_without_microseconds_is_isoformat():
    event = copy.deepcopy(EVENT)
    event["timestamp"] = "2026-10-10T12:00:00"
    assert logformat.compare(_fixture(), [event], TABLES) == []


def test_sqlite_columns_are_checked():
    problems = logformat.compare(_fixture(), [EVENT], {"downloads": {"download": "TEXT"}})
    assert any("download_url" in p for p in problems), problems
    assert any("download is TEXT, was INTEGER" in p for p in problems), problems
    assert any("table downloads is missing" in p for p in logformat.compare(_fixture(), [EVENT], {}))
