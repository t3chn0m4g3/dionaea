# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Fixtures of the functional tests.

tests/functional/run.sh starts the dionaea container and passes its place
to this client container:

DIONAEA_HOST       name of the dionaea container on the test network
DIONAEA_DATA_DIR   var/dionaea of dionaea (binaries/, bistreams/, ...), read-only
DIONAEA_LOG_DIR    var/log of dionaea (dionaea.json, dionaea.sqlite), read-only
"""

import os
import socket
import time
from pathlib import Path

import pytest

import helpers

# test_store_cap_instance.py and test_bistream_cap_instance.py run against a second
# dionaea (host-checks/40-store-cap.sh, 42-bistream-cap.sh)
if not os.environ.get("DIONAEA_CAP_INSTANCE"):
    collect_ignore = ["test_store_cap_instance.py", "test_bistream_cap_instance.py"]


@pytest.fixture(scope="session")
def dionaea_host():
    """Name of the dionaea container, resolvable on the test network."""
    return os.environ.get("DIONAEA_HOST", "dionaea")


@pytest.fixture(scope="session")
def dionaea_ip(dionaea_host):
    """IPv4 address of the dionaea container."""
    return socket.gethostbyname(dionaea_host)


@pytest.fixture(scope="session")
def data_dir():
    return Path(os.environ.get("DIONAEA_DATA_DIR", "/dionaea/data"))


@pytest.fixture(scope="session")
def log_dir():
    return Path(os.environ.get("DIONAEA_LOG_DIR", "/dionaea/log"))


@pytest.fixture(scope="session")
def json_log(log_dir):
    """Path of dionaea.json."""
    return log_dir / "dionaea.json"


@pytest.fixture(scope="session")
def sqlite_db(log_dir):
    """Path of dionaea.sqlite."""
    return log_dir / "dionaea.sqlite"


@pytest.fixture(scope="session")
def binaries_dir(data_dir):
    """Path of the downloaded files, named by their md5."""
    return data_dir / "binaries"


@pytest.fixture(scope="session", autouse=True)
def dionaea_ready(dionaea_host):
    """Wait once for dionaea to answer on FTP before the first test."""
    helpers.wait_for_port(dionaea_host, 21, timeout=float(os.environ.get("DIONAEA_START_TIMEOUT", "60")))


@pytest.fixture
def wait_for_event(json_log):
    """wait_for_event(predicate, timeout=30): first entry of dionaea.json that matches."""
    def wait(predicate, timeout=30.0):
        return helpers.wait_for_json_event(json_log, predicate, timeout=timeout)
    return wait


@pytest.fixture
def query_db(sqlite_db):
    """query_db(sql, params=()): rows of dionaea.sqlite as dicts."""
    def query(sql, params=()):
        return helpers.query_sqlite(sqlite_db, sql, params)
    return query


@pytest.fixture
def wait_for_rows(sqlite_db):
    """wait_for_rows(sql, params=(), count=1, timeout=10): the rows once there are at least count.

    log_sqlite commits once a second (a timer of the loop), so a row is in
    dionaea.sqlite up to a second after the incident; dionaea.json has it at once.
    Returns what the last query found (possibly fewer rows) when the time is up.
    """
    def wait(sql, params=(), count=1, timeout=10.0):
        deadline = time.monotonic() + timeout
        while True:
            rows = helpers.query_sqlite(sqlite_db, sql, params)
            if len(rows) >= count or time.monotonic() >= deadline:
                return rows
            time.sleep(0.2)
    return wait


@pytest.fixture
def my_ip(dionaea_ip):
    """The address of this container on the network of dionaea."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((dionaea_ip, 9))
        return sock.getsockname()[0]
