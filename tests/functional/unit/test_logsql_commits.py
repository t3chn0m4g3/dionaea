# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""logsql.py: the rows of a second go in one transaction, committed by a timer of the loop.

logsql committed every incident at once, about 130 transactions a second in the
replay. Each transaction costs sqlite file operations of its journal and fsyncs in
the event loop: strace of the main thread, 120 s of the replay, 22.4 s in unlinking
dionaea.sqlite-journal and 7.2 s in creating it (single calls up to 0.67 s; with
journal mode PERSIST instead, the hot journal check opened it 51,245 times in 600 s,
up to 0.74 s). The FTP banner waited up to 5 s. Now the incidents mark the
transaction and dionaea.core.timer commits it every second, and on stop; a reader
sees the rows at most a second later, the schema and the rows are the same.
"""

import contextlib
import importlib.util
import os
import sqlite3
import sys
import types
from pathlib import Path

import pytest


class FakeNode:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.hostname = ""


class FakeCon:
    transport = "tcp"
    protocol = "ftpd"
    local = FakeNode("192.0.2.1", 21)
    remote = FakeNode("198.51.100.4", 40000)


class FakeIncident:
    def __init__(self, **values):
        self.__dict__.update(values)


class FakeTimer:
    """dionaea.core.timer: the test fires it."""
    made = []

    def __init__(self, callback, after, repeat=0.0):
        self.callback, self.after, self.repeat, self.stopped = callback, after, repeat, False
        FakeTimer.made.append(self)

    def fire(self):
        assert not self.stopped
        self.callback()

    def stop(self):
        self.stopped = True


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins():
    """dionaea.core, and the two modules start() reads its tables of names from (no services in a unit test)."""
    names = ("dionaea", "dionaea.core", "dionaea.smb", "dionaea.smb.rpcservices", "dionaea.mysql",
             "dionaea.mysql.include", "dionaea.mysql.include.packets")
    saved = {name: sys.modules.get(name) for name in names}
    modules = {name: types.ModuleType(name) for name in names}
    for name in ("dionaea", "dionaea.smb", "dionaea.mysql", "dionaea.mysql.include"):
        modules[name].__path__ = []
    modules["dionaea"].IHandlerLoader = type("IHandlerLoader", (), {})
    modules["dionaea"].smb = modules["dionaea.smb"]
    modules["dionaea"].mysql = modules["dionaea.mysql"]
    modules["dionaea.smb"].rpcservices = modules["dionaea.smb.rpcservices"]
    modules["dionaea.smb.rpcservices"].RPCService = type("RPCService", (), {})
    modules["dionaea.mysql.include.packets"].MySQL_Commands = {3: "COM_QUERY"}
    modules["dionaea.core"].ihandler = type("ihandler", (), {"__init__": lambda self, path: None})
    modules["dionaea.core"].timer = FakeTimer
    sys.modules.update(modules)
    try:
        yield
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


with _stand_ins():
    spec = importlib.util.spec_from_file_location("logsql_under_test", _src_root() / "logsql.py")
    logsql = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(logsql)


@pytest.fixture(autouse=True)
def stand_ins():
    with _stand_ins():
        yield


@pytest.fixture
def handler(tmp_path):
    h = logsql.logsqlhandler("*", config={"file": str(tmp_path / "dionaea.sqlite")})
    h.start()
    yield h
    h.stop()   # as dionaea on SIGINT: the timer ends, the rest is committed
    del h      # then __del__ closes the database


def rows(db, table="connections"):
    reader = sqlite3.connect("file:%s?mode=ro" % db, uri=True)
    try:
        return reader.execute("SELECT count(*) FROM %s" % table).fetchone()[0]
    finally:
        reader.close()


def test_a_timer_of_one_second_commits(handler):
    timer = FakeTimer.made[-1]
    assert timer.callback == handler.flush
    assert timer.after == 1.0 and timer.repeat == 1.0


def test_the_rows_of_many_incidents_are_committed_together(handler, tmp_path):
    db = tmp_path / "dionaea.sqlite"
    for _ in range(50):
        handler.connection_insert(FakeIncident(con=FakeCon()), "accept")
    # nothing committed yet: one transaction for all of them
    assert rows(db) == 0
    FakeTimer.made[-1].fire()
    assert rows(db) == 50
    # nothing new: the timer does not commit
    FakeTimer.made[-1].fire()
    handler.connection_insert(FakeIncident(con=FakeCon()), "accept")
    FakeTimer.made[-1].fire()
    assert rows(db) == 51


def test_stop_commits_and_ends_the_timer(handler, tmp_path):
    handler.connection_insert(FakeIncident(con=FakeCon()), "accept")
    timer = FakeTimer.made[-1]
    handler.stop()
    assert timer.stopped
    assert rows(tmp_path / "dionaea.sqlite") == 1
    # a later incident (while dionaea stops) is committed at once
    handler.connection_insert(FakeIncident(con=FakeCon()), "accept")
    assert rows(tmp_path / "dionaea.sqlite") == 2


def test_the_journal_mode_is_unchanged(handler):
    assert handler.cursor.execute("PRAGMA journal_mode").fetchone()[0] == "delete"


def test_a_failed_commit_is_tried_again(handler, tmp_path):
    db = tmp_path / "dionaea.sqlite"
    handler.connection_insert(FakeIncident(con=FakeCon()), "accept")
    # a reader in a transaction holds its shared lock: the commit fails with "database is locked"
    reader = sqlite3.connect(str(db), timeout=0, isolation_level=None)
    reader.execute("BEGIN")
    assert reader.execute("SELECT count(*) FROM connections").fetchone()[0] == 0
    handler.dbh.execute("PRAGMA busy_timeout = 0")
    FakeTimer.made[-1].fire()
    assert handler._dirty, "the transaction is kept for the next flush"
    reader.execute("COMMIT")
    reader.close()
    FakeTimer.made[-1].fire()
    assert not handler._dirty
    assert rows(db) == 1


def test_an_existing_database_of_an_earlier_version_is_taken_over(tmp_path):
    db = tmp_path / "dionaea.sqlite"
    old = sqlite3.connect(db)
    old.execute("CREATE TABLE connections (connection INTEGER PRIMARY KEY, connection_type TEXT, "
                "connection_transport TEXT, connection_protocol TEXT, connection_timestamp INTEGER, "
                "connection_root INTEGER, connection_parent INTEGER, local_host TEXT, local_port INTEGER, "
                "remote_host TEXT, remote_hostname TEXT, remote_port INTEGER)")
    old.execute("INSERT INTO connections (connection_type) VALUES ('accept')")
    old.commit()
    old.close()
    h = logsql.logsqlhandler("*", config={"file": str(db)})
    h.start()
    try:
        h.connection_insert(FakeIncident(con=FakeCon()), "accept")
        h.stop()
        assert rows(db) == 2
    finally:
        del h
