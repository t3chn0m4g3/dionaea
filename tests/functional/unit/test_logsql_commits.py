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
import logging
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
    # the real logtext (stdlib only)
    spec = importlib.util.spec_from_file_location("dionaea.logtext", _src_root() / "logtext.py")
    logtext = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(logtext)
    saved.setdefault("dionaea.logtext", sys.modules.get("dionaea.logtext"))
    sys.modules["dionaea.logtext"] = logtext
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


def test_failed_commits_are_info_and_one_warning_a_minute(handler, tmp_path, caplog, summaries):
    """The flush of every second that fails: an info line each, one warning a minute."""
    clock = summaries(logsql.COMMIT_FAILED)
    db = tmp_path / "dionaea.sqlite"
    reader = sqlite3.connect(str(db), timeout=0, isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM connections").fetchone()
    handler.dbh.execute("PRAGMA busy_timeout = 0")
    with caplog.at_level(logging.INFO, logger="log_sqlite"):
        for _ in range(10):
            handler.connection_insert(FakeIncident(con=FakeCon()), "accept")
            FakeTimer.made[-1].fire()
            clock.advance(1)
        infos = [r.getMessage() for r in caplog.records
                 if r.levelno == logging.INFO and "Unable to commit" in r.getMessage()]
        assert len(infos) == 10
        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings == [("commits of the sqlite log tried again: 1 time(s) in the last minute, "
                            "the last: %s, database is locked") % db]
        clock.advance(60)
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings[1:] == [("commits of the sqlite log tried again: 9 time(s) in the last minute, "
                            "the last: %s, database is locked") % db]
    reader.execute("COMMIT")
    reader.close()


class FailingCursor:
    """The cursor of the handler whose statements fail as sqlite does without a free descriptor."""

    def __init__(self, cursor):
        self.cursor = cursor

    def execute(self, *args):
        raise sqlite3.OperationalError("unable to open database file")

    def __getattr__(self, name):
        return getattr(self.cursor, name)


def test_incidents_that_can_not_be_recorded_are_info_and_one_warning_a_minute(handler, tmp_path, caplog, summaries):
    """An insert of an incident that fails (sqlite3.Error) is an info line with the client, the
    summary warning sums them up; the handler and its connection to the database go on."""
    clock = summaries(logsql.NOT_RECORDED)
    db = tmp_path / "dionaea.sqlite"
    cursor = handler.cursor
    handler.cursor = FailingCursor(cursor)
    with caplog.at_level(logging.INFO, logger="log_sqlite"):
        for _ in range(4):
            handler.handle_incident_dionaea_connection_tcp_accept(FakeIncident(con=FakeCon()))
            clock.advance(1)
        handler.handle_incident_dionaea_download_offer(FakeIncident(con=FakeCon(), url="http://x/\n"))
        infos = [r.getMessage() for r in caplog.records
                 if r.levelno == logging.INFO and "not recorded" in r.getMessage()]
        assert infos == [("dionaea.connection.tcp.accept not recorded: unable to open database file "
                         "(198.51.100.4)")] * 4
        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings == [("incidents not recorded in the sqlite log: 1 incident(s) in the last minute, "
                            "the last: unable to open database file (198.51.100.4)")]
        clock.advance(60)
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings[1:] == [("incidents not recorded in the sqlite log: 3 incident(s) in the last minute, "
                            "the last: unable to open database file (198.51.100.4)")]
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    # the connection to the database is usable: the next incident is recorded
    handler.cursor = cursor
    handler.handle_incident_dionaea_connection_tcp_accept(FakeIncident(con=FakeCon()))
    FakeTimer.made[-1].fire()
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


class RollingBackCursor:
    """The cursor of the handler whose next statement fails as sqlite does on SQLITE_FULL, IOERR, ...:
    sqlite undoes the whole open transaction, not only the statement."""

    def __init__(self, handler):
        self.handler = handler
        self.cursor = handler.cursor

    def execute(self, *args):
        self.handler.dbh.rollback()
        raise sqlite3.OperationalError("database or disk is full")

    def __getattr__(self, name):
        return getattr(self.cursor, name)


@pytest.fixture
def memory_handler():
    h = logsql.logsqlhandler("*", config={"file": ":memory:"})
    h.start()
    yield h
    h.stop()
    del h


def memory_rows(handler, sql="SELECT count(*) FROM connections"):
    return handler.dbh.execute(sql).fetchone()[0]


class OtherCon(FakeCon):
    remote = FakeNode("198.51.100.5", 40001)


def test_a_rollback_of_the_transaction_forgets_its_connections(memory_handler, caplog, summaries):
    """A statement that makes sqlite undo the whole transaction: the rows of the connections since
    the last commit are gone, their ids are no ids of the handler any more; an event of such a
    connection later writes no row (as after an insert that failed), and no row of another
    connection that gets the same id."""
    summaries(logsql.COMMIT_FAILED, logsql.LOST, logsql.NOT_RECORDED)
    h = memory_handler
    committed = FakeCon()
    h.connection_insert(FakeIncident(con=committed), "accept")
    h._commit_timer.fire()
    a = OtherCon()
    h.connection_insert(FakeIncident(con=a), "accept")
    lost_id = h.attacks[a][1]
    cursor = h.cursor
    h.cursor = RollingBackCursor(h)
    with caplog.at_level(logging.INFO, logger="log_sqlite"):
        h.handle_incident_dionaea_connection_tcp_accept(FakeIncident(con=FakeCon()))
    h.cursor = cursor
    assert not h.dbh.in_transaction
    assert a not in h.attacks
    assert committed in h.attacks
    assert not h.uncommitted
    # a new connection: sqlite gives it the id of the row that is gone (no AUTOINCREMENT)
    b = FakeCon()
    h.connection_insert(FakeIncident(con=b), "accept")
    assert h.attacks[b][1] == lost_id
    # a later event of the connection whose row is gone writes nothing (not on the row of b)
    h.handle_incident_dionaea_download_offer(FakeIncident(con=a, url="http://x/"))
    h.handle_incident_dionaea_modules_python_ftp_login(FakeIncident(con=a, username="u", password="p"))
    h._commit_timer.fire()
    assert memory_rows(h, "SELECT count(*) FROM offers") == 0
    assert memory_rows(h, "SELECT count(*) FROM logins") == 0
    assert memory_rows(h) == 2
    # the connection of the earlier commit goes on
    h.handle_incident_dionaea_download_offer(FakeIncident(con=committed, url="http://x/"))
    h._commit_timer.fire()
    assert memory_rows(h, "SELECT count(*) FROM offers") == 1


def test_a_failed_statement_that_keeps_the_transaction_keeps_its_connections(memory_handler, summaries):
    """sqlite undoes only the statement (a constraint, ...): the rows before it stay, and so do the ids."""
    summaries(logsql.COMMIT_FAILED, logsql.LOST, logsql.NOT_RECORDED)
    h = memory_handler
    a = FakeCon()
    h.connection_insert(FakeIncident(con=a), "accept")
    cursor = h.cursor
    h.cursor = FailingCursor(cursor)
    h.handle_incident_dionaea_connection_tcp_accept(FakeIncident(con=FakeCon()))
    h.cursor = cursor
    assert h.dbh.in_transaction
    assert a in h.attacks
    h._commit_timer.fire()
    assert not h.uncommitted
    h.handle_incident_dionaea_download_offer(FakeIncident(con=a, url="http://x/"))
    h._commit_timer.fire()
    assert memory_rows(h, "SELECT count(*) FROM offers") == 1


def test_a_rollback_forgets_the_ids_of_links_and_pending_connections(memory_handler, summaries):
    """A connection linked to one whose row is gone takes no lost id: a child that shares the id of
    its parent is forgotten with it, a child of an earlier commit keeps its own id as its root, and
    a lost id is no pending child any more."""
    summaries(logsql.COMMIT_FAILED, logsql.LOST, logsql.NOT_RECORDED)
    h = memory_handler
    older = FakeCon()
    h.connection_insert(FakeIncident(con=older), "accept")
    h._commit_timer.fire()
    older_id = h.attacks[older][1]
    parent, shares = OtherCon(), FakeCon()
    h.connection_insert(FakeIncident(con=parent), "accept")
    lost_id = h.attacks[parent][1]
    # a child without a row of its own takes the id of its parent; a child of the earlier commit its root
    h.handle_incident_dionaea_connection_link(FakeIncident(parent=parent, child=shares))
    h.handle_incident_dionaea_connection_link(FakeIncident(parent=parent, child=older))
    assert h.attacks[shares] == (lost_id, lost_id) and h.attacks[older] == (lost_id, older_id)
    # the lost id waits for a parent dionaea does not know yet
    unknown = FakeCon()
    h.handle_incident_dionaea_connection_link_early(FakeIncident(parent=unknown, child=parent))
    assert h.pending[unknown] == {lost_id: True}
    cursor = h.cursor
    h.cursor = RollingBackCursor(h)
    h.handle_incident_dionaea_connection_tcp_accept(FakeIncident(con=FakeCon()))
    h.cursor = cursor
    assert parent not in h.attacks and shares not in h.attacks
    assert h.attacks[older] == (older_id, older_id)
    assert unknown not in h.pending


class CommitUndone:
    """The database of the handler whose commit fails as sqlite does on SQLITE_FULL, IOERR, ...:
    the transaction is undone."""

    def __init__(self, dbh):
        self.real = dbh

    def commit(self):
        self.real.rollback()
        raise sqlite3.OperationalError("disk I/O error")

    def __getattr__(self, name):
        return getattr(self.real, name)


def test_a_commit_that_undoes_the_transaction_forgets_its_connections(memory_handler, caplog, summaries):
    """The flush whose commit made sqlite undo the transaction: nothing is left to try again, the
    connections of it are forgotten, an info line and one warning a minute say the rows are lost."""
    clock = summaries(logsql.COMMIT_FAILED, logsql.LOST, logsql.NOT_RECORDED)
    h = memory_handler
    a = FakeCon()
    h.connection_insert(FakeIncident(con=a), "accept")
    real = h.dbh
    h.dbh = CommitUndone(real)
    with caplog.at_level(logging.INFO, logger="log_sqlite"):
        h._commit_timer.fire()
    h.dbh = real
    assert not h._dirty
    assert a not in h.attacks and not h.uncommitted
    infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert "The rows of :memory: since the last commit are lost: disk I/O error" in infos
    assert not [i for i in infos if "trying again" in i]
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings == [("transactions of the sqlite log undone: 1 transaction(s) in the last minute, "
                         "the last: :memory:, disk I/O error")]
    clock.advance(60)
    h.handle_incident_dionaea_download_offer(FakeIncident(con=a, url="http://x/"))
    h._commit_timer.fire()
    assert memory_rows(h, "SELECT count(*) FROM offers") == 0


def test_links_of_a_connection_without_an_id_are_left_out(memory_handler):
    """A link of a connection the handler has no id of (its row is gone or its insert failed):
    nothing is recorded and nothing raises (a KeyError went to the core as a warning)."""
    h = memory_handler
    known, unknown, waiting = FakeCon(), OtherCon(), FakeCon()
    h.connection_insert(FakeIncident(con=known), "accept")
    h.handle_incident_dionaea_connection_link_early(FakeIncident(parent=FakeCon(), child=unknown))
    assert not h.pending
    # waiting is the parent of known before it has an id of its own
    h.handle_incident_dionaea_connection_link_early(FakeIncident(parent=waiting, child=known))
    h.handle_incident_dionaea_connection_link(FakeIncident(parent=unknown, child=waiting))
    assert waiting in h.pending
    h._commit_timer.fire()
    assert memory_rows(h, "SELECT count(*) FROM connections WHERE connection_root != connection") == 0


def test_a_child_linked_again_keeps_the_root_of_its_committed_row(memory_handler, summaries):
    """A child linked to a parent of an earlier commit and then to a parent whose row is gone: it
    takes the root its committed row has again, not its own id."""
    summaries(logsql.COMMIT_FAILED, logsql.LOST, logsql.NOT_RECORDED)
    h = memory_handler
    first, child = FakeCon(), OtherCon()
    h.connection_insert(FakeIncident(con=first), "accept")
    h.connection_insert(FakeIncident(con=child), "accept")
    h.handle_incident_dionaea_connection_link(FakeIncident(parent=first, child=child))
    h._commit_timer.fire()
    first_id, child_id = h.attacks[first][1], h.attacks[child][1]
    assert h.attacks[child] == (first_id, child_id)
    second = FakeCon()
    h.connection_insert(FakeIncident(con=second), "accept")
    h.handle_incident_dionaea_connection_link(FakeIncident(parent=second, child=child))
    assert h.attacks[child] == (h.attacks[second][1], child_id)
    cursor = h.cursor
    h.cursor = RollingBackCursor(h)
    h.handle_incident_dionaea_connection_tcp_accept(FakeIncident(con=FakeCon()))
    h.cursor = cursor
    assert second not in h.attacks
    assert h.attacks[child] == (first_id, child_id)
    assert memory_rows(h, "SELECT connection_root FROM connections WHERE connection = %d" % child_id) == first_id


def test_a_link_the_rollback_undid_gives_the_child_its_committed_root(memory_handler, summaries):
    """A child with a committed root R1 is linked to a parent of an earlier commit with root R2;
    the transaction of that link is undone: the child has R1 again, in memory and in the database."""
    summaries(logsql.COMMIT_FAILED, logsql.LOST, logsql.NOT_RECORDED)
    h = memory_handler
    first, second, child = FakeCon(), FakeCon(), OtherCon()
    for con in (first, second, child):
        h.connection_insert(FakeIncident(con=con), "accept")
    h.handle_incident_dionaea_connection_link(FakeIncident(parent=first, child=child))
    h._commit_timer.fire()
    r1, r2, child_id = h.attacks[first][1], h.attacks[second][1], h.attacks[child][1]
    h.handle_incident_dionaea_connection_link(FakeIncident(parent=second, child=child))
    assert h.attacks[child] == (r2, child_id)
    cursor = h.cursor
    h.cursor = RollingBackCursor(h)
    h.handle_incident_dionaea_connection_tcp_accept(FakeIncident(con=FakeCon()))
    h.cursor = cursor
    assert h.attacks[child] == (r1, child_id)
    assert h.attacks[first] == (r1, r1) and h.attacks[second] == (r2, r2)
    assert memory_rows(h, "SELECT connection_root FROM connections WHERE connection = %d" % child_id) == r1
