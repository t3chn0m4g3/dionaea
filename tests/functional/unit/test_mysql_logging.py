# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""mysql.py: what the MySQL service logs, without dionaea.core.

- A database of the configuration whose sqlite file cannot be opened is logged once at
  warning (it was silent since the open moved to debug); a database name of the client
  that is not configured is no warning.
- A statement that sqlite refuses (sqlite3.Error) or that is no UTF-8 is logged at info,
  as the requests of every day are; any other exception of the statement is an error of
  dionaea: warning with its traceback.
"""

import contextlib
import importlib
import logging
import os
import sqlite3
import sys
import types
from pathlib import Path

import pytest


class FakeConnection:
    def __init__(self, proto="tcp"):
        self.sent = []

    def send(self, data):
        self.sent.append(data)


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins():
    root = _src_root()
    names = [n for n in sys.modules if n == "dionaea" or n.startswith("dionaea.")]
    saved = {name: sys.modules.pop(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(root)]
    package.ServiceLoader = type("ServiceLoader", (), {})
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    core.incident = type("incident", (), {"__init__": lambda self, origin: None, "report": lambda self: None})
    core.g_dionaea = None
    # the packages without their __init__ (they import the services)
    smb = types.ModuleType("dionaea.smb")
    smb.__path__ = [str(root / "smb")]
    mysql_package = types.ModuleType("dionaea.mysql")
    mysql_package.__path__ = [str(root / "mysql")]
    sys.modules.update({"dionaea": package, "dionaea.core": core, "dionaea.smb": smb,
                        "dionaea.mysql": mysql_package})
    try:
        yield
    finally:
        # the module under test keeps what it imported; the other tests get their modules back
        for name in [n for n in sys.modules if n == "dionaea" or n.startswith("dionaea.")]:
            sys.modules.pop(name)
        sys.modules.update(saved)


with _stand_ins():
    mysql = importlib.import_module("dionaea.mysql.mysql")


class Query:
    def __init__(self, query):
        self.Query = query

    def show(self):
        pass


class Cursor:
    def __init__(self, error):
        self.error = error

    def execute(self, query):
        raise self.error


@pytest.fixture
def server():
    m = mysql.mysqld()
    m.config = {"information_schema": {"path": ":memory:"}}
    return m


def test_a_database_that_cannot_be_opened_is_logged_once(server, tmp_path, caplog):
    server.config["broken"] = {"path": str(tmp_path / "no" / "such" / "folder" / "x.db")}
    with caplog.at_level(logging.DEBUG, logger="mysqld"):
        assert server._open_db("broken") is False
        assert server._open_db("broken") is False
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 1, [r.getMessage() for r in caplog.records]
    assert "broken" in warnings[0].getMessage()


def test_a_database_that_is_not_configured_is_no_warning(server, caplog):
    with caplog.at_level(logging.DEBUG, logger="mysqld"):
        assert server._open_db(b"") is False
        assert server._open_db("nope") is False
        assert server._open_db("information_schema") is True
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.parametrize("error", [sqlite3.OperationalError("no such table: t"),
                                   sqlite3.DatabaseError("authorization denied")])
def test_a_statement_sqlite_refuses_is_info(server, caplog, error):
    server.cursor = Cursor(error)
    with caplog.at_level(logging.DEBUG, logger="mysqld"):
        r = server._handle_COM_QUERY(Query(b"delete from t"))
    assert isinstance(r, mysql.MySQL_Result_Error)
    assert not [rec for rec in caplog.records if rec.levelno >= logging.WARNING]
    assert any(rec.levelno == logging.INFO and "SQL ERROR" in rec.getMessage() for rec in caplog.records)


def test_a_statement_that_is_no_utf8_is_info(server, caplog):
    server.cursor = Cursor(AssertionError("not reached"))
    with caplog.at_level(logging.DEBUG, logger="mysqld"):
        r = server._handle_COM_QUERY(Query(b"delete from \xff\xfe"))
    assert isinstance(r, mysql.MySQL_Result_Error)
    assert not [rec for rec in caplog.records if rec.levelno >= logging.WARNING]


def test_another_error_of_a_statement_is_a_warning_with_its_traceback(server, caplog):
    server.cursor = Cursor(RuntimeError("a bug"))
    with caplog.at_level(logging.DEBUG, logger="mysqld"):
        r = server._handle_COM_QUERY(Query(b"delete from t"))
    assert isinstance(r, mysql.MySQL_Result_Error)
    warnings = [rec for rec in caplog.records if rec.levelno >= logging.WARNING]
    assert len(warnings) == 1 and warnings[0].exc_info is not None
