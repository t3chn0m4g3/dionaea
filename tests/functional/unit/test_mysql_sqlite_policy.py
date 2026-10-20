# This file is part of the dionaea honeypot
# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: CC0-1.0

"""SQLite cannot attach host files, export databases, or enable extensions."""

import importlib.util
import os
import sqlite3
from pathlib import Path

import pytest

root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
    Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
spec = importlib.util.spec_from_file_location("mysql_sqlite_policy", root / "mysql" / "sqlite_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


@pytest.mark.parametrize("query", [
    "ATTACH DATABASE '{path}' AS other",
    "  attach database '{path}' as other",
    "/* ignored prefix */ AtTaCh DATABASE '{path}' AS other",
    "VACUUM INTO '{path}'",
    "/* ignored prefix */ vacuum into '{path}'",
    "PRAGMA temp_store_directory = '{path}'",
    "PRAGMA writable_schema = ON",
    "SELECT load_extension('{path}')",
    "SELECT readfile('{path}')",
    "SELECT writefile('{path}', 'content')",
])
def test_filesystem_sql_is_denied_without_creating_a_file(tmp_path, query):
    target = tmp_path / "forbidden.sqlite"
    with sqlite3.connect(":memory:") as database:
        database.execute("CREATE TABLE example (value TEXT)")
        policy.protect(database)
        with pytest.raises(sqlite3.DatabaseError):
            database.execute(query.format(path=target))
        assert not target.exists()
        assert database.execute("SELECT 1").fetchall() == [(1,)]
        assert database.execute("PRAGMA table_info(example)").fetchall()[0][1] == "value"


def test_honeypot_database_queries_still_work():
    with sqlite3.connect(":memory:") as database:
        policy.protect(database)
        database.execute("CREATE TABLE example (value TEXT)")
        database.execute("INSERT INTO example VALUES ('captured')")
        assert database.execute("SELECT value FROM example").fetchall() == [("captured",)]
        database.execute("UPDATE example SET value = upper(value)")
        assert database.execute("SELECT value FROM example").fetchall() == [("CAPTURED",)]
        database.execute("DELETE FROM example")
        assert database.execute("SELECT count(*) FROM example").fetchall() == [(0,)]
