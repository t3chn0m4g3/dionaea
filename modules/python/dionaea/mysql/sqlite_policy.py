# This file is part of the dionaea honeypot
# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: GPL-2.0-or-later

"""Keep attacker SQL inside the configured MySQL emulation database."""

import sqlite3


def authorize(action, first, second, database, source):
    # VACUUM INTO also requests SQLITE_ATTACH. Checking the SQLite operation
    # survives SQL comments, whitespace, casing, and statement rewrites.
    if action in (sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH):
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_PRAGMA and (first or "").lower() != "table_info":
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and (second or "").lower() in (
        "load_extension", "readfile", "writefile", "fts3_tokenizer",
    ):
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def protect(database):
    if hasattr(database, "enable_load_extension"):
        database.enable_load_extension(False)
    database.setlimit(sqlite3.SQLITE_LIMIT_ATTACHED, 0)
    database.set_authorizer(authorize)
