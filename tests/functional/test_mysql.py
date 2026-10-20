# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""MySQL service: queries of an attacker get an answer (and do not end in a TypeError).

The statements of the pattern matching (bytes of the wire against str patterns)
are the ones attackers send: SET, SELECT DATABASE(), SHOW DATABASES, SHOW TABLES,
SHOW VARIABLES, SELECT @@var and the dumps of files.
"""

import hashlib
import time
import uuid

import pymysql
import pytest

from servers import HttpServer


@pytest.fixture
def mysql(dionaea_host):
    cnx = pymysql.connect(user="root", host=dionaea_host, port=3306, connect_timeout=10, read_timeout=10)
    cursor = cnx.cursor()
    yield cursor
    try:
        cnx.close()
    except Exception:
        pass


def test_set(mysql):
    mysql.execute("SET @v1 = 2")
    mysql.execute("set names utf8")


def test_select_database(mysql):
    mysql.execute("select database()")
    assert mysql.fetchall() == (("information_schema",),)


def test_show_databases(mysql):
    mysql.execute("show databases")
    assert ("information_schema",) in mysql.fetchall()


def test_show_tables(mysql):
    mysql.execute("show tables")
    mysql.fetchall()


def test_show_variables_like(mysql):
    mysql.execute("show variables like 'version%'")
    rows = mysql.fetchall()
    assert rows and all(name.startswith("version") for name, _ in rows), rows
    # a length coded string has no terminating NUL (a MySQL server sends none)
    assert all("\0" not in name and "\0" not in value for name, value in rows), rows


def test_select_system_variable(mysql):
    mysql.execute("select @@version")
    rows = mysql.fetchall()
    assert len(rows) == 1 and rows[0][0] and "\0" not in rows[0][0], rows


def test_sql_of_the_database(mysql):
    mysql.execute("select 1 as one")
    assert len(mysql.fetchall()) == 1


def test_server_still_answers_after_queries(mysql):
    for query in ("select 1", "show databases", "select database()"):
        mysql.execute(query)
        mysql.fetchall()


def test_dumpfile_of_hex_data_is_stored(mysql, binaries_dir):
    data = ("dumped by a test %s\n" % uuid.uuid4().hex).encode()
    md5 = hashlib.md5(data).hexdigest()
    try:
        mysql.execute("select unhex('%s') into dumpfile '/tmp/x.bin'" % data.hex())
    except pymysql.err.MySQLError:
        pass
    deadline = time.monotonic() + 20
    while not (binaries_dir / md5).exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert (binaries_dir / md5).read_bytes() == data


def test_xpdl3_url_is_offered_and_downloaded(mysql, my_ip, query_db, binaries_dir):
    payload = ("mysql xpdl3 %s\n" % uuid.uuid4().hex).encode() * 10
    name = "x-%s.bin" % uuid.uuid4().hex[:10]
    server = HttpServer({"/" + name: payload}, my_ip)
    url = "http://%s:%d/%s" % (my_ip, server.port, name)
    try:
        try:
            mysql.execute("select xpdl3('%s') into dumpfile 'x'" % url)
        except pymysql.err.MySQLError:
            pass
        md5 = hashlib.md5(payload).hexdigest()
        deadline = time.monotonic() + 30
        rows = []
        while not rows and time.monotonic() < deadline:
            rows = query_db("SELECT download_md5_hash FROM downloads WHERE download_url = ?", (url,))
            time.sleep(0.5)
        assert query_db("SELECT offer_url FROM offers WHERE offer_url = ?", (url,)), "no offer for %s" % url
        assert rows and rows[0]["download_md5_hash"] == md5
        assert (binaries_dir / md5).read_bytes() == payload
    finally:
        server.close()


@pytest.mark.parametrize("statement", [
    "ATTACH DATABASE '{path}' AS capture",
    "  attach database '{path}' as capture",
    "/* prefix */ AtTaCh DATABASE '{path}' AS capture",
    "VACUUM INTO '{path}'",
    "/* prefix */ vacuum into '{path}'",
    "PRAGMA temp_store_directory = '{path}'",
    "SELECT load_extension('{path}')",
])
def test_filesystem_sql_is_rejected_and_session_survives(mysql, binaries_dir, statement):
    name = "sqlite-denied-%s" % uuid.uuid4().hex
    remote_path = "/opt/dionaea/var/dionaea/binaries/" + name
    with pytest.raises(pymysql.err.MySQLError):
        mysql.execute(statement.format(path=remote_path))
    assert not (binaries_dir / name).exists()
    mysql.execute("select 1")
    assert len(mysql.fetchall()) == 1
