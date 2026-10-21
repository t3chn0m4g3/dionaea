# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""ftp.py: the control and the data connections of the FTP service, without dionaea.core.

- Every command is logged at debug only; the incident
  dionaea.modules.python.ftp.command stays as it was.
- A PORT to another address than the client's (an FTP bounce scan) gets an FTP error
  (500 Illegal PORT command), the session goes on.
- A data connection whose file cannot be read (OSError of read) is closed and the
  control connection gets 451. A control connection that is gone (ReferenceError of the
  binding) does not end an upload error or an error callback in an exception.
- The safety net of processcmd: an OSError that is no error of the filesystem (EMFILE,
  ENFILE, EADDRINUSE of the socket of PASV or PORT) gets 425 and is logged with its
  traceback; errors of the filesystem (a read-only root) stay 550. A PASV whose socket
  cannot be made (the core frees the connection) gets 425 as well.
"""

import contextlib
import errno
import importlib.util
import logging
import os
import sys
import types
from pathlib import Path

import pytest


class FakeNode:
    def __init__(self, host="", port=0):
        self.host = host
        self.port = port


# what the binding raises ReferenceError for once the core freed the connection (its Python
# attributes stay readable)
BINDING = frozenset(("bind", "listen", "connect", "send", "close", "processors", "remote", "local", "status"))


class FakeConnection:
    created = []
    # None: bind and listen work. As the core does for TCP: bind only takes the address, listen makes
    # the socket. "socket": socket() fails in listen (EMFILE), the core calls handle_error and frees the
    # connection, listen is False; "listen": listen() fails (the socket is closed, no error callback)
    fail = None

    def __init__(self, proto="tcp"):
        object.__setattr__(self, "_freed", False)
        self.transport = proto
        self.sent = []
        self.closed = False
        self.remote = FakeNode("198.51.100.7", 40000)
        self.local = FakeNode("192.0.2.1", 21)
        FakeConnection.created.append(self)

    def __getattribute__(self, name):
        if name in BINDING and object.__getattribute__(self, "_freed"):
            raise ReferenceError("the object requested does not exist")
        return object.__getattribute__(self, name)

    def free(self):
        object.__setattr__(self, "_freed", True)

    def processors(self):
        pass

    def bind(self, host, port, iface=""):
        self.local = FakeNode(host, 0)
        return True

    def listen(self, size=20):
        if FakeConnection.fail == "socket":
            self.handle_error(OSError(errno.EMFILE, "Too many open files"))
            self.free()
            return False
        if FakeConnection.fail == "listen":
            return False
        self.local = FakeNode(self.local.host, 50000 + len(FakeConnection.created))
        return True

    def connect(self, host, port, iface=""):
        self.remote = FakeNode(host, port)
        if FakeConnection.fail == "connect":
            # socket() fails at once: the error callback comes inside connect, the core frees it
            self.handle_error(OSError(errno.EMFILE, "Too many open files"))
            self.free()

    def send(self, data):
        assert not self.closed, "send on a closed connection"
        self.sent.append(data if isinstance(data, str) else bytes(data).decode())

    def close(self):
        self.closed = True

    def handle_error(self, err):
        pass


class FakeIncident:
    reported = []

    def __init__(self, origin):
        self.origin = origin

    def report(self):
        FakeIncident.reported.append(self)


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins():
    names = ("dionaea", "dionaea.core", "dionaea.exception", "dionaea.upload")
    saved = {name: sys.modules.get(name) for name in names}
    package = types.ModuleType("dionaea")
    # the real upload (stdlib only) is found here, the rest are the stand-ins below
    package.__path__ = [str(_src_root())]
    package.ServiceLoader = type("ServiceLoader", (), {})
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    core.ihandler = type("ihandler", (), {"__init__": lambda self, path: None})
    core.incident = FakeIncident
    core.g_dionaea = None
    exception = types.ModuleType("dionaea.exception")
    exception.ServiceConfigError = type("ServiceConfigError", (Exception,), {})
    sys.modules.update({"dionaea": package, "dionaea.core": core, "dionaea.exception": exception})
    try:
        yield
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


with _stand_ins():
    spec = importlib.util.spec_from_file_location("ftp_under_test", _src_root() / "ftp.py")
    ftp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ftp)


@pytest.fixture(autouse=True)
def clean():
    FakeConnection.created.clear()
    FakeConnection.fail = None
    FakeIncident.reported.clear()
    yield
    FakeConnection.fail = None


@pytest.fixture(autouse=True)
def clock(summaries):
    """The summary warnings of ftp.py with the clock of the test, nothing logged before."""
    return summaries(ftp.STORAGE, ftp.NO_SOCKET, ftp.NO_FILE, ftp.DROPPED)


@pytest.fixture
def session(tmp_path):
    """A control connection of a logged in client."""
    (tmp_path / "file.bin").write_bytes(b"x" * 3000)
    d = ftp.FTPd()
    d.basedir = str(tmp_path)
    d.handle_io_in(b"USER root\r\nPASS secret\r\n")
    assert d.state == d.AUTHED
    d.sent.clear()
    return d


def replies(con):
    return [line for chunk in con.sent for line in chunk.splitlines()]


# ---- the commands are logged at debug only

def test_a_command_is_no_warning(tmp_path, caplog):
    d = ftp.FTPd()
    d.basedir = str(tmp_path)
    with caplog.at_level(logging.DEBUG, logger="ftp"):
        d.handle_io_in(b"USER root\r\nPASS s3cr3t-pass\r\nSYST\r\nNOOP x\r\n")
    loud = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert loud == [], [r.getMessage() for r in loud]
    assert not any("s3cr3t-pass" in r.getMessage() for r in caplog.records if r.levelno > logging.DEBUG)
    # the incident of every command stays as it was
    commands = [i for i in FakeIncident.reported if i.origin == "dionaea.modules.python.ftp.command"]
    assert [(i.command, i.arguments) for i in commands] == [
        (b"USER", ["root"]), (b"PASS", ["s3cr3t-pass"]), (b"SYST", []), (b"NOOP", ["x"])]


# ---- a bounce PORT gets an error, the session goes on

def test_a_bounce_port_gets_an_error(session, caplog):
    with caplog.at_level(logging.INFO, logger="ftp"):
        session.handle_io_in(b"PORT 203,0,113,9,4,1\r\n")
    assert replies(session) == ["500 Illegal PORT command."]
    assert session.dtp is None
    assert not any(isinstance(c, ftp.FTPDataConnect) for c in FakeConnection.created)
    # the line of the log stays as it was, at info: the client chooses it (and an IPv6 client always hits it)
    assert [(r.levelno, r.getMessage()) for r in caplog.records] == [
        (logging.INFO, "Potential FTP Bounce Scan detected")]
    assert not session.closed
    session.sent.clear()
    session.handle_io_in(b"PWD\r\n")
    assert replies(session) == ['257 "/"']


def test_a_port_of_the_client_connects(session):
    session.handle_io_in(b"PORT 198,51,100,7,4,1\r\n")
    assert isinstance(session.dtp, ftp.FTPDataConnect)
    assert (session.dtp.remote.host, session.dtp.remote.port) == ("198.51.100.7", 1025)


def test_a_port_of_an_ipv4_mapped_client_connects(session):
    # a dual-stack socket sees the client as ::ffff:a.b.c.d, PORT names a.b.c.d
    session.remote = FakeNode("::ffff:198.51.100.7", 40000)
    session.handle_io_in(b"PORT 198,51,100,7,4,1\r\n")
    assert isinstance(session.dtp, ftp.FTPDataConnect)
    assert replies(session) == []


# ---- data connections and the safety net

class BrokenFile:
    def __init__(self):
        self.closed = False

    def read(self, size):
        raise OSError(errno.EIO, "Input/output error")

    def close(self):
        self.closed = True


def data_connection(ctrl):
    con = ftp.FTPDataCon(ctrl)
    ctrl.dtp = con
    return con


def established(ctrl):
    con = data_connection(ctrl)
    con.status = "established"
    return con


def test_a_retr_of_a_file_that_cannot_be_opened_answers_550(session, monkeypatch, caplog):
    def denied(path, mode="r"):
        raise PermissionError(errno.EACCES, "Permission denied", path)
    monkeypatch.setattr(ftp, "open", denied, raising=False)
    con = established(session)
    with caplog.at_level(logging.DEBUG, logger="ftp"):
        session.handle_io_in(b"RETR file.bin\r\n")
    assert replies(session) == ["150 File status okay; about to open data connection.",
                                "550 /file.bin: Permission denied."]
    assert con.closed and con.mode is None and con.file is None
    assert session.dtp is None
    # info, not a warning: the file of the root is what the client asked for
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    session.sent.clear()
    session.handle_io_in(b"PWD\r\n")
    assert replies(session) == ['257 "/"']


def test_a_list_of_a_folder_that_cannot_be_read_answers_550(session, tmp_path, monkeypatch, caplog):
    (tmp_path / "closed").mkdir()

    def denied(path="."):
        raise PermissionError(errno.EACCES, "Permission denied", path)
    monkeypatch.setattr(ftp.os, "listdir", denied)
    con = established(session)
    with caplog.at_level(logging.DEBUG, logger="ftp"):
        session.handle_io_in(b"LIST closed\r\n")
    assert replies(session) == ["150 File status okay; about to open data connection.",
                                "550 /closed: Permission denied."]
    assert con.closed and con.mode is None and con.data == []
    assert session.dtp is None
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    session.sent.clear()
    session.handle_io_in(b"PWD\r\n")
    assert replies(session) == ['257 "/"']


def test_a_file_that_cannot_be_read_ends_the_transfer(session):
    con = data_connection(session)
    con.mode = "file"
    con.file = BrokenFile()
    con.handle_io_out()
    assert con.closed
    assert con.file is None or con.file.closed
    assert con.mode is None
    assert session.dtp is None
    assert replies(session) == ["451 Requested action aborted. Local error in processing."]
    assert not session.closed


def test_a_file_that_cannot_be_read_with_the_control_connection_gone(session):
    con = data_connection(session)
    con.mode = "file"
    con.file = BrokenFile()
    session.free()
    con.handle_io_out()
    assert con.closed


class TooLarge:
    def __init__(self, error):
        self.error = error
        self.discarded = False

    def write(self, data):
        raise self.error

    def discard(self):
        self.discarded = True


@pytest.mark.parametrize("error", [ftp.UploadTooLarge("too large"), ftp.UploadError("no space")])
def test_an_upload_error_with_the_control_connection_gone(session, error):
    con = data_connection(session)
    con.mode = "recv_file"
    upload = con.upload = TooLarge(error)
    session.free()
    assert con.handle_io_in(b"abc") == 3
    assert upload.discarded
    assert con.closed
    assert con.mode is None


@pytest.mark.parametrize("mode", [None, "list", "file"])
def test_data_that_is_no_upload_is_taken(session, mode):
    # data after a dropped upload (the client sends on until the close) or on a data connection
    # of a LIST or RETR: read and left; the binding takes the int handle_io_in returns
    con = data_connection(session)
    con.mode = mode
    assert con.handle_io_in(b"more data") == 9


def test_data_after_a_dropped_upload_is_taken(session):
    con = data_connection(session)
    con.mode = "recv_file"
    con.upload = TooLarge(ftp.UploadTooLarge("too large"))
    assert con.handle_io_in(b"abc") == 3
    assert con.handle_io_in(b"defg") == 4


def test_an_upload_error_answers_the_client(session):
    con = data_connection(session)
    con.mode = "recv_file"
    con.upload = TooLarge(ftp.UploadTooLarge("too large"))
    con.handle_io_in(b"abc")
    assert replies(session) == ["552 Exceeded storage allocation (file too large)."]
    assert session.dtp is None


def test_an_error_callback_with_the_control_connection_gone(session):
    con = data_connection(session)
    session.free()
    con.handle_error(OSError(errno.ECONNREFUSED, "Connection refused"))


def test_an_error_callback_answers_the_client(session):
    con = data_connection(session)
    con.handle_error(OSError(errno.ECONNREFUSED, "Connection refused"))
    assert replies(session) == ["425 Can't open data connection."]


@pytest.mark.parametrize("code", [errno.EMFILE, errno.ENFILE, errno.EADDRINUSE, errno.ENOBUFS])
def test_the_safety_net_answers_425_for_errors_of_the_sockets(session, monkeypatch, caplog, code):
    def no_socket(self):
        raise OSError(code, os.strerror(code))
    monkeypatch.setattr(ftp.FTPd, "ftp_PASV", no_socket)
    with caplog.at_level(logging.DEBUG, logger="ftp"):
        session.handle_io_in(b"PASV\r\n")
    assert replies(session) == ["425 Can't open data connection."]
    # the line of the command with its traceback at info, the summary warning
    # the resources of the system, no traceback: the line of the command at info, the summary warning
    infos = [r for r in caplog.records if r.levelno == logging.INFO and r.getMessage().startswith("PASV failed: ")]
    assert len(infos) == 1 and infos[0].exc_info is None, [r.getMessage() for r in caplog.records]
    logged = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert logged == [("FTP data connections failed for lack of sockets: 1 command(s) in the last minute, "
                      "the last: PASV failed: [Errno %d] %s (198.51.100.7)") % (code, os.strerror(code))], logged
    assert not session.closed


@pytest.mark.parametrize("code", [errno.EROFS, errno.EACCES, errno.ENOENT, errno.ENOTEMPTY])
def test_the_safety_net_answers_550_for_errors_of_the_filesystem(session, monkeypatch, caplog, code):
    def fails(self, p):
        raise OSError(code, os.strerror(code))
    monkeypatch.setattr(ftp.FTPd, "ftp_MKD", fails)
    with caplog.at_level(logging.DEBUG, logger="ftp"):
        session.handle_io_in(b"MKD new\r\n")
    assert replies(session) == ["550 new: Permission denied."]
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


@pytest.mark.parametrize("how", ["socket", "listen"])
def test_a_pasv_without_a_socket_gets_425(session, how):
    # "socket": socket() fails in listen (EMFILE): the core calls handle_error (425) and frees the
    # connection; "listen": listen() fails without an error callback
    FakeConnection.fail = how
    session.handle_io_in(b"PASV\r\n")
    assert replies(session) == ["425 Can't open data connection."]
    assert session.dtf is None
    assert not session.closed
    made = [c for c in FakeConnection.created if isinstance(c, ftp.FTPDataListen)]
    if how == "listen":
        assert made[-1].closed, "the listener that has no socket is closed"
    FakeConnection.fail = None
    session.sent.clear()
    # the next PASV does not touch the one before
    session.handle_io_in(b"PASV\r\n")
    assert replies(session)[0].startswith("227 Entering Passive Mode")
    assert not replies(session)[0].endswith("0,0).")


# ---- a full disk on STOR: 452, not 425 or 550

FULL = "452 Requested action not taken. Insufficient storage space in system."


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.EDQUOT])
def test_a_write_to_a_full_disk_answers_452(session, code):
    con = data_connection(session)
    con.mode = "recv_file"
    con.upload = TooLarge(ftp.UploadError("unable to write: disk full", errno=code))
    con.handle_io_in(b"abc")
    assert replies(session) == [FULL]
    assert session.dtp is None and con.closed


def test_another_write_error_answers_425(session):
    con = data_connection(session)
    con.mode = "recv_file"
    con.upload = TooLarge(ftp.UploadError("unable to write: I/O error", errno=errno.EIO))
    con.handle_io_in(b"abc")
    assert replies(session) == ["425 Can't open data connection."]


@pytest.mark.parametrize("code, answer", [(errno.ENOSPC, FULL), (errno.EDQUOT, FULL),
                                          (errno.EMFILE, "425 Can't open data connection.")])
def test_no_file_for_the_upload(session, monkeypatch, code, answer):
    def no_file(*args, **kwargs):
        raise OSError(code, os.strerror(code))
    monkeypatch.setattr(ftp, "UploadFile", no_file)
    con = data_connection(session)
    con.recv_file("x.bin")
    assert replies(session) == [answer]
    assert con.closed


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.EDQUOT])
def test_the_safety_net_answers_452_for_a_full_disk(session, monkeypatch, caplog, code):
    def fails(self, p):
        raise OSError(code, os.strerror(code))
    monkeypatch.setattr(ftp.FTPd, "ftp_MKD", fails)
    with caplog.at_level(logging.DEBUG, logger="ftp"):
        session.handle_io_in(b"MKD new\r\n")
    assert replies(session) == [FULL]
    # a full disk is no request of every day: a warning, so it is in dionaea-errors.log
    logged = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(logged) == 1, [r.getMessage() for r in caplog.records]
    assert os.strerror(code) in logged[0].getMessage()
    assert not session.closed


def test_the_warning_of_a_full_disk_holds_the_name_of_the_client_as_plain_text(session, monkeypatch, caplog):
    def fails(self, p):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
    monkeypatch.setattr(ftp.FTPd, "ftp_MKD", fails)
    name = b"new\x1b[31m\x07" + b"x" * 400
    with caplog.at_level(logging.DEBUG, logger="ftp"):
        session.handle_io_in(b"MKD " + name + b"\r\n")
    logged = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(logged) == 1, logged
    assert all(0x20 <= ord(c) <= 0x7e for c in logged[0]), logged[0]
    assert "MKD new?[31m?" + "x" * 247 + "... failed" in logged[0]
    assert len(logged[0]) < 400


@pytest.mark.parametrize("filename", ["new\n" + "x" * 400, "new\x1b[31m\n" + "y" * 400])
def test_the_error_of_a_full_disk_with_the_name_of_the_client_is_plain_text(session, monkeypatch, caplog, filename):
    def fails(self, p):
        # the OSError names the file of the client (and its text has the line break raw)
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC) + ": " + filename, filename)
    monkeypatch.setattr(ftp.FTPd, "ftp_MKD", fails)
    with caplog.at_level(logging.DEBUG, logger="ftp"):
        session.handle_io_in(b"MKD new\r\n")
    logged = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(logged) == 1, logged
    assert all(0x20 <= ord(c) <= 0x7e for c in logged[0]), logged[0]
    assert logged[0].endswith("..."), logged[0]
    # the text of the summary warning and the command line of at most 256 + 3 characters
    assert len(logged[0]) < 400


# ---- the lines of every session are info, one warning a minute sums them up

def test_full_disks_of_many_sessions_are_one_warning_a_minute(tmp_path, monkeypatch, caplog, clock):
    def fails(self, p):
        raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))
    monkeypatch.setattr(ftp.FTPd, "ftp_MKD", fails)
    with caplog.at_level(logging.DEBUG, logger="ftp"):
        for n in range(5):
            d = ftp.FTPd()
            d.basedir = str(tmp_path)
            d.handle_io_in(b"USER root\r\nPASS secret\r\nMKD dir%d\r\n" % n)
            assert replies(d)[-1] == FULL
            clock.advance(1)
        infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO and "failed" in r.getMessage()]
        assert infos == ["MKD dir%d failed: [Errno 28] No space left on device" % n for n in range(5)]
        logged = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert logged == [("FTP commands failed for lack of storage: 1 command(s) in the last minute, "
                          "the last: MKD dir0 failed: [Errno 28] No space left on device")]
        clock.advance(60)
    logged = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert logged[1:] == [("FTP commands failed for lack of storage: 4 command(s) in the last minute, "
                          "the last: MKD dir4 failed: [Errno 28] No space left on device")]


def test_dropped_uploads_of_many_sessions_are_one_warning_a_minute(session, caplog, clock):
    with caplog.at_level(logging.DEBUG, logger="ftp"):
        for _ in range(4):
            con = data_connection(session)
            con.mode = "recv_file"
            con.upload = TooLarge(ftp.UploadTooLarge("write of 3 bytes at offset 10, limit is 4"))
            con.handle_io_in(b"abc")
            clock.advance(1)
        infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO and "dropped" in r.getMessage()]
        assert infos == ["upload dropped: write of 3 bytes at offset 10, limit is 4 (198.51.100.7)"] * 4
        clock.advance(60)
    logged = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert logged == [
        ("uploads dropped: 1 upload(s) in the last minute, the last: write of 3 bytes at offset 10, limit is 4 "
         "(198.51.100.7)"),
        ("uploads dropped: 3 upload(s) in the last minute, the last: write of 3 bytes at offset 10, limit is 4 "
         "(198.51.100.7)")]


def test_uploads_without_a_file_are_info_and_one_warning_a_minute(session, monkeypatch, caplog, clock):
    def no_file(*args, **kwargs):
        raise OSError(errno.EMFILE, os.strerror(errno.EMFILE))
    monkeypatch.setattr(ftp, "UploadFile", no_file)
    with caplog.at_level(logging.DEBUG, logger="ftp"):
        for _ in range(3):
            data_connection(session).recv_file("x.bin")
        clock.advance(60)
    infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO and "unable" in r.getMessage()]
    assert infos == ["unable to create a file for the upload: [Errno 24] Too many open files (198.51.100.7)"] * 3
    logged = [(r.levelno, r.getMessage()) for r in caplog.records if r.levelno >= logging.WARNING]
    assert logged == [
        (logging.WARNING, ("uploads not stored, no file could be made: 1 upload(s) in the last minute, "
                           "the last: [Errno 24] Too many open files (198.51.100.7)")),
        (logging.WARNING, ("uploads not stored, no file could be made: 2 upload(s) in the last minute, "
                           "the last: [Errno 24] Too many open files (198.51.100.7)"))]


# ---- a PORT whose connect fails leaves no data connection behind

def test_a_refused_port_connection_is_forgotten(session):
    session.handle_io_in(b"PORT 198,51,100,7,4,1\r\n")
    dtp = session.dtp
    assert isinstance(dtp, ftp.FTPDataConnect)
    # the client does not listen: the core calls the error callback later and frees the connection
    dtp.handle_error(OSError(errno.ECONNREFUSED, "Connection refused"))
    dtp.free()
    assert session.dtp is None
    session.handle_io_in(b"RETR file.bin\r\nLIST\r\nPWD\r\n")
    assert replies(session) == ["425 Can't open data connection."] * 3 + ['257 "/"']


def test_a_port_connection_that_fails_at_once_is_not_kept(session):
    FakeConnection.fail = "connect"
    session.handle_io_in(b"PORT 198,51,100,7,4,1\r\n")
    FakeConnection.fail = None
    assert session.dtp is None
    session.handle_io_in(b"RETR file.bin\r\n")
    assert replies(session) == ["425 Can't open data connection."] * 2
    # a new PORT does not touch the freed one
    session.sent.clear()
    session.handle_io_in(b"PORT 198,51,100,7,4,2\r\n")
    assert isinstance(session.dtp, ftp.FTPDataConnect) and replies(session) == []
