# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""tftp.py: the TFTP server sessions are bounded.

Every read request makes a TftpServerHandler, a UDP socket of its own that lives until
the transfer ends or its idle timeout (3 s) runs out. Many read requests at once would
make as many sessions. There are at most 64 sessions at a time and at
most 4 per source address; a read request beyond that is answered with a TFTP ERROR
from the server socket and makes no session.

A handler whose socket cannot be made (socket() fails: the core calls handle_error and
frees the connection, no disconnect follows) gives its place back and the request goes
no further; an error of a session never leaves TftpServer.handle_io_in (the binding
would close the server socket). The source is the IPv4 address also when it comes as
::ffff:a.b.c.d. The ERROR replies of the server socket are rate limited per source and
in all.
"""

import contextlib
import importlib.util
import os
import struct
import sys
import types
from pathlib import Path

import pytest


class FakeTimeouts:
    idle = 0
    sustain = 0


class FakeNode:
    def __init__(self, host="", port=0):
        self.host = host
        self.port = port


class FakeConnectionTooMany(Exception):
    """dionaea.exception.ConnectionTooMany, what the binding hands handle_error for ECONMANY."""


class FakeConnection:
    created = []
    # how the next binds fail: None (they work), "socket" (socket() fails: the C core calls
    # protocol.error(ECONMANY), frees the connection, bind returns False) or "bind" (False only)
    fail_bind = None

    def __init__(self, proto="udp"):
        self.sent = []
        self.closed = False
        self.connected = False
        self.timeouts = FakeTimeouts()
        self.remote = FakeNode()
        self.local = FakeNode("192.0.2.1", 69)
        FakeConnection.created.append(self)

    def bind(self, host, port, iface=""):
        if FakeConnection.fail_bind == "socket":
            # connection_socket(): protocol.error(con, ECONMANY), connection_free(con); no disconnect
            self.handle_error(FakeConnectionTooMany())
            return False
        if FakeConnection.fail_bind == "bind":
            return False
        self.local = FakeNode(host, port)
        return True

    def connect(self, host, port, iface="", download=False):
        self.connected = True
        self.remote = FakeNode(host, port)

    def handle_error(self, err):
        # the binding's default: nothing
        pass

    def send(self, data, local=None, remote=None):
        assert not self.closed, "send on a closed connection"
        self.sent.append(bytes(data))

    def close(self):
        # as the binding: the UDP connection is disconnected at once
        if not self.closed:
            self.closed = True
            self.handle_disconnect()

    def handle_disconnect(self):
        return 0


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins():
    names = ("dionaea", "dionaea.core", "dionaea.exception", "dionaea.mirror_policy", "dionaea.upload")
    saved = {name: sys.modules.get(name) for name in names}
    package = types.ModuleType("dionaea")
    # the real mirror_policy and upload (stdlib only) are found here, the rest are the stand-ins below
    package.__path__ = [str(_src_root())]
    package.ServiceLoader = type("ServiceLoader", (), {})
    package.IHandlerLoader = type("IHandlerLoader", (), {})
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    core.ihandler = type("ihandler", (), {"__init__": lambda self, path: None})
    core.incident = type("incident", (), {})
    core.g_dionaea = None
    core.download_failed = lambda url, reason: None
    core.download_refused = lambda url: None
    exception = types.ModuleType("dionaea.exception")
    exception.ServiceConfigError = type("ServiceConfigError", (Exception,), {})
    exception.ConnectionRefusedByFilter = type("ConnectionRefusedByFilter", (Exception,), {})
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
    spec = importlib.util.spec_from_file_location("tftp_under_test", _src_root() / "tftp.py")
    tftp = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tftp)


def rrq(name, mode=b"octet"):
    return struct.pack("!H", 1) + name + b"\x00" + mode + b"\x00"


OPCODE_DAT, OPCODE_ERR = 3, 5


def reset_sessions():
    sessions = getattr(tftp, "SESSIONS", None)
    if sessions is not None:
        sessions.reset()


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock(monkeypatch):
    """The ERROR replies of the server socket get a fresh limiter on a clock the test moves."""
    c = FakeClock()
    if hasattr(tftp, "TftpErrorLimiter"):
        monkeypatch.setattr(tftp, "ERRORS", tftp.TftpErrorLimiter(clock=c))
    return c


@pytest.fixture
def server(tmp_path, clock):
    (tmp_path / "file.bin").write_bytes(b"x" * 2000)   # four blocks: a session waits for ACKs
    FakeConnection.created.clear()
    FakeConnection.fail_bind = None
    reset_sessions()
    s = tftp.TftpServer()
    s.root = str(tmp_path)
    yield s
    FakeConnection.fail_bind = None
    for con in list(FakeConnection.created):
        if isinstance(con, tftp.TftpServerHandler):
            con.close()
    reset_sessions()


def request(server, host, name=b"file.bin", port=40000, mode=b"octet"):
    """A read request on the server socket from host:port: the handler made for it, or None."""
    server.remote = FakeNode(host, port)
    before = len(FakeConnection.created)
    sent_before = len(server.sent)
    assert server.handle_io_in(rrq(name, mode)) == len(rrq(name, mode))
    made = [c for c in FakeConnection.created[before:] if isinstance(c, tftp.TftpServerHandler)]
    assert len(made) <= 1
    return (made[0] if made else None), server.sent[sent_before:]


def opcode(packet):
    return struct.unpack("!H", packet[:2])[0]


def handlers():
    return [c for c in FakeConnection.created if isinstance(c, tftp.TftpServerHandler) and not c.closed]


def test_four_sessions_per_source_address(server):
    for port in range(4):
        handler, replies = request(server, "198.51.100.1", port=40000 + port)
        assert handler is not None and replies == []
        assert opcode(handler.sent[0]) == OPCODE_DAT
    handler, replies = request(server, "198.51.100.1", port=40010)
    assert handler is None
    assert len(replies) == 1 and opcode(replies[0]) == OPCODE_ERR
    # another source still gets a session
    handler, replies = request(server, "198.51.100.2")
    assert handler is not None and replies == []
    assert len(handlers()) == 5


def test_sixty_four_sessions_in_all(server):
    for i in range(64):
        handler, _ = request(server, "198.51.100.%d" % (i // 4), port=40000 + i)
        assert handler is not None
    assert len(handlers()) == 64
    handler, replies = request(server, "203.0.113.9")
    assert handler is None
    assert len(replies) == 1 and opcode(replies[0]) == OPCODE_ERR
    assert len(handlers()) == 64


def test_an_ended_session_frees_its_place(server):
    sessions = [request(server, "198.51.100.1", port=40000 + i)[0] for i in range(4)]
    assert request(server, "198.51.100.1", port=40010)[0] is None
    sessions[0].handle_timeout_idle()    # what the idle timeout does: False closes the connection
    sessions[0].close()
    assert request(server, "198.51.100.1", port=40011)[0] is not None
    # a second disconnect of the same session does not free a place twice
    sessions[1].close()
    sessions[1].handle_disconnect()
    assert request(server, "198.51.100.1", port=40012)[0] is not None
    assert request(server, "198.51.100.1", port=40013)[0] is None


def test_a_request_that_ends_at_once_frees_its_place(server):
    # a missing file, a path outside the root, a mode other than octet: ERROR from the session
    for name, mode in ((b"missing.bin", b"octet"), (b"../../etc/passwd", b"octet"), (b"file.bin", b"netascii")):
        for i in range(6):
            handler, _ = request(server, "198.51.100.7", name=name, port=41000 + i, mode=mode)
            assert handler is not None and handler.closed
            assert opcode(handler.sent[-1]) == OPCODE_ERR
    assert handlers() == []
    assert tftp.SESSIONS.total == 0


def test_the_sessions_expire():
    con = tftp.TftpServerHandler(tftp.TftpState("rrq"), "/", "192.0.2.1", "198.51.100.1", 4000,
                                 tftp.TftpPacketFactory())
    # the timeouts of a session: idle 3 s, sustain 120 s, neither keeps it
    assert con.timeouts.idle == 3
    assert con.timeouts.sustain == 120
    assert con.handle_timeout_idle() is False
    assert con.handle_timeout_sustain() is False


# ---- a handler whose socket cannot be made (EMFILE, ENFILE, ENOBUFS)

def fill_source(server, host, count=4, first_port=42000):
    return [request(server, host, port=first_port + i)[0] for i in range(count)]


@pytest.mark.parametrize("how", ["socket", "bind"])
def test_a_handler_without_a_socket_gives_its_place_back(server, how):
    # the place is given back and the request goes no further
    FakeConnection.fail_bind = how
    for i in range(6):
        handler, replies = request(server, "198.51.100.20", port=43000 + i)
        assert handler is not None
        assert handler.sent == [], "the request goes no further without a socket"
        assert handler.fileobj is None
        assert not handler.connected, "no connect without a bound socket"
        assert replies == []
    assert tftp.SESSIONS.total == 0
    assert tftp.SESSIONS.per_source == {}
    # the fds are back: the source gets its four sessions again
    FakeConnection.fail_bind = None
    sessions = fill_source(server, "198.51.100.20")
    assert all(s is not None and opcode(s.sent[0]) == OPCODE_DAT for s in sessions)
    assert request(server, "198.51.100.20", port=43100)[0] is None


def test_the_place_is_given_back_once(server):
    others = fill_source(server, "198.51.100.30", count=3)
    assert tftp.SESSIONS.per_source["198.51.100.30"] == 3
    handler, _ = request(server, "198.51.100.31")
    assert tftp.SESSIONS.total == 4
    # an error callback, then the disconnect, then both again: one place
    handler.handle_error(FakeConnectionTooMany())
    handler.handle_error(FakeConnectionTooMany())
    handler.close()
    handler.handle_disconnect()
    assert tftp.SESSIONS.total == 3
    assert tftp.SESSIONS.per_source == {"198.51.100.30": 3}
    assert all(not o.closed for o in others)


def test_a_failing_constructor_gives_its_place_back(server, monkeypatch):
    def broken(self, *args, **kwargs):
        raise RuntimeError("broken")
    monkeypatch.setattr(tftp.TftpSession, "__init__", broken)
    server.remote = FakeNode("198.51.100.40", 40000)
    # logged, not raised: the binding would close the server socket
    assert server.handle_io_in(rrq(b"file.bin")) == len(rrq(b"file.bin"))
    assert tftp.SESSIONS.total == 0
    assert not server.closed


# ---- one source address, however it is written

def test_an_ipv4_mapped_address_is_the_same_source(server):
    # a dual-stack socket sees IPv4 clients as ::ffff:a.b.c.d
    for i in range(2):
        assert request(server, "::ffff:198.51.100.50", port=44000 + i)[0] is not None
    for i in range(2):
        assert request(server, "198.51.100.50", port=44010 + i)[0] is not None
    handler, replies = request(server, "::ffff:198.51.100.50", port=44020)
    assert handler is None and opcode(replies[0]) == OPCODE_ERR
    assert tftp.SESSIONS.per_source == {"198.51.100.50": 4}
    # an IPv6 address stays itself
    assert request(server, "2001:db8::1", port=44030)[0] is not None
    assert tftp.SESSIONS.per_source["2001:db8::1"] == 1


# ---- the ERROR replies of the server socket are rate limited

def refused(server, host, count, port=45000):
    """count refused read requests of host: the ERROR replies sent."""
    replies = 0
    for i in range(count):
        handler, sent = request(server, host, port=port + i)
        assert handler is None
        replies += len(sent)
    return replies


def test_the_error_replies_of_one_source_are_limited(server, clock):
    fill_source(server, "198.51.100.60")
    # a burst of 20, then 10 a second
    assert refused(server, "198.51.100.60", 100) == 20
    clock.now += 1.0
    assert refused(server, "198.51.100.60", 100) == 10
    clock.now += 0.5
    assert refused(server, "198.51.100.60", 100) == 5
    # another source is not held back by it
    fill_source(server, "198.51.100.61")
    assert refused(server, "198.51.100.61", 3) == 3


def test_the_error_replies_of_all_sources_are_limited(server, clock):
    for i in range(16):
        fill_source(server, "198.51.100.%d" % (100 + i))
    assert tftp.SESSIONS.total == 64
    # many sources, one request each: at most 200 at once, then 200 a second
    sent = sum(refused(server, "203.0.%d.%d" % (i // 250, i % 250), 1) for i in range(1000))
    assert sent == 200
    clock.now += 1.0
    sent = sum(refused(server, "203.1.%d.%d" % (i // 250, i % 250), 1) for i in range(1000))
    assert sent == 200


def test_the_table_of_the_sources_is_bounded(server, clock):
    limiter = tftp.ERRORS
    for i in range(3 * limiter.max_sources):
        limiter.allow("10.%d.%d.%d" % (i >> 16 & 255, i >> 8 & 255, i & 255))
        clock.now += 0.01
    assert len(limiter.sources) <= limiter.max_sources


def test_a_limited_source_is_logged_once_a_minute_without_payload(server, clock, caplog):
    fill_source(server, "198.51.100.70")
    with caplog.at_level("INFO", logger="tftp"):
        refused(server, "198.51.100.70", 200)
        clock.now += 30
        refused(server, "198.51.100.70", 200)
    lines = [r.getMessage() for r in caplog.records if "198.51.100.70" in r.getMessage() and r.levelname == "INFO"]
    assert len(lines) == 1, lines
    assert "file.bin" not in lines[0]
    with caplog.at_level("INFO", logger="tftp"):
        caplog.clear()
        clock.now += 31
        refused(server, "198.51.100.70", 200)
    assert len([r for r in caplog.records if "198.51.100.70" in r.getMessage() and r.levelname == "INFO"]) == 1


def test_the_limited_sources_are_info_and_one_warning_a_minute(server, clock, caplog, summaries):
    """A source whose ERROR replies are limited is an info line (once a minute per source); one
    warning a minute counts the sources."""
    summary_clock = summaries(tftp.RATE_LIMITED)
    for n in range(12):
        fill_source(server, "198.51.100.%d" % (150 + n))
    with caplog.at_level("INFO", logger="tftp"):
        for n in range(12):
            refused(server, "198.51.100.%d" % (150 + n), 30)
            summary_clock.advance(1)
        infos = [r.getMessage() for r in caplog.records if r.levelname == "INFO" and "rate limited" in r.getMessage()]
        # 10 sources by name, then one line for the rest
        assert len(infos) == 11
        assert infos[0] == "TFTP error replies to 198.51.100.150 are rate limited, 1 dropped"
        assert infos[10].startswith("TFTP error replies to more sources are rate limited")
        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert warnings == [("TFTP error replies rate limited: 1 source(s) in the last minute, "
                            "the last: 198.51.100.150, 1 dropped")]
        summary_clock.advance(60)
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert warnings[1:] == [("TFTP error replies rate limited: 11 source(s) in the last minute, "
                            "the last: 198.51.100.161, 1 dropped")]


def test_the_session_limit_is_info_and_one_warning_a_minute(server, caplog, summaries):
    """Every time the sessions reach the limit again is an info line; one warning a minute."""
    summary_clock = summaries(tftp.SESSION_LIMIT)
    with caplog.at_level("INFO", logger="tftp"):
        sessions = [request(server, "198.51.100.%d" % (i // 4), port=40000 + i)[0] for i in range(64)]
        for round in range(3):
            assert request(server, "203.0.113.9", port=41000 + round)[0] is None
            # a place is free and taken again: the limit is reached again
            sessions[round].close()
            sessions[round] = request(server, "203.0.113.%d" % (10 + round), port=42000 + round)[0]
            assert sessions[round] is not None
            summary_clock.advance(1)
        assert request(server, "203.0.113.9", port=41010)[0] is None
        infos = [r.getMessage() for r in caplog.records if r.levelname == "INFO" and "limit reached" in r.getMessage()]
        assert infos == ["TFTP session limit reached (64 sessions), refusing read requests"] * 4
        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert warnings == ["TFTP session limit reached: 1 time(s) in the last minute, the last: 64 sessions"]
        summary_clock.advance(60)
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert warnings[1:] == ["TFTP session limit reached: 3 time(s) in the last minute, the last: 64 sessions"]


def test_a_write_request_error_is_limited_too(server, clock):
    server.remote = FakeNode("198.51.100.80", 46000)
    wrq = struct.pack("!H", 2) + b"up.bin\x00octet\x00"
    before = len(server.sent)
    for _ in range(100):
        server.handle_io_in(wrq)
    assert len(server.sent) - before == 20


def test_an_error_of_a_session_does_not_close_the_server(server, monkeypatch):
    # the binding closes a connection whose handle_io_in raises; an error of a session
    # (here EMFILE) leaves the server socket open
    def broken(self, data):
        raise OSError(24, "Too many open files")
    monkeypatch.setattr(tftp.TftpServerHandler, "handle_io_in", broken)
    handler, replies = request(server, "198.51.100.90")
    assert not server.closed
    assert handler.closed and replies == []
    assert tftp.SESSIONS.total == 0


def test_a_file_that_cannot_be_opened_ends_the_session(server, monkeypatch):
    import builtins
    real_open = builtins.open

    def no_fds(path, *args, **kwargs):
        if str(path).endswith("file.bin"):
            raise OSError(24, "Too many open files")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", no_fds)
    handler, replies = request(server, "198.51.100.91")
    assert handler.closed and handler.sent == []
    assert tftp.SESSIONS.total == 0
    assert not server.closed


def test_files_that_cannot_be_opened_are_info_and_one_warning_a_minute(server, monkeypatch, caplog, summaries):
    import builtins
    real_open = builtins.open

    def no_fds(path, *args, **kwargs):
        if str(path).endswith("file.bin"):
            raise OSError(24, "Too many open files")
        return real_open(path, *args, **kwargs)
    monkeypatch.setattr(builtins, "open", no_fds)
    summary_clock = summaries(tftp.NOT_OPENED)
    with caplog.at_level("INFO", logger="tftp"):
        for n in range(5):
            request(server, "198.51.100.%d" % (92 + n))
            summary_clock.advance(1)
        infos = [r.getMessage() for r in caplog.records if r.levelname == "INFO" and "Unable to open" in r.getMessage()]
        assert len(infos) == 5
        assert infos[0].startswith("Unable to open ") and infos[0].endswith("file.bin: Too many open files")
        warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 1
        assert warnings[0].startswith("TFTP files not opened: 1 session(s) in the last minute, the last: ")
        assert warnings[0].endswith("file.bin: Too many open files")
        summary_clock.advance(60)
    warnings = [r.getMessage() for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 2 and warnings[1].startswith("TFTP files not opened: 4 session(s) in the last minute")


# ---- the ERROR replies of the sessions share the buckets of the server socket

def session_errors(server, host, count, name=b"missing.bin", mode=b"octet", port=47000):
    """count read requests of host that a session answers with an ERROR: the replies sent."""
    sent = 0
    for i in range(count):
        handler, replies = request(server, host, name=name, port=port + i, mode=mode)
        assert handler is not None and handler.closed and replies == []
        assert all(opcode(p) == OPCODE_ERR for p in handler.sent)
        sent += len(handler.sent)
    return sent


@pytest.mark.parametrize("name, mode", [
    (b"missing.bin", b"octet"), (b"../../etc/passwd", b"octet"), (b"file.bin", b"netascii"),
], ids=["missing", "outside", "mode"])
def test_the_error_replies_of_the_sessions_are_limited(server, clock, name, mode):
    # a session ends at once and gives its place back; its ERROR replies share the buckets
    assert session_errors(server, "198.51.100.120", 100, name=name, mode=mode) == 20
    clock.now += 1.0
    assert session_errors(server, "198.51.100.120", 100, name=name, mode=mode, port=48000) == 10
    # another source is not held back by it
    assert session_errors(server, "198.51.100.121", 3, name=name, mode=mode) == 3
    assert tftp.SESSIONS.total == 0


def test_the_sessions_and_the_server_share_the_bucket_of_a_source(server, clock):
    assert session_errors(server, "198.51.100.130", 20) == 20
    # the source is at its limit: the server socket does not answer it either
    fill_source(server, "198.51.100.130")
    assert refused(server, "198.51.100.130", 5) == 0
    # and the other way round: refusals of the server use up the bucket of the sessions
    fill_source(server, "198.51.100.131")
    assert refused(server, "198.51.100.131", 20) == 20
    for s in [h for h in handlers() if h.remote.host == "198.51.100.131"]:
        s.close()
    assert session_errors(server, "198.51.100.131", 5, port=49000) == 0


def test_the_error_replies_of_the_sessions_of_all_sources_are_limited(server, clock):
    sent = sum(session_errors(server, "203.2.%d.%d" % (i // 250, i % 250), 1) for i in range(1000))
    assert sent == 200
