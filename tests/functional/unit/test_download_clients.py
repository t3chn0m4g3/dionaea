# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The TFTP and FTP download clients (tftp.py, ftp_download.py) without dionaea.core.

A download whose target the download target filter refused (the core hands
handle_error ConnectionRefusedByFilter, ECONFILTERED) is download_refused() with
its url; any other end before the file is complete is download_failed() with the
url and a reason, once per download. dionaea.core.download_refused() and
download_failed() (src/download_log.c) make the log lines: one info line each,
and at most one warning a minute that sums the failures up.
"""

import contextlib
import importlib.util
import os
import struct
import sys
import types
from pathlib import Path

import pytest

REFUSED = []
FAILED = []


class FakeTimeouts:
    idle = 0
    sustain = 0
    listen = 0


class FakeNode:
    def __init__(self, host="", port=0):
        self.host = host
        self.port = port
        self.hostname = host


class FakeConnection:
    def __init__(self, proto="tcp"):
        self.timeouts = FakeTimeouts()
        self.remote = FakeNode()
        self.local = FakeNode("192.0.2.1", 0)
        self.sent = []
        self.closed = False

    def bind(self, host, port, iface=""):
        self.local = FakeNode(host, port)
        return True

    def listen(self, *args):
        return True

    def connect(self, host, port, iface="", download=False):
        assert download, "a download client connects with download=True"
        self.remote = FakeNode(host, port)

    def send(self, data, local=None, remote=None):
        self.sent.append(data)

    def close(self):
        self.closed = True


class FakeConnectionError(Exception):
    def __init__(self, connection=None, error_id=None):  # noqa: B042 - as dionaea.exception.ConnectionError
        self.connection = connection
        self.error_id = error_id


class FakeRefusedByFilter(FakeConnectionError):
    def __str__(self):
        return "download target refused by the filter"


class FakeUnreachable(FakeConnectionError):
    def __str__(self):
        return "Could not connect to host(s): %s:%d" % (self.connection.remote.host, self.connection.remote.port)


class FakeConfig:
    def __init__(self, download_dir):
        self.download_dir = download_dir

    def config(self):
        return {"dionaea": {"download.dir": str(self.download_dir), "download.suffix": ".tmp"}}


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


CORE = types.ModuleType("dionaea.core")


@contextlib.contextmanager
def _stand_ins():
    names = ("dionaea", "dionaea.core", "dionaea.exception", "dionaea.mirror_policy", "dionaea.upload")
    saved = {name: sys.modules.get(name) for name in names}
    package = types.ModuleType("dionaea")
    # the real mirror_policy and upload (stdlib only) are found here, the rest are the stand-ins below
    package.__path__ = [str(_src_root())]
    package.ServiceLoader = type("ServiceLoader", (), {})
    package.IHandlerLoader = type("IHandlerLoader", (), {})
    CORE.connection = FakeConnection
    CORE.ihandler = type("ihandler", (), {"__init__": lambda self, path: None})
    CORE.incident = type("incident", (), {"__init__": lambda self, name: None, "report": lambda self: None})
    CORE.g_dionaea = None
    CORE.download_refused = lambda url: REFUSED.append(url)
    CORE.download_failed = lambda url, reason: FAILED.append((url, reason))
    exception = types.ModuleType("dionaea.exception")
    exception.ServiceConfigError = type("ServiceConfigError", (Exception,), {})
    exception.ConnectionRefusedByFilter = FakeRefusedByFilter
    sys.modules.update({"dionaea": package, "dionaea.core": CORE, "dionaea.exception": exception})
    try:
        yield
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, _src_root() / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


with _stand_ins():
    tftp = _load("tftp_download_under_test", "tftp.py")
    ftp_download = _load("ftp_download_under_test", "ftp_download.py")


@pytest.fixture(autouse=True)
def reports(tmp_path):
    REFUSED.clear()
    FAILED.clear()
    tftp.g_dionaea = FakeConfig(tmp_path)
    yield
    REFUSED.clear()
    FAILED.clear()


TFTP_URL = "tftp://203.0.113.5/x.exe"
FTP_URL = "ftp://203.0.113.5/x.exe"


def tftp_client():
    client = tftp.TftpClient()
    client.download(None, "203.0.113.5", 69, "x.exe", TFTP_URL)
    return client


def tftp_err(code):
    return struct.pack("!HH", 5, code) + b"no\x00"


# ---- TFTP

def test_tftp_refused_target_is_a_refusal_and_no_failure():
    client = tftp_client()
    client.handle_error(FakeRefusedByFilter(connection=client))
    assert REFUSED == [TFTP_URL]
    assert FAILED == []


def test_tftp_unreachable_target_is_a_failure_with_its_reason():
    client = tftp_client()
    client.handle_error(FakeUnreachable(connection=client))
    assert REFUSED == []
    assert FAILED == [(TFTP_URL, "Could not connect to host(s): 203.0.113.5:0")]


def test_tftp_error_of_the_server_is_a_failure_and_the_file_is_gone(tmp_path):
    client = tftp_client()
    client.handle_established()
    name = client.fileobj.name
    assert os.path.exists(name)
    client.handle_io_in(tftp_err(1))
    assert FAILED == [(TFTP_URL, "the server answered ERROR 1 (File not found)")]
    assert not os.path.exists(name)
    assert client.closed


@pytest.mark.parametrize("packet, reason", [
    (struct.pack("!HH", 4, 1), "the server sent an ACK"),
    (struct.pack("!H", 2) + b"x\x00octet\x00", "the server sent a write request"),
    (struct.pack("!H", 9) + b"x", "the server sent a packet that can not be read"),
    (struct.pack("!H", 5) + b"x", "the server sent a packet that can not be read"),
], ids=["ack", "wrq", "unknown", "short"])
def test_tftp_packets_a_server_does_not_send_are_a_failure(packet, reason):
    client = tftp_client()
    client.handle_established()
    name = client.fileobj.name
    assert client.handle_io_in(packet) == len(packet)
    assert FAILED == [(TFTP_URL, reason)]
    assert not os.path.exists(name)
    assert client.closed


def test_tftp_no_answer_is_one_failure():
    client = tftp_client()
    client.handle_established()
    for _ in range(11):
        assert client.handle_timeout_idle() is True
    assert FAILED == []
    assert client.handle_timeout_idle() is False
    assert FAILED == [(TFTP_URL, "no answer from the server")]


def test_tftp_a_transfer_that_takes_too_long_is_one_failure():
    client = tftp_client()
    client.handle_established()
    assert client.handle_timeout_sustain() is False
    client.handle_timeout_sustain()
    assert FAILED == [(TFTP_URL, "the transfer took too long")]


# ---- FTP

def ftp_client(tmp_path):
    client = ftp_download.FTPClient(download_dir=str(tmp_path), download_suffix=".tmp")
    client.download(None, "anonymous", "anonymous@", "203.0.113.5", 21, "/x.exe", "binary", FTP_URL)
    return client


def test_ftp_refused_target_is_a_refusal_and_no_failure(tmp_path):
    client = ftp_client(tmp_path)
    ctrl = client.ctrl
    ctrl.handle_error(FakeRefusedByFilter(connection=ctrl))
    # the core closes the connection afterwards
    ctrl.handle_disconnect()
    assert REFUSED == [FTP_URL]
    assert FAILED == []


def test_ftp_unreachable_target_is_one_failure(tmp_path):
    client = ftp_client(tmp_path)
    ctrl = client.ctrl
    ctrl.handle_error(FakeUnreachable(connection=ctrl))
    ctrl.handle_disconnect()
    assert REFUSED == []
    assert FAILED == [(FTP_URL, "Could not connect to host(s): 203.0.113.5:21")]


def test_ftp_server_that_closes_before_the_file_is_a_failure(tmp_path):
    client = ftp_client(tmp_path)
    ctrl = client.ctrl
    ctrl.handle_io_in(b"220 hello\r\n")
    assert ctrl.state == "USER"
    ctrl.handle_disconnect()
    assert FAILED == [(FTP_URL, "the server closed the control connection (state USER)")]


def test_ftp_no_data_connection_is_a_failure(tmp_path):
    client = ftp_client(tmp_path)
    data = ftp_download.FTPData(ftp=client)
    client.datalistener = data
    data.handle_timeout_listen()
    assert FAILED == [(FTP_URL, "no data connection from the server within 10 s")]


def test_ftp_data_that_stops_is_a_failure(tmp_path):
    client = ftp_client(tmp_path)
    data = ftp_download.FTPData(ftp=client)
    client.dataconn = data
    data.handle_established()
    name = data.fileobj.name
    data.handle_timeout_idle()
    assert FAILED == [(FTP_URL, "no data from the server for 30 s")]
    assert not os.path.exists(name)


def test_ftp_quit_after_the_file_is_no_failure(tmp_path):
    client = ftp_client(tmp_path)
    ctrl = client.ctrl
    ctrl.state = "QUIT"
    ctrl.handle_disconnect()
    assert FAILED == [] and REFUSED == []
