# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""http.py: where the body of a multipart POST ends, without dionaea.core.

The HTTP service took a multipart body as complete at the first ``--boundary--\\r\\n``
anywhere in the data. So a bare-LF body (``--boundary--\\n``) and a closing
delimiter without a line break never ended the request (it waited until the idle
timeout and nothing was stored), a quoted boundary (``boundary="..."``) was never
found, and ``--boundary--\\r\\n`` inside a file ended the request in the middle of
the file. Now the closing delimiter is a whole line (CRLF or LF), the boundary
comes from the Content-Type as the parser reads it, and the request ends at the
Content-Length at the latest.

handle_POST is replaced: the test looks at the body handed to it and at what
handle_io_in takes; the parsing of that body is test_http_multipart.py.
"""

import contextlib
import importlib.util
import io
import os
import sys
import types
from pathlib import Path

import pytest


class FakeSpeed:
    limit = 0


class FakeOut:
    speed = FakeSpeed()


class FakeNode:
    def __init__(self, host="", port=0):
        self.host = host
        self.port = port


class FakeConnection:
    def __init__(self, proto="tcp"):
        self._out = FakeOut()
        self.remote = FakeNode("198.51.100.7", 40000)
        self.local = FakeNode("192.0.2.1", 80)
        self.sent = []
        self.closed = False

    def send(self, data):
        self.sent.append(bytes(data))

    def close(self):
        self.closed = True


class FakeIncident:
    def __init__(self, origin):
        self.origin = origin

    def report(self):
        pass


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins():
    names = ("dionaea", "dionaea.core", "dionaea.exception", "dionaea.upload", "dionaea.util")
    saved = {name: sys.modules.get(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(_src_root())]
    package.ServiceLoader = type("ServiceLoader", (), {})
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    core.incident = FakeIncident
    core.g_dionaea = None
    exception = types.ModuleType("dionaea.exception")
    exception.ServiceConfigError = type("ServiceConfigError", (Exception,), {})
    util = types.ModuleType("dionaea.util")
    util.detect_shellshock = lambda con, value: None
    sys.modules.update({"dionaea": package, "dionaea.core": core, "dionaea.exception": exception,
                        "dionaea.util": util})
    try:
        yield
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


with _stand_ins():
    spec = importlib.util.spec_from_file_location("http_under_test", _src_root() / "http.py")
    http = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(http)


@pytest.fixture
def con(tmp_path):
    c = http.httpd()
    c.download_dir = str(tmp_path)
    c.posts = []

    def handle_post():
        c.fp_tmp.flush()
        c.posts.append(Path(c.fp_tmp.name).read_bytes())
        c.state = "done"

    c.handle_POST = handle_post
    return c


def request(body, boundary="b0und", length=None, content_type=None):
    content_type = content_type or "multipart/form-data; boundary=%s" % boundary
    length = len(body) if length is None else length
    return (("POST /upload HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n"
             % (content_type, length)).encode() + body)


def feed(con, reads):
    """The binding: bytes handle_io_in leaves stay in front of the next read; returns the rest."""
    pending = b""
    for data in reads:
        pending += data
        if con.state == "done":
            break
        taken = con.handle_io_in(pending)
        assert 0 <= taken <= len(pending)
        pending = pending[taken:]
    return pending


def chunks(data, size):
    return [data[i:i + size] for i in range(0, len(data), size)]


def files(body, boundary="b0und"):
    return list(http.iter_uploaded_files(io.BytesIO(body), "multipart/form-data; boundary=%s" % boundary, 100))


def crlf_body(payload, boundary=b"b0und"):
    return (b"--" + boundary + b'\r\nContent-Disposition: form-data; name="f"; filename="a.bin"\r\n\r\n'
            + payload + b"\r\n--" + boundary + b"--\r\n")


def lf_body(payload, boundary=b"b0und"):
    return (b"--" + boundary + b'\nContent-Disposition: form-data; name="f"; filename="a.bin"\n\n'
            + payload + b"\n--" + boundary + b"--\n")


@pytest.mark.parametrize("size", [100000, 7, 1], ids=["one-read", "7-bytes", "1-byte"])
@pytest.mark.parametrize("make", [crlf_body, lf_body], ids=["crlf", "lf"])
def test_the_body_ends_at_the_closing_delimiter(con, make, size):
    payload = b"MZ\x90\x00 data\r\nmore\nend"
    body = make(payload)
    rest = feed(con, chunks(request(body), size))
    assert rest == b""
    assert len(con.posts) == 1
    assert files(con.posts[0]) == [("f", "a.bin", payload)]


def test_a_closing_delimiter_inside_a_line_of_the_file_does_not_end_it(con):
    payload = b"before xx--b0und--\r\nafter"
    rest = feed(con, chunks(request(crlf_body(payload)), 5))
    assert rest == b""
    assert len(con.posts) == 1
    assert files(con.posts[0]) == [("f", "a.bin", payload)]


def test_a_quoted_boundary(con):
    payload = b"quoted"
    body = crlf_body(payload, b"q-b")
    rest = feed(con, [request(body, content_type='multipart/form-data; boundary="q-b"; charset=utf-8')])
    assert rest == b""
    assert len(con.posts) == 1
    assert files(con.posts[0], "q-b") == [("f", "a.bin", payload)]


def test_a_closing_delimiter_without_line_break_ends_at_the_content_length(con):
    body = crlf_body(b"no eol")[:-2]
    rest = feed(con, chunks(request(body), 9))
    assert rest == b""
    assert len(con.posts) == 1
    assert files(con.posts[0]) == [("f", "a.bin", b"no eol")]


def test_a_closing_delimiter_with_padding_ends_at_the_content_length(con):
    body = crlf_body(b"padded")[:-2] + b" \t\r\n"
    rest = feed(con, [request(body)])
    assert rest == b""
    assert len(con.posts) == 1
    assert files(con.posts[0]) == [("f", "a.bin", b"padded")]


def test_a_body_of_only_the_closing_delimiter(con):
    body = b"--b0und--\r\n"
    assert feed(con, [request(body)]) == b""
    assert con.posts == [body]


def test_the_closing_delimiter_ends_the_body_before_a_too_large_content_length(con):
    body = lf_body(b"short")
    rest = feed(con, [request(body, length=len(body) + 1000)])
    assert rest == b""
    assert len(con.posts) == 1
    assert files(con.posts[0]) == [("f", "a.bin", b"short")]


# --- the temporary file of a request that is never complete ---------------------------


def incoming(tmp_path):
    folder = tmp_path / ".incoming"
    return sorted(p.name for p in folder.iterdir()) if folder.exists() else []


@pytest.mark.parametrize("multipart", [True, False], ids=["multipart", "content-length"])
def test_the_temporary_file_of_a_request_whose_client_leaves_is_removed(con, tmp_path, multipart):
    if multipart:
        data = request(crlf_body(b"x" * 5000))[:-200]
    else:
        body = b"y" * 5000
        data = request(body, content_type="application/octet-stream")[:-200]
    feed(con, [data])
    assert con.posts == []
    assert len(incoming(tmp_path)) == 1
    con.handle_disconnect()
    assert incoming(tmp_path) == []
    assert con.fp_tmp is None


def test_the_temporary_file_of_a_request_over_max_request_size_is_removed(tmp_path, monkeypatch):
    c = http.httpd()
    c.download_dir = str(tmp_path)
    c.max_request_size = 10000
    errors = []
    monkeypatch.setattr(c, "send_error", lambda code, *a: errors.append(code))
    body = crlf_body(b"z" * 50000)
    feed(c, chunks(request(body), 4096))
    assert errors and errors[0] == 413
    assert incoming(tmp_path) == []
    c.handle_disconnect()
    assert incoming(tmp_path) == []


def test_a_complete_post_leaves_no_temporary_file(tmp_path, monkeypatch):
    c = http.httpd()
    c.download_dir = str(tmp_path)
    monkeypatch.setattr(c, "send_head", lambda: None)
    feed(c, [request(crlf_body(b"done"))])
    assert incoming(tmp_path) == []
    assert c.fp_tmp is None


def test_a_multipart_body_longer_than_its_content_length_ends_there(con):
    # the body ends at the Content-Length: what follows is not part of it (and not taken
    # as its data), the file in it is stored as far as it came
    payload = b"MZ" + b"w" * 1000
    body = crlf_body(payload)
    short = len(body) - 500
    data = request(body, length=short)
    rest = feed(con, chunks(data, 333))
    assert len(con.posts) == 1
    assert con.posts[0] == body[:short]
    assert rest == data[len(data) - 500:]
    assert files(con.posts[0]) == [("f", "a.bin", body[:short][body.index(b"MZ"):])]
