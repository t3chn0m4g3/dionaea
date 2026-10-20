# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import base64
import hashlib
import socket
import time
import uuid

import pytest

import helpers


def test_ftp_banner(dionaea_host):
    with socket.create_connection((dionaea_host, 21), timeout=10) as sock:
        banner = helpers.recv_line(sock)
    assert banner.startswith("220 "), banner


def test_json_log_exists(json_log):
    # dionaea opens the file at start
    assert json_log.exists(), "%s is missing" % json_log


def test_ftp_login_in_json_log(dionaea_host, wait_for_event):
    user = "smoke-%s" % uuid.uuid4().hex[:8]
    with socket.create_connection((dionaea_host, 21), timeout=10) as sock:
        helpers.recv_line(sock)
        sock.sendall(("USER %s\r\n" % user).encode())
        helpers.recv_line(sock)

    def is_ours(event):
        commands = event["ftp"]["commands"]
        users = commands["arguments"]
        return user in (users if isinstance(users, list) else [users])

    event = wait_for_event(is_ours)
    assert event["connection"]["protocol"] == "ftpd"


# TCP ports of the services of the T-Pot config (config/services)
SERVICE_PORTS = {
    "ftp": 21,
    "http": 81,
    "https": 443,
    "epmap": 135,
    "smb": 445,
    "mssql": 1433,
    "pptp": 1723,
    "mqtt": 1883,
    "mysql": 3306,
    "mongo": 27017,
}


@pytest.mark.parametrize("service", sorted(SERVICE_PORTS))
def test_service_listens(dionaea_host, service):
    helpers.wait_for_port(dionaea_host, SERVICE_PORTS[service], timeout=10)


def _post_multipart(host, body, boundary, timeout=10):
    """POST body as multipart/form-data to the HTTP service, return (response, seconds)."""
    request = (
        "POST /upload HTTP/1.1\r\nHost: %s\r\nContent-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\nConnection: close\r\n\r\n" % (host, boundary, len(body))
    ).encode() + body
    start = time.monotonic()
    with socket.create_connection((host, 81), timeout=timeout) as sock:
        sock.sendall(request)
        sock.settimeout(timeout)
        response = sock.recv(4096)
    return response, time.monotonic() - start


def _file_part(boundary, payload, headers=""):
    return (
        ("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"smoke.bin\"\r\n%s\r\n"
         % (boundary, headers)).encode()
        + payload
        + b"\r\n"
    )


def _wait_for_binary(binaries_dir, md5, timeout=15):
    deadline = time.monotonic() + timeout
    while not (binaries_dir / md5).exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    return binaries_dir / md5


def test_http_multipart_upload_is_stored(dionaea_host, binaries_dir):
    # the POST handler parses multipart/form-data (the cgi module is gone in Python 3.13)
    payload = ("MZ smoke upload %s" % uuid.uuid4().hex).encode()
    md5 = hashlib.md5(payload).hexdigest()
    boundary = "smoke" + uuid.uuid4().hex
    body = (
        ("--%s\r\nContent-Disposition: form-data; name=\"note\"\r\n\r\nhello\r\n" % boundary).encode()
        + _file_part(boundary, payload, "Content-Type: application/octet-stream\r\n")
        + ("--%s--\r\n" % boundary).encode()
    )
    response, _ = _post_multipart(dionaea_host, body, boundary)
    assert response.startswith(b"HTTP/1."), response[:100]
    assert _wait_for_binary(binaries_dir, md5).read_bytes() == payload


def test_http_multipart_part_is_stored_as_sent(dionaea_host, binaries_dir):
    # a Content-Transfer-Encoding is not decoded: the raw bytes of the part are stored
    raw = base64.b64encode(("MZ base64 part %s" % uuid.uuid4().hex).encode())
    md5 = hashlib.md5(raw).hexdigest()
    boundary = "smoke" + uuid.uuid4().hex
    body = _file_part(boundary, raw, "Content-Transfer-Encoding: base64\r\n") + ("--%s--\r\n" % boundary).encode()
    response, _ = _post_multipart(dionaea_host, body, boundary)
    assert response.startswith(b"HTTP/1."), response[:100]
    assert _wait_for_binary(binaries_dir, md5).read_bytes() == raw


@pytest.mark.parametrize("suffix", ["-NOT-A-DELIMITER", "--NOT-A-DELIMITER", "X", " \tX"])
def test_http_multipart_boundary_prefix_keeps_sample_hash(dionaea_host, binaries_dir, suffix):
    boundary = "smoke" + uuid.uuid4().hex
    payload = b"MZ before\r\n--" + boundary.encode() + suffix.encode() + b"\r\nafter\0\xff"
    md5 = hashlib.md5(payload).hexdigest()
    body = _file_part(boundary, payload) + ("--%s--\r\n" % boundary).encode()
    response, _ = _post_multipart(dionaea_host, body, boundary)
    assert response.startswith(b"HTTP/1."), response[:100]
    assert _wait_for_binary(binaries_dir, md5).read_bytes() == payload


def test_http_multipart_bare_lf_body_is_stored(dionaea_host, binaries_dir):
    # a body with bare LF line breaks: the service ends it at "--boundary--\n", the parser splits it
    payload = ("MZ bare lf %s\nline two\r\nthree" % uuid.uuid4().hex).encode()
    md5 = hashlib.md5(payload).hexdigest()
    boundary = "smoke" + uuid.uuid4().hex
    body = (("--%s\nContent-Disposition: form-data; name=\"file\"; filename=\"lf.bin\"\n\n" % boundary).encode()
            + payload + ("\n--%s--\n" % boundary).encode())
    response, seconds = _post_multipart(dionaea_host, body, boundary)
    assert response.startswith(b"HTTP/1."), response[:100]
    assert seconds < 3, "answered after %.1f s" % seconds
    assert _wait_for_binary(binaries_dir, md5).read_bytes() == payload


def test_http_multipart_nested_mixed_files_are_stored(dionaea_host, binaries_dir):
    # several files of one field in a multipart/mixed part
    token = uuid.uuid4().hex
    first, second = ("MZ nested one %s" % token).encode(), ("MZ nested two %s\r\n" % token).encode()
    boundary, inner = "smoke" + token, "inner" + token
    body = (
        ("--%s\r\nContent-Disposition: form-data; name=\"files\"\r\n"
         "Content-Type: multipart/mixed; boundary=%s\r\n\r\n" % (boundary, inner)).encode()
        + ("--%s\r\nContent-Disposition: file; filename=\"one.exe\"\r\n\r\n" % inner).encode() + first
        + ("\r\n--%s\r\nContent-Disposition: file; filename=\"two.exe\"\r\n\r\n" % inner).encode() + second
        + ("\r\n--%s--\r\n--%s--\r\n" % (inner, boundary)).encode()
    )
    response, _ = _post_multipart(dionaea_host, body, boundary)
    assert response.startswith(b"HTTP/1."), response[:100]
    for content in (first, second):
        assert _wait_for_binary(binaries_dir, hashlib.md5(content).hexdigest()).read_bytes() == content


@pytest.mark.parametrize("line_break", [b"\n", b"\r\n"], ids=["lf", "crlf-nested"])
def test_http_multipart_many_bare_lf_or_nested_parts_fail_fast(dionaea_host, line_break):
    if line_break == b"\n":
        body = b"--b\n\n" * 900000 + b"--b--\n"
    else:
        body = (b"--b\r\nContent-Type: multipart/mixed; boundary=i\r\n\r\n" + b"--i\r\n\r\n" * 900000
                + b"--i--\r\n--b--\r\n")
    response, seconds = _post_multipart(dionaea_host, body, "b", timeout=30)
    assert response.startswith(b"HTTP/1."), response[:100]
    assert seconds < 3, "answered after %.1f s" % seconds
    response, seconds = _post_multipart(dionaea_host, b"--b--\n", "b")
    assert response.startswith(b"HTTP/1."), response[:100]
    assert seconds < 1, "answered after %.1f s" % seconds


def _http_temp_files(binaries_dir):
    return helpers.temp_names(binaries_dir, ("http-",))


def test_http_multipart_over_max_request_size_is_refused_and_not_stored(dionaea_host, binaries_dir):
    # max_request_size is 32 MiB in T-Pot: a larger request gets 413, nothing of it is stored
    # (no truncated sample) and its temporary file is removed
    payload = b"MZ" + uuid.uuid4().bytes * (33 * 1024 * 1024 // 16)
    boundary = "smoke" + uuid.uuid4().hex
    body = _file_part(boundary, payload) + ("--%s--\r\n" % boundary).encode()
    request = (
        "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\n\r\n" % (boundary, len(body))
    ).encode() + body
    response = b""
    with socket.create_connection((dionaea_host, 81), timeout=30) as sock:
        try:
            sock.sendall(request)
        except OSError:
            # dionaea answers and closes before the rest is sent
            pass
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except OSError:
            pass
    assert response.startswith(b"HTTP/1.1 413") or response == b"", response[:100]
    time.sleep(2)
    for size in (len(payload), 32 * 1024 * 1024):
        assert not (binaries_dir / hashlib.md5(payload[:size]).hexdigest()).exists()
    assert _http_temp_files(binaries_dir) == []


def test_http_post_of_a_client_that_leaves_leaves_no_temporary_file(dionaea_host, binaries_dir):
    boundary = "smoke" + uuid.uuid4().hex
    body = _file_part(boundary, b"MZ" + b"q" * 100000) + ("--%s--\r\n" % boundary).encode()
    request = (
        "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Type: multipart/form-data; boundary=%s\r\n"
        "Content-Length: %d\r\n\r\n" % (boundary, len(body))
    ).encode() + body
    with socket.create_connection((dionaea_host, 81), timeout=10) as sock:
        sock.sendall(request[:len(request) // 2])
        time.sleep(0.5)
    deadline = time.monotonic() + 10
    while _http_temp_files(binaries_dir) and time.monotonic() < deadline:
        time.sleep(0.5)
    assert _http_temp_files(binaries_dir) == []


def test_http_multipart_many_parts_fail_fast(dionaea_host):
    # about 7 MB of empty parts must be refused without parsing them all
    body = b"--b\r\n\r\n" * 900000 + b"--b--\r\n"
    response, seconds = _post_multipart(dionaea_host, body, "b", timeout=30)
    assert response.startswith(b"HTTP/1."), response[:100]
    assert seconds < 3, "answered after %.1f s" % seconds
    # dionaea still answers
    response, seconds = _post_multipart(dionaea_host, b"--b--\r\n", "b")
    assert response.startswith(b"HTTP/1."), response[:100]
    assert seconds < 1, "answered after %.1f s" % seconds
    with socket.create_connection((dionaea_host, 21), timeout=10) as sock:
        assert helpers.recv_line(sock).startswith("220 ")
