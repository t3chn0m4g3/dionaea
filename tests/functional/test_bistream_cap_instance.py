# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The limits of the streamdumper (``config.max_files``, ``config.max_size``), against a second dionaea.

host-checks/42-bistream-cap.sh starts that dionaea three times with a limit in
``[processor.streamdumper]`` of dionaea.cfg and runs this file against it
(DIONAEA_BISTREAM_CAP=files: ``config.max_files=40``; =size and =long:
``config.max_size=0.25``). host-checks/43-limits-env.sh runs the bursts as well, with the
limits from the environment (DIONAEA_BISTREAM_CAP_MAX_SIZE: the max_size in bytes). The
main run of pytest does not collect it (conftest.py).

A burst of HTTP connections from 32 threads: every one is answered, the dumps in
bistreams/ stay within the limit. With max_files the folder is emptied from outside
afterwards and the next count (every 60 s) notices it. With max_size (long) one FTP
connection goes on sending past the limit: its dump stops at the limit, stays a valid
dump, and the connection is still answered. The numbers go to
``$DIONAEA_CAP_OUT/bistream-cap-<mode>`` for the report of the host check.
"""

import ast
import concurrent.futures
import os
import shutil
import socket
import time

import pytest

KIB = 1024
MIB = 1024 * 1024
THREADS = 32
MODE = os.environ.get("DIONAEA_BISTREAM_CAP", "")
MAX_FILES = 40
# config.max_size=0.25 of 42-bistream-cap.sh; 43-limits-env.sh sets 1 MiB by DIONAEA_STREAMDUMPER_MAX_SIZE
MAX_SIZE = int(os.environ.get("DIONAEA_BISTREAM_CAP_MAX_SIZE", MIB // 4))
# the HTTP and FTP services of the T-Pot config
HTTP_PORT = 81
FTP_PORT = 21


def _bistreams(data_dir):
    return data_dir / "bistreams"


def _usage(data_dir):
    files = 0
    size = 0
    for root, _dirs, names in os.walk(_bistreams(data_dir)):
        for name in names:
            try:
                st = os.lstat(os.path.join(root, name))
            except FileNotFoundError:
                continue
            files += 1
            size += st.st_size
    return files, size


def _dumps(data_dir):
    return sorted(
        os.path.join(root, name) for root, _dirs, names in os.walk(_bistreams(data_dir)) for name in names
    )


def _parse_dump(path):
    """A dump is Python source: ``stream = [('in', b'...'), ('out', b'...'), ...]``."""
    with open(path, "rb") as fp:
        text = fp.read().decode("ascii")
    name, sep, value = text.partition(" = ")
    assert (name, sep) == ("stream", " = "), text[:40]
    stream = ast.literal_eval(value)
    assert isinstance(stream, list) and stream, text[:40]
    for direction, data in stream:
        assert direction in ("in", "out") and isinstance(data, bytes)
    return stream


def _request(host, pad, number):
    """One HTTP request (a single segment), the answer up to its end."""
    request = (
        "GET /bistream-cap-%d HTTP/1.0\r\nHost: dionaea\r\nX-Pad: %s\r\n\r\n" % (number, "A" * pad)
    ).encode()
    with socket.create_connection((host, HTTP_PORT), timeout=10) as sock:
        sock.sendall(request)
        answer = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            answer += chunk
    return answer


def _burst(host, count, pad):
    with concurrent.futures.ThreadPoolExecutor(THREADS) as pool:
        return list(pool.map(lambda n: _request(host, pad, n), range(count)))


def _settled(data_dir, timeout=10.0):
    """The usage once it stopped changing (the last dumps are closed after their connections)."""
    deadline = time.monotonic() + timeout
    last = _usage(data_dir)
    while time.monotonic() < deadline:
        time.sleep(1.0)
        now = _usage(data_dir)
        if now == last:
            return now
        last = now
    return last


def _record(name, text):
    out = os.environ.get("DIONAEA_CAP_OUT")
    if out:
        with open(os.path.join(out, name), "a") as fp:
            fp.write(text + "\n")


@pytest.mark.skipif(MODE != "files", reason="DIONAEA_BISTREAM_CAP=files")
def test_a_burst_stops_at_max_files(dionaea_host, data_dir):
    answers = _burst(dionaea_host, 200, 100)
    # the connections without a dump are answered as the others
    assert all(a.startswith(b"HTTP/1.") for a in answers), [a[:40] for a in answers if not a.startswith(b"HTTP/1.")]
    files, size = _settled(data_dir)
    _record("bistream-cap-files", "burst 200 connections: %d files, %d bytes (max_files %d)" % (files, size, MAX_FILES))
    assert files == MAX_FILES


@pytest.mark.skipif(MODE != "files", reason="DIONAEA_BISTREAM_CAP=files")
def test_an_emptied_folder_is_noticed(dionaea_host, data_dir):
    base = _bistreams(data_dir)
    for entry in base.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()
    assert _usage(data_dir) == (0, 0)
    start = time.monotonic()
    # the next count of the folder takes at most 60 s
    while _usage(data_dir)[0] == 0:
        assert time.monotonic() - start < 75, "no dump 75 s after the folder was emptied"
        assert _request(dionaea_host, 10, 9999).startswith(b"HTTP/1.")
        time.sleep(2.0)
    _record("bistream-cap-files", "emptied folder noticed after %.1f s" % (time.monotonic() - start))


@pytest.mark.skipif(MODE != "size", reason="DIONAEA_BISTREAM_CAP=size")
def test_a_burst_stays_within_max_size(dionaea_host, data_dir):
    # 400 connections reach 0.25 MiB, more for a larger limit
    count = 400 * max(1, MAX_SIZE // (MIB // 4))
    pad = 1200
    answers = _burst(dionaea_host, count, pad)
    assert all(a.startswith(b"HTTP/1.") for a in answers), [a[:40] for a in answers if not a.startswith(b"HTTP/1.")]
    files, size = _settled(data_dir)
    # a dump is admitted if its request fits; then its answer may follow (escaped:
    # up to 4 bytes per byte), only by the dumps that were open at the limit
    # an open dump counts with what it will hold: a dump whose answer does not fit
    # stops before it, closed in the format of a dump
    stopped = 0
    for path in _dumps(data_dir):
        stream = _parse_dump(path)
        if [d for d, _ in stream] == ["in"]:
            stopped += 1
    _record(
        "bistream-cap-size",
        "burst %d connections of %d bytes: %d files, %d bytes (max_size %d bytes), %d dump(s) stopped before the answer"
        % (count, pad, files, size, MAX_SIZE, stopped),
    )
    assert files < count, "no connection was refused"
    assert size <= MAX_SIZE
    # the limit was reached: no room left for another request
    assert size > MAX_SIZE - 2 * (pad + 200)


def _ftp_reply(sock, buf):
    """One reply line of the FTP server, and what came after it."""
    while b"\r\n" not in buf:
        chunk = sock.recv(65536)
        assert chunk, "the FTP connection was closed"
        buf += chunk
    line, _, rest = buf.partition(b"\r\n")
    return line, rest


@pytest.mark.skipif(MODE != "long", reason="DIONAEA_BISTREAM_CAP=long")
def test_a_long_connection_stops_at_max_size(dionaea_host, data_dir):
    # the dump of the probe of port 21 (conftest.py) may be there: a small one
    before = _settled(data_dir, timeout=3.0)
    assert before[1] < 1000, before
    line_size = 1000
    lines = 400  # about 1.5 times max_size
    line = b"NOOP " + b"A" * (line_size - 7) + b"\r\n"
    replies = 0
    with socket.create_connection((dionaea_host, FTP_PORT), timeout=10) as sock:
        port = sock.getsockname()[1]
        banner, buf = _ftp_reply(sock, b"")
        assert banner.startswith(b"220"), banner
        for _ in range(lines):
            sock.sendall(line)
            reply, buf = _ftp_reply(sock, buf)
            assert reply[:3].isdigit(), reply[:40]
            replies += 1
        # the connection is still served after its dump stopped (530: not logged in)
        sock.sendall(b"QUIT\r\n")
        reply, buf = _ftp_reply(sock, buf)
        assert reply.startswith((b"221", b"530")), reply
    # a new connection: no room left for its dump (less than one line), it is answered
    assert _request(dionaea_host, 2 * line_size, 1).startswith(b"HTTP/1.")
    files, size = _settled(data_dir)
    dumps = [path for path in _dumps(data_dir) if "-%d-" % port in os.path.basename(path)]
    _record(
        "bistream-cap-long",
        "one FTP connection of %d lines of %d bytes (%d replies): %d file(s), %d bytes (max_size %d bytes, %d before)"
        % (lines, line_size, replies, files, size, MAX_SIZE, before[1]),
    )
    assert replies == lines
    # its dump, and the new connection got none
    assert len(dumps) == 1, _dumps(data_dir)
    assert files == before[0] + 1, _dumps(data_dir)
    # within the limit, close to it
    assert size <= MAX_SIZE
    assert size > MAX_SIZE - 4 * line_size
    # a valid dump: banner, lines and replies up to the stop, no part of a chunk
    stream = _parse_dump(dumps[0])
    assert stream[0][0] == "out" and stream[0][1].startswith(b"220")
    sent = b"".join(data for direction, data in stream if direction == "in")
    assert 0 < len(sent) < lines * line_size
    assert (line * lines).startswith(sent)
    _record("bistream-cap-long", "the dump parses: %d chunk(s), %d of %d bytes sent"
            % (len(stream), len(sent), lines * line_size))
