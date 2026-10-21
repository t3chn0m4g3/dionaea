# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""dionaea-errors.log (errors.levels=warning,error,critical, the log file of T-Pot) is written per
line: a warning is in the file within a second while dionaea runs, not only at the stop.
dionaea.log (info and above) keeps the buffer of stdio.

The warning is one the operator needs: an SMB1 write beyond max_upload_size, so the upload is
dropped. A message of a client that dionaea only refuses (an SMB message it can not read, a
POST with more parts than max_num_fields) is info, no line of the errors log."""

import socket
import time

import pytest
from impacket.smbconnection import SessionError

from test_smoke import _post_multipart
from test_upload import MAX_UPLOAD_SIZE, _smb1

OFFSET = MAX_UPLOAD_SIZE + 4096
WARNING = "upload dropped: write of 100 bytes at offset %d" % OFFSET
CLIENT_NOISE = ("Invalid SMB request", "Ignoring the POST data")


def text_of(path):
    try:
        return path.read_text(errors="replace")
    except FileNotFoundError:
        return ""


def wait_for_more(log, text, before, deadline):
    while text_of(log).count(text) <= before:
        assert time.monotonic() < deadline, "no new '%s' in %s in time" % (text, log)
        time.sleep(0.05)


def drop_an_upload(host, log, before, seconds):
    """One SMB1 write beyond max_upload_size: dionaea drops the upload with one warning, which
    is in log within seconds of the write."""
    conn = _smb1(host)
    try:
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, "\\errors-log-live.bin")
        deadline = time.monotonic() + seconds
        with pytest.raises(SessionError):
            conn.writeFile(tid, fid, b"X" * 100, OFFSET)
        wait_for_more(log, WARNING, before, deadline)
        conn.closeFile(tid, fid)
    finally:
        conn.close()


def test_a_warning_is_in_the_errors_log_within_a_second(dionaea_host, data_dir):
    log = data_dir / "dionaea-errors.log"
    drop_an_upload(dionaea_host, log, text_of(log).count(WARNING), 1.0)


def test_a_message_a_client_sends_is_no_line_of_the_errors_log(dionaea_host, data_dir):
    log = data_dir / "dionaea-errors.log"
    before = text_of(log)
    # an SMB1 message shorter than its header: dionaea answers nothing, the connection stays open
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        sock.sendall(b"\x00\x00\x00\x08\xffSMB\x72\x00\x00\x00")
        time.sleep(0.2)
    # a POST of 200 empty parts, more than max_num_fields (100): the POST data is ignored
    response, _ = _post_multipart(dionaea_host, b"--b\r\n\r\n" * 200 + b"--b--\r\n", "b")
    assert response.startswith(b"HTTP/1."), response[:100]
    # a warning afterwards: the file is written per line, so lines of the two requests
    # before it would be in it by then
    drop_an_upload(dionaea_host, log, before.count(WARNING), 10.0)
    after = text_of(log)
    for text in CLIENT_NOISE:
        assert after.count(text) == before.count(text), "dionaea-errors.log has a new line of '%s'" % text
