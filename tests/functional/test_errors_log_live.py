# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""dionaea-errors.log (errors.levels=warning,error,critical, the log file of T-Pot) is written per
line: a warning is in the file within a second while dionaea runs, not only at the stop.
dionaea.log (info and above) keeps the buffer of stdio.

The warning is one the operator needs: SMB1 writes beyond max_upload_size, so the uploads are
dropped. The line of each upload is info; one warning a minute sums them up for all
connections: the first upload after a quiet minute at once, the ones after it when that minute
ends (a timer of the event loop). A message of a client that dionaea only refuses (an SMB
message it can not read, a POST with more parts than max_num_fields) is info, no line of the
errors log."""

import re
import socket
import time

import pytest
from impacket.smbconnection import SessionError

from test_smoke import _post_multipart
from test_upload import MAX_UPLOAD_SIZE, _smb1

OFFSET = MAX_UPLOAD_SIZE + 4096
# the summary of the dropped uploads of SMB ("[date] SMB[ file:line]-warning: uploads dropped: "),
# with the upload of this test as the last one
SUMMARY = "uploads dropped: "
SMB_SUMMARY = re.compile(r"^\[[^]]*\] SMB( \S+)?-warning: " + SUMMARY)
WARNING = "the last: write of 100 bytes at offset %d" % OFFSET
CLIENT_NOISE = ("Invalid SMB request", "Ignoring the POST data")
# the timer of a summary ends the minute of the warning before it
MINUTE = 60.0


def text_of(path):
    try:
        return path.read_text(errors="replace")
    except FileNotFoundError:
        return ""


def summaries(log):
    """Every summary warning of the dropped SMB uploads in log, whatever upload is its last one."""
    return [line for line in text_of(log).splitlines() if SMB_SUMMARY.search(line)]


def wait_for_more(log, before, deadline):
    """A summary after the first before ones that names the upload of this test as the last one."""
    while not any(WARNING in line for line in summaries(log)[before:]):
        assert time.monotonic() < deadline, "no new '%s ... %s' in %s in time" % (SUMMARY, WARNING, log)
        time.sleep(0.05)


def drop_an_upload(host, log, before, seconds):
    """One SMB1 write beyond max_upload_size: dionaea drops the upload with an info line, the
    summary warning names it as the last one; it is in log within seconds."""
    conn = _smb1(host)
    try:
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, "\\errors-log-live.bin")
        deadline = time.monotonic() + seconds
        with pytest.raises(SessionError):
            conn.writeFile(tid, fid, b"X" * 100, OFFSET)
        wait_for_more(log, before, deadline)
        conn.closeFile(tid, fid)
    finally:
        conn.close()


def test_a_warning_is_in_the_errors_log_within_a_second(dionaea_host, data_dir):
    log = data_dir / "dionaea-errors.log"
    before = summaries(log)
    # the first drop after a quiet minute warns at once; after a summary of any drop before it
    # (another test) within the minute, the warning comes when that minute ends
    drop_an_upload(dionaea_host, log, len(before), 1.0 if not before else MINUTE + 2.0)


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
    # before it would be in it by then. The drop of the test before is in the same minute: this
    # one is in the summary at the end of that minute (the timer of the event loop)
    drop_an_upload(dionaea_host, log, len(summaries(log)), MINUTE + 2.0)
    after = text_of(log)
    for text in CLIENT_NOISE:
        assert after.count(text) == before.count(text), "dionaea-errors.log has a new line of '%s'" % text
