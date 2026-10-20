# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""dionaea-errors.log (errors.levels=warning,error, the log file of T-Pot) is written per
line: a warning is in the file within a second while dionaea runs, not only at the stop.
dionaea.log (info and above) keeps the buffer of stdio."""

import socket
import time

WARNING = "Invalid SMB request: invalid SMB1 header"


def count(path, text):
    try:
        return path.read_text(errors="replace").count(text)
    except FileNotFoundError:
        return 0


def test_a_warning_is_in_the_errors_log_within_a_second(dionaea_host, data_dir):
    log = data_dir / "dionaea-errors.log"
    before = count(log, WARNING)
    # an SMB1 message shorter than its header: one warning, the connection stays open
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        sock.sendall(b"\x00\x00\x00\x08\xffSMB\x72\x00\x00\x00")
        deadline = time.monotonic() + 1.0
        while count(log, WARNING) <= before:
            assert time.monotonic() < deadline, "no new '%s' in %s within 1 s" % (WARNING, log)
            time.sleep(0.05)
