# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""FTP commands that would change the file system, with a read-only root (as T-Pot mounts it).

run.sh mounts roots/{ftp,tftp,www,upnp} of dionaea read-only (``:ro``). ``MKD`` and ``RMD`` used to
raise OSError (EROFS) in the handler: a Traceback in the log, no reply, and the connection was gone.
Now every command that touches the root answers an error of the reply table (550) and the session
goes on. Commands dionaea does not implement (DELE, RNFR / RNTO, STOU, APPE, SITE) change nothing
and are answered 502 as before. The command is still logged with its name and arguments.
"""

import socket

import pytest

from test_ftp import _command, _login

CHANGING = [
    "MKD newdir",
    "MKD a/b/c",
    "MKD /newdir",
    "RMD /",
    "RMD .",
    "RMD ..",
]
NOT_IMPLEMENTED = [
    "DELE functional-list.txt",
    "RNFR functional-list.txt",
    "RNTO renamed.txt",
    "STOU",
    "APPE functional-list.txt",
    "SITE CHMOD 755 functional-list.txt",
]


@pytest.mark.parametrize("command", CHANGING)
def test_changing_commands_get_550_and_the_session_goes_on(dionaea_host, command):
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        reply = _command(ctrl, command)
        assert reply.startswith("550"), reply
        assert _command(ctrl, "PWD").startswith("257")
        assert _command(ctrl, "TYPE I").startswith("200")
        _command(ctrl, "QUIT")


@pytest.mark.parametrize("command", NOT_IMPLEMENTED)
def test_unimplemented_commands_are_answered_and_the_session_goes_on(dionaea_host, command):
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        reply = _command(ctrl, command)
        assert reply[:3] in ("502", "550"), reply
        assert _command(ctrl, "PWD").startswith("257")
        _command(ctrl, "QUIT")


def test_all_of_them_in_one_session(dionaea_host):
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        for command in CHANGING + NOT_IMPLEMENTED:
            reply = _command(ctrl, command)
            assert reply[:3] in ("550", "502"), (command, reply)
        assert _command(ctrl, "PWD").startswith("257")
        _command(ctrl, "QUIT")


def test_the_commands_are_still_logged(dionaea_host, wait_for_event):
    marker = "logged-dir-%d" % id(object())
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        port = ctrl.getsockname()[1]
        _login(ctrl)
        assert _command(ctrl, "MKD " + marker).startswith("550")
        assert _command(ctrl, "RMD /").startswith("550")
        _command(ctrl, "QUIT")
    event = wait_for_event(lambda e: e.get("src_port") == port and "ftp" in e and "commands" in e["ftp"], timeout=40)
    commands = event["ftp"]["commands"]
    assert "MKD" in commands["command"] and "RMD" in commands["command"]
    assert marker in " ".join(str(a) for a in commands["arguments"])
