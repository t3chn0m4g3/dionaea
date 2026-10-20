# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""FTP service: data connections in active (PORT) and passive (PASV) mode.

ftp.FTPDataConnect (the connection dionaea opens to the client's data port) is
a connection subclass; it used to fail with LoaderError (arguments of
__init__ without defaults). A transfer command without a data connection ended
in an AttributeError (self.dtp is None), and after the first passive transfer
the control connection was gone. run.sh puts functional-list.txt into roots/ftp.
"""

import socket
import time
import uuid

import pytest

import helpers


def _read_reply(sock, timeout=10.0):
    """Read one reply (multi-line replies included), return it as text."""
    deadline = time.monotonic() + timeout
    lines = []
    while True:
        line = helpers.recv_line(sock, timeout=max(deadline - time.monotonic(), 0.1))
        assert line, "connection closed, replies so far: %r" % lines
        line = line.rstrip("\r\n")
        lines.append(line)
        if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
            return "\n".join(lines)


def _command(sock, line):
    sock.sendall((line + "\r\n").encode())
    return _read_reply(sock)


def _login(sock):
    assert _read_reply(sock).startswith("220")
    assert _command(sock, "USER anonymous").startswith("331")
    assert _command(sock, "PASS test@example.org").startswith("230")


def test_ftp_active_mode_list(dionaea_host):
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        my_ip = ctrl.getsockname()[0]
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((my_ip, 0))
            listener.listen(1)
            listener.settimeout(10)
            port = listener.getsockname()[1]
            reply = _command(ctrl, "PORT %s,%d,%d" % (my_ip.replace(".", ","), port >> 8, port & 255))
            # dionaea connects to the client and answers 200 once connected
            assert reply.startswith("200"), reply
            data_sock, _ = listener.accept()
            with data_sock:
                ctrl.sendall(b"LIST\r\n")
                data = b""
                data_sock.settimeout(10)
                while True:
                    chunk = data_sock.recv(4096)
                    if not chunk:
                        break
                    data += chunk
            first = _read_reply(ctrl)
            assert first.startswith("150"), first
            last = _read_reply(ctrl)
            assert last.startswith("226"), last
        assert b"functional-list.txt" in data, data
        _command(ctrl, "QUIT")


def _passive_data_socket(ctrl, host):
    reply = _command(ctrl, "PASV")
    assert reply.startswith("227"), reply
    numbers = reply[reply.index("(") + 1:reply.index(")")].split(",")
    port = int(numbers[4]) * 256 + int(numbers[5])
    return socket.create_connection((host, port), timeout=10)


def _read_all(sock):
    sock.settimeout(10)
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk


@pytest.mark.parametrize("command", ["LIST", "RETR functional-list.txt", "STOR no-data-connection.bin"])
def test_ftp_transfer_without_data_connection_is_answered(dionaea_host, command):
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        reply = _command(ctrl, command)
        assert reply.startswith("425"), reply
        # the control connection still works
        assert _command(ctrl, "PWD").startswith("257")


def test_ftp_passive_mode_transfers_on_one_connection(dionaea_host):
    """LIST, RETR and STOR one after the other, each over a new passive data connection."""
    name = "pasv-%s.bin" % uuid.uuid4().hex[:8]
    upload = b"uploaded by the functional test\n"
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)

        with _passive_data_socket(ctrl, dionaea_host) as data_sock:
            first = _command(ctrl, "LIST")
            assert first.startswith("150"), first
            listing = _read_all(data_sock)
        assert b"functional-list.txt" in listing, listing
        assert _read_reply(ctrl).startswith("226")

        with _passive_data_socket(ctrl, dionaea_host) as data_sock:
            first = _command(ctrl, "RETR functional-list.txt")
            assert first.startswith("150"), first
            content = _read_all(data_sock)
        assert content == b"ftp functional test file\n"
        assert _read_reply(ctrl).startswith("226")

        with _passive_data_socket(ctrl, dionaea_host) as data_sock:
            first = _command(ctrl, "STOR " + name)
            assert first.startswith("150"), first
            data_sock.sendall(upload)
        assert _read_reply(ctrl).startswith("226")

        # an upload is captured (test_upload.py), it is not kept in the FTP root
        assert _command(ctrl, "SIZE " + name).startswith("550")
        _command(ctrl, "QUIT")

    # the passive listener of a transfer is closed while dionaea accepts on it;
    # the service must still answer afterwards
    time.sleep(2.5)
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        assert _read_reply(ctrl).startswith("220")


@pytest.mark.parametrize("command", [
    "PORT", "PORT x", "PORT 1,2,3", "PORT 1,2,3,4,5,300", "CWD", "SIZE", "RETR", "STOR",
])
def test_ftp_malformed_command_gets_501_and_keeps_the_session(dionaea_host, command):
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        reply = _command(ctrl, command)
        assert reply.startswith("501"), reply
        assert _command(ctrl, "PWD").startswith("257")


@pytest.mark.parametrize("step", ["USER", "PASS"])
def test_ftp_login_without_argument_gets_501_and_keeps_the_session(dionaea_host, step):
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        assert _read_reply(ctrl).startswith("220")
        if step == "PASS":
            assert _command(ctrl, "USER reference").startswith("331")
        assert _command(ctrl, step).startswith("501")
        # the same step with an argument still works
        if step == "USER":
            assert _command(ctrl, "USER reference").startswith("331")
            assert _command(ctrl, "PASS secret").startswith("230")
        else:
            assert _command(ctrl, "PASS secret").startswith("230")


def test_ftp_malformed_port_is_still_logged(dionaea_host, wait_for_event):
    token = uuid.uuid4().hex[:10]
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        assert _command(ctrl, "PORT x-" + token).startswith("501")
        _command(ctrl, "QUIT")

    def ours(event):
        commands = event["ftp"]["commands"]
        arguments = commands["arguments"]
        return ("x-" + token) in (arguments if isinstance(arguments, list) else [arguments])

    event = wait_for_event(ours)
    assert "PORT" in event["ftp"]["commands"]["command"]


def test_ftp_bounce_port_gets_an_error_and_keeps_the_session(dionaea_host, wait_for_event):
    """A PORT to an address other than the client's (an FTP bounce scan) gets 500, the session goes on.

    The command is logged.
    """
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        port = 1024 + int(uuid.uuid4().hex[:4], 16) % 60000
        argument = "203,0,113,9,%d,%d" % (port >> 8, port & 255)
        assert _command(ctrl, "PORT " + argument) == "500 Illegal PORT command."
        assert _command(ctrl, "PWD").startswith("257")
        _command(ctrl, "QUIT")

    def ours(event):
        commands = event["ftp"]["commands"]
        arguments = commands["arguments"]
        return argument in (arguments if isinstance(arguments, list) else [arguments])

    event = wait_for_event(ours)
    assert "PORT" in event["ftp"]["commands"]["command"]


def test_ftp_port_to_a_closed_port_gets_425_and_no_stale_data_connection(dionaea_host):
    """dionaea cannot connect to the PORT of the client: 425, and RETR / LIST afterwards get 425 as well."""
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        my_ip = ctrl.getsockname()[0]
        # a port nobody listens on: bind it, do not listen
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as closed:
            closed.bind((my_ip, 0))
            port = closed.getsockname()[1]
            reply = _command(ctrl, "PORT %s,%d,%d" % (my_ip.replace(".", ","), port >> 8, port & 255))
            assert reply.startswith("425"), reply
            assert _command(ctrl, "RETR functional-list.txt").startswith("425")
            assert _command(ctrl, "LIST").startswith("425")
            assert _command(ctrl, "PWD").startswith("257")
