# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""TFTP service: a read request is answered from a new socket of the handler.

The handler (tftp.TftpServerHandler) is a connection subclass; it used to fail
with LoaderError (arguments of __init__ without defaults) and never answered.
run.sh puts functional-test.txt into roots/tftp.
"""

import socket
import struct

EXPECTED = b"tftp functional test file\n"


def _rrq(filename, mode=b"octet"):
    return b"\x00\x01" + filename + b"\x00" + mode + b"\x00"


def _request(host, packet, timeout=10.0):
    """Send packet to port 69 and return (reply, address of the reply)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (host, 69))
        return sock.recvfrom(4096)


def test_tftp_rrq_returns_data(dionaea_ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(10)
        sock.sendto(_rrq(b"functional-test.txt"), (dionaea_ip, 69))
        reply, peer = sock.recvfrom(4096)
        opcode, block = struct.unpack("!HH", reply[:4])
        assert (opcode, block) == (3, 1), reply
        assert reply[4:] == EXPECTED
        # the handler answers from a socket of its own, ACK goes there
        sock.sendto(struct.pack("!HH", 4, 1), peer)


def test_tftp_rrq_for_a_missing_file_returns_error(dionaea_ip):
    reply, _ = _request(dionaea_ip, _rrq(b"does-not-exist.bin"))
    opcode, code = struct.unpack("!HH", reply[:4])
    assert opcode == 5, reply
    assert code == 1, reply  # file not found
    assert reply.endswith(b"\x00")


def test_tftp_rrq_outside_the_root_is_refused(dionaea_ip):
    reply, _ = _request(dionaea_ip, _rrq(b"../../../../etc/passwd"))
    opcode, code = struct.unpack("!HH", reply[:4])
    assert opcode == 5, reply
    assert code == 2, reply  # access violation


def test_tftp_still_answers_after_requests(dionaea_ip):
    # the server socket keeps working after the handlers of earlier requests
    reply, _ = _request(dionaea_ip, _rrq(b"functional-test.txt"))
    assert struct.unpack("!HH", reply[:4]) == (3, 1)


def test_tftp_rrq_is_logged_with_the_port_of_the_service(dionaea_ip, my_ip, wait_for_event, wait_for_rows):
    # the session answers from a port of its own (RFC 1350), its events name the service port 69:
    # dst_port of dionaea.json and local_port of the connections table
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(10)
        sock.bind(("", 0))
        src_port = sock.getsockname()[1]
        sock.sendto(_rrq(b"functional-test.txt"), (dionaea_ip, 69))
        reply, peer = sock.recvfrom(4096)
        assert struct.unpack("!HH", reply[:4]) == (3, 1), reply
        assert peer[1] != 69
        # the last block: the session ends with this ACK (dionaea.json writes the event then)
        sock.sendto(struct.pack("!HH", 4, 1), peer)

    event = wait_for_event(lambda e: e.get("connection", {}).get("protocol") == "TftpServerHandler"
                           and e.get("src_port") == src_port)
    assert event["dst_port"] == 69, event
    assert event["dst_ip"] == dionaea_ip, event
    assert event["src_ip"] == my_ip, event
    assert event["connection"]["transport"] == "udp", event
    assert isinstance(event["dst_port"], int)

    rows = wait_for_rows("SELECT local_host, local_port, remote_host FROM connections "
                         "WHERE connection_protocol = 'TftpServerHandler' AND remote_port = ?", (src_port,))
    assert [(r["local_host"], r["local_port"], r["remote_host"]) for r in rows] == [(dionaea_ip, 69, my_ip)]
