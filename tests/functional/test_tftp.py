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
