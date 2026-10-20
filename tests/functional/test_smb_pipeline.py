# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""SMB1 requests that arrive in one read are all processed.

Exploits send their requests in bursts (the *_SECONDARY packets of MS17-010),
and TCP delivers them in one read. The SMB service used to parse the first
message, take the rest of the buffer as the data of that request (an SMB_COM_ECHO
even answered with it) or leave it unprocessed until more data arrived.
"""

import socket

import pytest

from smb1_raw import Raw, SMB_COM_ECHO


def _echo_reply_sizes(smb, count):
    sizes = []
    for _ in range(count):
        data = smb._frame()
        assert data[4] == SMB_COM_ECHO
        sizes.append(len(data))
    return sizes


@pytest.fixture
def smb(dionaea_host):
    session = Raw(dionaea_host)
    try:
        yield session
    finally:
        session.close()


def test_requests_in_one_segment_are_all_answered(smb):
    echo = smb.echo()
    smb.sock.sendall(echo * 5)
    sizes = _echo_reply_sizes(smb, 5)
    # every answer carries the data of its own request only
    assert len(set(sizes)) == 1, sizes


def test_a_request_split_in_two_segments_is_answered_once(smb):
    echo = smb.echo()
    smb.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    smb.sock.sendall(echo[:10])
    smb.sock.sendall(echo[10:] + echo[:7])
    first = _echo_reply_sizes(smb, 1)
    smb.sock.sendall(echo[7:])
    second = _echo_reply_sizes(smb, 1)
    assert first == second


def test_a_burst_with_garbage_behind_the_messages_does_not_close_the_session(smb):
    echo = smb.echo()
    smb.sock.sendall(echo + echo + b"\x00\x00")  # the start of one more message
    assert len(_echo_reply_sizes(smb, 2)) == 2
    smb.sock.sendall(echo[2:])  # completes it
    assert len(_echo_reply_sizes(smb, 1)) == 1
