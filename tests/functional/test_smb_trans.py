# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""SMB1 transactions and their *_SECONDARY packets (MS17-010 / EternalBlue flows).

A large SMB_COM_TRANSACTION, SMB_COM_TRANSACTION2 or SMB_COM_NT_TRANSACT is
sent in pieces: the primary request carries the first part, the *_SECONDARY
requests the rest. A server answers a continuation only when it completes the
transaction, so dionaea gives none of them an answer of its own.

The EternalBlue exploit sends a SMB_COM_NT_TRANSACT first and continues it with
SMB_COM_TRANSACTION2_SECONDARY packets, in an order that no client would use,
with other commands in between. dionaea tracks only whether a transaction was
started on the connection: a secondary after a primary of any of the three kinds
is accepted whatever its kind, order or displacement, and an error status
(STATUS_INVALID_PARAMETER) is answered only to a secondary without any
transaction before it. Nothing of the secondaries is buffered, so declared totals
and displacements cannot make dionaea allocate.

The requests are made byte by byte (the layouts of [MS-CIFS] 2.2.4.33 to 2.2.4.35
and [MS-SMB] NT_TRANSACT); the replies are read until the answer to an
SMB_COM_ECHO that is sent behind them, so "no answer" is a fact and not a timeout.
nmap's scripts for MS17-010 and DoublePulsar run as the reference of what a scanner
sees: both report VULNERABLE, as they do on the 24.04.1 image.
"""

import socket
import struct
import subprocess

import pytest

from smb1_raw import (
    Raw, SMB_COM_NT_TRANSACT, SMB_COM_NT_TRANSACT_SECONDARY, SMB_COM_TRANSACTION,
    SMB_COM_TRANSACTION2, SMB_COM_TRANSACTION2_SECONDARY, SMB_COM_TRANSACTION_SECONDARY, STATUS_INVALID_PARAMETER,
    STATUS_SUCCESS, _login,
)

# --- requests -------------------------------------------------------------------


def trans2_primary(total_param, total_data, param, data, setup=0x0005):
    """SMB_COM_TRANSACTION2 (14 words + 1 setup word); 1 pad byte before the parameters."""
    pad = b"\x00"
    param_offset = 32 + 1 + 28 + 2 + 2 + len(pad)
    words = struct.pack("<HHHHBBHIHHHHHBB", total_param, total_data, 10, 1024, 0, 0, 0, 0, 0,
                        len(param), param_offset, len(data), param_offset + len(param), 1, 0)
    words += struct.pack("<H", setup)
    return bytes([15]) + words + struct.pack("<H", len(pad) + len(param) + len(data)) + pad + param + data


def trans_primary(total_param, total_data, param, data, setup=0x0053):
    """SMB_COM_TRANSACTION on \\PIPE\\ (14 words + 1 setup word, ASCII names)."""
    name = b"\\PIPE\\\x00"
    param_offset = 32 + 1 + 28 + 2 + 2 + len(name)
    words = struct.pack("<HHHHBBHIHHHHHBB", total_param, total_data, 10, 1024, 0, 0, 0, 0, 0,
                        len(param), param_offset, len(data), param_offset + len(param), 1, 0)
    words += struct.pack("<H", setup)  # 0x0053 is TRANS_NMPIPE_WAIT: dionaea does not act on it
    return bytes([15]) + words + struct.pack("<H", len(name) + len(param) + len(data)) + name + param + data


def nt_trans_primary(total_param, total_data, param, data, function=1):
    """SMB_COM_NT_TRANSACT: 19 words, no setup."""
    param_offset = 32 + 1 + 38 + 2 + 3
    words = struct.pack("<BHIIIIIIIIBH", 0, 0, total_param, total_data, 1024, 65504, len(param), param_offset,
                        len(data), param_offset + len(param), 0, function)
    return bytes([19]) + words + struct.pack("<H", 3 + len(param) + len(data)) + b"\x00" * 3 + param + data


def secondary(kind, total_param, total_data, param, data, param_displacement=0, data_displacement=0, fid=0):
    """The *_SECONDARY request of a kind (0x26, 0x33 or 0xa1)."""
    if kind == SMB_COM_NT_TRANSACT_SECONDARY:
        offset = 32 + 1 + 36 + 2 + 1
        words = b"\x00" * 3 + struct.pack("<IIIIIIII", total_param, total_data, len(param), offset,
                                          param_displacement, len(data), offset + len(param), data_displacement)
        words += b"\x00"
        count = 18
    else:
        count = 9 if kind == SMB_COM_TRANSACTION2_SECONDARY else 8
        offset = 32 + 1 + 2 * count + 2 + 1
        words = struct.pack("<HHHHHHHH", total_param, total_data, len(param), offset, param_displacement,
                            len(data), offset + len(param), data_displacement)
        if kind == SMB_COM_TRANSACTION2_SECONDARY:
            words += struct.pack("<H", fid)
    return bytes([count]) + words + struct.pack("<H", 1 + len(param) + len(data)) + b"\x00" + param + data


PRIMARIES = {
    SMB_COM_TRANSACTION: lambda: trans_primary(0, 100, b"", b"A" * 40),
    SMB_COM_TRANSACTION2: lambda: trans2_primary(4, 100, b"\x00" * 4, b"A" * 40),
    SMB_COM_NT_TRANSACT: lambda: nt_trans_primary(4, 100, b"\x00" * 4, b"A" * 40),
}
SECONDARIES = (SMB_COM_TRANSACTION_SECONDARY, SMB_COM_TRANSACTION2_SECONDARY, SMB_COM_NT_TRANSACT_SECONDARY)
NAMES = {
    SMB_COM_TRANSACTION: "trans", SMB_COM_TRANSACTION2: "trans2", SMB_COM_NT_TRANSACT: "nt_trans",
    SMB_COM_TRANSACTION_SECONDARY: "trans_secondary", SMB_COM_TRANSACTION2_SECONDARY: "trans2_secondary",
    SMB_COM_NT_TRANSACT_SECONDARY: "nt_trans_secondary",
}


@pytest.fixture
def smb(dionaea_host):
    session = Raw(dionaea_host)
    try:
        yield session
    finally:
        session.close()


def _errors(replies):
    return [r for r in replies if r[1] not in (STATUS_SUCCESS,)]


# --- order ------------------------------------------------------------------------


def test_trans2_followed_by_secondaries_out_of_order_gets_no_error(smb):
    """TRANS2, then the secondary with the higher displacement first: no error status for any packet."""
    first = smb.message(SMB_COM_TRANSACTION2, 10, trans2_primary(4, 100, b"\x00" * 4, b"A" * 40))
    last = smb.message(SMB_COM_TRANSACTION2_SECONDARY, 10, secondary(SMB_COM_TRANSACTION2_SECONDARY, 4, 100,
                                                                     b"", b"C" * 30, 0, 70))
    middle = smb.message(SMB_COM_TRANSACTION2_SECONDARY, 10, secondary(SMB_COM_TRANSACTION2_SECONDARY, 4, 100,
                                                                       b"", b"B" * 30, 0, 40))
    replies = smb.replies(first + last + middle)
    assert not _errors(replies), replies
    # the primary is answered (as before), the secondaries are not
    assert [r[0] for r in replies] == [SMB_COM_TRANSACTION2], replies


@pytest.mark.parametrize("secondary_kind", SECONDARIES, ids=[NAMES[k] for k in SECONDARIES])
@pytest.mark.parametrize("primary_kind", sorted(PRIMARIES), ids=[NAMES[k] for k in sorted(PRIMARIES)])
def test_secondary_after_any_primary_gets_no_error(smb, primary_kind, secondary_kind):
    """MS17-010 starts an SMB_COM_NT_TRANSACT and continues it with TRANS2 secondaries: any pair is accepted."""
    stream = smb.message(primary_kind, 11, PRIMARIES[primary_kind]())
    for displacement in (70, 40, 0):  # backwards
        stream += smb.message(secondary_kind, 11, secondary(secondary_kind, 4, 100, b"", b"B" * 30, 0, displacement))
    replies = smb.replies(stream)
    assert not _errors(replies), replies
    assert all(r[0] == primary_kind for r in replies), replies  # at most the answer to the primary


@pytest.mark.parametrize("secondary_kind", SECONDARIES, ids=[NAMES[k] for k in SECONDARIES])
@pytest.mark.parametrize("primary_kind", sorted(PRIMARIES), ids=[NAMES[k] for k in sorted(PRIMARIES)])
def test_secondary_after_an_other_command_in_between_gets_no_error(smb, primary_kind, secondary_kind):
    """An SMB_COM_ECHO between the primary and its secondary does not end the transaction."""
    assert smb.replies(smb.message(primary_kind, 12, PRIMARIES[primary_kind]()))[0][0] == primary_kind
    replies = smb.replies(smb.message(secondary_kind, 12, secondary(secondary_kind, 4, 100, b"", b"B" * 60, 0, 40)))
    assert replies == [], replies


@pytest.mark.parametrize("kind", SECONDARIES, ids=[NAMES[k] for k in SECONDARIES])
def test_secondary_without_a_transaction_is_an_error(smb, kind):
    """No primary on the connection before: STATUS_INVALID_PARAMETER, with the command and the MID of the request."""
    replies = smb.replies(smb.message(kind, 0x1234, secondary(kind, 4, 100, b"", b"B" * 60, 0, 40)))
    assert replies == [(kind, STATUS_INVALID_PARAMETER, 0x1234)], replies
    # and the session goes on
    assert smb.replies() == []


# --- bounds -----------------------------------------------------------------------


def test_many_secondaries_are_not_buffered_or_answered(smb):
    """Thousands of valid secondaries: no answer for any of them, the next command is answered at once."""
    stream = smb.message(SMB_COM_TRANSACTION2, 20, trans2_primary(0xffff, 0xffff, b"", b"A" * 8))
    for number in range(3000):
        stream += smb.message(SMB_COM_TRANSACTION2_SECONDARY, 20, secondary(
            SMB_COM_TRANSACTION2_SECONDARY, 0xffff, 0xffff, b"", b"B" * 1024, 0, (number * 1024) & 0xffff))
    replies = smb.replies(stream)
    assert [r[0] for r in replies] == [SMB_COM_TRANSACTION2], replies
    assert not _errors(replies)


@pytest.mark.parametrize("kind", SECONDARIES, ids=[NAMES[k] for k in SECONDARIES])
def test_huge_totals_and_displacements_are_harmless(smb, kind):
    """Declared totals, counts, offsets and displacements at their maximum, or not at all."""
    smb.replies(smb.message(SMB_COM_NT_TRANSACT, 21, PRIMARIES[SMB_COM_NT_TRANSACT]()))
    big = 0xffffffff if kind == SMB_COM_NT_TRANSACT_SECONDARY else 0xffff
    stream = b""
    stream += smb.message(kind, 21, secondary(kind, big, big, b"x" * 8, b"y" * 8, big, big, 0xffff))
    stream += smb.message(kind, 21, secondary(kind, 0, 0, b"", b"", 0, 0))
    # WordCount and ByteCount that do not match what follows
    stream += smb.message(kind, 21, bytes([0]) + struct.pack("<H", 0xffff) + b"z" * 5)
    stream += smb.message(kind, 21, bytes([255]) + b"\xff" * 20)
    stream += smb.message(kind, 21, secondary(kind, 4, 100, b"", b"B" * 30, 0, 40)[:7])
    replies = smb.replies(stream)
    assert not _errors(replies), replies
    assert replies == [], replies


def test_orphan_secondaries_are_answered_one_for_one(smb):
    """Without a transaction every secondary gets its own error, nothing piles up: the count of answers is the count
    sent."""
    stream = b"".join(smb.message(SMB_COM_TRANSACTION2_SECONDARY, 30 + number, secondary(
        SMB_COM_TRANSACTION2_SECONDARY, 4, 100, b"", b"B", 0, 0)) for number in range(300))
    replies = smb.replies(stream)
    assert len(replies) == 300
    assert {r[1] for r in replies} == {STATUS_INVALID_PARAMETER}
    assert [r[2] for r in replies] == list(range(30, 330))


@pytest.mark.parametrize("kind", SECONDARIES, ids=[NAMES[k] for k in SECONDARIES])
def test_the_error_of_an_orphan_secondary_has_the_ids_of_the_request(smb, kind):
    """TID, PID, UID and MID of the error are those of the request, as a server answers."""
    headers = smb.headers(smb.message(kind, 77, secondary(kind, 4, 100, b"", b"B", 0, 0), tid=0x0805, pid=0x4d2e,
                                      uid=0x0a01))
    assert headers == [(kind, STATUS_INVALID_PARAMETER, 0x0805, 0x4d2e, 0x0a01, 77)], headers


def test_a_new_session_does_not_inherit_a_transaction(dionaea_host):
    """The state is per connection: a secondary on a new connection is an orphan again."""
    first = Raw(dionaea_host)
    try:
        first.replies(first.message(SMB_COM_TRANSACTION2, 40, PRIMARIES[SMB_COM_TRANSACTION2]()))
        assert first.replies(first.message(SMB_COM_TRANSACTION2_SECONDARY, 40, secondary(
            SMB_COM_TRANSACTION2_SECONDARY, 4, 100, b"", b"B", 0, 40))) == []
    finally:
        first.close()
    second = Raw(dionaea_host)
    try:
        replies = second.replies(second.message(SMB_COM_TRANSACTION2_SECONDARY, 41, secondary(
            SMB_COM_TRANSACTION2_SECONDARY, 4, 100, b"", b"B", 0, 40)))
        assert replies == [(SMB_COM_TRANSACTION2_SECONDARY, STATUS_INVALID_PARAMETER, 41)]
    finally:
        second.close()


def test_dionaea_answers_new_connections_after_all_that(dionaea_host):
    with socket.create_connection((dionaea_host, 445), timeout=10):
        pass
    conn, _ = _login(dionaea_host)
    conn.close()


# --- what a scanner sees ------------------------------------------------------------


def _nmap(host, script):
    result = subprocess.run(["nmap", "-Pn", "-p445", "--script", script, host],
                            capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stderr
    return result.stdout


def test_nmap_ms17_010_still_reports_vulnerable(dionaea_host):
    """State of nmap's smb-vuln-ms17-010 without the order check: VULNERABLE."""
    output = _nmap(dionaea_host, "smb-vuln-ms17-010")
    assert "State: VULNERABLE" in output, output
    assert "CVE-2017-0143" in output, output


def test_nmap_double_pulsar_still_reports_vulnerable(dionaea_host):
    """State of nmap's smb-double-pulsar-backdoor: VULNERABLE."""
    output = _nmap(dionaea_host, "smb-double-pulsar-backdoor")
    assert "State: VULNERABLE" in output, output
