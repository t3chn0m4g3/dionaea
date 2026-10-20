# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The *_SECONDARY requests of smb/include/smbfields.py: they are read by their word and byte counts.

SMB_COM_TRANSACTION2_SECONDARY is read by its word and byte counts like the other
*_SECONDARY requests, not by the fixed layout of SMB_Trans2_Secondary_Request. The
loading of the classes is the one of test_smb_write_fields.py.
"""

import os
import struct
import sys
from pathlib import Path

import pytest

_root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
    Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
sys.path.insert(0, str(_root / "smb"))
from include.packet import Raw  # noqa: E402
from include.smbfields import (  # noqa: E402
    NBTSession, SMB_Header, SMB_Parameters, SMB_Data,
    SMB_COM_TRANSACTION_SECONDARY, SMB_COM_TRANSACTION2_SECONDARY, SMB_COM_NT_TRANSACT_SECONDARY,
)

KINDS = (SMB_COM_TRANSACTION_SECONDARY, SMB_COM_TRANSACTION2_SECONDARY, SMB_COM_NT_TRANSACT_SECONDARY)


def message(command, words, data):
    header = SMB_Header(Command=command, Flags=0x18).build()
    body = bytes([len(words) // 2]) + words + struct.pack("<H", len(data)) + data
    msg = header + body
    return b"\x00" + len(msg).to_bytes(3, "big") + msg


@pytest.mark.parametrize("command", KINDS)
@pytest.mark.parametrize("word_count", (0, 1, 8, 9, 18, 100, 255))
def test_secondary_with_any_word_count_is_read_by_its_counts(command, word_count):
    # up to the largest WordCount a byte holds (255 words, 510 bytes), every word sent
    data = b"\x00" + b"D" * 20
    words = bytes(range(256)) * 2
    p = NBTSession(message(command, words[:2 * word_count], data))
    assert not p.haslayer(Raw), p.show()
    parameters = p.getlayer(SMB_Parameters)
    assert parameters.Wordcount == word_count
    assert parameters.Words == words[:2 * word_count]
    assert p.getlayer(SMB_Data).Bytes.endswith(b"D" * 20)


@pytest.mark.parametrize("command", KINDS)
def test_secondary_without_the_byte_count_does_not_raise_in_the_header_layer(command):
    # WordCount 9 (the parameters of a TRANSACTION2_SECONDARY), all 18 bytes there, the message ends before
    # the byte count: the class of the secondary must not be the one that raises (its fixed layout), the
    # parameters are read by their count, nothing of the message is left over or taken as data
    words = bytes(range(1, 19))
    msg = SMB_Header(Command=command, Flags=0x18).build() + bytes([9]) + words
    p = NBTSession(b"\x00" + len(msg).to_bytes(3, "big") + msg)
    assert p.getlayer(SMB_Header).Command == command
    parameters = p.getlayer(SMB_Parameters)
    assert parameters is not None, p.show()
    assert parameters.Wordcount == 9
    assert parameters.Words == words
    assert not p.haslayer(Raw), p.show()
