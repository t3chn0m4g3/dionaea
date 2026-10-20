# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""SMB_COM_WRITE_ANDX / SMB_COM_WRITE of smb/include/smbfields.py: where the data starts.

The packet classes do not import dionaea.core; the field definitions are
loaded straight from the source folder. Requests are built byte by byte as a
client would (padding between the parameters and the data, 32 and 64 bit
offsets), not with the classes, so the parser is what is tested.
"""

import os
import struct
import sys
from pathlib import Path

import pytest

_root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
    Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
sys.path.insert(0, str(_root / "smb"))
from include.smbfields import (  # noqa: E402
    NBTSession, SMB_Header, SMB_Write_AndX_Request, SMB_Write_Request,
    SMB_COM_WRITE_ANDX, SMB_COM_WRITE,
)


def smb_header(command):
    return SMB_Header(Command=command, Flags=0x18).build()


def write_andx(data, pad=0, long_form=True, declared=None, data_offset=None, high_offset=0, offset=0x1000, fid=0x4000):
    """A WRITE_ANDX request; pad bytes between the byte count and the data."""
    header = smb_header(SMB_COM_WRITE_ANDX)
    words = 14 if long_form else 12
    params_len = 1 + 2 * 12 + (4 if long_form else 0) + 2  # up to and with ByteCount
    if data_offset is None:
        data_offset = len(header) + params_len + pad
    declared = len(data) if declared is None else declared
    body = struct.pack("<BBBHHIIHHHHH", words, 0xff, 0, 0, fid, offset, 0xffffffff, 8, len(data) & 0xffff,
                       declared >> 16, declared & 0xffff, data_offset)
    if long_form:
        body += struct.pack("<I", high_offset)
    body += struct.pack("<H", (pad + len(data)) & 0xffff) + b"\xaa" * pad + data
    msg = header + body
    return b"\x00" + len(msg).to_bytes(3, "big") + msg


def parse(raw):
    p = NBTSession(raw)
    return p.getlayer(SMB_Write_AndX_Request)


@pytest.mark.parametrize("long_form", [True, False])
@pytest.mark.parametrize("pad", [0, 1, 3])
def test_data_starts_after_the_padding(long_form, pad):
    data = b"HELLO-WORLD"
    h = parse(write_andx(data, pad=pad, long_form=long_form))
    assert h.Data == data
    assert h.FID == 0x4000
    assert h.Offset == 0x1000


def test_data_offset_64_with_one_pad_byte_is_the_case_of_a_windows_client():
    # WordCount 14: header 32 + 31 + 1 pad = 64
    h = parse(write_andx(b"MZ" + b"\x90" * 20, pad=1, data_offset=64))
    assert h.DataOffset == 64
    assert h.Data == b"MZ" + b"\x90" * 20


def test_a_pipe_write_keeps_the_dcerpc_header_intact():
    # bind request header of DCERPC: version 5.0, type 11 (bind), flags 3
    dcerpc = b"\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00\x01\x00\x00\x00" + b"\x00" * 40
    h = parse(write_andx(dcerpc, pad=1, data_offset=64))
    assert h.Data[:3] == b"\x05\x00\x0b"
    assert h.Data == dcerpc


def test_offset_is_little_endian_and_the_high_part_is_there():
    h = parse(write_andx(b"x", offset=0x00010000, high_offset=2))
    assert h.Offset == 0x10000
    assert h.HighOffset == 2


@pytest.mark.parametrize("size", [65535, 65536, 100000, 120000])
def test_large_write_with_padding_whose_bytecount_wrapped_around(size):
    data = bytes(range(256)) * (size // 256 + 1)
    data = data[:size]
    h = parse(write_andx(data, pad=1, declared=size))
    assert h.Data == data


def test_data_never_goes_beyond_what_was_sent():
    h = parse(write_andx(b"short", declared=60000))
    assert h.Data == b"short"


@pytest.mark.parametrize("data_offset", [0, 5, 20])
def test_a_data_offset_inside_the_header_does_not_cut_from_the_end(data_offset):
    h = parse(write_andx(b"HELLO", data_offset=data_offset))
    assert len(h.Data) <= len(b"HELLO") + 40


def test_padding_larger_than_the_message_is_clamped():
    h = parse(write_andx(b"HELLO", data_offset=60000))
    assert h.Data == b""


def write_old(data, offset, fid=0x4000):
    """SMB_COM_WRITE (0x0b): WriteOffsetInBytes is a little endian 32 bit value."""
    header = smb_header(SMB_COM_WRITE)
    body = struct.pack("<BHHIHH", 5, fid, len(data), offset, 0, len(data) + 3)
    body += b"\x01" + struct.pack("<H", len(data)) + data
    msg = header + body
    return b"\x00" + len(msg).to_bytes(3, "big") + msg


def test_write_offset_of_the_old_write_is_little_endian():
    p = NBTSession(write_old(b"chunk", 0x1000))
    h = p.getlayer(SMB_Write_Request)
    assert h.WriteOffsetInBytes == 0x1000
    assert h.Data == b"chunk"
