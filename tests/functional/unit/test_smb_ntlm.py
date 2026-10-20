# This file is part of the dionaea honeypot
# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: CC0-1.0

"""NTLM offsets, BER lengths and challenge metadata."""

import importlib.util
import os
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
    Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
spec = importlib.util.spec_from_file_location("smb_ntlm_under_test", root / "smb" / "ntlm.py")
ntlm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ntlm)
CONFIG = SimpleNamespace(server_name="SERVER", oem_domain_name="DOMAIN", primary_domain="example.test")


def auth(response=b"x" * 24, flags=1):
    values = (b"x" * 24, response, "DOMAIN".encode("utf-16-le"), "USER".encode("utf-16-le"),
              "CLIENT".encode("utf-16-le"), b"")
    result = b"NTLMSSP\0" + struct.pack("<I", 3)
    offset = 64
    for value in values:
        result += struct.pack("<HHI", len(value), len(value), offset)
        offset += len(value)
    return result + struct.pack("<I", flags) + b"".join(values)


def test_authentication_metadata_and_variants():
    login = ntlm.authenticate(auth())
    assert login == dict(username="USER", domain="DOMAIN", workstation="CLIENT", ntlm_version="NTLMv1")
    response = b"x" * 16 + b"\x01\x01\0\0" + b"\0" * 24 + b"\0" * 4
    assert ntlm.authenticate(auth(response))["ntlm_version"] == "NTLMv2"
    assert ntlm.authenticate(auth(b"unrecognized"))["ntlm_version"] == "unknown"
    assert ntlm.authenticate(auth(b""))["ntlm_version"] == "unknown"


@pytest.mark.parametrize("pos", [12, 20, 28, 36, 44, 52])
@pytest.mark.parametrize("offset", [1, 63, 0xffffffff])
def test_all_authentication_field_offsets_are_bounded(pos, offset):
    token = bytearray(auth())
    struct.pack_into("<HHI", token, pos, 2, 2, offset)
    with pytest.raises(ValueError):
        ntlm.authenticate(token)


@pytest.mark.parametrize("pos", [12, 20, 28, 36, 44, 52])
def test_all_authentication_field_lengths_are_bounded(pos):
    token = bytearray(auth())
    struct.pack_into("<HHI", token, pos, 65535, 65535, 64)
    with pytest.raises(ValueError):
        ntlm.authenticate(token)


@pytest.mark.parametrize("length", range(64))
def test_truncated_authentication_headers(length):
    with pytest.raises(ValueError):
        ntlm.authenticate(auth()[:length])


def test_invalid_unicode_and_ntlm_version_bounds():
    token = bytearray(auth())
    struct.pack_into("<H", token, 36, 1)
    with pytest.raises(UnicodeError):
        ntlm.authenticate(token)
    token = bytearray(auth())
    struct.pack_into("<I", token, 60, 0x02000001)
    with pytest.raises(ValueError):
        ntlm.authenticate(token)


@pytest.mark.parametrize("blob", [b"", b"\xa1", b"\xa1\x80", b"\xa1\x84\xff\xff\xff\xff",
                                  b"\xa1\x02\x04\x10", b"\xa1\x85\0\0\0\0\0"])
def test_malformed_ber_is_rejected(blob):
    with pytest.raises(ValueError):
        ntlm.unpack_token(blob)


def test_nested_ber_limit_and_duplicate_tokens():
    token = b"NTLMSSP\0" + struct.pack("<II", 1, 1)
    blob = ntlm.tlv(4, token)
    for _ in range(10):
        blob = ntlm.tlv(0xa1, blob)
    with pytest.raises(ValueError):
        ntlm.unpack_token(blob)
    with pytest.raises(ValueError):
        ntlm.unpack_token(ntlm.tlv(0xa1, ntlm.tlv(4, token) * 2))


def test_challenge_and_exchange():
    type1 = b"NTLMSSP\0" + struct.pack("<II", 1, 1)
    exchange = ntlm.Exchange()
    first, login = exchange.process(type1, CONFIG)
    assert login is None and first[:12] == b"NTLMSSP\0\x02\0\0\0"
    other, _ = ntlm.Exchange().process(type1, CONFIG)
    assert first[24:32] != other[24:32]
    size, maximum, offset = struct.unpack_from("<HHI", first, 40)
    assert size == maximum and offset + size == len(first)
    assert first[-4:] == b"\0" * 4
    reply, login = exchange.process(auth(), CONFIG)
    assert reply == b"" and login["username"] == "USER"
    with pytest.raises(ValueError):
        exchange.process(auth(), CONFIG)


def test_ntlmv2_av_pairs_are_bounded():
    response = b"x" * 16 + b"\x01\x01\0\0" + b"\0" * 24 + struct.pack("<HH", 1, 65535)
    assert ntlm.authenticate(auth(response))["username"] == "USER"


@pytest.mark.parametrize("version", [False, True])
def test_spnego_exchange_with_version(version):
    flags = 1 | (0x02000000 if version else 0)
    type1 = b"NTLMSSP\0" + struct.pack("<I", 1) + struct.pack("<I", flags)
    type1 += b"\0" * 16 + (b"\0" * 8 if version else b"")
    initial = ntlm.tlv(0x60, ntlm.tlv(6, ntlm.SPNEGO_OID) + ntlm.tlv(0xa0, ntlm.tlv(0x30,
                       ntlm.tlv(0xa0, ntlm.tlv(0x30, ntlm.tlv(6, ntlm.NTLM_OID)))
                       + ntlm.tlv(0xa2, ntlm.tlv(4, type1)))))
    exchange = ntlm.Exchange()
    reply, _ = exchange.process(initial, CONFIG)
    token, wrapped = ntlm.unpack_token(reply)
    assert wrapped and token[:12] == b"NTLMSSP\0\x02\0\0\0"
    assert struct.unpack_from("<I", token, 20)[0] & 0x02000000 == 0
    reply, login = exchange.process(ntlm.response_token(auth()), CONFIG)
    assert reply == ntlm.response_token(result=0) and login["username"] == "USER"


@pytest.mark.parametrize("pos", [16, 24])
def test_negotiate_fields_are_bounded(pos):
    token = bytearray(b"NTLMSSP\0" + struct.pack("<II", 1, 1) + b"\0" * 16)
    struct.pack_into("<HHI", token, pos, 1, 1, 0xffffffff)
    with pytest.raises(ValueError):
        ntlm.Exchange().process(token, CONFIG)


def test_ntlmv1_extended_session_security_is_still_v1():
    assert ntlm.authenticate(auth(flags=0x80001))["ntlm_version"] == "NTLMv1"


def test_unknown_spnego_oid_is_rejected():
    blob = ntlm.tlv(0x60, ntlm.tlv(6, b"wrong") + ntlm.negotiate_token())
    with pytest.raises(ValueError):
        ntlm.unpack_token(blob)


def test_maximum_length_is_not_a_payload_boundary():
    token = bytearray(auth())
    struct.pack_into("<H", token, 38, 0)
    assert ntlm.authenticate(token)["username"] == "USER"


@pytest.mark.parametrize("tail", [b"", b"arbitrary", b"\0" * 12])
def test_noncanonical_v2_tail_keeps_login(tail):
    response = b"x" * 16 + b"\x01\x01\0\0" + b"\0" * 28 + tail
    assert ntlm.authenticate(auth(response))["ntlm_version"] == "NTLMv2"


@pytest.mark.parametrize("password", [b"secret", b"a" * 24, b"secret\0", b"caf\x82"])
def test_legacy_cleartext_password(password):
    assert ntlm.legacy_password(password, b"", False) == password.decode("cp437").rstrip("\0")


def test_legacy_unicode_password_and_ntlm_responses():
    assert ntlm.legacy_password(b"", "secret\0".encode("utf-16-le"), True) == "secret"
    assert ntlm.legacy_password(b"LM" * 12, b"NT" * 12, True) == ""
    response = b"x" * 16 + b"\x01\x01\0\0" + b"\0" * 28
    assert ntlm.legacy_password(b"LM" * 12, response, True) == ""
    assert ntlm.legacy_password(b"binary\x01", b"", False) == ""
