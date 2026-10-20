# This file is part of the dionaea honeypot
# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: GPL-2.0-or-later

"""Bounded SPNEGO/NTLM token handling shared by SMB1 and SMB2."""

import os
import struct
import time

SIGNATURE = b"NTLMSSP\0"
NTLM_OID = bytes.fromhex("2b06010401823702020a")
SPNEGO_OID = bytes.fromhex("2b0601050502")
UNICODE = 1
VERSION = 0x02000000


def filetime():
    return time.time_ns() // 100 + 116444736000000000


def tlv(tag, value):
    size = len(value)
    if size < 128:
        length = bytes([size])
    else:
        raw = size.to_bytes((size.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + value


def elements(data):
    """Read definite BER lengths without accepting data outside a container."""
    pos = 0
    while pos < len(data):
        if len(data) - pos < 2:
            raise ValueError("truncated BER header")
        tag, length = data[pos:pos + 2]
        pos += 2
        if tag & 0x1f == 0x1f:
            raise ValueError("unsupported BER tag")
        if length & 0x80:
            count = length & 0x7f
            if not 1 <= count <= 4 or pos + count > len(data):
                raise ValueError("invalid BER length")
            length = int.from_bytes(data[pos:pos + count], "big")
            pos += count
        if pos + length > len(data):
            raise ValueError("BER value outside token")
        yield tag, data[pos:pos + length]
        pos += length


def unpack_token(blob):
    if blob.startswith(SIGNATURE):
        return blob, False

    def single(data, expected):
        items = list(elements(data))
        if len(items) != 1 or items[0][0] != expected:
            raise ValueError("invalid SPNEGO container")
        return items[0][1]

    outer = list(elements(blob))
    if len(outer) != 1:
        raise ValueError("invalid SPNEGO envelope")
    tag, value = outer[0]
    if tag == 0x60:
        application = list(elements(value))
        if len(application) != 2 or application[0] != (6, SPNEGO_OID):
            raise ValueError("invalid SPNEGO OID")
        tag, value = application[1]
    if tag not in (0xa0, 0xa1):
        raise ValueError("unsupported authentication token")
    fields = {}
    sequence = single(value, 0x30)
    for name, value in elements(sequence):
        if name not in (0xa0, 0xa1, 0xa2, 0xa3) or name in fields:
            raise ValueError("invalid SPNEGO field")
        fields[name] = value
    if tag == 0xa0:
        mechanisms = list(elements(single(fields.get(0xa0, b""), 0x30)))
        if not mechanisms or any(name != 6 for name, _ in mechanisms) or (6, NTLM_OID) not in mechanisms:
            raise ValueError("SPNEGO does not offer NTLM")
    elif 0xa1 in fields and single(fields[0xa1], 6) != NTLM_OID:
        raise ValueError("unsupported SPNEGO mechanism")
    # Validate optional result and MIC fields too, even though we do not use them.
    if tag == 0xa1 and 0xa0 in fields:
        result = single(fields[0xa0], 0x0a)
        if len(result) != 1:
            raise ValueError("invalid SPNEGO result")
    if 0xa3 in fields:
        single(fields[0xa3], 4)
    token = single(fields.get(0xa2, b""), 4)
    if not token.startswith(SIGNATURE):
        raise ValueError("SPNEGO response is not NTLM")
    return token, True


def negotiate_token():
    mechanisms = tlv(0xa0, tlv(0x30, tlv(6, NTLM_OID)))
    return tlv(0x60, tlv(6, SPNEGO_OID) + tlv(0xa0, tlv(0x30, mechanisms)))


def response_token(token=None, result=1):
    body = tlv(0xa0, tlv(0x0a, bytes([result])))
    if token is not None:
        body += tlv(0xa1, tlv(6, NTLM_OID)) + tlv(0xa2, tlv(4, token))
    return tlv(0xa1, tlv(0x30, body))


def field(token, pos, minimum):
    if pos + 8 > len(token):
        raise ValueError("truncated NTLM field")
    size, _maximum, offset = struct.unpack_from("<HHI", token, pos)
    if size and (offset < minimum or offset + size > len(token)):
        raise ValueError("NTLM field outside token")
    return token[offset:offset + size] if size else b""


def variant(response):
    if len(response) == 24:
        return "NTLMv1"
    # Classify the response without requiring a canonical client AV list.
    # The security-buffer boundary was checked by field(); unfamiliar challenge
    # content must not discard otherwise readable login metadata.
    if len(response) >= 48 and response[16:20] == b"\x01\x01\0\0":
        return "NTLMv2"
    return "unknown"


def legacy_password(ansi, unicode, unicode_names):
    """Read plaintext when no legacy challenge was advertised by this server.

    Unicode response buffers containing recognizable NTLM must never become a
    password. Legacy clients without a challenge send their password in the
    ANSI buffer; its length alone cannot distinguish a 24-character password
    from an LM response.
    """
    if unicode:
        if variant(unicode) != "unknown" or not unicode_names:
            return ""
        text = unicode.decode("utf-16-le").rstrip("\0")
    else:
        text = ansi.decode("cp437").rstrip("\0")
    return text if all(character.isprintable() for character in text) else ""


def authenticate(token):
    if len(token) < 64:
        raise ValueError("truncated NTLM authenticate")
    flags = struct.unpack_from("<I", token, 60)[0]
    minimum = 72 if flags & VERSION else 64
    if len(token) < minimum:
        raise ValueError("truncated NTLM version")
    values = [field(token, pos, minimum) for pos in (12, 20, 28, 36, 44, 52)]
    codec = "utf-16-le" if flags & UNICODE else "cp437"
    domain, username, workstation = [value.decode(codec) for value in values[2:5]]
    return dict(username=username, domain=domain, workstation=workstation, ntlm_version=variant(values[1]))


def challenge(config, flags):
    # Offer NTLM and TargetInfo; do not promise signing or session key exchange.
    server_flags = 0x00808204 | (flags & (UNICODE | 2 | 0x80000 | 0x20000000 | 0x80000000))
    names = ((1, config.server_name), (2, config.oem_domain_name),
             (3, config.server_name), (4, config.primary_domain))
    target = config.oem_domain_name.encode("utf-16-le" if flags & UNICODE else "cp437")
    info = b""
    for avid, name in names:
        value = name.encode("utf-16-le")
        info += struct.pack("<HH", avid, len(value)) + value
    info += struct.pack("<HHQHH", 7, 8, filetime(), 0, 0)
    # No configured OS build is available: omit the optional version structure.
    version = b""
    offset = 48 + len(version)
    return (SIGNATURE + struct.pack("<IHHII", 2, len(target), len(target), offset, server_flags)
            + os.urandom(8) + b"\0" * 8
            + struct.pack("<HHI", len(info), len(info), offset + len(target))
            + version + target + info)


class Exchange:
    def __init__(self):
        self.pending = False

    def process(self, blob, config):
        token, wrapped = unpack_token(blob)
        if len(token) < 12 or token[:8] != SIGNATURE:
            raise ValueError("invalid NTLM header")
        kind = struct.unpack_from("<I", token, 8)[0]
        if kind == 1:
            if len(token) < 16 or self.pending:
                raise ValueError("invalid NTLM negotiate state")
            flags = struct.unpack_from("<I", token, 12)[0]
            if len(token) >= 32:
                minimum = 40 if flags & VERSION else 32
                if len(token) < minimum:
                    raise ValueError("truncated NTLM negotiate version")
                field(token, 16, minimum)
                field(token, 24, minimum)
            elif len(token) != 16 or flags & VERSION:
                raise ValueError("truncated NTLM negotiate fields")
            reply = challenge(config, flags)
            self.pending = True
            return (response_token(reply) if wrapped else reply), None
        if kind == 3 and self.pending:
            login = authenticate(token)
            self.pending = False
            return (response_token(result=0) if wrapped else b""), login
        raise ValueError("unexpected NTLM message")
