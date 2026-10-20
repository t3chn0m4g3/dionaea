# This file is part of the dionaea honeypot
# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: GPL-2.0-or-later

"""SMB2 negotiation and rejected authentication; no file service."""

import os
import struct

from .ntlm import Exchange, filetime, negotiate_token

MAX_MESSAGE = 128 * 1024
NOT_SUPPORTED = 0xc00000bb
MORE_PROCESSING = 0xc0000016
LOGON_FAILURE = 0xc000006d
HEADER = struct.Struct("<4sHHIHHIIQIIQ16s")


def frame(payload):
    return b"\0" + len(payload).to_bytes(3, "big") + payload


class SMB2:
    def __init__(self, con):
        self.con = con
        self.dialect = None
        self.active = False
        self.session_id = 0
        self.exchange = Exchange()
        self.finished = False

    def reply(self, command, message_id, status, body, session=0):
        # Synchronous server response, one credit, no compound chain or signing.
        header = HEADER.pack(b"\xfeSMB", 64, 0, status, command, 1, 1, 0,
                             message_id, 0, 0, session, b"\0" * 16)
        self.con.send(frame(header + body))

    def error(self, command, message_id, status, session=0):
        self.reply(command, message_id, status, struct.pack("<HBBI", 9, 0, 0, 0), session)

    def negotiate(self, dialect, message_id=0):
        self.active = True
        self.dialect = None if dialect == 0x02ff else dialect
        token = negotiate_token()
        body = struct.pack("<HHHH16sIIIIQQHHI", 65, 1, dialect, 0, self.con.server_guid,
                           0, 65536, 65536, 65536, filetime(), self.con.server_start,
                           128, len(token), 0) + token
        self.reply(0, message_id, 0, body)

    def process(self, payload):
        if len(payload) < 64 or len(payload) > MAX_MESSAGE:
            raise ValueError("invalid SMB2 message length")
        fields = HEADER.unpack_from(payload)
        magic, size, _, _, command, _, flags, next_command, mid, _, _, sid, _ = fields
        if magic != b"\xfeSMB" or size != 64 or flags & 3 or next_command:
            raise ValueError("invalid or compound SMB2 header")
        if command == 0:
            if self.dialect is not None or sid or len(payload) < 100:
                raise ValueError("invalid SMB2 negotiate state or length")
            size, count = struct.unpack_from("<HH", payload, 64)
            if size != 36 or not count or 100 + count * 2 > len(payload):
                raise ValueError("invalid SMB2 dialect list")
            dialects = struct.unpack_from("<%dH" % count, payload, 100)
            selected = next((d for d in (0x0210, 0x0202) if d in dialects), None)
            if selected is None:
                self.error(command, mid, NOT_SUPPORTED)
            else:
                self.negotiate(selected, mid)
        elif command == 1:
            if self.dialect is None or self.finished or len(payload) < 88:
                raise ValueError("invalid SMB2 session setup state or length")
            size = struct.unpack_from("<H", payload, 64)[0]
            offset, length = struct.unpack_from("<HH", payload, 76)
            if size != 25 or offset < 88 or not length or offset + length > len(payload):
                raise ValueError("SMB2 security buffer outside message")
            if sid != self.session_id:
                raise ValueError("invalid SMB2 session ID")
            token, login = self.exchange.process(payload[offset:offset + length], self.con.config)
            if login is None:
                self.session_id = int.from_bytes(os.urandom(8), "little") or 1
                body = struct.pack("<HHHH", 9, 0, 72, len(token)) + token
                self.reply(command, mid, MORE_PROCESSING, body, self.session_id)
            else:
                self.finished = True
                self.con.report_login(login, "2.10" if self.dialect == 0x0210 else "2.02")
                self.error(command, mid, LOGON_FAILURE, self.session_id)
        else:
            self.error(command, mid, NOT_SUPPORTED, sid)
