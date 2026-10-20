# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""SMB1 requests as bytes on the socket of an impacket session (for tests that need what impacket does not send)."""

import struct

SMB_COM_ECHO = 0x2b
SMB_COM_TRANSACTION = 0x25
SMB_COM_TRANSACTION_SECONDARY = 0x26
SMB_COM_TRANSACTION2 = 0x32
SMB_COM_TRANSACTION2_SECONDARY = 0x33
SMB_COM_NT_TRANSACT = 0xa0
SMB_COM_NT_TRANSACT_SECONDARY = 0xa1

STATUS_SUCCESS = 0
STATUS_INVALID_PARAMETER = 0xc000000d

ECHO_MID = 0x7e7e


def _login(host):
    """An SMB1 session with extended security with a tree connect to IPC$."""
    from impacket.smb import SMB_DIALECT
    from impacket.smbconnection import SMBConnection
    conn = SMBConnection(host, host, sess_port=445, preferredDialect=SMB_DIALECT, timeout=20)
    conn.login("user", "password", "WORKGROUP")
    tid = conn.connectTree("IPC$")
    return conn, tid


class Raw:
    """Requests as bytes on the socket of an impacket session, replies read up to an echo."""

    def __init__(self, host):
        self.conn, self.tid = _login(host)
        smb = self.conn._SMBConnection
        self.sock = smb.get_socket()
        self.sock.settimeout(20)
        self.uid = smb.get_uid()

    def close(self):
        self.conn.close()

    def message(self, command, mid, body, tid=None, pid=1234, uid=None):
        tid = self.tid if tid is None else tid
        uid = self.uid if uid is None else uid
        header = (b"\xffSMB" + bytes([command]) + struct.pack("<I", 0) + b"\x18" + struct.pack("<H", 0x4001)
                  + struct.pack("<H", 0) + b"\x00" * 8 + struct.pack("<H", 0)
                  + struct.pack("<HHHH", tid, pid, uid, mid))
        msg = header + body
        return b"\x00" + len(msg).to_bytes(3, "big") + msg

    def send(self, command, mid, body):
        self.sock.sendall(self.message(command, mid, body))

    def echo(self):
        # WordCount 1 (EchoCount), ByteCount 4
        return self.message(SMB_COM_ECHO, ECHO_MID, bytes([1]) + struct.pack("<HH", 1, 4) + b"abcd")

    def _frame(self):
        head = b""
        while len(head) < 4:
            chunk = self.sock.recv(4 - len(head))
            assert chunk, "dionaea closed the connection"
            head += chunk
        size = int.from_bytes(head[1:], "big")
        data = b""
        while len(data) < size:
            chunk = self.sock.recv(size - len(data))
            assert chunk, "dionaea closed the connection"
            data += chunk
        return data

    def replies(self, extra=b""):
        """Send an echo (behind `extra`) and return [(command, status, mid)] of everything before its answer."""
        return [(command, status, mid) for command, status, _, _, _, mid in self.headers(extra)]

    def headers(self, extra=b""):
        """As replies(), with the ids of the headers: [(command, status, tid, pid, uid, mid)]."""
        self.sock.sendall(extra + self.echo())
        found = []
        while True:
            data = self._frame()
            command, status = data[4], struct.unpack("<I", data[5:9])[0]
            tid, pid, uid, mid = struct.unpack("<HHHH", data[24:32])
            if command == SMB_COM_ECHO and mid == ECHO_MID:
                return found
            found.append((command, status, tid, pid, uid, mid))
