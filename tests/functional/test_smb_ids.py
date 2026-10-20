# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""SMB1: the UID of a session and the TID of a tree, as a Windows server gives them.

A Windows server gives a session a UID in the reply to SESSION_SETUP_ANDX, a tree
a TID in the reply to TREE_CONNECT_ANDX, and echoes the TID and the UID of the
request in every other reply. The share of a tree is
kept per TID: an upload has the url ``smb://<client>/<share>/<file name>``.
"""

import hashlib
import socket
import struct
import time
import uuid

import pytest

from smb1_raw import ECHO_MID, SMB_COM_ECHO, Raw

SMB_COM_NEGOTIATE = 0x72
SMB_COM_TREE_CONNECT_ANDX = 0x75
SMB_COM_TREE_DISCONNECT = 0x71
STATUS_SUCCESS = 0


def _smb1(host):
    from impacket.smb import SMB_DIALECT
    from impacket.smbconnection import SMBConnection
    conn = SMBConnection(host, host, sess_port=445, preferredDialect=SMB_DIALECT, timeout=20)
    conn.login("user", "password", "WORKGROUP")
    return conn


def _reply(raw, data):
    """Send one request on the socket of the session, return (command, status, tid, pid, uid, mid) of the reply."""
    raw.sock.sendall(data)
    frame = raw._frame()
    return (frame[4], struct.unpack("<I", frame[5:9])[0]) + struct.unpack("<HHHH", frame[24:32])


def _echo(raw, tid, uid, pid=0x1234):
    body = bytes([1]) + struct.pack("<HH", 1, 4) + b"abcd"
    return raw.message(SMB_COM_ECHO, ECHO_MID, body, tid=tid, pid=pid, uid=uid)


def test_session_setup_gives_the_session_a_uid(dionaea_host):
    conn = _smb1(dionaea_host)
    try:
        uid = conn._SMBConnection.get_uid()
        assert uid not in (0, 0xffff), hex(uid)
    finally:
        conn.close()


def test_sessions_of_two_connections_get_their_own_uid(dionaea_host):
    first, second = _smb1(dionaea_host), _smb1(dionaea_host)
    try:
        assert first._SMBConnection.get_uid() != second._SMBConnection.get_uid()
    finally:
        first.close()
        second.close()


def test_tree_connect_gives_each_tree_a_tid(dionaea_host):
    conn = _smb1(dionaea_host)
    try:
        ipc = conn.connectTree("IPC$")
        disk = conn.connectTree("C$")
        assert ipc not in (0, 0xffff), hex(ipc)
        assert disk not in (0, 0xffff, ipc), hex(disk)
    finally:
        conn.close()


def test_replies_carry_the_tid_and_uid_of_the_request(dionaea_host):
    raw = Raw(dionaea_host)
    try:
        assert raw.tid not in (0, 0xffff)
        command, status, tid, pid, uid, mid = _reply(raw, _echo(raw, raw.tid, raw.uid))
        assert (command, status, tid, pid, uid, mid) == (SMB_COM_ECHO, STATUS_SUCCESS, raw.tid, 0x1234, raw.uid,
                                                         ECHO_MID)
        # what the client sends, also ids the server never gave
        assert _reply(raw, _echo(raw, 0x0bad, 0x0f0f))[2:5] == (0x0bad, 0x1234, 0x0f0f)
    finally:
        raw.close()


def test_negotiate_reply_echoes_the_ids_of_the_request(dionaea_host):
    dialects = b"\x02NT LM 0.12\x00"
    body = bytes([0]) + struct.pack("<H", len(dialects)) + dialects
    header = (b"\xffSMB" + bytes([SMB_COM_NEGOTIATE]) + struct.pack("<I", 0) + b"\x18" + struct.pack("<H", 0xc853)
              + b"\x00" * 12 + struct.pack("<HHHH", 0, 0x0feb, 0, 1))
    msg = header + body
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        sock.sendall(b"\x00" + len(msg).to_bytes(3, "big") + msg)
        sock.settimeout(10)
        data = b""
        while len(data) < 36:
            chunk = sock.recv(4096)
            assert chunk
            data += chunk
    assert data[8] == SMB_COM_NEGOTIATE
    assert struct.unpack("<HHHH", data[28:36]) == (0, 0x0feb, 0, 1)


def test_tree_disconnect_reply_has_the_tid_of_the_tree(dionaea_host):
    raw = Raw(dionaea_host)
    try:
        msg = raw.message(SMB_COM_TREE_DISCONNECT, 9, bytes([0]) + struct.pack("<H", 0))
        command, status, tid, _, uid, mid = _reply(raw, msg)
        assert (command, status, tid, uid, mid) == (SMB_COM_TREE_DISCONNECT, STATUS_SUCCESS, raw.tid, raw.uid, 9)
    finally:
        raw.close()


def _download_url(query_db, md5, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = query_db("SELECT download_url FROM downloads WHERE download_md5_hash = ?", (md5,))
        if rows:
            return rows[0]["download_url"]
        time.sleep(0.5)
    return None


@pytest.mark.parametrize("share, url_share", [("C$", "C$"), ("ADMIN$", "ADMIN$"), ("c$", "c$")])
def test_the_share_is_in_the_url_of_an_upload(dionaea_host, my_ip, query_db, share, url_share):
    content = ("smb share %s %s\n" % (share, uuid.uuid4().hex)).encode() * 50
    md5 = hashlib.md5(content).hexdigest()
    name = "share-%s.bin" % uuid.uuid4().hex[:8]
    conn = _smb1(dionaea_host)
    try:
        # the file is opened on the second tree: the share is that of its TID
        conn.connectTree("IPC$")
        tid = conn.connectTree(share)
        fid = conn.createFile(tid, "\\" + name)
        conn.writeFile(tid, fid, content, 0)
        conn.closeFile(tid, fid)
    finally:
        conn.close()
    url = "smb://%s/%s/%s" % (my_ip, url_share, name)
    assert _download_url(query_db, md5) == url
    assert query_db("SELECT offer_url FROM offers WHERE offer_url = ?", (url,))


# --- the shares of the persona (smb.yaml: ADMIN$, C$, IPC$, Printer) ---------------------

STATUS_ACCESS_DENIED = 0xC0000022
STATUS_BAD_NETWORK_NAME = 0xC00000CC


def _tree_connect(raw, path, extended=False, unicode=False):
    """A TREE_CONNECT_ANDX on the session of raw; returns (status, tid, service, native file system)."""
    flags2 = 0xc001 if unicode else 0x4001
    name = path.encode("utf-16-le") + b"\0\0" if unicode else path.encode() + b"\0"
    # one byte of password: the path starts at offset 44 from the header, word-aligned, no pad
    password = b"\0"
    data = password + name + b"?????\0"
    words = struct.pack("<BBBHHH", 4, 0xff, 0, 0, 0x0008 if extended else 0, len(password))
    body = words + struct.pack("<H", len(data)) + data
    header = (b"\xffSMB" + bytes([SMB_COM_TREE_CONNECT_ANDX]) + struct.pack("<I", 0) + b"\x18"
              + struct.pack("<H", flags2) + b"\x00" * 12 + struct.pack("<HHHH", 0, 0x1234, raw.uid, 0x51))
    msg = header + body
    raw.sock.sendall(b"\x00" + len(msg).to_bytes(3, "big") + msg)
    frame = raw._frame()
    status = struct.unpack("<I", frame[5:9])[0]
    tid = struct.unpack("<H", frame[24:26])[0]
    if status:
        return status, tid, None, None
    words = frame[32]
    count = struct.unpack("<H", frame[33 + 2 * words:35 + 2 * words])[0]
    start = 35 + 2 * words
    data = frame[start:start + count]
    end = data.index(b"\0")
    service, rest = data[:end].decode(), start + end + 1
    if unicode:
        rest += rest % 2   # word-aligned from the start of the SMB header
        fs = frame[rest:start + count].decode("utf-16-le").split("\0")[0]
    else:
        fs = frame[rest:start + count].split(b"\0")[0].decode()
    return status, tid, service, fs


@pytest.mark.parametrize("unicode", [False, True], ids=["oem", "unicode"])
@pytest.mark.parametrize("extended", [False, True], ids=["plain", "extended"])
@pytest.mark.parametrize("share, service, fs", [
    ("C$", "A:", "NTFS"), ("ADMIN$", "A:", "NTFS"), ("IPC$", "IPC", ""), ("Printer", "LPT1:", ""),
    ("ipc$", "IPC", ""),
])
def test_the_service_of_a_tree_is_that_of_its_share(dionaea_host, share, service, fs, extended, unicode):
    raw = Raw(dionaea_host)
    try:
        status, tid, got_service, got_fs = _tree_connect(raw, "\\\\ADFS\\" + share, extended, unicode)
        assert status == STATUS_SUCCESS
        assert tid not in (0, 0xffff, raw.tid)
        assert (got_service, got_fs) == (service, fs)
    finally:
        raw.close()


@pytest.mark.parametrize("share", ["DATA", "nmap-share-test", "D$"])
def test_a_share_the_persona_has_not_is_a_bad_network_name(dionaea_host, share):
    raw = Raw(dionaea_host)
    try:
        status, tid, _, _ = _tree_connect(raw, "\\\\ADFS\\" + share)
        assert status == STATUS_BAD_NETWORK_NAME
        assert tid == 0   # the TID of the request (_tree_connect sends 0), no new tree
    finally:
        raw.close()


@pytest.mark.parametrize("user", ["", "guest", "Guest"])
def test_an_anonymous_or_guest_session_gets_no_admin_share(dionaea_host, user):
    from impacket.smb import SMB_DIALECT
    from impacket.smbconnection import SessionError, SMBConnection
    conn = SMBConnection(dionaea_host, dionaea_host, sess_port=445, preferredDialect=SMB_DIALECT, timeout=20)
    try:
        conn.login(user, "")
        for share in ("C$", "ADMIN$"):
            with pytest.raises(SessionError) as error:
                conn.connectTree(share)
            assert error.value.getErrorCode() == STATUS_ACCESS_DENIED
        # IPC$ is open to everybody (the null session of the MS17-010 scanners)
        assert conn.connectTree("IPC$") not in (0, 0xffff)
    finally:
        conn.close()


# --- a TREE_CONNECT_ANDX chained behind SESSION_SETUP_ANDX --------------------------------


def _header(command, tid=0xffff, uid=0, mid=1, flags2=0x4001):
    return (b"\xffSMB" + bytes([command]) + struct.pack("<I", 0) + b"\x18" + struct.pack("<H", flags2)
            + b"\x00" * 12 + struct.pack("<HHHH", tid, 0x2222, uid, mid))


def _send(sock, msg):
    sock.sendall(b"\x00" + len(msg).to_bytes(3, "big") + msg)


def _recv(sock):
    head = b""
    while len(head) < 4:
        chunk = sock.recv(4 - len(head))
        assert chunk, "dionaea closed the connection"
        head += chunk
    size = int.from_bytes(head[1:], "big")
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        assert chunk, "dionaea closed the connection"
        data += chunk
    return data


def _chained_login(sock, path, user=b"user"):
    """NEGOTIATE (NT LM 0.12, no extended security), then SESSION_SETUP_ANDX + TREE_CONNECT_ANDX in one message."""
    dialects = b"\x02NT LM 0.12\x00"
    _send(sock, _header(SMB_COM_NEGOTIATE, flags2=0x0001) + bytes([0]) + struct.pack("<H", len(dialects)) + dialects)
    assert _recv(sock)[4] == SMB_COM_NEGOTIATE
    password = b"secret"
    data = password + user + b"\0" + b"WORKGROUP\0" + b"Unix\0" + b"Samba\0"
    tree_data = b"\0" + path.encode() + b"\0" + b"?????\0"
    setup_len = 1 + 26 + 2 + len(data)
    tree_offset = 32 + setup_len
    setup = (struct.pack("<BBBHHHHIHHII", 13, SMB_COM_TREE_CONNECT_ANDX, 0, tree_offset, 4356, 10, 0, 0,
                         len(password), 0, 0, 0x0000d4) + struct.pack("<H", len(data)) + data)
    assert len(setup) == setup_len
    tree = struct.pack("<BBBHHH", 4, 0xff, 0, 0, 0, 1) + struct.pack("<H", len(tree_data)) + tree_data
    _send(sock, _header(0x73, flags2=0x0001) + setup + tree)
    return _recv(sock)


def test_a_tree_connect_chained_behind_the_session_setup_is_answered_in_the_chain(dionaea_host):
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        reply = _chained_login(sock, "\\\\ADFS\\C$")
    assert reply[4] == 0x73
    assert struct.unpack("<I", reply[5:9])[0] == STATUS_SUCCESS
    tid, _, uid, _ = struct.unpack("<HHHH", reply[24:32])
    assert uid not in (0, 0xffff) and tid not in (0, 0xffff)
    # the session setup response points at the tree connect response
    assert reply[32] == 3 and reply[33] == SMB_COM_TREE_CONNECT_ANDX
    offset = struct.unpack("<H", reply[35:37])[0]
    assert reply[offset] in (3, 7) and reply[offset + 1] == 0xff
    words = reply[offset]
    start = offset + 1 + 2 * words + 2
    assert reply[start:start + 3] == b"A:\0"


def test_a_chained_tree_connect_of_an_anonymous_session_to_c_is_denied(dionaea_host):
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        reply = _chained_login(sock, "\\\\ADFS\\C$", user=b"")
    assert struct.unpack("<I", reply[5:9])[0] == STATUS_ACCESS_DENIED
    assert struct.unpack("<H", reply[24:26])[0] == 0xffff   # the TID of the request


def test_an_upload_on_a_chained_tree_has_its_share_in_the_url(dionaea_host, my_ip, query_db):
    content = ("chained %s\n" % uuid.uuid4().hex).encode() * 40
    md5 = hashlib.md5(content).hexdigest()
    name = "chain-%s.bin" % uuid.uuid4().hex[:8]
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        reply = _chained_login(sock, "\\\\ADFS\\C$")
        tid, _, uid, _ = struct.unpack("<HHHH", reply[24:32])
        # NT_CREATE_ANDX of a normal file
        filename = b"\\" + name.encode() + b"\0"
        words = struct.pack("<BBBHBHIIIQIIIIIB", 24, 0xff, 0, 0, 0, len(filename) - 1, 0, 0, 0x2019f, 0, 0x80,
                            7, 5, 0x44, 2, 0)
        _send(sock, _header(0xa2, tid, uid, 2, flags2=0x0001) + words + struct.pack("<H", len(filename)) + filename)
        created = _recv(sock)
        assert struct.unpack("<I", created[5:9])[0] == STATUS_SUCCESS
        fid = struct.unpack("<H", created[38:40])[0]
        # WRITE_ANDX (WordCount 14), the data right after the byte count
        data_offset = 32 + 1 + 28 + 2
        write = struct.pack("<BBBHHIIHHHHHI", 14, 0xff, 0, 0, fid, 0, 0xffffffff, 0, len(content) & 0xffff,
                            len(content) >> 16, len(content) & 0xffff, data_offset, 0)
        _send(sock, _header(0x2f, tid, uid, 3, flags2=0x0001) + write + struct.pack("<H", len(content)) + content)
        assert struct.unpack("<I", _recv(sock)[5:9])[0] == STATUS_SUCCESS
        # CLOSE
        _send(sock, _header(0x04, tid, uid, 4, flags2=0x0001) + struct.pack("<BHIH", 3, fid, 0, 0))
        _recv(sock)
    url = "smb://%s/C$/%s" % (my_ip, name)
    assert _download_url(query_db, md5) == url


def test_an_upload_on_a_long_share_has_255_characters_of_it_in_the_url(dionaea_host, my_ip, query_db):
    # a share whose name ends in "share" is taken (CVE-2017-7494); its name is the client's, any length
    share = "x" * 1000 + "share"
    content = ("smb long share %s\n" % uuid.uuid4().hex).encode() * 50
    md5 = hashlib.md5(content).hexdigest()
    name = "long-%s.bin" % uuid.uuid4().hex[:8]
    conn = _smb1(dionaea_host)
    try:
        tid = conn.connectTree(share)
        fid = conn.createFile(tid, "\\" + name)
        conn.writeFile(tid, fid, content, 0)
        conn.closeFile(tid, fid)
    finally:
        conn.close()
    # the tree keeps 256 characters of it (the path of a share of Windows), the url 255 of them
    # (upload.MAX_URL_NAME_LENGTH)
    assert _download_url(query_db, md5) == "smb://%s/%s/%s" % (my_ip, share[:255], name)
