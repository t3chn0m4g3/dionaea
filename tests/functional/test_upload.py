# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Files that a client uploads (FTP STOR, SMB1 write) are captured.

An upload takes the same way as a download: the service writes the data into a
temporary file in download.dir and reports ``dionaea.download.complete``;
store.py hashes it, links it as ``binaries/<md5>`` and reports
``dionaea.download.complete.hash``, from which ``dionaea.sqlite`` (table
``downloads``, read by ewsposter) and ``dionaea.json`` (the new key
``downloads``) are made. The url of an upload is ``ftp://<client address>/<file
name>`` or ``smb://<client address>/<share>/<file name>``, the address of the client as
for a download from that client (``offers`` has the same url for SMB).

The size of a file is bounded (``max_upload_size``, default 32 MiB): a
larger FTP upload is answered with 552 and dropped, an SMB write that ends beyond
the limit is refused and the file is dropped when it is closed.
"""

import hashlib
import os
import random
import socket
import struct
import time
import uuid
from urllib.parse import quote

import pytest
from impacket.smbconnection import SessionError

import helpers
from test_ftp import _command, _login, _passive_data_socket, _read_reply

MAX_UPLOAD_SIZE = 32 * 1024 * 1024
STATUS_DISK_FULL = 0xC000007F


def _wait_for(query, timeout=30.0):
    deadline = time.monotonic() + timeout
    while True:
        rows = query()
        if rows or time.monotonic() >= deadline:
            return rows
        time.sleep(0.5)


def _unique(label, size=2000):
    token = uuid.uuid4().hex
    return ("%s %s\n" % (label, token)).encode() * (size // 40 + 1)


def _download_rows(query_db, md5):
    return query_db(
        "SELECT d.download_url, d.download_md5_hash, c.connection_protocol, c.remote_host, c.local_port "
        "FROM downloads d JOIN connections c ON c.connection = d.connection "
        "WHERE d.download_md5_hash = ?",
        (md5,)
    )


def _entries(flat):
    """The list of objects of a flattened list (flat_data of the T-Pot config: {"key": [values]})."""
    return [dict(zip(flat, values)) for values in zip(*flat.values())]


def _json_download(wait_for_event, md5):
    return wait_for_event(
        lambda e: any(d["md5"] == md5 for d in _entries(e["downloads"])),
        timeout=40
    )


def _check_upload_recorded(query_db, wait_for_event, binaries_dir, content, url, protocol, port, my_ip):
    md5 = hashlib.md5(content).hexdigest()
    rows = _wait_for(lambda: _download_rows(query_db, md5))
    assert rows, "no row in downloads for md5 %s" % md5
    assert rows[0]["download_url"] == url
    assert rows[0]["connection_protocol"] == protocol
    assert rows[0]["local_port"] == port
    assert rows[0]["remote_host"] == my_ip
    assert (binaries_dir / md5).read_bytes() == content
    # dionaea.json: the entry of the connection is written when the connection is closed
    event = _json_download(wait_for_event, md5)
    download = [d for d in _entries(event["downloads"]) if d["md5"] == md5][0]
    assert download["url"] == url
    assert download["sha256"] == hashlib.sha256(content).hexdigest()
    assert download["path"].endswith("/" + md5)
    assert event["connection"]["protocol"] == protocol
    assert event["dst_port"] == port
    return event


# --- FTP ------------------------------------------------------------------------


def test_ftp_stor_is_captured(dionaea_host, my_ip, query_db, wait_for_event, binaries_dir):
    content = _unique("ftp upload")
    name = "stor-%s.bin" % uuid.uuid4().hex[:8]
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        with _passive_data_socket(ctrl, dionaea_host) as data_sock:
            assert _command(ctrl, "STOR " + name).startswith("150")
            data_sock.sendall(content)
        assert _read_reply(ctrl).startswith("226")
        _command(ctrl, "QUIT")
    event = _check_upload_recorded(
        query_db, wait_for_event, binaries_dir, content, "ftp://%s/%s" % (my_ip, name), "ftpd", 21, my_ip
    )
    # the upload sits in the entry of the control connection, next to the login
    assert "STOR" in event["ftp"]["commands"]["command"]
    assert event["credentials"]["username"] == ["anonymous"]


def test_ftp_stor_in_active_mode_with_an_odd_name(dionaea_host, my_ip, query_db, wait_for_event, binaries_dir):
    content = _unique("ftp active upload")
    name = "dir with space/ä x%20y#?.bin"
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.bind((my_ip, 0))
            listener.listen(1)
            listener.settimeout(10)
            port = listener.getsockname()[1]
            reply = _command(ctrl, "PORT %s,%d,%d" % (my_ip.replace(".", ","), port >> 8, port & 255))
            assert reply.startswith("200"), reply
            data_sock, _ = listener.accept()
            with data_sock:
                ctrl.sendall(b"STOR " + name.encode() + b"\r\n")
                assert _read_reply(ctrl).startswith("150")
                data_sock.sendall(content)
        assert _read_reply(ctrl).startswith("226")
        _command(ctrl, "QUIT")
    # the name is part of the url as a path: percent encoded, no way to break out of it
    url = "ftp://%s/%s" % (my_ip, quote(name, safe="/"))
    _check_upload_recorded(query_db, wait_for_event, binaries_dir, content, url, "ftpd", 21, my_ip)


def test_ftp_stor_of_an_existing_content_is_recorded_again(dionaea_host, my_ip, query_db, binaries_dir):
    """The same file uploaded twice: two rows (as for downloads), one file."""
    content = _unique("ftp twice")
    md5 = hashlib.md5(content).hexdigest()
    for _ in range(2):
        with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
            _login(ctrl)
            with _passive_data_socket(ctrl, dionaea_host) as data_sock:
                assert _command(ctrl, "STOR twice.bin").startswith("150")
                data_sock.sendall(content)
            assert _read_reply(ctrl).startswith("226")
            _command(ctrl, "QUIT")
    rows = _wait_for(lambda: [r for r in [_download_rows(query_db, md5)] if len(r) >= 2])
    assert rows and len(rows[0]) == 2
    assert (binaries_dir / md5).read_bytes() == content


def test_ftp_empty_stor_is_not_a_download(dionaea_host, query_db):
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        with _passive_data_socket(ctrl, dionaea_host) as data_sock:
            assert _command(ctrl, "STOR empty.bin").startswith("150")
            data_sock.shutdown(socket.SHUT_WR)
        assert _read_reply(ctrl).startswith("226")
        _command(ctrl, "QUIT")
    time.sleep(3)
    # md5 of the empty file
    assert not _download_rows(query_db, "d41d8cd98f00b204e9800998ecf8427e")


def test_ftp_oversized_stor_is_dropped(dionaea_host, binaries_dir, query_db):
    """An upload of more than max_upload_size is answered with 552 and not stored; dionaea keeps running."""
    chunk = (b"%032d\n" % 7) * 2048  # 64 KiB
    sent = 0
    before = set(helpers.binaries_names(binaries_dir))
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        with _passive_data_socket(ctrl, dionaea_host) as data_sock:
            assert _command(ctrl, "STOR big.bin").startswith("150")
            data_sock.settimeout(30)
            try:
                while sent < MAX_UPLOAD_SIZE + 8 * 1024 * 1024:
                    data_sock.sendall(chunk)
                    sent += len(chunk)
            except OSError:
                pass  # dionaea closed the data connection
        reply = _read_reply(ctrl, timeout=30)
        assert reply.startswith("552"), reply
        assert _command(ctrl, "PWD").startswith("257")
        _command(ctrl, "QUIT")
    assert sent <= MAX_UPLOAD_SIZE + 8 * 1024 * 1024
    time.sleep(2)
    after = set(helpers.binaries_names(binaries_dir))
    assert after == before, "files appeared: %s" % sorted(after - before)
    # dionaea is still there and there are no temporary files left behind
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        assert _read_reply(ctrl).startswith("220")


def test_ftp_stor_up_to_the_limit_is_stored(dionaea_host, binaries_dir, query_db):
    """A file of exactly max_upload_size is fine."""
    block = os.urandom(1024 * 1024)
    digest = hashlib.md5()
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        with _passive_data_socket(ctrl, dionaea_host) as data_sock:
            assert _command(ctrl, "STOR limit.bin").startswith("150")
            for i in range(MAX_UPLOAD_SIZE // len(block)):
                part = block[:-8] + i.to_bytes(8, "big")
                digest.update(part)
                data_sock.sendall(part)
        assert _read_reply(ctrl, timeout=60).startswith("226")
        _command(ctrl, "QUIT")
    md5 = digest.hexdigest()
    assert _wait_for(lambda: _download_rows(query_db, md5), timeout=60)
    assert (binaries_dir / md5).stat().st_size == MAX_UPLOAD_SIZE


# --- SMB1 -----------------------------------------------------------------------


def _smb1(host):
    """An SMB1 connection (dialect NT LM 0.12), logged in with extended security.
    """
    from impacket.smb import SMB_DIALECT
    from impacket.smbconnection import SMBConnection
    conn = SMBConnection(host, host, sess_port=445, preferredDialect=SMB_DIALECT, timeout=20)
    assert conn.getDialect() == SMB_DIALECT
    conn.login("user", "password", "WORKGROUP")
    return conn


def test_smb1_write_is_captured(dionaea_host, my_ip, query_db, wait_for_event, binaries_dir):
    content = _unique("smb upload", size=300000)  # more than one write
    name = "smb-%s.bin" % uuid.uuid4().hex[:8]
    conn = _smb1(dionaea_host)
    try:
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, "\\" + name)
        offset = 0
        while offset < len(content):
            part = content[offset:offset + 60000]
            conn.writeFile(tid, fid, part, offset)
            offset += len(part)
        conn.closeFile(tid, fid)
    finally:
        conn.close()
    event = _check_upload_recorded(
        query_db, wait_for_event, binaries_dir, content, "smb://%s/C$/%s" % (my_ip, name), "smbd", 445, my_ip
    )
    # the commands of the session are logged (names only, no arguments)
    commands = event["smb"]["commands"]["command"]
    for expected in ("SMB_COM_NEGOTIATE", "SMB_COM_SESSION_SETUP_ANDX", "SMB_COM_TREE_CONNECT_ANDX",
                     "SMB_COM_NT_CREATE_ANDX", "SMB_COM_WRITE_ANDX", "SMB_COM_CLOSE"):
        assert expected in commands, commands
    assert set(event["smb"]["commands"]) == {"command"}


def _x86_like(size, seed=5):
    """Data that costs the emu as much as x86 code: random bytes with a near call every 2400 bytes.

    libemu tries a GetPC candidate (call with a displacement of at most 512) from
    every one; this density scans at about 0.5 MB/s per core (libcrypto.so.3 of
    x86-64 Linux: 0.9), much slower than such an upload arrives (the window sizes:
    modules/emu/detect.c). Seed 5 has no shellcode hit in the windows of the
    emu, so the emu does not stop on its own early.
    """
    rnd = random.Random(seed)
    data = bytearray(rnd.randbytes(size))
    for offset in range(1200, size - 5, 2400):
        data[offset] = 0xE8
        data[offset + 1:offset + 5] = struct.pack("<i", rnd.randint(16, 512))
    return bytes(data)


@pytest.mark.parametrize("pause", [0.0, 0.02], ids=["full-speed", "3MBps"])
def test_smb1_large_upload_of_x86_code_is_captured(
        dionaea_host, my_ip, query_db, wait_for_event, binaries_dir, pause):
    """An upload of x86 code larger than the stream limits of the emu (1 MiB stored, the first 4 MiB scanned).

    smbd is behind filter_emu, so the emu sees the file data as it arrives. When
    it can not keep up or has scanned its part, it stops for this connection; the
    connection and the upload go on (smb.py stores the file at SMB_COM_CLOSE, a
    closed connection would lose it).
    """
    name = "smb-x86-%s.bin" % uuid.uuid4().hex[:8]
    # its own md5 per run: the end differs, after the part the emu scans
    content = _x86_like(6 * 1024 * 1024 + 12345) + name.encode()
    conn = _smb1(dionaea_host)
    try:
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, "\\" + name)
        for offset in range(0, len(content), 60000):
            conn.writeFile(tid, fid, content[offset:offset + 60000], offset)
            if pause:
                time.sleep(pause)
        conn.closeFile(tid, fid)
        # the connection still answers after the upload
        conn.closeFile(tid, conn.createFile(tid, "\\after-" + name))
    finally:
        conn.close()
    _check_upload_recorded(
        query_db, wait_for_event, binaries_dir, content, "smb://%s/C$/%s" % (my_ip, name), "smbd", 445, my_ip
    )


def test_smb1_write_at_an_offset_leaves_a_hole(dionaea_host, my_ip, query_db, binaries_dir):
    """Writes are put where the client says, within the limit."""
    first, second = _unique("smb part one", 100), _unique("smb part two", 100)
    gap = 5000
    content = first + b"\x00" * (gap - len(first)) + second
    conn = _smb1(dionaea_host)
    try:
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, "\\holes.bin")
        conn.writeFile(tid, fid, second, gap)
        conn.writeFile(tid, fid, first, 0)
        conn.closeFile(tid, fid)
    finally:
        conn.close()
    md5 = hashlib.md5(content).hexdigest()
    assert _wait_for(lambda: _download_rows(query_db, md5)), "no download for the file written out of order"
    assert (binaries_dir / md5).read_bytes() == content


def test_smb1_write_beyond_the_limit_is_refused(dionaea_host, binaries_dir, query_db):
    """A small write at a huge offset must not make dionaea hash gigabytes of a sparse file.

    The write is refused, the file is dropped (what is left would be a truncated
    sample), the connection still works for the next file.
    """
    before = set(helpers.binaries_names(binaries_dir))
    other = _unique("smb after refused write", 100)
    conn = _smb1(dionaea_host)
    try:
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, "\\sparse.bin")
        conn.writeFile(tid, fid, b"Y" * 100, 0)
        with pytest.raises(SessionError):
            conn.writeFile(tid, fid, b"X" * 100, 0x7ffff000)
        with pytest.raises(SessionError):
            conn.writeFile(tid, fid, b"X" * 100, MAX_UPLOAD_SIZE - 50)
        # the file is gone, the client can not add to it
        with pytest.raises(SessionError):
            conn.writeFile(tid, fid, b"Y" * 100, 100)
        conn.closeFile(tid, fid)
        fid = conn.createFile(tid, "\\after.bin")
        conn.writeFile(tid, fid, other, 0)
        conn.closeFile(tid, fid)
    finally:
        conn.close()
    md5 = hashlib.md5(other).hexdigest()
    assert _wait_for(lambda: _download_rows(query_db, md5))
    time.sleep(1)
    after = set(helpers.binaries_names(binaries_dir))
    assert after - before == {md5}, sorted(after - before)


def test_smb1_many_writes_beyond_the_limit_drop_the_file(dionaea_host, binaries_dir, query_db):
    """Consecutive writes that reach max_upload_size: the one that crosses it fails, the file is dropped."""
    before = set(helpers.binaries_names(binaries_dir))
    block = b"Z" * 60000
    conn = _smb1(dionaea_host)
    refused = False
    try:
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, "\\toolarge.bin")
        offset = 0
        try:
            while offset < MAX_UPLOAD_SIZE + 4 * len(block):
                conn.writeFile(tid, fid, block, offset)
                offset += len(block)
        except SessionError as error:
            # the answer of smb.py, not a closed connection
            assert error.getErrorCode() == STATUS_DISK_FULL, hex(error.getErrorCode())
            refused = True
        try:
            conn.closeFile(tid, fid)
        except Exception:
            pass
    finally:
        conn.close()
    assert refused, "writes beyond the limit were accepted"
    assert offset <= MAX_UPLOAD_SIZE
    time.sleep(3)
    assert set(helpers.binaries_names(binaries_dir)) == before


def test_smb1_open_of_many_files_is_bounded(dionaea_host, binaries_dir):
    """A client that opens one file after the other without closing them does not get an unlimited number of
    temporary files."""
    conn = _smb1(dionaea_host)
    failed = 0
    try:
        tid = conn.connectTree("C$")
        for i in range(200):
            try:
                conn.createFile(tid, "\\open%d.bin" % i)
            except Exception:
                failed += 1
    finally:
        conn.close()
    assert failed > 0
    time.sleep(1)
    leftovers = helpers.temp_names(binaries_dir, ("smb-", "ftp-"))
    assert not leftovers, leftovers
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        assert _read_reply(ctrl).startswith("220")


def test_ftp_upload_is_kept_when_the_client_closes_everything_at_once(dionaea_host, my_ip, query_db, binaries_dir):
    content = _unique("ftp closed at once")
    md5 = hashlib.md5(content).hexdigest()
    ctrl = socket.create_connection((dionaea_host, 21), timeout=10)
    try:
        _login(ctrl)
        data_sock = _passive_data_socket(ctrl, dionaea_host)
        assert _command(ctrl, "STOR gone.bin").startswith("150")
        data_sock.sendall(content)
    finally:
        # no QUIT, no wait for 226: the control connection goes first
        ctrl.close()
        data_sock.close()
    assert _wait_for(lambda: _download_rows(query_db, md5)), "upload of a client that left was not recorded"
    assert (binaries_dir / md5).read_bytes() == content
    with socket.create_connection((dionaea_host, 21), timeout=10) as again:
        assert _read_reply(again).startswith("220")


@pytest.mark.parametrize("path, url_name", [
    ("\\über dir\\x y.bin", "%C3%BCber%20dir/x%20y.bin"),
    ("\\plain.bin", "plain.bin"),
])
def test_smb1_name_of_the_file_is_in_the_url(dionaea_host, my_ip, query_db, binaries_dir, path, url_name):
    content = _unique("smb name " + path)
    md5 = hashlib.md5(content).hexdigest()
    conn = _smb1(dionaea_host)
    try:
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, path)
        conn.writeFile(tid, fid, content, 0)
        conn.closeFile(tid, fid)
    finally:
        conn.close()
    rows = _wait_for(lambda: _download_rows(query_db, md5))
    assert rows and rows[0]["download_url"] == "smb://%s/C$/%s" % (my_ip, url_name), rows
    # the offer has the same url
    assert query_db("SELECT offer_url FROM offers WHERE offer_url = ?", ("smb://%s/C$/%s" % (my_ip, url_name),))


def test_smb1_unnamed_command_is_logged_by_number(dionaea_host, wait_for_event):
    """A command byte without a name is logged as 0x<hex> and does not end the session."""
    header = (b"\xffSMB\xf0" + b"\x00" * 4 + b"\x18" + b"\x01\xc8" + b"\x00" * 2 + b"\x00" * 8 + b"\x00" * 2
              + b"\xff\xff" + b"\x01\x00" + b"\x00\x00" + b"\x01\x00")
    assert len(header) == 32
    body = header + b"\x00\x00\x00"
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        port = sock.getsockname()[1]
        sock.sendall(b"\x00" + len(body).to_bytes(3, "big") + body)
        time.sleep(1)
        # still there: an echo request
        sock.sendall(b"\x00" + len(body).to_bytes(3, "big") + body)
        time.sleep(1)
    event = wait_for_event(lambda e: e["src_port"] == port and "smb" in e, timeout=40)
    assert event["smb"]["commands"]["command"] == ["0xf0", "0xf0"]


def test_smb1_service_pipe_is_not_an_upload(dionaea_host, query_db):
    """A pipe of a service (\\srvsvc) is opened with the attributes of a file; its writes are DCERPC.

    Once these writes ended up in a temporary file and the client waited for an answer.
    """
    conn = _smb1(dionaea_host)
    try:
        shares = [share["shi1_netname"][:-1] for share in conn.listShares()]
    finally:
        conn.close()
    assert sorted(shares) == ["ADMIN$", "C$", "IPC$", "Printer"], shares
    assert not query_db("SELECT offer_url FROM offers WHERE offer_url LIKE '%srvsvc%'")


# --- SMB1 write layouts, FTP data connections after a STOR ---------------------------


def _padded_write_andx(self, tid, fid, data, offset=0, wait_answer=1, write_pipe_mode=False, smb_packet=None):
    """impacket's SMB.write_andx, but the data starts one byte after the end of the parameters (DataOffset + 1).

    A Windows client pads the data like this (DataOffset 64 for WordCount 14).
    """
    from impacket import smb
    packet = smb.NewSMBPacket()
    packet["Tid"] = tid
    command = smb.SMBCommand(smb.SMB.SMB_COM_WRITE_ANDX)
    packet.addCommand(command)
    command["Parameters"] = smb.SMBWriteAndX_Parameters()
    command["Parameters"]["Fid"] = fid
    command["Parameters"]["Offset"] = offset
    command["Parameters"]["WriteMode"] = 8
    command["Parameters"]["Remaining"] = len(data)
    command["Parameters"]["DataLength"] = len(data)
    command["Parameters"]["DataOffset"] = len(packet) + 1
    command["Data"] = b"\xaa" + data
    self.sendSMB(packet)
    if wait_answer:
        answer = self.recvSMB()
        if answer.isValidAnswer(smb.SMB.SMB_COM_WRITE_ANDX):
            return answer
    return None


def test_smb1_write_with_a_padded_data_offset_keeps_every_byte(dionaea_host, query_db, binaries_dir, monkeypatch):
    from impacket import smb
    monkeypatch.setattr(smb.SMB, "write_andx", _padded_write_andx)
    content = b"MZ" + _unique("smb padded write", 300)
    conn = _smb1(dionaea_host)
    try:
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, "\\padded.bin")
        conn.writeFile(tid, fid, content[:100], 0)
        conn.writeFile(tid, fid, content[100:], 100)
        conn.closeFile(tid, fid)
    finally:
        conn.close()
    md5 = hashlib.md5(content).hexdigest()
    assert _wait_for(lambda: _download_rows(query_db, md5)), "padded writes lost or kept bytes"
    assert (binaries_dir / md5).read_bytes() == content


def test_smb1_service_pipe_answers_padded_writes(dionaea_host, monkeypatch):
    """DCERPC over WRITE_ANDX with padding: the first byte of the request must not be the pad byte."""
    from impacket import smb
    monkeypatch.setattr(smb.SMB, "write_andx", _padded_write_andx)
    conn = _smb1(dionaea_host)
    try:
        shares = [share["shi1_netname"][:-1] for share in conn.listShares()]
    finally:
        conn.close()
    assert sorted(shares) == ["ADMIN$", "C$", "IPC$", "Printer"], shares


def test_smb1_old_write_command_with_offsets_in_several_chunks(dionaea_host, query_db, binaries_dir):
    """SMB_COM_WRITE: the offset is little endian (once 0x1000 landed at 1 MiB)."""
    content = _unique("smb old write", 6000)
    chunks = [(0x0, content[:1500]), (3000, content[3000:4500]), (1500, content[1500:3000]), (4500, content[4500:])]
    conn = _smb1(dionaea_host)
    try:
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, "\\oldwrite.bin")
        for offset, chunk in chunks:
            conn._SMBConnection.write(tid, fid, chunk, offset)
        conn.closeFile(tid, fid)
    finally:
        conn.close()
    md5 = hashlib.md5(content).hexdigest()
    assert _wait_for(lambda: _download_rows(query_db, md5)), "chunks of SMB_COM_WRITE were put at the wrong offsets"
    assert (binaries_dir / md5).read_bytes() == content


def test_smb1_hundred_bytes_at_a_huge_offset_are_dropped_fast(dionaea_host, binaries_dir, query_db):
    """100 bytes at offset 32 MiB - 100 are within max_upload_size but a file of holes: dionaea would read 32 MiB
    twice."""
    before = set(helpers.binaries_names(binaries_dir))
    content = b"S" * 100
    conn = _smb1(dionaea_host)
    started = time.monotonic()
    try:
        tid = conn.connectTree("C$")
        for i in range(8):
            fid = conn.createFile(tid, "\\sparse%d.bin" % i)
            conn.writeFile(tid, fid, content, MAX_UPLOAD_SIZE - len(content))
            conn.closeFile(tid, fid)
    finally:
        conn.close()
    time.sleep(2)
    assert not _download_rows(query_db, hashlib.md5(content).hexdigest())
    assert set(helpers.binaries_names(binaries_dir)) == before
    # dionaea was not busy hashing: a new connection is answered at once
    begin = time.monotonic()
    with socket.create_connection((dionaea_host, 21), timeout=5) as ctrl:
        assert _read_reply(ctrl, timeout=3).startswith("220")
    assert time.monotonic() - begin < 2
    assert time.monotonic() - started < 30


def _ftp_temp_files(binaries_dir):
    return helpers.temp_names(binaries_dir, ("ftp-", "smb-"))


def test_ftp_second_stor_on_one_data_connection_leaves_no_temp_file(dionaea_host, my_ip, query_db, binaries_dir):
    first, second = _unique("ftp first stor"), _unique("ftp second stor")
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        with _passive_data_socket(ctrl, dionaea_host) as data_sock:
            assert _command(ctrl, "STOR first.bin").startswith("150")
            data_sock.sendall(first)
            time.sleep(1)
            assert _command(ctrl, "STOR second.bin").startswith("150")
            data_sock.sendall(second)
        assert _read_reply(ctrl).startswith("226")
        _command(ctrl, "QUIT")
    md5 = hashlib.md5(second).hexdigest()
    assert _wait_for(lambda: _download_rows(query_db, md5))
    time.sleep(1)
    assert _ftp_temp_files(binaries_dir) == []


@pytest.mark.parametrize("command", ["RETR functional-list.txt", "LIST"])
def test_ftp_stor_followed_by_another_transfer_leaves_no_temp_file(dionaea_host, binaries_dir, command):
    with socket.create_connection((dionaea_host, 21), timeout=10) as ctrl:
        _login(ctrl)
        with _passive_data_socket(ctrl, dionaea_host) as data_sock:
            assert _command(ctrl, "STOR dropped.bin").startswith("150")
            data_sock.sendall(_unique("ftp stor then " + command))
            time.sleep(1)
            assert _command(ctrl, command).startswith("150")
            try:
                data_sock.settimeout(5)
                while data_sock.recv(4096):
                    pass
            except OSError:
                pass
        time.sleep(1)
        _command(ctrl, "QUIT")
    time.sleep(1)
    assert _ftp_temp_files(binaries_dir) == []


def test_ftp_stor_and_control_connection_freed_first_leaves_no_temp_file(dionaea_host, binaries_dir):
    """Many uploads whose connections end in different orders: no temp file stays."""
    for _ in range(5):
        ctrl = socket.create_connection((dionaea_host, 21), timeout=10)
        _login(ctrl)
        data_sock = _passive_data_socket(ctrl, dionaea_host)
        assert _command(ctrl, "STOR gone.bin").startswith("150")
        data_sock.sendall(_unique("ftp freed"))
        ctrl.close()
        time.sleep(0.3)
        data_sock.close()
    time.sleep(2)
    assert _ftp_temp_files(binaries_dir) == []
