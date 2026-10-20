# This file is part of the dionaea honeypot
# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: CC0-1.0

"""SMB authentication interoperability, metadata, and malformed input."""

import random
import socket
import struct
import subprocess
import time

import pytest
from impacket import ntlm
from impacket.smb import SMB, SMB_DIALECT
from impacket.smbconnection import SMBConnection, SessionError

HEADER = struct.Struct("<4sHHIHHIIQIIQ16s")
LOGON_FAILURE = 0xc000006d
MORE_PROCESSING = 0xc0000016


def packet(command, body, mid=0, sid=0, next_command=0):
    header = HEADER.pack(b"\xfeSMB", 64, 0, 0, command, 1, 0, next_command,
                         mid, 0, 0, sid, b"\0" * 16)
    payload = header + body
    return b"\0" + len(payload).to_bytes(3, "big") + payload


def negotiate(dialects=(0x0202,), mid=0):
    body = struct.pack("<HHHHI16sQ", 36, len(dialects), 1, 0, 0, b"\0" * 16, 0)
    return packet(0, body + struct.pack("<%dH" % len(dialects), *dialects), mid)


def setup(token, sid=0, mid=1):
    return packet(1, struct.pack("<HBBIIHHQ", 25, 0, 1, 0, 0, 88, len(token), 0) + token, mid, sid)


def receive(sock):
    def exact(count):
        data = b""
        while len(data) < count:
            chunk = sock.recv(count - len(data))
            assert chunk, "connection closed before the complete response"
            data += chunk
        return data
    header = exact(4)
    assert header[0] == 0
    return exact(int.from_bytes(header[1:], "big"))


def connect(host):
    sock = socket.create_connection((host, 445), timeout=5)
    sock.settimeout(5)
    return sock


def login_event(event, port):
    # Different services can reuse a client port; match the SMB connection too.
    return (event.get("src_port") == port and
            event.get("connection", {}).get("protocol") == "smbd" and "credentials" in event)


def check_login(port, username, dialect, version, wait_for_rows, wait_for_event):
    event = wait_for_event(lambda e: login_event(e, port))
    expected = dict(domain="AUTHDOMAIN", workstation="AUTHCLIENT", dialect=dialect, ntlm_version=version)
    for name, value in expected.items():
        assert event["smb"][name] == value
        assert event["credentials"][name] == [value]
    assert event["credentials"]["username"] == [username]
    assert event["credentials"]["password"] == [""]
    rows = wait_for_rows("SELECT login_username, login_password FROM logins JOIN connections USING(connection) "
                         "WHERE remote_port = ? AND connection_protocol = 'smbd'", (port,))
    assert rows == [dict(login_username=username, login_password="")]


@pytest.mark.parametrize("dialect", [0x0202, 0x0210])
def test_impacket_smb2_login(dionaea_host, dialect, wait_for_rows, wait_for_event):
    conn = SMBConnection(dionaea_host, dionaea_host, sess_port=445, preferredDialect=dialect, timeout=10)
    port = conn.getSMBServer().get_socket().getsockname()[1]
    actual = conn.getDialect()
    assert actual == (dialect if dialect is not None else 0x0210)
    try:
        with pytest.raises(SessionError) as failure:
            conn.login("smb2-user", "secret", "AUTHDOMAIN")
        assert failure.value.getErrorCode() == LOGON_FAILURE
    finally:
        conn.close()
    # Impacket uses its default workstation (empty) here; check raw auth below
    # for a nonempty workstation and both NTLM variants.
    event = wait_for_event(lambda e: login_event(e, port))
    assert event["credentials"]["username"] == ["smb2-user"]
    assert event["credentials"]["password"] == [""]
    assert event["smb"]["domain"] == "AUTHDOMAIN"
    assert event["smb"]["ntlm_version"] == "NTLMv2"
    assert event["smb"]["dialect"] == ("2.10" if actual == 0x0210 else "2.02")
    rows = wait_for_rows("SELECT login_password FROM logins JOIN connections USING(connection) "
                         "WHERE remote_port = ? AND connection_protocol = 'smbd'",
                         (port,))
    assert rows == [dict(login_password="")]


@pytest.mark.parametrize("use_v2", [False, True])
@pytest.mark.parametrize("dialect", [0x0202, 0x0210])
def test_raw_ntlm_login(dionaea_host, use_v2, dialect, wait_for_rows, wait_for_event):
    with connect(dionaea_host) as sock:
        port = sock.getsockname()[1]
        sock.sendall(negotiate((dialect,)))
        receive(sock)
        type1 = ntlm.getNTLMSSPType1("AUTHCLIENT", "AUTHDOMAIN", use_ntlmv2=use_v2)
        sock.sendall(setup(type1.getData()))
        reply = receive(sock)
        assert struct.unpack_from("<I", reply, 8)[0] == MORE_PROCESSING
        sid = struct.unpack_from("<Q", reply, 40)[0]
        offset, length = struct.unpack_from("<HH", reply, 68)
        challenge = reply[offset:offset + length]
        parsed = ntlm.NTLMAuthChallenge(challenge)
        pairs = ntlm.AV_PAIRS(parsed["TargetInfoFields"])
        assert pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode("utf-16-le") == "ADFS"
        assert pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode("utf-16-le") == "DACH"
        assert pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode("utf-16-le") == "ADFS"
        assert pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode("utf-16-le") == "DACH"
        stamp = struct.unpack("<Q", pairs[ntlm.NTLMSSP_AV_TIME][1])[0]
        assert abs((stamp - 116444736000000000) / 10000000 - time.time()) < 10
        type3, _ = ntlm.getNTLMSSPType3(type1, challenge, "raw-user", "secret", "AUTHDOMAIN", use_ntlmv2=use_v2)
        sock.sendall(setup(type3.getData(), sid, 2))
        reply = receive(sock)
        assert struct.unpack_from("<I", reply, 8)[0] == LOGON_FAILURE
        assert struct.unpack_from("<Q", reply, 24)[0] == 2
        assert struct.unpack_from("<Q", reply, 40)[0] == sid
    check_login(port, "raw-user", "2.10" if dialect == 0x0210 else "2.02",
                "NTLMv2" if use_v2 else "NTLMv1", wait_for_rows, wait_for_event)


@pytest.mark.parametrize("extended", [False, True])
@pytest.mark.parametrize("password", ["secret", "a" * 24])
def test_smb1_login(dionaea_host, extended, password, wait_for_rows, wait_for_event):
    conn = SMBConnection(dionaea_host, dionaea_host, sess_port=445, preferredDialect=SMB_DIALECT, timeout=10)
    port = conn.getSMBServer().get_socket().getsockname()[1]
    if not extended:
        # Explicit coverage of legacy session setup. With no legacy challenge,
        # impacket sends a password rather than an identifiable NTLM response.
        conn.getSMBServer()._dialects_parameters["Capabilities"] &= ~SMB.CAP_EXTENDED_SECURITY
    try:
        conn.login("smb1-user", password, "AUTHDOMAIN")
        assert conn.connectTree("IPC$")
    finally:
        conn.close()
    event = wait_for_event(lambda e: login_event(e, port))
    assert event["credentials"]["username"] == ["smb1-user"]
    assert event["credentials"]["password"] == ([""] if extended else [password])
    assert event["smb"]["dialect"] == "NT LM 0.12"
    assert event["smb"]["ntlm_version"] == ("NTLMv2" if extended else "unknown")
    assert wait_for_rows("SELECT login_password FROM logins JOIN connections USING(connection) "
                         "WHERE remote_port = ? AND connection_protocol = 'smbd'",
                         (port,)) == [dict(login_password="" if extended else password)]


def test_smb1_repeated_logins_are_bounded(dionaea_host, wait_for_rows, wait_for_event):
    conn = SMBConnection(dionaea_host, dionaea_host, sess_port=445, preferredDialect=SMB_DIALECT, timeout=20)
    port = conn.getSMBServer().get_socket().getsockname()[1]
    usernames = ["bounded-login-%d" % index for index in range(1001)]
    try:
        for username in usernames:
            conn.login(username, "secret", "AUTHDOMAIN")
        assert conn.connectTree("IPC$")
    finally:
        conn.close()
    event = wait_for_event(lambda e: login_event(e, port) and
                           "bounded-login-0" in e.get("credentials", {}).get("username", []), timeout=30)
    assert event["credentials"]["username"] == usernames[:1000]
    assert event["credentials"]["password"] == [""] * 1000
    rows = wait_for_rows("SELECT login_username, login_password FROM logins JOIN connections USING(connection) "
                         "WHERE remote_port = ? AND connection_protocol = 'smbd' "
                         "AND login_username LIKE 'bounded-login-%' ORDER BY login",
                         (port,), count=len(usernames))
    assert [row["login_username"] for row in rows] == usernames
    assert all(row["login_password"] == "" for row in rows)


def test_smb2_negotiation_identity_and_selection(dionaea_host):
    replies = []
    for dialects in ((0x0202,), (0x0210,), (0x0202, 0x0210, 0x0311)):
        with connect(dionaea_host) as sock:
            sock.sendall(negotiate(dialects, mid=37))
            reply = receive(sock)
            assert struct.unpack_from("<H", reply, 68)[0] == max(d for d in dialects if d <= 0x0210)
            assert struct.unpack_from("<Q", reply, 24)[0] == 37
            replies.append(reply)
    assert replies[0][72:88] == replies[1][72:88] == replies[2][72:88]
    assert replies[0][112:120] == replies[1][112:120] == replies[2][112:120]
    assert replies[0][72:88] != b"\0" * 16
    with connect(dionaea_host) as sock:
        sock.sendall(negotiate((0x0311,)))
        assert struct.unpack_from("<I", receive(sock), 8)[0] == 0xc00000bb


@pytest.mark.parametrize("dialect, expected", [(b"SMB 2.002", 0x0202), (b"SMB 2.???", 0x02ff)])
def test_smb1_upgrade(dionaea_host, dialect, expected):
    from impacket.smb import NewSMBPacket, SMBCommand
    request = NewSMBPacket()
    command = SMBCommand(SMB.SMB_COM_NEGOTIATE)
    command["Data"] = b"\x02" + dialect + b"\0"
    request.addCommand(command)
    payload = request.getData()
    with connect(dionaea_host) as sock:
        sock.sendall(b"\0" + len(payload).to_bytes(3, "big") + payload)
        reply = receive(sock)
        assert reply[:4] == b"\xfeSMB"
        assert struct.unpack_from("<H", reply, 68)[0] == expected
        if expected == 0x02ff:
            sock.sendall(negotiate((0x0202, 0x0210), mid=1))
            assert struct.unpack_from("<H", receive(sock), 68)[0] == 0x0210


def test_smb2_fragmented_and_bundled_transport(dionaea_host):
    with connect(dionaea_host) as sock:
        request = negotiate()
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(request[:7])
        sock.sendall(request[7:])
        assert struct.unpack_from("<I", receive(sock), 8)[0] == 0
        # Unsupported independent commands are answered individually.
        a = packet(2, b"\x04\0\0\0", mid=1)
        b = packet(3, b"\0" * 8, mid=2)
        sock.sendall(a + b + a[:3])
        assert struct.unpack_from("<Q", receive(sock), 24)[0] == 1
        assert struct.unpack_from("<Q", receive(sock), 24)[0] == 2
        sock.sendall(a[3:])
        assert struct.unpack_from("<Q", receive(sock), 24)[0] == 1


def test_nmap_smb_dialects(dionaea_host):
    result = subprocess.run(["nmap", "-Pn", "-p", "445", "--script", "smb-protocols", dionaea_host],
                            capture_output=True, text=True, timeout=60, check=True)
    assert "2:0:2" in result.stdout, result.stdout
    assert "2:1:0" in result.stdout, result.stdout
    assert "3:0:" not in result.stdout and "3:1:1" not in result.stdout


def test_500_malformed_smb2_messages(dionaea_host):
    rng = random.Random(9)
    type1 = ntlm.getNTLMSSPType1("CLIENT", "DOMAIN").getData()
    bases = (negotiate(), setup(type1))
    for number in range(500):
        base = bases[number % len(bases)]
        if number < 200:
            payload = base[4:4 + number % (len(base) - 4)]
        else:
            payload = bytearray(base[4:])
            for _ in range(1 + number % 4):
                pos = rng.randrange(len(payload))
                payload[pos] ^= rng.randrange(1, 256)
        with connect(dionaea_host) as sock:
            if number % 2:
                sock.sendall(negotiate())
                receive(sock)
            sock.sendall(b"\0" + len(payload).to_bytes(3, "big") + payload)
            try:
                sock.recv(4096)
            except (ConnectionResetError, socket.timeout):
                pass
    with connect(dionaea_host) as sock:
        sock.sendall(negotiate())
        assert struct.unpack_from("<I", receive(sock), 8)[0] == 0


@pytest.mark.parametrize("bad", [
    b"\0\x02\0\x01",  # announced length above 128 KiB, no body required
    packet(0, b"\0" * 36, next_command=64),
])
def test_smb2_oversized_and_compound_close(dionaea_host, bad):
    with connect(dionaea_host) as sock:
        sock.sendall(bad)
        try:
            assert sock.recv(1) == b""
        except ConnectionResetError:
            pass


@pytest.mark.parametrize("offset, length", [(0, 16), (64, 16), (87, 1), (88, 65535), (65535, 1)])
def test_smb2_security_buffer_bounds(dionaea_host, offset, length):
    request = bytearray(setup(b"NTLMSSP\0" + struct.pack("<II", 1, 1)))
    struct.pack_into("<HH", request, 80, offset, length)
    with connect(dionaea_host) as sock:
        sock.sendall(negotiate())
        receive(sock)
        sock.sendall(request)
        try:
            assert sock.recv(1) == b""
        except ConnectionResetError:
            pass


def test_automatic_negotiation_retains_upload_service(dionaea_host):
    conn = SMBConnection(dionaea_host, dionaea_host, sess_port=445, timeout=10)
    try:
        assert conn.getDialect() == SMB_DIALECT
        conn.login("automatic-user", "secret", "AUTHDOMAIN")
        assert conn.connectTree("IPC$")
    finally:
        conn.close()


def test_smb2_netbios_keepalive(dionaea_host):
    with connect(dionaea_host) as sock:
        sock.sendall(negotiate())
        receive(sock)
        sock.sendall(b"\x85\0\0\0" + packet(2, b"\x04\0\0\0", mid=19))
        assert struct.unpack_from("<Q", receive(sock), 24)[0] == 19


def test_malformed_smb1_frame_does_not_discard_following_message(dionaea_host):
    from impacket.smb import NewSMBPacket, SMBCommand
    request = NewSMBPacket()
    command = SMBCommand(SMB.SMB_COM_NEGOTIATE)
    command["Data"] = b"\x02NT LM 0.12\0"
    request.addCommand(command)
    payload = request.getData()
    malformed = bytearray(payload)
    malformed[32] = 255  # word count exceeds this complete frame
    with connect(dionaea_host) as sock:
        sock.sendall(b"\0" + len(malformed).to_bytes(3, "big") + malformed
                     + b"\0" + len(payload).to_bytes(3, "big") + payload)
        assert receive(sock)[:4] == b"\xffSMB"
