# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Shellcode detection and profiling of the emu module (bundled libemu).

The sample is built here, so every run has its own marker in the command line:

    call $+5 / pop esi          GetPC, found by emu_shellcode_test
    xor ecx,ecx / mov cl,0x40   a loop of 64 x 2 steps (libemu only reports
    add ebx,1 / loop            code that runs for more than 100 steps)
    push 1 / lea eax,[esi+24] / push eax
    mov eax,0x7c86136d / call eax   kernel32!WinExec, address in libemu's kernel32
    ret
    "cmd.exe /c echo <marker>"

The emu processor of the T-Pot config (filter_emu: smbd, epmapper, ...) finds
it in the stream, runs it in the emulator and emits dionaea.module.emu.profile;
log_sqlite stores the API calls in emu_profiles.
"""

import json
import socket
import struct
import time
import uuid

import pytest


WINEXEC = 0x7C86136D  # kernel32 base 0x7c800000 + export RVA 0x6136d of libemu


def winexec_shellcode(command):
    code = (
        b"\xe8\x00\x00\x00\x00"      # call $+5
        b"\x5e"                      # pop esi (esi = address of this pop)
        b"\x31\xc9"                  # xor ecx,ecx
        b"\xb1\x40"                  # mov cl,0x40
        b"\x83\xc3\x01"              # add ebx,1
        b"\xe2\xfb"                  # loop -5
        b"\x6a\x01"                  # push 1 (uCmdShow)
        b"\x8d\x46\x18"              # lea eax,[esi+24] (the command, 29 - 5)
        b"\x50"                      # push eax (lpCmdLine)
        b"\xb8" + struct.pack("<I", WINEXEC) +  # mov eax,WinExec
        b"\xff\xd0"                  # call eax
        b"\xc3"                      # ret
    )
    assert len(code) == 29
    return code + command + b"\x00"


def pe_resolved_winexec_shellcode(command):
    """Own emulator fixture: resolve WinExec through PEB and PE export tables.

    It contains no Windows code and only calls the emulator's WinExec hook.
    Name comparison, ordinal lookup and EAT lookup use the generated PE data.
    """
    code = bytearray(bytes.fromhex(
        "e800000000 5d 31c9 b140 83c301 e2fb"  # GetPC and detection loop
        "31c0 648b4030 8b400c 8b401c 8b00 8b5808"  # PEB -> kernel32 base
        "8b7b3c 01df 8b7f78 01df"  # PE -> export directory
        "8b7720 01de 8b4f18"  # name pointer table and count
    ))
    search = len(code)
    code.extend(bytes.fromhex("49 8b048e 01d8 813857696e45"))  # compare WinE
    code.extend(b"\x75\x00")
    first_jump = len(code) - 1
    code.extend(bytes.fromhex("81780478656300"))  # compare xec + NUL
    code.extend(b"\x75\x00")
    second_jump = len(code) - 1
    for jump in (first_jump, second_jump):
        code[jump] = (search - jump - 1) & 0xff
    code.extend(bytes.fromhex(
        "8b5724 01da 0fb70c4a"  # name index -> export ordinal index
        "8b7f1c 01df 8b048f 01d8 6a01"  # EAT -> WinExec; show=1
    ))
    code.extend(b"\x8d\x95" + b"\x00" * 4)  # lea edx,[ebp+command offset]
    displacement = len(code) - 4
    code.extend(bytes.fromhex("52 ffd0 c3"))
    struct.pack_into("<I", code, displacement, len(code) - 5)
    return bytes(code) + command + b"\x00"


def _profiles_with(query_db, marker):
    try:
        rows = query_db("SELECT emu_profile_json FROM emu_profiles")
    except Exception:
        # the table or the file is not there yet
        return []
    return [row["emu_profile_json"] for row in rows if marker in (row["emu_profile_json"] or "")]


@pytest.mark.parametrize("port", [445, 135])
@pytest.mark.parametrize("builder", [winexec_shellcode, pe_resolved_winexec_shellcode])
def test_shellcode_is_detected_and_profiled(dionaea_host, query_db, port, builder):
    marker = "emu-%d-%s" % (port, uuid.uuid4().hex[:12])
    payload = builder(("cmd.exe /c echo %s" % marker).encode())

    with socket.create_connection((dionaea_host, port), timeout=10) as sock:
        sock.sendall(payload)
        time.sleep(1)

    deadline = time.monotonic() + 30
    found = []
    while not found and time.monotonic() < deadline:
        found = _profiles_with(query_db, marker)
        if not found:
            time.sleep(0.5)
    assert found, "no emu profile with %r in emu_profiles within 30 s" % marker

    calls = json.loads(found[0])
    assert [call["call"] for call in calls] == ["WinExec"]
    assert marker in json.dumps(calls[0]["args"])


def test_shellcode_without_getpc_is_not_profiled(dionaea_host, query_db):
    # the same code with the call/pop GetPC replaced by nops is not detected;
    # a detected sample sent afterwards shows that the emu processor is working
    marker = "emu-nogetpc-%s" % uuid.uuid4().hex[:12]
    control = "emu-control-%s" % uuid.uuid4().hex[:12]
    broken = winexec_shellcode(("cmd.exe /c echo %s" % marker).encode())
    broken = b"\x90" * 6 + broken[6:]

    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        sock.sendall(broken)
        time.sleep(1)
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        sock.sendall(winexec_shellcode(("cmd.exe /c echo %s" % control).encode()))
        time.sleep(1)

    deadline = time.monotonic() + 30
    while not _profiles_with(query_db, control) and time.monotonic() < deadline:
        time.sleep(0.5)
    assert _profiles_with(query_db, control), "the control sample was not profiled"
    assert not _profiles_with(query_db, marker), "a sample without GetPC was profiled"


# The emu processor scans a long stream in windows of at most 64 KiB of new data
# plus 300 bytes of the window before (modules/emu/detect.c, 65535 bytes at
# most). The stream below is NetBIOS frames of a type smbd ignores (0x86), so
# the connection stays open; the filler is ret (0xc3), no GetPC.
SCAN_WINDOW = 65535


def nbt_stream(total, blob, at, frame_body=40000):
    """total bytes of NetBIOS frames with blob at the absolute offset at."""
    data = bytearray(b"\xc3" * total)
    pos = 0
    while pos < total:
        assert total - pos >= 5
        end = min(total, pos + 4 + frame_body)
        if at - 4 < end < at + len(blob):
            # no frame header inside the blob
            end = min(total, at + len(blob))
        if 0 < total - end < 5:
            end = total
        data[pos:pos + 4] = bytes([0x86]) + (end - pos - 4).to_bytes(3, "big")
        assert not (at <= pos < at + len(blob))
        pos = end
    data[at:at + len(blob)] = blob
    return bytes(data)


def _wait_for_profile(query_db, marker, interval=0.5):
    deadline = time.monotonic() + 60
    found = []
    while not found and time.monotonic() < deadline:
        found = _profiles_with(query_db, marker)
        if not found:
            time.sleep(interval)
    assert found, "no emu profile with %r in emu_profiles within 60 s" % marker
    calls = json.loads(found[0])
    assert [call["call"] for call in calls] == ["WinExec"]
    assert marker in json.dumps(calls[0]["args"])


@pytest.mark.parametrize("windows", [3, 8])
def test_shellcode_after_several_windows_is_profiled(dionaea_host, query_db, windows):
    marker = "streams-%dw-%s" % (windows, uuid.uuid4().hex[:12])
    shellcode = winexec_shellcode(("cmd.exe /c echo %s" % marker).encode())
    at = windows * SCAN_WINDOW + 1234
    stream = nbt_stream(at + 4096, shellcode, at)
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        sock.sendall(stream)
        time.sleep(1)
    _wait_for_profile(query_db, marker)


@pytest.mark.parametrize("offset", [SCAN_WINDOW - 10, 2 * SCAN_WINDOW - 300 - 20])
def test_shellcode_across_a_window_end_in_fragments_is_profiled(dionaea_host, query_db, offset):
    """In small pieces, so the emu jobs run while the stream arrives."""
    marker = "streams-cut-%d-%s" % (offset, uuid.uuid4().hex[:12])
    shellcode = winexec_shellcode(("cmd.exe /c echo %s" % marker).encode())
    stream = nbt_stream(offset + 8192, shellcode, offset)
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for start in range(0, len(stream), 1460):
            sock.sendall(stream[start:start + 1460])
            if start % (16 * 1460) == 0:
                time.sleep(0.01)
        time.sleep(1)
    _wait_for_profile(query_db, marker)


def _still_open(sock, timeout=1.0):
    """True if the peer neither closed nor reset the connection."""
    sock.settimeout(timeout)
    try:
        return sock.recv(1) != b""
    except socket.timeout:
        return True
    except OSError:
        return False


LONG_STREAM = 2 * 1024 * 1024


def test_shellcode_before_a_long_stream_is_profiled_once(dionaea_host, query_db):
    """Detected in the first window; the emu keeps nothing of the 2 MiB behind it.

    The stream after the detection is twice the stream data limit of one
    processor instance (1 MiB, include/bistream.h): had the emu kept it, the
    connection would be closed as overloaded. The shellcode goes first and the
    rest only once it is profiled, so the scan of the first window does not
    race the burst (see the next test).

    The check has to be done within 3 s of the profile: emu.py then sets the
    sustain timeout of the connection to 3 s, so dionaea closes it on purpose.
    log_sqlite commits once a second, the profile is in emu_profiles up to a
    second after it was made; the test polls every 0.1 s and checks the
    connection 0.2 s after the burst (with a 1 s wait it saw that close).
    """
    marker = "streams-first-%s" % uuid.uuid4().hex[:12]
    shellcode = winexec_shellcode(("cmd.exe /c echo %s" % marker).encode())
    stream = nbt_stream(LONG_STREAM, shellcode, 1000)
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        sock.sendall(stream[:8192])
        _wait_for_profile(query_db, marker, interval=0.1)
        sock.sendall(stream[8192:])
        time.sleep(0.2)
        assert _still_open(sock, timeout=0.3), "the connection was closed after the shellcode was profiled"
    time.sleep(1)
    assert len(_profiles_with(query_db, marker)) == 1


def test_burst_faster_than_the_scan_is_profiled(dionaea_host, query_db):
    """2 MiB in one burst, the shellcode in the first window.

    A 64 KiB window with a GetPC candidate takes the emu tens of milliseconds
    (libemu runs from every candidate), the burst arrives faster. What arrives
    meanwhile is kept for the scan and may cross the 1 MiB limit of the
    instance: then the emu gives up on the rest (logged once), the connection
    stays open. The window under scan is finished: the shellcode is still
    profiled, once.
    """
    marker = "streams-burst-%s" % uuid.uuid4().hex[:12]
    shellcode = winexec_shellcode(("cmd.exe /c echo %s" % marker).encode())
    stream = nbt_stream(LONG_STREAM, shellcode, 1000)
    with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
        sock.sendall(stream)
        time.sleep(1)
        assert _still_open(sock), "the connection was closed during the burst"
    _wait_for_profile(query_db, marker)
    time.sleep(1)
    assert len(_profiles_with(query_db, marker)) == 1
