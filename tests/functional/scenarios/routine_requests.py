# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Requests of every day that are no error of dionaea, for host-checks/48-errors-log.sh.

    python routine_requests.py --host DIONAEA [--rounds 5]

None of them may write a line to dionaea-errors.log (the only log of T-Pot).

- FTP: a login, PWD, SYST, LIST and RETR without a data connection (425), a PORT to
  another address (500), QUIT, and a client that resets after its request (recv ECONNRESET)
- TFTP: read requests for a missing file, for a path outside the root and in mode netascii
  (the session closes itself after its ERROR reply), a whole file (the session closes itself
  on the last ACK, which its own socket read)
- MySQL: a login and a refused statement (load_extension)
- SMB: a message longer than the limit (an HTTP request on port 445), the transactions of
  test_smb_trans.py with data dionaea does not parse (SMB1, impacket login)
- epmap: the first bytes of a DCERPC bind, then the client leaves
- port scans: connections closed with a reset at once

Exit 0 when every service answered as expected; the host check reads the logs.
"""

import argparse
import socket
import struct
import sys
import time

sys.path.insert(0, "/tests")


def ftp(host):
    with socket.create_connection((host, 21), timeout=10) as s:
        f = s.makefile("rwb")

        def reply():
            while True:
                line = f.readline().decode(errors="replace")
                if not line:
                    raise SystemExit("FTP: connection closed")
                if len(line) >= 4 and line[:3].isdigit() and line[3] == " ":
                    return line

        def command(line):
            f.write((line + "\r\n").encode())
            f.flush()
            return reply()

        assert reply().startswith("220")
        assert command("USER routine").startswith("331")
        assert command("PASS routine-secret").startswith("230")
        assert command("PWD").startswith("257")
        assert command("SYST").startswith("215")
        assert command("LIST").startswith("425")
        assert command("RETR functional-list.txt").startswith("425")
        assert command("PORT 203,0,113,9,4,1").startswith("500")
        assert command("QUIT").startswith("221")


def tftp(host, name, mode=b"octet"):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        s.sendto(struct.pack("!H", 1) + name + b"\x00" + mode + b"\x00", (host, 69))
        data, _ = s.recvfrom(1024)
        if struct.unpack("!H", data[:2])[0] != 5:
            raise SystemExit("TFTP: no ERROR for %r %r" % (name, mode))


def tftp_file(host, name):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(5)
        s.sendto(struct.pack("!H", 1) + name + b"\x00octet\x00", (host, 69))
        while True:
            data, peer = s.recvfrom(1024)
            opcode, block = struct.unpack("!HH", data[:4])
            if opcode != 3:
                raise SystemExit("TFTP: no DATA for %r" % name)
            s.sendto(struct.pack("!HH", 4, block), peer)
            if len(data) - 4 < 512:
                return


def mysql(host):
    import pymysql
    cnx = pymysql.connect(user="root", host=host, port=3306, connect_timeout=10, read_timeout=10)
    try:
        cursor = cnx.cursor()
        try:
            cursor.execute("select load_extension('/tmp/x.so')")
        except pymysql.err.MySQLError:
            pass
    finally:
        cnx.close()


def smb_too_long(host):
    with socket.create_connection((host, 445), timeout=10) as s:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        s.settimeout(5)
        try:
            while s.recv(1024):
                pass
        except OSError:
            pass


def smb_trans2(host):
    from smb1_raw import Raw
    from test_smb_trans import PRIMARIES
    raw = Raw(host)
    try:
        for mid, (command, primary) in enumerate(sorted(PRIMARIES.items())):
            raw.replies(raw.message(command, 50 + mid, primary()))
    finally:
        raw.close()


def epmap_partial(host):
    # version 5.0, bind (11), flags, data representation, FragLen 72, AuthLen 0, CallID 1: 16 of 72 bytes
    header = bytes([5, 0, 11, 3, 0x10, 0, 0, 0]) + struct.pack("<HHI", 72, 0, 1)
    with socket.create_connection((host, 135), timeout=10) as s:
        s.sendall(header)
        time.sleep(0.2)


def reset_after_request(host):
    """A request, then a reset while dionaea still reads: recv() of dionaea fails with ECONNRESET.

    Prints the port of the client, which 48-errors-log.sh looks for in the info line of dionaea."""
    s = socket.create_connection((host, 21), timeout=10)
    print("reset after request from port %d" % s.getsockname()[1], flush=True)
    s.recv(1024)
    s.sendall(b"USER x\r\n")
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    s.close()


def reset(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    try:
        s.connect((host, port))
    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--rounds", type=int, default=5)
    args = parser.parse_args()
    for _ in range(args.rounds):
        ftp(args.host)
        tftp(args.host, b"missing-routine.bin")
        tftp(args.host, b"../../etc/passwd")
        tftp(args.host, b"functional.txt", b"netascii")
        tftp_file(args.host, b"functional.txt")
        mysql(args.host)
        smb_too_long(args.host)
        smb_trans2(args.host)
        epmap_partial(args.host)
        for _ in range(10):
            for port in (21, 445):
                reset(args.host, port)
            reset_after_request(args.host)
        # the TFTP replies of the sessions are rate limited per source (burst 20)
        time.sleep(0.5)
    print("routine requests done", flush=True)


if __name__ == "__main__":
    main()
