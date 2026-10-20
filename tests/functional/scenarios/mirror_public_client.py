# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Client of host-checks/32-mirror-public.sh (client container with a public address).

The mirror service connects back to a client with a public address, on the port the
client connected to, and passes the data both ways; one mirror per source at a time:

- connection A to --host:--port: dionaea connects back to the listener of the client on
  --port, the line A sends comes out of the connect-back, a line sent into the connect-back
  comes out of A
- connection B from the same source while A is open: no second connect-back
- A closed: connection C gets a connect-back again

Prints one line per step and exits 0 if every step held.
"""

import argparse
import select
import socket
import sys
import time


def read_line(sock, timeout):
    sock.settimeout(timeout)
    data = b""
    try:
        while not data.endswith(b"\n"):
            chunk = sock.recv(100)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data


def connect_back(listener, timeout):
    readable, _, _ = select.select([listener], [], [], timeout)
    if not readable:
        return None
    conn, _addr = listener.accept()
    return conn


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=42)
    args = parser.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("", args.port))
    listener.listen(16)
    ip = socket.gethostbyname(args.host)
    ok = True

    a = socket.create_connection((ip, args.port), timeout=5)
    back = connect_back(listener, 10)
    if back is None:
        print("A: no connect-back within 10 s", flush=True)
        return 1
    print("A: connect-back from %s:%d" % back.getpeername(), flush=True)
    a.sendall(b"from the client\n")
    got = read_line(back, 5)
    print("A -> connect-back: %r" % got, flush=True)
    ok &= got == b"from the client\n"
    back.sendall(b"from the mirror\n")
    got = read_line(a, 5)
    print("connect-back -> A: %r" % got, flush=True)
    ok &= got == b"from the mirror\n"

    b = socket.create_connection((ip, args.port), timeout=5)
    b.sendall(b"second\n")
    second = connect_back(listener, 4)
    print("B while A is open: %s" % ("a second connect-back" if second else "no connect-back"), flush=True)
    ok &= second is None
    if second is not None:
        second.close()
    b.close()

    a.close()
    back.close()
    # the mirror of A ends with A: the source gets its next one
    time.sleep(1)
    c = socket.create_connection((ip, args.port), timeout=5)
    again = connect_back(listener, 10)
    print("C after A closed: %s" % ("connect-back" if again else "no connect-back"), flush=True)
    ok &= again is not None
    if again is not None:
        again.close()
    c.close()
    print("mirror public: %s" % ("ok" if ok else "FAILED"), flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
