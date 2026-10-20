# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Client of host-checks/30-mirror-loop.sh (client container).

Listens on --port, opens --count connections to --host:--port (all from the
same source address, each sends a line), prints "holding", holds them for
--hold seconds and counts what comes back: connections to the listener
(connect-back of the mirror) and data on the client connections (mirrored).
Exit 0 if nothing came back.
"""

import argparse
import select
import socket
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=42)
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--hold", type=float, default=12.0)
    args = parser.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("", args.port))
    listener.listen(16)

    ip = socket.gethostbyname(args.host)
    clients = []
    for _ in range(args.count):
        c = socket.create_connection((ip, args.port), timeout=5)
        c.sendall(b"mirror me\n")
        clients.append(c)
    print("holding", flush=True)

    accepted = []
    connect_backs = 0
    mirrored = 0
    end = time.monotonic() + args.hold
    while time.monotonic() < end:
        readable, _, _ = select.select([listener] + clients, [], [], 0.5)
        if listener in readable:
            conn, _addr = listener.accept()
            connect_backs += 1
            accepted.append(conn)  # held open, so the host check sees it
        for c in list(clients):
            if c in readable:
                if c.recv(100):
                    mirrored += 1
                else:
                    clients.remove(c)
    print(f"connect-backs: {connect_backs}, mirrored reads: {mirrored}", flush=True)
    return 0 if connect_backs == 0 and mirrored == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
