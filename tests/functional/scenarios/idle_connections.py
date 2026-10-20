# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Idle connections for host-checks/10-fd-limit.sh (client container).

Opens --count idle TCP connections to each of --ports (non-blocking, they
may stay in the backlog), prints "holding", holds them for --hold seconds,
closes them, prints "closed", then waits up to --banner-timeout seconds for
a new connection to --banner-port that sends a 220 banner. Exit 0 if the
banner came.
"""

import argparse
import select
import socket
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--ports", required=True)
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--hold", type=float, default=15.0)
    parser.add_argument("--banner-port", type=int, default=21)
    parser.add_argument("--banner-timeout", type=float, default=30.0)
    args = parser.parse_args()

    ip = socket.gethostbyname(args.host)
    socks = []
    for port in (int(p) for p in args.ports.split(",")):
        for _ in range(args.count):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            s.connect_ex((ip, port))
            socks.append((port, s))
    time.sleep(2)
    _, writable, _ = select.select([], [s for _, s in socks], [], 0)
    print("connections opened: %d, established: %d" % (len(socks), len(writable)), flush=True)
    print("holding", flush=True)
    time.sleep(args.hold)
    for _, s in socks:
        s.close()
    print("closed", flush=True)

    deadline = time.monotonic() + args.banner_timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((ip, args.banner_port), timeout=3) as c:
                c.settimeout(3)
                banner = c.recv(128)
            if banner.startswith(b"220"):
                print("banner on %d: %r" % (args.banner_port, banner.strip()), flush=True)
                return 0
        except OSError:
            pass
        time.sleep(0.5)
    print("no banner on %d within %.0fs" % (args.banner_port, args.banner_timeout), flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
