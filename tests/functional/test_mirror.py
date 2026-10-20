# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The mirror service (port 42) does not connect back to private addresses.

The client container has a private address on the Docker network. Behind
docker-proxy the client is the bridge gateway, i.e. dionaea itself. A listener
on port 42 in the client sees whether dionaea connects back.
host-checks/30-mirror-loop.sh checks the same from inside the
dionaea container (/proc/net/tcp and tcp6, the image has no ss) together with
the CPU use.
"""

import select
import socket
import time

MIRROR_PORT = 42


def test_no_connect_back_to_a_private_client(dionaea_ip):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("", MIRROR_PORT))
    listener.listen(5)
    try:
        # a few connections from the same source, each sends data
        clients = []
        for _ in range(3):
            c = socket.create_connection((dionaea_ip, MIRROR_PORT), timeout=5)
            c.sendall(b"mirror me\n")
            clients.append(c)

        # nothing may come back (neither a connect-back nor the echoed data)
        deadline = time.monotonic() + 4
        accepted = []
        while time.monotonic() < deadline:
            readable, _, _ = select.select([listener] + clients, [], [], 0.5)
            if listener in readable:
                conn, addr = listener.accept()
                accepted.append(addr)
                conn.close()
            for c in clients:
                if c in readable:
                    data = c.recv(100)
                    assert data == b"", f"dionaea mirrored data to a private client: {data!r}"
        assert not accepted, f"dionaea connected back to the client on port {MIRROR_PORT}: {accepted}"
        for c in clients:
            c.close()
    finally:
        listener.close()
