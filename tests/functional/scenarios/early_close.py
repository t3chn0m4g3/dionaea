# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Clients that leave while dionaea still answers, and MQTT packets across reads.

Run by host-checks/35-early-close.sh in a client container:

    python early_close.py --host DIONAEA [--count 400] [--threads 8]

- HTTPS (443), 8 clients at once: GET /, read the first record, close the socket
  without a TLS shutdown (a quarter of them with a reset, SO_LINGER 0) while
  dionaea still sends the headers and the directory listing.
- the same over plain HTTP (81)
- MQTT (1883): PUBLISH with the first byte of the DISCONNECT in one segment, the
  second byte in the next one.

Exit 0 when dionaea still answers an HTTPS request in full and an MQTT CONNECT
afterwards; the host check reads the Tracebacks from the container log.
"""

import argparse
import socket
import ssl
import struct
import sys
import threading
import time


def tls_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


REQUEST = b"GET / HTTP/1.1\r\nHost: early-close\r\nConnection: close\r\n\r\n"


def leave_early(host, port, tls, reset):
    """GET /, read the first record (or bytes), close without a TLS shutdown."""
    with socket.create_connection((host, port), timeout=10) as raw:
        sock = tls_context().wrap_socket(raw, server_hostname="early-close") if tls else raw
        try:
            sock.sendall(REQUEST)
            sock.recv(4096)
            if reset:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        finally:
            sock.close()   # no unwrap: the TLS session is cut


def full_request(host, port, tls):
    with socket.create_connection((host, port), timeout=10) as raw:
        sock = tls_context().wrap_socket(raw, server_hostname="early-close") if tls else raw
        sock.sendall(REQUEST)
        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        return data


def mqtt_connect_packet(clientid=b"early-close"):
    body = b"\x00\x04MQTT\x04\x02" + struct.pack("!H", 60) + struct.pack("!H", len(clientid)) + clientid
    return b"\x10" + bytes([len(body)]) + body


def mqtt_split(host):
    with socket.create_connection((host, 1883), timeout=10) as sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.sendall(mqtt_connect_packet())
        if not sock.recv(4).startswith(b"\x20"):
            raise AssertionError("no CONNACK")
        topic = b"early/close"
        sock.sendall(b"\x30" + bytes([2 + len(topic) + 2]) + struct.pack("!H", len(topic)) + topic + b"hi" + b"\xe0")
        time.sleep(0.05)
        sock.sendall(b"\x00")
        time.sleep(0.05)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--count", type=int, default=400, help="rounds of 3 HTTPS and 1 HTTP request")
    parser.add_argument("--threads", type=int, default=8)
    args = parser.parse_args()
    errors = []

    def worker(offset):
        for i in range(offset, args.count, args.threads):
            for port, tls in ((443, True), (443, True), (443, True), (81, False)):
                try:
                    leave_early(args.host, port, tls, reset=i % 4 == 1)
                except OSError as error:
                    errors.append(error)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(args.threads)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    for _ in range(20):
        try:
            mqtt_split(args.host)
        except (OSError, AssertionError) as error:
            errors.append(error)
    print("early closes done, %d connection errors" % len(errors), flush=True)
    answer = full_request(args.host, 443, True)
    if not answer.startswith(b"HTTP/1.") or b"</html>" not in answer.lower():
        print("HTTPS does not answer in full afterwards: %r" % answer[:200], flush=True)
        return 1
    with socket.create_connection((args.host, 1883), timeout=10) as sock:
        sock.sendall(mqtt_connect_packet(b"after"))
        if not sock.recv(4).startswith(b"\x20"):
            print("MQTT does not answer afterwards", flush=True)
            return 1
    print("dionaea answers HTTPS and MQTT afterwards", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
