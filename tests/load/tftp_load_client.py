# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""TFTP read requests under load, one source address (a client container of tftp_load.py).

    python tftp_load_client.py --host DIONAEA --duration 60 --threads 4 --rate 1200 --out /out/NAME.json

Every thread sends read requests from new source ports at its share of --rate
requests a second, without waiting for a reply (a reply that does not come is no
brake: the ERROR replies of dionaea are rate limited), for a file that exists
(none is acknowledged, so a session waits for its idle timeout; every fourth for
a missing file). It reads the replies that come on the last 64 ports and counts
them by opcode: DATA (a session was made) and ERROR (refused: "Too many sessions",
or the file is missing). Writes the counts as JSON.
"""

import argparse
import collections
import json
import select
import socket
import struct
import threading
import time
from collections import Counter

FILE = b"functional-test.txt"
HELD = 64     # ports kept open for their replies (the session of dionaea is connected to one)


def rrq(name):
    return struct.pack("!H", 1) + name + b"\x00octet\x00"


def count_reply(data, local):
    opcode = struct.unpack("!H", data[:2])[0] if len(data) >= 2 else 0
    if opcode == 3:
        local["data"] += 1
    elif opcode == 5:
        message = data[4:-1].decode("ascii", "replace")
        local["busy" if "Too many" in message else "error"] += 1
    else:
        local["other"] += 1


def drain(sock, local):
    while True:
        try:
            data = sock.recv(2048)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            local["oserror"] += 1
            return
        count_reply(data, local)


def read_replies(held, local, timeout):
    if not held:
        if timeout > 0:
            time.sleep(timeout)
        return
    readable, _, _ = select.select(list(held), [], [], timeout)
    for sock in readable:
        drain(sock, local)


def send_requests(host, until, rate, counts, lock):
    local = Counter()
    held = collections.deque()
    interval = 1.0 / rate
    next_send = time.monotonic()
    i = 0
    while True:
        now = time.monotonic()
        if now >= until:
            break
        if now < next_send:
            read_replies(held, local, next_send - now)
            continue
        next_send = max(next_send + interval, now - 1.0)   # no catching up after a stall of more than a second
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.sendto(rrq(b"missing-%d" % i if i % 4 == 3 else FILE), (host, 69))
            local["sent"] += 1
        except (BlockingIOError, InterruptedError):
            local["send_blocked"] += 1
        except OSError:
            local["oserror"] += 1
        held.append(sock)
        if len(held) > HELD:
            old = held.popleft()
            drain(old, local)
            old.close()
        i += 1
    # the replies on their way
    end = time.monotonic() + 1.0
    while time.monotonic() < end:
        read_replies(held, local, 0.1)
    for sock in held:
        sock.close()
    with lock:
        counts.update(local)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--rate", type=float, default=1200, help="requests a second of all threads (default 1200)")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    counts = Counter()
    lock = threading.Lock()
    until = time.monotonic() + args.duration
    threads = [threading.Thread(target=send_requests, args=(args.host, until, args.rate / args.threads, counts, lock))
               for _ in range(args.threads)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    with open(args.out, "w") as out:
        json.dump(dict(counts), out)
    print(json.dumps(dict(counts)), flush=True)


if __name__ == "__main__":
    main()
