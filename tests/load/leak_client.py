# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""One scenario of replay_client.py n times, one connection at a time (the client of leak.py).

    python leak_client.py SCENARIO COUNT [--seed N] [--unique-share X]

Prints one JSON line: the scenario, how many worked and failed, the first errors.
"""

import argparse
import json
import random
import socket
import sys

sys.path.insert(0, "/work")

import replay_client as rc  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("scenario")
    parser.add_argument("count", type=int)
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--unique-share", type=float, default=0.15)
    args = parser.parse_args()
    rc.UNIQUE_SHARE = args.unique_share
    rc.POOL = rc.make_pool(args.seed)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.connect((socket.gethostbyname(rc.HOST), 9))
    address = probe.getsockname()[0]
    probe.close()
    rc.CONTENT = rc.Content(rc.POOL, address)
    http_server = rc.TrimmedHttpServer(rc.CONTENT, address)
    rc.CONTENT.http_port = http_server.port
    rc.CountingTftp(rc.TftpFiles(rc.CONTENT), address).start()
    rnd = random.Random(args.seed)
    for _ in range(args.count):
        rc.run_scenario(args.scenario, rnd)
    print(json.dumps({"scenario": args.scenario, "ok": rc.STATS.ok[args.scenario], "err": rc.STATS.err[args.scenario],
                      "errors": sorted(set(rc.STATS.errors[args.scenario]))[:3]}), flush=True)


if __name__ == "__main__":
    main()
