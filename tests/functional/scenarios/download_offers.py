# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Download offers and the log lines they give, for host-checks/51-download-log.sh (client container).

    python download_offers.py offer --host DIONAEA --seconds 65 --out /out/offers.json
    python download_offers.py check --offers /out/offers.json --errors dionaea-errors.log --log dionaea.log

offer: three TFTP downloads from 127.0.0.1 (a command in shellcode on port 445, the emu offers
them), then for --seconds, four offers a second over the MySQL service (``xpdl3('<url>') into
dumpfile``) in turn: HTTP and FTP from 127.0.0.1, which the download target filter refuses,
and HTTP and FTP from a closed port of this container, which the filter allows (the network of
the test is in allowed_networks) and which fail. Every url has a marker of its own; the urls
go to --out.

check: dionaea-errors.log has no line of a refused target and no info line of a failure;
it has a summary warning ``downloads: <N> failed in the last minute, the last: <url>
(<reason>)`` at most once a minute, at least two for the 65 s of failures, and the N of
them add up to the failed offers. dionaea.log has one info line per refused target and per
failure.
"""

import argparse
import json
import re
import socket
import sys
import time
import uuid
from datetime import datetime

sys.path.insert(0, "/tests")

CLOSED_PORT = 9
SUMMARY = re.compile(r"^\[(\d{8} \d\d:\d\d:\d\d)\] .*-warning: downloads: (\d+) failed in the last minute, "
                     r"the last: (\S+) \((.*)\)$")
# lines that must not be in dionaea-errors.log
NOT_IN_ERRORS = ("download target refused", "-warning: download failed", "-info: download failed",
                 "DOWNLOAD FAIL", "failed to open socket", "Download destination denied", "Could not connect")


def own_address(host):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((host, 9))
        return s.getsockname()[0]


def mysql_offers(host):
    import pymysql

    cnx = None
    while True:
        url = yield
        if cnx is None:
            cnx = pymysql.connect(user="root", host=host, port=3306, connect_timeout=10, read_timeout=10)
        try:
            cnx.cursor().execute("select xpdl3('%s') into dumpfile 'x'" % url)
        except pymysql.err.OperationalError:
            # the offer is made; the next one comes on a new connection
            cnx = None
        except pymysql.err.MySQLError:
            pass


def offer(args):
    from test_emu import winexec_shellcode

    me = own_address(args.host)
    out = {"refused": [], "failed": [], "tftp_refused_markers": []}
    for _ in range(3):
        name = "refused-%s" % uuid.uuid4().hex
        command = "cmd.exe /c tftp -i 127.0.0.1 GET %s" % name
        with socket.create_connection((args.host, 445), timeout=10) as sock:
            sock.sendall(winexec_shellcode(command.encode()))
            time.sleep(0.5)
        out["tftp_refused_markers"].append(name)
    sender = mysql_offers(args.host)
    next(sender)
    kinds = (
        ("refused", "http://127.0.0.1:81/refused-%s"),
        ("refused", "ftp://127.0.0.1/refused-%s"),
        ("failed", "http://%s:%d/failed-%%s" % (me, CLOSED_PORT)),
        ("failed", "ftp://%s:%d/failed-%%s" % (me, CLOSED_PORT)),
    )
    start = time.monotonic()
    i = 0
    while time.monotonic() - start < args.seconds:
        kind, pattern = kinds[i % len(kinds)]
        url = pattern % uuid.uuid4().hex
        sender.send(url)
        out[kind].append(url)
        i += 1
        time.sleep(max(0.0, start + i / args.rate - time.monotonic()))
    out["seconds"] = time.monotonic() - start
    with open(args.out, "w") as f:
        json.dump(out, f)
    print("offered %d refused and %d failing downloads in %.0f s, 3 TFTP from 127.0.0.1" % (
        len(out["refused"]), len(out["failed"]), out["seconds"]))


def check(args):
    with open(args.offers) as f:
        offers = json.load(f)
    errors = open(args.errors, errors="replace").read().splitlines()
    log = open(args.log, errors="replace").read().splitlines()
    problems = []

    markers = [u.rsplit("/", 1)[1] for u in offers["refused"]] + offers["tftp_refused_markers"]
    # the summary names the reason of the last failure (curl's "Could not connect to server")
    unwanted = [line for line in errors if not SUMMARY.match(line) and (
        any(text in line for text in NOT_IN_ERRORS) or "refused-" in line)]
    print("%d lines of refused targets or failed downloads in dionaea-errors.log" % len(unwanted))
    if unwanted:
        problems.append("%d lines in dionaea-errors.log of refused targets or failed downloads, e.g. %s" % (
            len(unwanted), " | ".join(line[:200] for line in unwanted[:3])))

    summaries = [SUMMARY.match(line) for line in errors]
    summaries = [m for m in summaries if m]
    times = [datetime.strptime(m.group(1), "%d%m%Y %H:%M:%S") for m in summaries]
    total = sum(int(m.group(2)) for m in summaries)
    print("%d summary warnings: %s" % (len(summaries), ", ".join(
        "%s N=%s" % (m.group(1), m.group(2)) for m in summaries)))
    if not 2 <= len(summaries) <= 3:
        problems.append("%d summary warnings, 2 or 3 expected" % len(summaries))
    for earlier, later in zip(times, times[1:]):
        if (later - earlier).total_seconds() < 59:
            problems.append("two summary warnings %s apart" % (later - earlier))
    if total != len(offers["failed"]):
        problems.append("the summaries count %d failures, %d downloads failed" % (total, len(offers["failed"])))
    failed = set(offers["failed"])
    for m in summaries:
        if m.group(3) not in failed:
            problems.append("the last url of a summary is not a failed offer: %s" % m.group(3))

    def info_count(prefix, needle):
        return sum(1 for line in log if "-info: " + prefix in line and needle in line)

    failed_once = sum(1 for url in offers["failed"] if info_count("download failed: ", url + " (") == 1)
    refused_once = sum(1 for marker in markers if info_count("download target refused by the filter: ", marker) == 1)
    print("info lines in dionaea.log: %d of %d failed and %d of %d refused downloads have exactly one" % (
        failed_once, len(offers["failed"]), refused_once, len(markers)))
    if failed_once != len(offers["failed"]):
        problems.append("%d failed downloads without exactly one info line" % (len(offers["failed"]) - failed_once))
    if refused_once != len(markers):
        problems.append("%d refused targets without exactly one info line" % (len(markers) - refused_once))
    for problem in problems[:40]:
        print("FAIL: " + problem)
    return 1 if problems else 0


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("offer")
    p.add_argument("--host", required=True)
    p.add_argument("--seconds", type=float, default=65)
    p.add_argument("--rate", type=float, default=4, help="offers a second (default 4)")
    p.add_argument("--out", required=True)
    p = sub.add_parser("check")
    p.add_argument("--offers", required=True)
    p.add_argument("--errors", required=True)
    p.add_argument("--log", required=True)
    args = parser.parse_args()
    if args.command == "offer":
        offer(args)
        return 0
    return check(args)


if __name__ == "__main__":
    sys.exit(main())
