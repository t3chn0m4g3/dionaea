#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""TFTP read requests under load against dionaea as in T-Pot (see README.md).

    tests/load/tftp_load.py --image IMAGE [--duration 60] [--clients 20] [--artifacts DIR]

dionaea runs as in the replay (T-Pot configuration and limits, replay.Replay).
--clients client containers (one source address each) send TFTP read requests at
--rate a second each (default 1200, 24,000 a second in all), without waiting for a
reply and without acknowledging a block, for --duration seconds.
dionaea is sampled every 2 s: its sessions (the connected UDP sockets in
/proc/net/udp), per source address, fds, RSS. Pass:

- never more than 64 sessions, never more than 4 of one source address (counted
  above the connected UDP sockets dionaea has when idle: the resolver)
- fds at most the idle count + 2 x 64 + 16 (a session has its socket and the file it
  sends), RSS at most 64 MiB above the idle RSS
- no restart, no OOM kill, no Traceback
- the clients got DATA (sessions were made) and "Too many sessions" ERRORs (refused)
- the ERROR replies of the server socket are rate limited: at most 10 a second per
  source (burst 20) and 200 a second in all (burst 200), the rest gets no reply
- 15 s after the load no session is left (they expire), and a TFTP read request
  and the FTP banner are answered

Exit 0 pass, 1 fail, 3 environment.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import replay  # noqa: E402
from run import BAD_LOG, CLIENT_IMAGE, docker, say  # noqa: E402

MAX_SESSIONS = 64
MAX_PER_SOURCE = 4
FD_MARGIN = 16
FDS_PER_SESSION = 2   # its UDP socket and the file it sends
RSS_MARGIN_MIB = 64
EXPIRE_S = 15
# the rate limit of the ERROR replies of the server socket (tftp.py ERRORS_*)
ERRORS_PER_SOURCE_RATE, ERRORS_PER_SOURCE_BURST = 10, 20
ERRORS_RATE, ERRORS_BURST = 200, 200
ERRORS_SLACK_S = 2      # the client reads replies a second after its load

# connected UDP sockets of dionaea: the TFTP sessions (the listeners have no remote address)
SESSIONS = ("cat /proc/net/udp /proc/net/udp6 2>/dev/null | "
            "awk 'NR > 1 && $3 !~ /:0000$/ {split($3, r, \":\"); print r[1]}'")

POST = r"""
import socket, struct, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(5)
s.sendto(struct.pack("!H", 1) + b"functional-test.txt\x00octet\x00", (sys.argv[1], 69))
data, peer = s.recvfrom(2048)
assert data[:2] == b"\x00\x03" and b"tftp functional test file" in data, data
s.sendto(struct.pack("!HH", 4, 1), peer)
c = socket.create_connection((sys.argv[1], 21), timeout=10)
assert c.recv(1024).startswith(b"220"), "no FTP banner"
print("tftp and ftp answer")
"""


class TftpLoad:
    def __init__(self, args, root):
        self.args = args
        self.root = root
        ns = argparse.Namespace(config=args.config, platform=args.platform, quick=True, duration=1,
                                concurrency=0, idle=0, interval=2)
        self.replay = replay.Replay(ns, args.image, root)
        self.clients = ["%s-tftpload-%d" % (self.replay.server, n) for n in range(args.clients)]
        self.checks = []
        self.samples = []
        self.per_client = {}

    def check(self, name, ok, **details):
        self.checks.append({"name": name, "ok": bool(ok), **details})
        say("%s %s %s" % ("PASS" if ok else "FAIL", name, json.dumps(details)[:300]))

    def sample(self):
        try:
            return self._sample()
        except subprocess.TimeoutExpired as error:
            # docker exec / stats can take longer than their timeout under the load: a gap, no result
            row = {"epoch": time.time(), "sample_failed": str(error)[:200]}
            self.samples.append(row)
            return row

    def _sample(self):
        row = self.replay.sample()
        if row.get("running"):
            out = docker("exec", self.replay.server, "sh", "-c", replay.SAMPLE
                         + "; echo ---; " + SESSIONS, capture_output=True, check=False, timeout=60).stdout
            remotes = out.split("---", 1)[1].split() if "---" in out else []
            per_source = Counter(remotes)
            row["sessions"] = len(remotes)
            row["max_per_source"] = max(per_source.values()) if per_source else 0
        self.samples.append(row)
        return row

    def execute(self):
        r = self.replay
        try:
            r.prepare()
            r.start_server()
            time.sleep(5)
            idle = self.sample()
            say("idle: rss %.1f MiB, fds %s" % (idle.get("VmRSS", 0) / 1024, idle.get("Fds")))
            (self.root / "out").mkdir(exist_ok=True)
            for name in self.clients:
                docker("run", "-d", "--name", name, "--network", r.network, *replay.CLIENT_LIMITS[:2],
                       "-v", "%s:/work:ro" % HERE, "-v", "%s:/out" % (self.root / "out"), CLIENT_IMAGE,
                       "python", "/work/tftp_load_client.py", "--host", r.server, "--duration",
                       str(self.args.duration), "--threads", str(self.args.threads), "--rate", str(self.args.rate),
                       "--out", "/out/%s.json" % name,
                       stdout=subprocess.DEVNULL)
            deadline = time.monotonic() + self.args.duration + 60
            while time.monotonic() < deadline:
                time.sleep(2)
                row = self.sample()
                say("t=%3.0fs sessions=%s max/source=%s fds=%s rss=%.1f MiB restarts=%s" % (
                    row["epoch"] - idle["epoch"], row.get("sessions"), row.get("max_per_source"), row.get("Fds"),
                    row.get("VmRSS", 0) / 1024, row.get("restarts")))
                if row.get("sample_failed"):
                    continue
                if not row.get("running") or row.get("restarts"):
                    break
                running = docker("ps", "-q", "--filter", "name=%s-tftpload-" % r.server,
                                 capture_output=True).stdout.split()
                if not running:
                    break
            load_end = time.time()
            time.sleep(EXPIRE_S)
            after = self.sample()
            counts = Counter()
            for name in self.clients:
                try:
                    self.per_client[name] = json.loads((self.root / "out" / ("%s.json" % name)).read_text())
                    counts.update(self.per_client[name])
                except (OSError, ValueError):
                    counts["client_missing"] += 1
            post = docker("run", "--rm", "--network", r.network, CLIENT_IMAGE, "python", "-c", POST, r.server,
                          capture_output=True, check=False, timeout=60)
            self.judge(idle, after, counts, post, load_end)
            docker("stop", "-t", "60", r.server, stdout=subprocess.DEVNULL, check=False)
            log = docker("logs", r.server, capture_output=True, check=False)
            text = log.stdout + log.stderr
            (self.root / "container.log").write_text(text)
            self.check("no Traceback, LoaderError or crash in the container log", not BAD_LOG.search(text),
                       found=BAD_LOG.findall(text)[:3])
        finally:
            for name in self.clients:
                docker("rm", "-f", name, capture_output=True, check=False)
            summary = {"image": self.args.image, "clients": self.args.clients, "threads": self.args.threads,
                       "rate_per_client": self.args.rate, "duration_s": self.args.duration,
                       "dionaea_run_args": os.environ.get("DIONAEA_RUN_ARGS", ""), "checks": self.checks,
                       "per_client": self.per_client,
                       "pass": bool(self.checks) and all(c["ok"] for c in self.checks), "samples": self.samples}
            (self.root / "summary.json").write_text(json.dumps(summary, indent=1) + "\n")
            if not self.args.keep:
                r.cleanup()
        return summary["pass"]

    def judge(self, idle, after, counts, post, load_end):
        load = [s for s in self.samples[1:] if s["epoch"] <= load_end and s.get("running")]
        base = idle.get("sessions", 0)
        sessions = max([s.get("sessions", 0) for s in load] or [0]) - base
        per_source = max([s.get("max_per_source", 0) for s in load] or [0])
        fds = max([s.get("Fds", 0) for s in load] or [0])
        rss = max([s.get("VmRSS", 0) for s in load] or [0]) / 1024
        restarts = {s.get("restarts") for s in self.samples if s.get("restarts") is not None}
        sampled = [s for s in self.samples if not s.get("sample_failed")]
        self.check("no restart, no OOM kill, dionaea runs", restarts == {0} and all(s.get("running") for s in sampled)
                   and not any(s.get("oom") for s in self.samples), restarts=sorted(restarts),
                   samples_failed=len(self.samples) - len(sampled))
        self.check("at most %d sessions, at most %d per source address" % (MAX_SESSIONS, MAX_PER_SOURCE),
                   load and sessions <= MAX_SESSIONS and per_source <= MAX_PER_SOURCE,
                   max_sessions=sessions, max_per_source=per_source, idle_connected_sockets=base, samples=len(load))
        self.check("fds at most idle + %d x %d + %d" % (FDS_PER_SESSION, MAX_SESSIONS, FD_MARGIN),
                   load and fds <= idle["Fds"] + FDS_PER_SESSION * MAX_SESSIONS + FD_MARGIN, idle=idle["Fds"], max=fds)
        self.check("RSS at most %d MiB above idle" % RSS_MARGIN_MIB,
                   load and rss <= idle["VmRSS"] / 1024 + RSS_MARGIN_MIB,
                   idle_mib=round(idle["VmRSS"] / 1024, 1), max_mib=round(rss, 1))
        self.check("the load got sessions (DATA) and refusals (Too many sessions)",
                   counts["data"] > 0 and counts["busy"] > 0, **dict(counts))
        seconds = self.args.duration + ERRORS_SLACK_S
        busy_max = max([c.get("busy", 0) for c in self.per_client.values()] or [0])
        self.check("ERROR replies at most %d/s per source (burst %d), %d/s in all (burst %d)" % (
                   ERRORS_PER_SOURCE_RATE, ERRORS_PER_SOURCE_BURST, ERRORS_RATE, ERRORS_BURST),
                   busy_max <= seconds * ERRORS_PER_SOURCE_RATE + ERRORS_PER_SOURCE_BURST
                   and counts["busy"] <= seconds * ERRORS_RATE + ERRORS_BURST,
                   busy=counts["busy"], busy_bound=int(seconds * ERRORS_RATE + ERRORS_BURST),
                   busy_max_per_source=busy_max,
                   per_source_bound=int(seconds * ERRORS_PER_SOURCE_RATE + ERRORS_PER_SOURCE_BURST),
                   requests=counts["sent"])
        self.check("%d s after the load no session is left" % EXPIRE_S,
                   after.get("running") and after.get("sessions") == base
                   and after.get("Fds", 1 << 20) <= idle["Fds"] + 4,
                   sessions=after.get("sessions", 0) - base, fds=after.get("Fds"), idle_fds=idle["Fds"])
        self.check("afterwards a TFTP read request and the FTP banner are answered", post.returncode == 0,
                   output=(post.stdout + post.stderr).strip()[-300:])


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", default="dionaea:local")
    parser.add_argument("--duration", type=float, default=60, help="seconds of load (default 60)")
    parser.add_argument("--clients", type=int, default=20,
                        help="client containers, one source address each (default 20)")
    parser.add_argument("--threads", type=int, default=4, help="threads per client (default 4)")
    parser.add_argument("--rate", type=float, default=1200, help="requests a second per client (default 1200)")
    parser.add_argument("--platform")
    parser.add_argument("--config", type=Path, default=replay.DEFAULT_CONFIG, required=replay.DEFAULT_CONFIG is None)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if shutil.which("docker") is None or docker("info", capture_output=True, check=False).returncode != 0:
        print("docker is not available", file=sys.stderr)
        return 3
    root = (args.artifacts or Path(tempfile.mkdtemp(prefix="dionaea-tftp-load."))).resolve()
    if root.exists() and any(root.iterdir()):
        print("%s is not empty" % root, file=sys.stderr)
        return 3
    root.mkdir(parents=True, exist_ok=True)
    docker("build", "-q", "-t", CLIENT_IMAGE, str(replay.FUNCTIONAL / "client"), stdout=subprocess.DEVNULL)
    passed = TftpLoad(args, root).execute()
    say("%s, artifacts in %s" % ("PASSED" if passed else "FAILED", root))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
