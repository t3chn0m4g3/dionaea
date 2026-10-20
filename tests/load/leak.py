#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Memory per scenario: does a connection leave anything behind? (see README.md)

    tests/load/leak.py --image IMAGE                         # the upload scenarios
    tests/load/leak.py --image IMAGE --scenarios ftp_stor --warm 500 --step 1000 --steps 3 --trace

For every scenario a fresh dionaea as in the replay (T-Pot configuration and limits)
with leak_probe.py loaded. The scenario of replay_client.py runs --warm times (the
working set: caches, the sqlite pages, the arenas of malloc), then --steps times
--step times, one connection at a time; after each part the probe counts, after a
full collection, the objects the GC tracks and the heap glibc has in use (mallinfo2).
Pass:

- the objects grow by at most 0.01 per scenario over the measured steps
- the heap in use outside sqlite grows by at most 0.1 KiB per scenario in the last
  step (sqlite3_memory_used() is taken off: the page cache of dionaea.sqlite fills up
  to its 2 MiB over the first thousands of uploads, that is no leak)
- g_dionaea.config() leaves no object behind (2,000 calls, first server only)

The RSS and the free memory of the arenas are reported, not judged: RSS moves in
steps, and what malloc keeps free after the working set was built is no leak.
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
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import replay  # noqa: E402
from run import CLIENT_IMAGE, docker, say  # noqa: E402

DEFAULT_SCENARIOS = "ftp_stor,smb1_upload,http_multipart,mysql_session"
OBJECTS_MAX = 0.01
HEAP_MAX_KIB = 0.1
CONFIG_CALLS = 2000


class Leak:
    def __init__(self, args, root):
        self.args = args
        self.root = root
        self.checks = []
        self.results = {}

    def check(self, name, ok, **details):
        self.checks.append({"name": name, "ok": bool(ok), **details})
        say("%s %s %s" % ("PASS" if ok else "FAIL", name, json.dumps(details)[:300]))

    def server(self, scenario):
        root = self.root / scenario
        config = root / "config"
        shutil.copytree(self.args.config, config)
        text = (config / "dionaea.cfg").read_text()
        imports = "imports=dionaea.log,dionaea.services,dionaea.ihandlers"
        assert imports + "\n" in text, "dionaea.cfg has no plain imports line, adjust leak.py"
        (config / "dionaea.cfg").write_text(text.replace(imports + "\n", imports + ",leak_probe\n"))
        ns = argparse.Namespace(config=config, platform=self.args.platform, quick=True, duration=1,
                                concurrency=0, idle=0, interval=10)
        run = replay.Replay(ns, self.args.image, root / "run")
        before = os.environ.get("DIONAEA_RUN_ARGS", "")
        os.environ["DIONAEA_RUN_ARGS"] = (before + " -v %s:/opt/dionaea/lib/dionaea/python/leak_probe.py:ro"
                                          % (HERE / "leak_probe.py")).strip()
        try:
            run.prepare()
            run.start_server()
        finally:
            os.environ["DIONAEA_RUN_ARGS"] = before
        run.commands = 0
        return run

    def probe(self, run, command, timeout=600):
        run.commands += 1
        docker("exec", run.server, "sh", "-c", "mkdir -p /opt/dionaea/var/log/probe-cmd && touch "
               "/opt/dionaea/var/log/probe-cmd/%04d-%s" % (run.commands, command))
        if command == "trace":
            time.sleep(1)
            return None
        path = run.root / "log" / ("probe-%s.json" % command)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return json.loads(path.read_text())
            error = run.root / "log" / "probe-error.txt"
            if error.exists():
                raise RuntimeError("probe: " + error.read_text().strip())
            time.sleep(0.5)
        tail = docker("logs", "--tail", "30", run.server, capture_output=True, check=False)
        raise RuntimeError("the probe did not answer %s; container log:\n%s" % (command, tail.stdout + tail.stderr))

    def client(self, run, scenario, count):
        mounts = ["-v", "%s:/tests:ro" % replay.FUNCTIONAL, "-v", "%s:/work:ro" % HERE,
                  "-v", "%s:/out" % (run.root / "out"), "-v", "%s:/logs:ro" % (run.root / "log"),
                  "-v", "%s:/data:ro" % (run.root / "data")]
        out = docker("run", "--rm", "--network", run.network, *replay.CLIENT_LIMITS, "-e", "DIONAEA_HOST=" + run.server,
                     *mounts, CLIENT_IMAGE, "python", "-u", "/work/leak_client.py", scenario, str(count),
                     "--seed", str(self.args.seed), "--unique-share", str(self.args.unique_share),
                     capture_output=True, check=False)
        lines = out.stdout.strip().splitlines()
        try:
            return json.loads(lines[-1])
        except (IndexError, ValueError):
            return {"scenario": scenario, "ok": 0, "err": count, "errors": [out.stderr[-300:]]}

    @staticmethod
    def numbers(snap):
        heap, sqlite = snap["mallinfo"].get("uordblks", 0), snap.get("sqlite") or 0
        return {"rss_kib": snap["status"].get("VmRSS"), "heap_in_use": heap, "sqlite": sqlite,
                "heap_outside_sqlite": heap - sqlite, "heap_free": snap["mallinfo"].get("fordblks"),
                "objects": snap["objects"]}

    def measure(self, scenario, first):
        run = self.server(scenario)
        result = {"scenario": scenario, "steps": []}
        self.results[scenario] = result
        try:
            time.sleep(3)
            if first:
                result["config_check"] = check = self.probe(run, "config-%d" % CONFIG_CALLS)
                self.check("g_dionaea.config() leaves nothing behind (%d calls)" % CONFIG_CALLS,
                           check["objects_grown"] <= 0, **check)
            if self.args.trace:
                self.probe(run, "trace")
            self.probe(run, "snap-base")
            result["warm_client"] = self.client(run, scenario, self.args.warm)
            time.sleep(5)
            previous = self.numbers(self.probe(run, "snap-warm"))
            result["warm"] = previous
            for step in range(self.args.steps):
                client = self.client(run, scenario, self.args.step)
                time.sleep(5)
                snap = self.probe(run, "snap-step%d" % step)
                now = self.numbers(snap)
                per = {key: (now[key] - previous[key]) / self.args.step for key in now}
                result["steps"].append({"client": client, "numbers": now, "per_scenario": per,
                                        "types_grown": snap.get("types_grown", [])[:10],
                                        "lines_grown": snap.get("lines_grown", [])[:10]})
                say("%s step %d: %s, objects %+.3f, heap in use %+.3f KiB (sqlite %+.3f, outside %+.3f), "
                    "rss %+.3f KiB per scenario" % (
                        scenario, step, "%d ok %d failed" % (client["ok"], client["err"]), per["objects"],
                        per["heap_in_use"] / 1024, per["sqlite"] / 1024, per["heap_outside_sqlite"] / 1024,
                        per["rss_kib"]))
                previous = now
        finally:
            if not self.args.keep:
                run.cleanup()
        steps = result["steps"]
        clients_ok = all(s["client"]["err"] == 0 and s["client"]["ok"] == self.args.step for s in steps)
        objects = (steps[-1]["numbers"]["objects"] - result["warm"]["objects"]) / (self.args.step * len(steps))
        heap = steps[-1]["per_scenario"]["heap_outside_sqlite"] / 1024
        rss = (steps[-1]["numbers"]["rss_kib"] - result["warm"]["rss_kib"]) / (self.args.step * len(steps))
        self.check("%s: objects grow <= %.2f per scenario" % (scenario, OBJECTS_MAX),
                   clients_ok and objects <= OBJECTS_MAX, per_scenario=round(objects, 4),
                   grown=steps[-1]["types_grown"][:5], clients_ok=clients_ok)
        self.check("%s: heap in use outside sqlite grows <= %.2f KiB per scenario in the last step" % (
                   scenario, HEAP_MAX_KIB), clients_ok and heap <= HEAP_MAX_KIB, per_scenario_kib=round(heap, 4),
                   sqlite_kib_per_scenario=round(steps[-1]["per_scenario"]["sqlite"] / 1024, 4),
                   rss_kib_per_scenario=round(rss, 4),
                   heap_free_mib=round(steps[-1]["numbers"]["heap_free"] / 2**20, 1))

    def execute(self):
        try:
            for index, scenario in enumerate(self.args.scenarios.split(",")):
                self.measure(scenario, index == 0)
        finally:
            passed = bool(self.checks) and all(c["ok"] for c in self.checks)
            (self.root / "summary.json").write_text(json.dumps(
                {"image": self.args.image, "warm": self.args.warm, "step": self.args.step, "steps": self.args.steps,
                 "checks": self.checks, "results": self.results, "pass": passed}, indent=1) + "\n")
        return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", default="dionaea:local")
    parser.add_argument("--scenarios", default=DEFAULT_SCENARIOS,
                        help="comma separated (default %s)" % DEFAULT_SCENARIOS)
    parser.add_argument("--warm", type=int, default=500, help="scenarios before the first measurement (default 500)")
    parser.add_argument("--step", type=int, default=1000, help="scenarios per measured step (default 1000)")
    parser.add_argument("--steps", type=int, default=2, help="measured steps (default 2)")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--unique-share", type=float, default=0.15)
    parser.add_argument("--trace", action="store_true", help="tracemalloc in dionaea: the lines that grew")
    parser.add_argument("--platform")
    parser.add_argument("--config", type=Path, default=replay.DEFAULT_CONFIG, required=replay.DEFAULT_CONFIG is None)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()
    if shutil.which("docker") is None or docker("info", capture_output=True, check=False).returncode != 0:
        print("docker is not available", file=sys.stderr)
        return 3
    root = (args.artifacts or Path(tempfile.mkdtemp(prefix="dionaea-leak."))).resolve()
    if root.exists() and any(root.iterdir()):
        print("%s is not empty" % root, file=sys.stderr)
        return 3
    root.mkdir(parents=True, exist_ok=True)
    docker("build", "-q", "-t", CLIENT_IMAGE, str(replay.FUNCTIONAL / "client"), stdout=subprocess.DEVNULL)
    passed = Leak(args, root).execute()
    say("%s, artifacts in %s" % ("PASSED" if passed else "FAILED", root))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
