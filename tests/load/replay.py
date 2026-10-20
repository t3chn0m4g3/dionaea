#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Synthetic accelerated replay: the acceptance test before a release (see README.md).

    tests/load/replay.py --image dionaea:local                # 60 minutes
    tests/load/replay.py --image IMAGE --quick                 # 5 minutes
    tests/load/replay.py --duration 120 --concurrency 12 --artifacts DIR

Starts dionaea as T-Pot does (the T-Pot configuration, uid/gid 2000, read-only,
the service roots read-only, a 16 MiB tmpfs on /tmp, 1 GiB without swap, 256 pids, 1 CPU, restart
always) on an internal Docker network, runs replay_client.py in the client
container of the functional tests for the duration (the benign scenarios of the
functional tests in a loop, at a high rate, weighted at random), samples dionaea
every 30 s and judges the run by machine-checked criteria. Exit 0: every
criterion passed; 1: one failed (summary.json says which); 2: DIONAEA_RUN_ARGS
has another option than a read-only file mount or --ulimit nofile; 3: environment.
Python standard library and the docker CLI only.
"""

import argparse
import json
import math
import os
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
FUNCTIONAL = REPO / "tests" / "functional"
sys.path.insert(0, str(FUNCTIONAL))
sys.path.insert(0, str(HERE))

import logformat  # noqa: E402  (tests/functional: event types)
from run import BAD_LOG, CLIENT_IMAGE, docker, inspect, say  # noqa: E402  (tests/load/run.py)
from runargs import run_args  # noqa: E402,F401  (tests/load/runargs.py, also replay.run_args)

# the configuration of dionaea: --config, or the folder DIONAEA_CONFIG_DIR names
# (docker/dionaea/dist/etc of a T-Pot checkout)
DEFAULT_CONFIG = Path(os.environ["DIONAEA_CONFIG_DIR"]) if os.environ.get("DIONAEA_CONFIG_DIR") else None
# the limits of the dionaea service of T-Pot (docker/dionaea/docker-compose.yml)
LIMITS = ["--memory", "1g", "--memory-swap", "1g", "--cpus", "1", "--pids-limit", "256", "--restart", "always"]
# /tmp as in the T-Pot compose files: the files of the emulation (CreateFile, _lcreat) are made there
TMPFS = ["--tmpfs", "/tmp:uid=2000,gid=2000,size=16m"]
CLIENT_LIMITS = ["--memory", "2g", "--cpus", "4", "--pids-limit", "512"]
# the 1 s memory probe (test only): mounted into the python modules of dionaea, its lines go to out/
PROBE = HERE / "rss_probe.py"
PROBE_TARGET = "/opt/dionaea/lib/dionaea/python/rss_probe.py"
PROBE_CSV = "rss_probe.csv"
PROBE_MINUTE_SAMPLES = 30      # a minute of the gates has at least this many 1 s samples
PROBE_COVERAGE = 0.9           # share of the seconds of the second half the probe has to sample
# dionaea starts through this (test only, the image and T-Pot stay as they are): PR_SET_THP_DISABLE (41)
# for the process, which execve keeps, then exec of the entrypoint and command of the image (looked up on
# PATH). With THP on ("always", Docker Desktop) the floor of RSS wanders by about 3 MiB for 10 to 30 minutes
# (AnonHugePages collapse and split), which the RSS floor gate can not tell from a leak (README.md).
# argv[1] "required": a failed prctl stops the start (native); "optional": dionaea runs under emulation,
# where qemu-user answers EINVAL, starts anyway, and the memory checks do not apply
THP_SCRIPT = ("import ctypes, os, sys\n"
              "libc = ctypes.CDLL(None, use_errno=True)\n"
              "if libc.prctl(41, 1, 0, 0, 0) != 0:\n"
              "    reason = 'PR_SET_THP_DISABLE: ' + os.strerror(ctypes.get_errno())\n"
              "    if sys.argv[1] != 'optional':\n"
              "        sys.exit(reason)\n"
              "    print(reason + ' under emulation: THP stays on, the memory checks are not applicable',\n"
              "          file=sys.stderr, flush=True)\n"
              "os.execvp(sys.argv[2], sys.argv[2:])\n")
# uname -m and docker info name the architectures differently
ARCH_NAMES = {"amd64": "x86_64", "arm64": "aarch64"}
EMULATED = "not applicable: dionaea runs under emulation (%s on a %s host), THP and memory are those of the emulator"
# criteria
RSS_SLOPE_MAX_MIB_PER_10MIN = 1.0
RSS_MAX_MIB = 768
BANNER_P99_MAX_S = 1.0
FD_TOLERANCE = (16, 0.10)       # growth over the second half: 16 or 10 % of the median, the larger
THREAD_TOLERANCE = (4, 0.10)
ERROR_RATE_MAX = 0.05
# the event types of dionaea.json that the replay has to cause: the reference session of the
# functional tests (fixtures/log_0.11.1.json) and the services of the mix that it does not cover
EXTRA_TYPES = ["mirrord/accept", "mongod/accept", "ftpdatalisten/accept", "ftpdataconnect/connect",
               "TftpServerHandler/connect", "TftpClient/connect"]
SAMPLE = ("grep -E '^(VmRSS|VmHWM|VmSwap|Threads|THP_enabled):' /proc/1/status; "
          "echo \"Fds: $(ls /proc/1/fd | wc -l)\"; echo \"CgMem: $(cat /sys/fs/cgroup/memory.current)\"; "
          "grep -E '^(anon|file) ' /sys/fs/cgroup/memory.stat | sed 's/^/Cg_/; s/ /: /'")


def mib(kib):
    return kib / 1024.0


def percentile(values, share):
    values = sorted(values)
    if not values:
        return 0.0
    return values[min(len(values) - 1, math.ceil(share * len(values)) - 1)]


def slope(points):
    """Least squares slope of [(x, y)]."""
    if len(points) < 2:
        return 0.0
    mean_x = sum(x for x, _ in points) / len(points)
    mean_y = sum(y for _, y in points) / len(points)
    denominator = sum((x - mean_x) ** 2 for x, _ in points)
    return sum((x - mean_x) * (y - mean_y) for x, y in points) / denominator if denominator else 0.0


def theil_sen(points):
    """Theil-Sen slope of [(x, y)]: the median of the slopes of all pairs with different x."""
    slopes = [(y2 - y1) / (x2 - x1) for i, (x1, y1) in enumerate(points) for x2, y2 in points[i + 1:] if x2 != x1]
    return statistics.median(slopes) if slopes else 0.0


def thp_wrapper(entrypoint, command, native):
    """(entrypoint, arguments) for docker run: THP_SCRIPT in the python of the image, then the entrypoint
    and the command of the image (docker image inspect); a failed prctl stops a native start only."""
    argv = list(entrypoint or []) + list(command or [])
    if not argv:
        raise ValueError("the image has neither an entrypoint nor a command")
    return "python3", ["-c", THP_SCRIPT, "required" if native else "optional", *argv]


class PlatformUnknown(RuntimeError):
    """the architecture of the image or of the docker host could not be found out (exit 3): the run must not
    take itself for emulated, which would turn the memory gates off"""


def same_arch(container, host):
    """the architecture of the container (uname -m) is that of the docker host (docker info); PlatformUnknown
    when one of them is empty"""
    container, host = container.strip(), host.strip()
    if not container or not host:
        raise PlatformUnknown("the architecture of the image (%r) or of the docker host (%r) is unknown"
                              % (container, host))
    return ARCH_NAMES.get(container, container) == ARCH_NAMES.get(host, host)


def image_command(image):
    out = docker("image", "inspect", "--format", "{{json .Config.Entrypoint}}|{{json .Config.Cmd}}", image,
                 capture_output=True).stdout.strip()
    entrypoint, _, command = out.partition("|")
    return json.loads(entrypoint), json.loads(command)


def probe_window(start, end, domain, offset):
    """The window of the load in the clock of the containers (the probe, the banner probes of the client):
    one taken from the samples is in the clock of the host, the clock of the containers is that plus offset
    (Docker Desktop runs them in a VM); the client's load_start / load_end are in the clock of the
    containers already."""
    return (start + offset, end + offset) if domain == "host" else (start, end)


def host_window(start, end, domain, offset):
    """The window of the load in the clock of the host (the samples of docker exec)."""
    return (start - offset, end - offset) if domain == "container" else (start, end)


def read_probe(path):
    """[(epoch, rss_kib, inuse_bytes, cost_us, anon_huge_kib or None)] of the probe's file; the probe reads
    AnonHugePages once a minute. A cut last line is left out."""
    rows = []
    try:
        with open(path) as file:
            next(file, None)
            for line in file:
                parts = line.strip().split(",")
                if len(parts) in (4, 5):
                    try:
                        anon = int(parts[4]) if len(parts) == 5 and parts[4] else None
                        rows.append((float(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]), anon))
                    except ValueError:
                        pass
    except OSError:
        pass
    return rows


def counted(values):
    """[(x, count)] has a count above 0 (a /proc/1/fd that can not be read counts 0)"""
    return any(value > 0 for _, value in values)


def anon_huge_max(rows):
    """the largest AnonHugePages (KiB) the probe saw, None if it never read them"""
    values = [row[4] for row in rows if row[4] is not None]
    return max(values) if values else None


def probe_ok(samples, seconds, anon_huge):
    """the probe covered the second half, and dionaea had no transparent huge pages"""
    return samples >= PROBE_COVERAGE * seconds and anon_huge == 0


def per_minute(points, start, reduce):
    """[(minute + 0.5, reduce(values of that minute))] of [(epoch, value)], minutes counted from start;
    a minute with fewer than PROBE_MINUTE_SAMPLES samples is left out."""
    minutes = {}
    for epoch, value in points:
        minutes.setdefault(int((epoch - start) // 60), []).append(value)
    return [(minute + 0.5, reduce(values)) for minute, values in sorted(minutes.items())
            if len(values) >= PROBE_MINUTE_SAMPLES]


def memory_slopes(rows, start, end):
    """The gates over the probe's samples from start to end (the second half of the load), MiB / 10 min:
    rss_floor is the Theil-Sen slope of the per-minute minimum of RSS, inuse that of the per-minute
    median of glibc's bytes in use (see README.md)."""
    window = [row for row in rows if start <= row[0] <= end]
    floors = per_minute([(row[0], row[1] / 1024.0) for row in window], start, min)
    inuse = per_minute([(row[0], row[2] / 1048576.0) for row in window], start, statistics.median)
    return {"rss_floor": theil_sen(floors) * 10, "inuse": theil_sen(inuse) * 10, "samples": len(window),
            "minutes": len(floors), "floors_mib": [round(v, 1) for _, v in floors],
            "inuse_mib": [round(v, 2) for _, v in inuse]}


class Replay:
    def __init__(self, args, image, root):
        self.args = args
        self.image = image
        self.root = root
        tag = "%d-replay" % os.getpid()
        self.server = "dionaea-replay-%s" % tag
        self.client = "dionaea-replay-%s-client" % tag
        self.network = "dionaea-replay-%s" % tag
        self.samples = []
        self.checks = []
        self.summary = {"image": image, "limits": LIMITS, "mode": "quick" if args.quick else "full",
                        "duration_s": args.duration * 60, "concurrency": args.concurrency, "idle": args.idle,
                        "interval_s": args.interval, "platform": args.platform or "native",
                        "dionaea_run_args": os.environ.get("DIONAEA_RUN_ARGS", ""),
                        "inject_leak": getattr(args, "inject_leak", None)}
        self.clock_offset = 0.0
        self.window_domain = "host"
        self.aborted = None
        self.native = True

    # ---- environment

    def prepare(self):
        for sub in ("etc", "log", "out", "data/binaries", "data/bistreams", "data/rtp",
                    "data/roots/ftp", "data/roots/tftp", "data/roots/www", "data/roots/upnp"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        shutil.copytree(self.args.config, self.root / "etc", dirs_exist_ok=True)
        # the 1 s memory probe, in the copy of the configuration only
        config = self.root / "etc/dionaea.cfg"
        text, count = re.subn(r"(?m)^(imports[ \t]*=.*?)[ \t]*$", r"\1,rss_probe", config.read_text(), count=1)
        if not count:
            raise RuntimeError("%s has no imports= line for the probe" % config)
        config.write_text(text)
        (self.root / "data/roots/ftp/functional-list.txt").write_text("ftp functional test file\n")
        (self.root / "data/roots/tftp/functional-test.txt").write_text("tftp functional test file\n")
        for path in [self.root, *self.root.rglob("*")]:
            path.chmod(0o777 if path.is_dir() else 0o666)
        store = (self.root / "etc/ihandlers/store.yaml").read_text()
        match = re.search(r"max_size:\s*(\d+)", store)
        self.max_size_mib = int(match.group(1)) if match else 0
        self.summary["store_max_size_mib"] = self.max_size_mib

    def start_server(self):
        docker("network", "create", "--internal", self.network, stdout=subprocess.DEVNULL)
        subnet = docker("network", "inspect", "--format", "{{(index .IPAM.Config 0).Subnet}}", self.network,
                        capture_output=True).stdout.strip()
        # downloads only from the test network (the T-Pot default allows public addresses only)
        (self.root / "etc/ihandlers/download_policy.yaml").write_text(
            "- name: download_policy\n  config:\n    allowed_networks: [\"%s\"]\n" % subnet)
        args = ["run", "-d", "--name", self.server, "--network", self.network, "--read-only",
                "--user", "2000:2000", *LIMITS, *TMPFS]
        if self.args.platform:
            args += ["--platform", self.args.platform]
        args += ["-v", "%s:/opt/dionaea/etc/dionaea:ro" % (self.root / "etc"),
                 "-v", "%s:/opt/dionaea/var/dionaea" % (self.root / "data"),
                 "-v", "%s:/opt/dionaea/var/log" % (self.root / "log")]
        for name in ("ftp", "tftp", "www", "upnp"):
            args += ["-v", "%s:/opt/dionaea/var/dionaea/roots/%s:ro" % (self.root / "data/roots" / name, name)]
        args += ["-v", "%s:%s:ro" % (PROBE, PROBE_TARGET), "-v", "%s:/probe" % (self.root / "out")]
        args += self.leak_env()
        # more arguments for docker run of dionaea (debugging, e.g. a probe): the allowed ones only
        args += run_args()
        self.native = self.platform_is_native()
        entrypoint, command = thp_wrapper(*image_command(self.image), native=self.native)
        docker(*args, "--entrypoint", entrypoint, self.image, *command, stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + 120
        while True:
            state = inspect(self.server)
            # --restart always starts it again: a restart is an exit as well
            if not state or not state["State"]["Running"] or state["RestartCount"]:
                raise RuntimeError(self.start_failure())
            ready = docker("exec", self.server, "sh", "-c", "grep -q ':0015 ' /proc/net/tcp", check=False,
                           capture_output=True)
            if ready.returncode == 0:   # port 21 listens
                break
            if time.monotonic() > deadline:
                raise RuntimeError(self.start_failure("dionaea did not listen on port 21 within 120 s"))
            time.sleep(1)
        self.clock_offset = self.container_clock_offset()
        self.summary["probe_clock_offset_s"] = round(self.clock_offset, 3)

    def platform_is_native(self):
        """dionaea runs on the architecture of the docker host (not emulated: --platform of another one, or
        an image of another one); the summary records both"""
        platform = ["--platform", self.args.platform] if self.args.platform else []
        try:
            uname = docker("run", "--rm", *platform, "--entrypoint", "uname", self.image, "-m",
                           capture_output=True, check=False, timeout=120)
            info = docker("info", "--format", "{{.Architecture}}", capture_output=True, check=False, timeout=60)
        except subprocess.TimeoutExpired as error:
            # an answer that does not come is as unknown as a failed one
            raise PlatformUnknown("the probe of the architecture timed out after %s s: %s"
                                  % (error.timeout, " ".join(map(str, error.cmd)))) from None
        for what, out in (("uname -m in the image", uname), ("docker info", info)):
            if out.returncode != 0:
                raise PlatformUnknown("%s failed (exit %s): %s" % (what, out.returncode, (out.stderr or "").strip()))
        container, host = uname.stdout.strip(), info.stdout.strip()
        native = same_arch(container, host)
        self.summary.update(container_arch=container, host_arch=host, native=native)
        return native

    def start_failure(self, what="dionaea exited during the start"):
        """what went wrong during the start, with the last lines of the container log (the wrapper's reason)"""
        logs = docker("logs", "--tail", "20", self.server, capture_output=True, check=False)
        tail = (logs.stdout + logs.stderr).strip()
        return what + (": " + tail if tail else "")

    def leak_env(self):
        kind = getattr(self.args, "inject_leak", None)
        return ["-e", "LEAK_INJECT=%s:%s" % (kind, getattr(self.args, "leak_rate", 2.0))] if kind else []

    def container_clock_offset(self):
        """the clock of the containers minus that of the host, from the middle of a docker exec"""
        before = time.time()
        out = docker("exec", self.server, "python3", "-c", "import time; print(repr(time.time()))",
                     capture_output=True, check=False, timeout=60)
        after = time.time()
        try:
            return float(out.stdout.strip()) - (before + after) / 2
        except ValueError:
            return 0.0

    def cleanup(self):
        docker("rm", "-f", self.client, capture_output=True, check=False)
        docker("rm", "-f", self.server, capture_output=True, check=False)
        docker("network", "rm", self.network, capture_output=True, check=False)

    # ---- sampling

    def sample(self):
        state = inspect(self.server)
        row = {"epoch": time.time()}
        if not state:
            row.update(running=False, restarts=None, oom=None, started=None)
            return row
        row.update(running=state["State"]["Running"], restarts=state["RestartCount"],
                   oom=state["State"]["OOMKilled"], started=state["State"]["StartedAt"],
                   exit_code=state["State"]["ExitCode"])
        if not row["running"]:
            return row
        out = docker("exec", self.server, "sh", "-c", SAMPLE, capture_output=True, check=False, timeout=60)
        for line in out.stdout.splitlines():
            key, _, value = line.partition(":")
            value = value.strip().split()
            if value:
                row[key] = int(value[0])
        stats = docker("stats", "--no-stream", "--format", "{{.CPUPerc}} {{.MemUsage}}", self.server,
                       capture_output=True, check=False, timeout=60)
        row["stats"] = stats.stdout.strip()
        match = re.match(r"([\d.]+)%", row["stats"])
        row["cpu_percent"] = float(match.group(1)) if match else None
        return row

    def run_client(self):
        args = self.args
        mounts = ["-v", "%s:/tests:ro" % FUNCTIONAL, "-v", "%s:/work:ro" % HERE,
                  "-v", "%s:/out" % (self.root / "out"), "-v", "%s:/logs:ro" % (self.root / "log"),
                  "-v", "%s:/data:ro" % (self.root / "data")]
        command = ["python", "-u", "/work/replay_client.py", "--duration", str(args.duration * 60),
                   "--concurrency", str(args.concurrency), "--idle", str(args.idle), "--think-ms", str(args.think_ms),
                   "--interval", str(args.interval), "--seed", str(args.seed), "--settle", str(args.settle)]
        if args.only:
            command += ["--only", args.only]
        command += ["--unique-share", str(args.unique_share)]
        log = (self.root / "client.log").open("w")
        process = subprocess.Popen(["docker", "run", "--rm", "--name", self.client, "--network", self.network,
                                    *CLIENT_LIMITS, "-e", "DIONAEA_HOST=" + self.server, *mounts, CLIENT_IMAGE,
                                    *command], stdout=log, stderr=subprocess.STDOUT)
        self.samples.append(self.sample())
        self.write_samples()
        base = self.samples[0]["restarts"]
        deadline = time.monotonic() + args.duration * 60 + args.settle + 65 + 300 + 120
        next_at = time.monotonic() + args.interval
        while process.poll() is None:
            time.sleep(1)
            if time.monotonic() < next_at:
                continue
            next_at += args.interval
            row = self.sample()
            self.samples.append(row)
            self.write_samples()
            say("t=%4.0fs rss=%s MiB fds=%s threads=%s cpu=%s restarts=%s oom=%s" % (
                row["epoch"] - self.samples[0]["epoch"], mib(row.get("VmRSS", 0)) and round(mib(row["VmRSS"]), 1),
                row.get("Fds"), row.get("Threads"), row.get("cpu_percent"), row.get("restarts"), row.get("oom")))
            if (not row["running"] or row["restarts"] != base or row.get("oom")) and not args.keep_going:
                self.aborted = "dionaea restarted, stopped or was OOM killed at %.0f s" % (
                    row["epoch"] - self.samples[0]["epoch"])
                say("ABORT: " + self.aborted)
                docker("kill", self.client, capture_output=True, check=False)
                break
            if time.monotonic() > deadline:
                self.aborted = "the client did not end in time"
                docker("kill", self.client, capture_output=True, check=False)
                break
        process.wait()
        log.close()
        self.samples.append(self.sample())
        self.write_samples()
        return process.returncode

    def write_samples(self):
        (self.root / "samples.json").write_text(json.dumps(self.samples, indent=1) + "\n")

    # ---- judgement

    def check(self, name, ok, gating=True, applicable=True, **details):
        """applicable False: reported as "n/a" (under emulation), never gating"""
        gating = gating and applicable
        self.checks.append({"name": name, "ok": bool(ok), "gating": gating, "applicable": applicable, **details})
        status = "N/A" if not applicable else "PASS" if ok else "FAIL" if gating else "WARN"
        say("%s %s %s" % (status, name, json.dumps(details)[:400]))

    def load_window(self, result):
        phase = {}
        try:
            phase = json.loads((self.root / "out/phase.json").read_text())
        except (OSError, ValueError):
            pass
        start = result.get("load_start") or phase.get("load_start")
        end = result.get("load_end") or phase.get("load_end")
        # the client's times are in the clock of the containers, the samples' in that of the host
        self.window_domain = "container" if start and end else "host"
        start = start or self.samples[0]["epoch"]
        end = end or self.samples[-1]["epoch"]
        # the workers end at the deadline, idle and slow connections run out up to 25 s later
        return start, min(end, start + self.args.duration * 60)

    def judge(self, result, rc):
        args = self.args
        samples = [s for s in self.samples if s.get("VmRSS") is not None]
        start, end = self.load_window(result)
        # the samples of docker exec in the clock of the host, the probe and the banner in that of the containers
        host_start, host_end = host_window(start, end, self.window_domain, self.clock_offset)
        window = [s for s in samples if host_start <= s["epoch"] <= host_end]
        half = host_start + (host_end - host_start) / 2
        second = [s for s in window if s["epoch"] >= half]
        strict = not args.quick
        self.summary.update(load_start=start, load_end=end, load_seconds=round(end - start, 1),
                            samples=len(self.samples), samples_in_load=len(window))

        # --- process
        last = self.samples[-1]
        restarts = {s["restarts"] for s in self.samples if s.get("restarts") is not None}
        started = {s["started"] for s in self.samples if s.get("started")}
        oom = any(s.get("oom") for s in self.samples)
        final = inspect(self.server)
        self.check("no restart, no OOM kill, dionaea runs", restarts == {0} and len(started) == 1 and not oom
                   and all(s["running"] for s in self.samples) and not self.aborted,
                   restarts=sorted(restarts), starts=len(started), oom_killed=oom, aborted=self.aborted,
                   exit_code=last.get("exit_code"), running_at_end=bool(final and final["State"]["Running"]))
        if self.aborted or not window:
            self.check("samples of the load", bool(window), samples_in_load=len(window))
            return

        # --- memory: the 1 s probe (README.md, "What it checks"); least squares of the 30 s samples is reported
        points = [((s["epoch"] - host_start) / 60.0, mib(s["VmRSS"])) for s in second]
        ols_per_10min = slope(points) * 10
        hwm = max(mib(s.get("VmHWM", 0)) for s in samples)
        peak = max(mib(s["VmRSS"]) for s in samples)
        probe = read_probe(self.root / "out" / PROBE_CSV)
        probe_start, probe_end = probe_window(start, end, self.window_domain, self.clock_offset)
        probe_half = probe_start + (probe_end - probe_start) / 2
        slopes = memory_slopes(probe, probe_half, probe_end)
        costs = [row[3] for row in probe if probe_start <= row[0] <= probe_end]
        anon_huge = anon_huge_max(probe)
        thp = {s.get("THP_enabled") for s in self.samples if s.get("running")}
        self.summary.update(rss_slope_ols_mib_per_10min=round(ols_per_10min, 3),
                            rss_floor_slope_mib_per_10min=round(slopes["rss_floor"], 3),
                            inuse_slope_mib_per_10min=round(slopes["inuse"], 3),
                            probe_samples=len(probe), probe_minutes_second_half=slopes["minutes"],
                            thp_disabled=thp == {0}, anon_huge_max_kib=anon_huge,
                            window_clock=self.window_domain,
                            probe_floors_mib=slopes["floors_mib"], probe_inuse_mib=slopes["inuse_mib"],
                            probe_cost_us={"p50": percentile(costs, 0.5), "p99": percentile(costs, 0.99),
                                           "max": max(costs or [0])},
                            rss_max_mib=round(max(peak, hwm), 1),
                            rss_first_mib=round(mib(window[0]["VmRSS"]), 1),
                            rss_last_mib=round(mib(window[-1]["VmRSS"]), 1))
        self.check_memory(slopes, probe_end - probe_half, anon_huge, thp, ols_per_10min, peak, hwm)

        # --- fds and threads
        for label, key, (floor, share) in (("fd count", "Fds", FD_TOLERANCE),
                                           ("thread count", "Threads", THREAD_TOLERANCE)):
            values = [(((s["epoch"] - host_start) / 60.0), s[key]) for s in second if s.get(key) is not None]
            if not counted(values):
                self.check(label + " is stable", False, reason="no samples, or none could be read")
                continue
            growth = slope(values) * (host_end - half) / 60.0
            median = statistics.median(v for _, v in values)
            tolerance = max(floor, share * median)
            quarters = [v for _, v in values]
            q = max(1, len(quarters) // 2)
            third_vs_fourth = statistics.median(quarters[q:]) - statistics.median(quarters[:q])
            ok = not (growth > tolerance and third_vs_fourth > tolerance / 2)
            self.summary[key.lower() + "_growth_second_half"] = round(growth, 2)
            self.check(label + " is stable (no monotonic growth in the second half)", ok, gating=strict,
                       growth=round(growth, 2), tolerance=round(tolerance, 1), median=median,
                       min=min(v for _, v in values), max=max(v for _, v in values),
                       later_half_minus_earlier_half=third_vs_fourth,
                       note=None if strict else "quick mode: indicative only")

        # --- event loop latency (the client's clock)
        latencies = []
        try:
            with (self.root / "out/banner.csv").open() as file:
                next(file)
                for line in file:
                    parts = line.rstrip("\n").split(",")
                    if probe_start <= float(parts[0]) <= probe_end:
                        latencies.append(float(parts[1]))
        except (OSError, ValueError):
            pass
        p99 = percentile(latencies, 0.99)
        self.summary.update(banner_samples=len(latencies), banner_p50_s=round(percentile(latencies, 0.5), 4),
                            banner_p99_s=round(p99, 4), banner_max_s=round(max(latencies or [0]), 4))
        self.check("p99 of the FTP banner latency below %.0f s" % BANNER_P99_MAX_S,
                   bool(latencies) and p99 < BANNER_P99_MAX_S, samples=len(latencies),
                   p50_s=round(percentile(latencies, 0.5), 4), p99_s=round(p99, 4),
                   max_s=round(max(latencies or [0]), 4))

    def check_memory(self, slopes, seconds, anon_huge, thp, ols, peak, hwm):
        """The THP check, the two memory gates and the max RSS backstop; under emulation (THP stays on where
        qemu-user refuses the prctl, RSS is that of the emulator) they are reported as not applicable."""
        strict = not self.args.quick
        emulated = None if self.native else EMULATED % (self.summary.get("container_arch"),
                                                        self.summary.get("host_arch"))
        applicable = emulated is None
        self.check("the 1 s memory probe sampled the second half of the load, dionaea had no huge pages",
                   probe_ok(slopes["samples"], seconds, anon_huge), applicable=applicable,
                   samples=slopes["samples"], seconds=round(seconds), minutes=slopes["minutes"],
                   anon_huge_max_kib=anon_huge, thp_enabled=sorted(v for v in thp if v is not None), note=emulated)
        note = emulated or (None if strict else "quick mode: the window is too short to judge a slope, indicative only")
        self.check("RSS floor slope (Theil-Sen of the per-minute minimum of the 1 s RSS) over the second half "
                   "<= %.0f MiB / 10 min" % RSS_SLOPE_MAX_MIB_PER_10MIN,
                   slopes["rss_floor"] <= RSS_SLOPE_MAX_MIB_PER_10MIN, gating=strict, applicable=applicable,
                   slope_mib_per_10min=round(slopes["rss_floor"], 3), minutes=slopes["minutes"],
                   ols_30s_slope_mib_per_10min=round(ols, 3), note=note)
        self.check("glibc in use slope (Theil-Sen of the per-minute median) over the second half "
                   "<= %.0f MiB / 10 min" % RSS_SLOPE_MAX_MIB_PER_10MIN,
                   slopes["inuse"] <= RSS_SLOPE_MAX_MIB_PER_10MIN, gating=strict, applicable=applicable,
                   slope_mib_per_10min=round(slopes["inuse"], 3), minutes=slopes["minutes"], note=note)
        self.check("max RSS below %d MiB" % RSS_MAX_MIB, max(peak, hwm) < RSS_MAX_MIB, applicable=applicable,
                   max_rss_mib=round(peak, 1), vm_hwm_mib=round(hwm, 1), note=emulated)

    def judge_after_stop(self, result):
        """Logs, binaries, JSON, sqlite and the client's own results."""
        data = self.root / "data"
        container_log = docker("logs", self.server, capture_output=True, check=False)
        (self.root / "container.log").write_text(container_log.stdout + container_log.stderr)
        texts = {"container.log": container_log.stdout + container_log.stderr}
        for name in ("dionaea.log", "dionaea-errors.log"):
            path = data / name
            texts[name] = path.read_text(errors="replace") if path.exists() else ""
        bad = {name: BAD_LOG.findall(text)[:3] for name, text in texts.items() if BAD_LOG.search(text)}
        # what the Tracebacks are: the last frame of dionaea and the exception line, counted
        signatures = {}
        for text in texts.values():
            for block in re.findall(r"Traceback \(most recent call last\):\n((?:[ \t].*\n)+)(\S[^\n]*)", text):
                frames = re.findall(r'File "([^"]+)", line (\d+), in (\w+)', block[0])
                where = ["%s:%s %s" % (Path(f).name, n, fn) for f, n, fn in frames
                         if "/dionaea/" in f or "binding" in f]
                key = "%s <- %s" % (block[1][:100], " > ".join(where[-3:]))
                signatures[key] = signatures.get(key, 0) + 1
        self.summary["traceback_signatures"] = signatures
        self.summary["log_bytes"] = {name: len(text) for name, text in texts.items()}
        self.check("no Traceback, LoaderError or crash in the logs", not bad, found=bad, tracebacks=signatures,
                   errors_log_lines=len(texts["dionaea-errors.log"].splitlines()))
        final = inspect(self.server)
        self.summary["exit_code_after_stop"] = final["State"]["ExitCode"] if final else None
        segfault = final and final["State"]["ExitCode"] == 139
        self.check("no segmentation fault (exit status)", not segfault, exit_code=self.summary["exit_code_after_stop"])

        # --- binaries
        count = size = 0
        for path in (data / "binaries").iterdir():
            try:
                info = path.lstat()
            except OSError:
                continue
            count += 1
            size += info.st_size
        limit = self.max_size_mib * 1024 * 1024
        client_series = self.read_client_series()
        peak_size = max([size] + [row.get("binaries_bytes", 0) for row in client_series])
        self.summary.update(binaries_files=count, binaries_bytes=size, binaries_peak_bytes=peak_size)
        self.check("binaries/ stays <= max_size (%d MiB)" % self.max_size_mib,
                   self.max_size_mib == 0 or peak_size <= limit, files=count, mib=round(size / 2**20, 1),
                   peak_mib=round(peak_size / 2**20, 1))
        bistreams = 0
        files = 0
        for path in (data / "bistreams").rglob("*"):
            if path.is_file():
                files += 1
                bistreams += path.stat().st_size
        self.summary.update(bistreams_files=files, bistreams_bytes=bistreams)

        # --- dionaea.json
        invalid = []
        types = {}
        lines = 0
        json_path = self.root / "log/dionaea.json"
        with json_path.open("rb") as file:
            for number, line in enumerate(file, 1):
                if not line.strip():
                    continue
                lines += 1
                try:
                    event = json.loads(line)
                    key = logformat.event_type(event)
                    types[key] = types.get(key, 0) + 1
                except (ValueError, AttributeError, TypeError):
                    if len(invalid) < 5:
                        invalid.append((number, line[:80]))
                    types["<invalid>"] = types.get("<invalid>", 0) + 1
        fixture = json.loads((FUNCTIONAL / "fixtures/log_0.11.1.json").read_text())
        expected = sorted(set(logformat.expected_types(fixture)) | set(EXTRA_TYPES))
        missing = [name for name in expected if name not in types]
        self.summary.update(json_lines=lines, json_bytes=json_path.stat().st_size, json_event_types=types)
        self.check("dionaea.json is valid JSON line by line and has every expected event type",
                   not invalid and not missing and lines > 0, lines=lines, invalid=invalid, missing=missing,
                   event_types=len(types))

        # --- sqlite
        import sqlite3
        db = sqlite3.connect("file:%s?mode=ro" % (self.root / "log/dionaea.sqlite"), uri=True)
        tables = {t: db.execute("SELECT count(*) FROM %s" % t).fetchone()[0]
                  for t in ("connections", "logins", "downloads", "offers", "emu_profiles")}
        integrity = db.execute("PRAGMA integrity_check").fetchone()[0]
        db.close()
        self.summary["sqlite_rows"] = tables
        self.summary["sqlite_integrity"] = integrity
        made = result.get("connections_made") or 0
        series = [row["sqlite"]["connections"] for row in client_series if row.get("sqlite")]
        monotonic = all(b >= a for a, b in zip(series, series[1:]))
        stalls = 0
        run = 0
        for a, b in zip(series, series[1:]):
            run = run + 1 if b == a else 0
            stalls = max(stalls, run)
        ratio = tables["connections"] / made if made else 0
        self.check("sqlite rows grow plausibly", monotonic and stalls < 4 and 0.5 <= ratio <= 4 and integrity == "ok"
                   and tables["logins"] > 0 and tables["downloads"] > 0 and tables["emu_profiles"] > 0,
                   rows=tables, connections_made_by_the_client=made, rows_per_client_connection=round(ratio, 2),
                   monotonic=monotonic, longest_stall_samples=stalls, integrity=integrity)

        # --- the client
        scenarios = result.get("scenarios", {})
        never = [name for name, row in scenarios.items() if row["ok"] == 0]
        total_ok = sum(row["ok"] for row in scenarios.values())
        total_err = sum(row["err"] for row in scenarios.values())
        rate = total_err / max(1, total_ok + total_err)
        self.summary.update(scenarios_ok=total_ok, scenarios_err=total_err, error_rate=round(rate, 4))
        self.check("every scenario succeeded at least once, errors <= %.0f %%" % (100 * ERROR_RATE_MAX),
                   bool(scenarios) and not never and rate <= ERROR_RATE_MAX, never=never,
                   done=total_ok, errors=total_err, error_rate=round(rate, 4))
        self.check("every upload is stored (binaries/<md5>, 0440), nothing mirrored back",
                   result.get("uploads_missing_count") == 0 and result.get("mirror_connect_backs") == 0
                   and result.get("uploads_checked", 0) > 0,
                   checked=result.get("uploads_checked"), missing=result.get("uploads_missing", []),
                   mirror_connect_backs=result.get("mirror_connect_backs"))
        self.check("the emu chain downloaded from the servers of the client",
                   result.get("tftp_requests_served", 0) > 0 and result.get("http_requests_served", 0) > 0,
                   tftp=result.get("tftp_requests_served"), http=result.get("http_requests_served"))
        post = result.get("post", {})
        self.check("after the run new connections and an upload still work",
                   bool(post) and all(value is True for value in post.values()), **{k: v for k, v in post.items()})

    def read_client_series(self):
        rows = []
        try:
            for line in (self.root / "out/client.jsonl").read_text().splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
        except OSError:
            pass
        return rows

    # ---- report

    def write_report(self, result, passed):
        samples = [s for s in self.samples if s.get("VmRSS") is not None]
        t0 = self.samples[0]["epoch"]
        csv = [("t_s,rss_mib,hwm_mib,fds,threads,cgroup_mem_mib,cgroup_anon_mib,cgroup_file_mib,cpu_percent,"
                "restarts,oom")]
        for s in samples:
            csv.append("%.0f,%.1f,%.1f,%s,%s,%.1f,%.1f,%.1f,%s,%s,%s" % (
                s["epoch"] - t0, mib(s["VmRSS"]), mib(s.get("VmHWM", 0)), s.get("Fds"), s.get("Threads"),
                s.get("CgMem", 0) / 2**20, s.get("Cg_anon", 0) / 2**20, s.get("Cg_file", 0) / 2**20,
                s.get("cpu_percent"), s.get("restarts"), s.get("oom")))
        (self.root / "samples.csv").write_text("\n".join(csv) + "\n")
        self.summary.update(checks=self.checks, pass_=bool(passed))
        summary = dict(self.summary)
        summary["pass"] = summary.pop("pass_")
        if result:
            summary["client"] = {k: v for k, v in result.items() if k != "banner"}
        (self.root / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        lines = ["# Replay %s: %s" % (self.image, "PASS" if passed else "FAIL"), "",
                 "Mode %s, %.0f min of load, %d workers + %d idle / slow threads, platform %s, artifacts `%s`." % (
                     self.summary["mode"], self.summary["duration_s"] / 60, self.args.concurrency, self.args.idle,
                     self.summary["platform"], self.root), ""]
        if self.aborted:
            lines += ["Aborted: %s." % self.aborted, ""]
        lines += ["| criterion | result | numbers |", "| --- | --- | --- |"]
        for item in self.checks:
            details = {k: v for k, v in item.items()
                       if k not in ("name", "ok", "gating", "applicable", "note") and v is not None}
            status = ("n/a" if not item["applicable"] else "PASS" if item["ok"] else
                      "FAIL" if item["gating"] else "warn")
            lines.append("| %s | %s | `%s` |" % (item["name"], status, json.dumps(details)[:300]))
        lines += ["", "| t (s) | RSS (MiB) | cgroup memory (MiB) | of it page cache | fds | threads | CPU % |",
                  "| ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
        step = max(1, len(samples) // 30)
        for s in samples[::step]:
            lines.append("| %.0f | %.1f | %.0f | %.0f | %s | %s | %s |" % (
                s["epoch"] - t0, mib(s["VmRSS"]), s.get("CgMem", 0) / 2**20, s.get("Cg_file", 0) / 2**20,
                s.get("Fds"), s.get("Threads"), s.get("cpu_percent")))
        (self.root / "result.md").write_text("\n".join(lines) + "\n")

    def execute(self):
        started = time.monotonic()
        result = {}
        passed = False
        try:
            self.prepare()
            say("dionaea %s as %s" % (self.image, self.server))
            self.start_server()
            rc = self.run_client()
            self.summary["client_exit_code"] = rc
            try:
                result = json.loads((self.root / "out/result.json").read_text())
            except (OSError, ValueError):
                result = {}
            self.judge(result, rc)
            # SIGINT, as T-Pot: the log files are buffered and written now
            docker("stop", "-t", "60", self.server, stdout=subprocess.DEVNULL, check=False)
            if not self.aborted:
                self.judge_after_stop(result)
            else:
                container_log = docker("logs", "--tail", "100", self.server, capture_output=True, check=False)
                (self.root / "container-tail.log").write_text(container_log.stdout + container_log.stderr)
            passed = all(item["ok"] or not item["gating"] for item in self.checks) and not self.aborted
        except Exception as error:
            self.summary["error"] = "%s: %s" % (type(error).__name__, error)
            say("ERROR " + self.summary["error"])
            raise
        finally:
            self.summary["elapsed_seconds"] = round(time.monotonic() - started, 1)
            if self.samples:
                self.write_report(result, passed)
            if self.args.keep:
                say("--keep: %s and network %s left" % (self.server, self.network))
            else:
                self.cleanup()
        return passed


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", default="dionaea:local", help="image under test (default dionaea:local)")
    parser.add_argument("--duration", type=float, default=60, help="minutes of load (default 60)")
    parser.add_argument("--quick", action="store_true",
                        help="5 minutes, sample every 10 s; slope and growth are only indicative")
    parser.add_argument("--concurrency", type=int, default=8, help="parallel clients (default 8)")
    parser.add_argument("--idle", type=int, default=4, help="extra threads with idle / slow connections (default 4)")
    parser.add_argument("--think-ms", type=float, default=0, help="mean pause of a client between two scenarios")
    parser.add_argument("--interval", type=float, default=None, help="seconds between samples (default 30, quick 10)")
    parser.add_argument("--settle", type=float, default=30, help="seconds without load before the final checks")
    parser.add_argument("--seed", type=int, default=1)
    parser.add_argument("--inject-leak", choices=("malloc", "mmap"),
                        help="the probe leaks memory through malloc or anonymous mmap (a test of the gates)")
    parser.add_argument("--leak-rate", type=float, default=2.0, help="MiB / 10 min of --inject-leak (default 2)")
    parser.add_argument("--unique-share", type=float, default=0.15,
                        help="share of the uploads that are a new sample (default 0.15, the rest is one of a "
                             "pool of 48)")
    parser.add_argument("--only", default="",
                        help="comma separated scenarios of replay_client.py (debugging): these only")
    parser.add_argument("--platform", help="docker --platform of dionaea, e.g. linux/amd64 (emulated on arm64)")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG, required=DEFAULT_CONFIG is None,
                        help="configuration of dionaea, docker/dionaea/dist/etc of a T-Pot checkout "
                             "(default: $DIONAEA_CONFIG_DIR)")
    parser.add_argument("--artifacts", type=Path, help="folder for config, data, logs and results (default: temporary)")
    parser.add_argument("--keep", action="store_true", help="leave dionaea and its network (debugging)")
    parser.add_argument("--keep-going", action="store_true", help="go on after a restart or an OOM kill")
    args = parser.parse_args()
    if args.quick:
        args.duration = 5
    if args.interval is None:
        args.interval = 10 if args.quick else 30
    try:
        run_args()
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2

    if shutil.which("docker") is None or docker("info", capture_output=True, check=False).returncode != 0:
        print("docker is not available", file=sys.stderr)
        return 3
    if not (args.config / "dionaea.cfg").exists():
        print("no dionaea.cfg in %s (--config)" % args.config, file=sys.stderr)
        return 3
    root = (args.artifacts or Path(tempfile.mkdtemp(prefix="dionaea-replay."))).resolve()
    if root.exists() and any(root.iterdir()):
        print("%s is not empty" % root, file=sys.stderr)
        return 3
    say("building the client image")
    docker("build", "-q", "-t", CLIENT_IMAGE, str(FUNCTIONAL / "client"), stdout=subprocess.DEVNULL)
    try:
        passed = Replay(args, args.image, root).execute()
    except PlatformUnknown as error:
        print(error, file=sys.stderr)
        return 3
    say("%s, artifacts in %s" % ("PASSED" if passed else "FAILED", root))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
