#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The streamcap count on a slow share (see README.md).

    tests/load/slowfs/repro.py --image IMAGE [--prefill N] [--minutes M] [--stop-early S]
                               [--entry-us US] [--batch N] [--data-bind DIR] [--no-shim]
                               [--drop-caches] [--store-prefill N] [--store-max-size MIB]
                               [--artifacts DIR]

dionaea with the T-Pot limits (streamdumper 2048 MiB / 200,000 dumps, store
1024 MiB) and slowfs.so (LD_PRELOAD: a share that serves one request at a time,
with a slow cold directory read) on a Docker named volume, a bistreams folder
prefilled with N dumps, the replay client (8 workers and the FTP banner every
0.5 s) for M minutes, then ``docker stop -t 10`` while a count of the folder
runs (if one does within 90 s). ``--stop-early S``: no client, the stop comes S
seconds after dionaea listens, during the first count. ``--data-bind DIR``: the
data folder is the host folder DIR (on Docker Desktop: the virtiofs bind mount),
``--no-shim`` runs without slowfs.so, ``--drop-caches`` drops the dentries and
inodes of the Docker VM before the start (a cold folder; privileged).
``--store-prefill N`` puts N samples of ``--store-size`` bytes into binaries/
first; with ``--store-max-size`` (MiB, default 1024 as T-Pot) just above them the
store is at its cap while the client's samples come.

Afterwards it prints the walks of the counting threads (slowfs.log), the banner
latency inside and outside of them, when dionaea listened, and the stop.
Exit 0: the stop took less than --max-stop seconds with exit code 0, no walk
of the streamcap thread began after its first count, and with --store-prefill
no walk of binaries/ (the store-count thread) after its first one; 1: not so;
3: environment.
Python standard library and the docker CLI only.
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
FUNCTIONAL = REPO / "tests" / "functional"
LOAD = REPO / "tests" / "load"
CLIENT_IMAGE = "dionaea-func-client:local"
BUILDER_IMAGE = "dionaea-slowfs-builder:local"
DUMP_PATH = "config.path=/opt/dionaea/var/dionaea/bistreams/%Y-%m-%d/\n"

PREFILL = r"""
import os, sys
folder, n, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
os.makedirs(folder, exist_ok=True)
# the content is a valid dump
body = ("stream = [('in', b'" + "A" * max(0, size - 21) + "')]")[:size].encode()
for i in range(len(os.listdir(folder)), n):
    with open(os.path.join(folder, "prefill-%07d" % i), "wb") as f:
        f.write(body)
print("prefilled", folder, n, size, flush=True)
"""

STORE_PREFILL = r"""
import os, sys
folder, n, size = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
os.makedirs(folder, exist_ok=True)
# samples as the store names them (md5), read-only
for i in range(n):
    path = os.path.join(folder, "%032x" % (0x5a5a0000000000000000000000000000 + i))
    with open(path, "wb") as f:
        f.write(b"MZ prefill %d\n" % i + b"A" * max(0, size - 20))
    os.chmod(path, 0o440)
print("prefilled", folder, n, size, flush=True)
"""


def docker(*args, check=True, **kwargs):
    return subprocess.run(["docker", *args], check=check, text=True, **kwargs)


def say(*args):
    print(time.strftime("%H:%M:%S"), *args, flush=True)


def build_shim(builder):
    """slowfs.so with gcc on the base of the dionaea image (the glibc of the image), or in --builder-image"""
    if builder is None:
        builder = BUILDER_IMAGE
        base = re.findall(r"^FROM (\S+)\s*$", (REPO / "Dockerfile").read_text(), re.M)[-1]
        say("building the compiler image on", base, "(cached after the first time)")
        docker("build", "-q", "-t", builder, "-", stdout=subprocess.DEVNULL,
               input="FROM %s\nRUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev "
                     "&& rm -rf /var/lib/apt/lists/*\n" % base)
    out = Path(tempfile.mkdtemp(prefix="dionaea-slowfs-so."))
    out.chmod(0o755)
    docker("run", "--rm", "-v", "%s:/src:ro" % HERE, "-v", "%s:/out" % out, "--entrypoint", "sh", builder, "-c",
           "gcc -O2 -Wall -shared -fPIC -o /out/slowfs.so /src/slowfs.c -ldl -lpthread && chmod 0755 /out/slowfs.so")
    return out


def walks_of(log_text):
    """thread name -> [(time, entries of the thread by then)] of the lines of SLOWFS_LOG"""
    walks = {}
    for line in log_text.splitlines():
        parts = line.split()
        if len(parts) == 4:
            walks.setdefault(parts[2], []).append((float(parts[0]), int(parts[3])))
    return walks


def spans(points, gap=5.0):
    """
    [start, end, entries]: the log lines of a thread with less than gap seconds between them, and about the
    entries the thread read in that time (the shim logs every 2,000 entries, its count runs since the start)
    """
    out = []
    first = None
    for t, n in points:
        if out and t - out[-1][1] <= gap:
            out[-1][1] = t
            out[-1][2] = n - first + 2000
        else:
            first = n
            out.append([t, t, 2000])
    return out


def stats(values):
    values = sorted(values)
    if not values:
        return "n=0"
    pct = lambda q: values[min(len(values) - 1, int(len(values) * q))]  # noqa: E731
    return "n=%d p50 %.3f s p99 %.2f s max %.2f s, %d >= 0.5 s" % (
        len(values), pct(.5), pct(.99), values[-1], sum(v >= .5 for v in values))


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--image", required=True, help="the dionaea image under test")
    p.add_argument("--prefill", type=int, default=190000, help="dumps put into bistreams/2026-10-01 first")
    p.add_argument("--size", type=int, default=100, help="bytes per prefilled dump")
    p.add_argument("--minutes", type=float, default=5, help="minutes of load")
    p.add_argument("--stop-early", type=float, default=0, help="no load; stop S seconds after dionaea listens")
    p.add_argument("--entry-us", default="500", help="SLOWFS_ENTRY_US: microseconds per directory entry")
    p.add_argument("--batch", default="128", help="SLOWFS_BATCH: entries per getdents request")
    p.add_argument("--stat-us", default="20", help="SLOWFS_STAT_US: microseconds per stat")
    p.add_argument("--no-shim", action="store_true", help="without slowfs.so (a bind mount that is slow itself)")
    p.add_argument("--data-bind", type=Path, help="host folder for var/dionaea instead of a named volume")
    p.add_argument("--drop-caches", action="store_true", help="drop the dentries and inodes of the Docker VM first")
    p.add_argument("--stop-timeout", type=int, default=10, help="docker stop -t (T-Pot's compose default)")
    p.add_argument("--max-stop", type=float, default=2.0,
                   help="seconds the stop may take (dionaea's own stop takes 0.6 to 0.8 s without a walk)")
    p.add_argument("--store-prefill", type=int, default=0, help="samples put into binaries/ first")
    p.add_argument("--store-size", type=int, default=4096, help="bytes per prefilled sample")
    p.add_argument("--store-max-size", type=int, default=1024, help="max_size of the store in MiB (T-Pot: 1024)")
    p.add_argument("--builder-image", help="image with gcc and the glibc of the dionaea image")
    p.add_argument("--artifacts", type=Path, help="folder for config, logs and results (new; default: a temp folder)")
    a = p.parse_args()

    if shutil.which("docker") is None or docker("info", check=False, capture_output=True).returncode:
        print("docker is not available", file=sys.stderr)
        return 3
    root = (a.artifacts or Path(tempfile.mkdtemp(prefix="dionaea-slowfs."))).resolve()
    root.mkdir(parents=True, exist_ok=a.artifacts is None)
    if any(root.iterdir()):
        print("%s is not empty" % root, file=sys.stderr)
        return 3
    say("artifacts in", root)
    shim = None if a.no_shim else build_shim(a.builder_image)
    if docker("image", "inspect", CLIENT_IMAGE, check=False, capture_output=True).returncode:
        say("building the client image")
        docker("build", "-q", "-t", CLIENT_IMAGE, str(FUNCTIONAL / "client"), stdout=subprocess.DEVNULL)

    for sub in ("etc", "out", "roots/ftp", "roots/tftp", "roots/www", "roots/upnp"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    shutil.copytree(FUNCTIONAL / "config", root / "etc", dirs_exist_ok=True)
    (root / "roots/ftp/functional-list.txt").write_text("ftp functional test file\n")
    (root / "roots/tftp/functional-test.txt").write_text("tftp functional test file\n")
    cfg = (root / "etc/dionaea.cfg").read_text()
    # the limits of T-Pot's dionaea.cfg and store.yaml
    if DUMP_PATH not in cfg:
        print("no streamdumper path %r in the functional config" % DUMP_PATH, file=sys.stderr)
        return 3
    cfg = cfg.replace(DUMP_PATH, DUMP_PATH + "config.max_size=2048\nconfig.max_files=200000\n", 1)
    (root / "etc/dionaea.cfg").write_text(cfg)
    (root / "etc/ihandlers/store.yaml").write_text("- name: store\n  config:\n    max_size: %d\n" % a.store_max_size)
    for path in [root, *root.rglob("*")]:
        path.chmod(0o777 if path.is_dir() else 0o666)

    tag = "dionaea-slowfs-%d" % int(time.time())
    server, client, net = tag, tag + "-client", tag
    vlog = tag + "-log"
    if a.data_bind:
        a.data_bind = a.data_bind.resolve()
        a.data_bind.mkdir(parents=True, exist_ok=True)
        vdata = str(a.data_bind)
    else:
        vdata = tag + "-data"
    meta = {"args": {k: str(v) for k, v in vars(a).items()}, "events": []}

    def event(name, **kwargs):
        meta["events"].append({"t": time.time(), "name": name, **kwargs})
        say(name, kwargs or "")
        (root / "meta.json").write_text(json.dumps(meta, indent=1))

    def slowfs_log():
        r = docker("run", "--rm", "-v", "%s:/l:ro" % vlog, "--entrypoint", "sh", a.image, "-c",
                   "cat /l/slowfs.log 2>/dev/null", capture_output=True, check=False)
        return r.stdout

    def walking(thread, within=3.0):
        """the shim logged directory entries of thread in the last within seconds"""
        lines = [line.split() for line in slowfs_log().splitlines()[-50:]]
        return any(len(x) == 4 and x[2] == thread and time.time() - float(x[0]) < within for x in lines)

    try:
        docker("network", "create", "--internal", net, stdout=subprocess.DEVNULL)
        subnet = docker("network", "inspect", "--format", "{{(index .IPAM.Config 0).Subnet}}", net,
                        capture_output=True).stdout.strip()
        (root / "etc/ihandlers/download_policy.yaml").write_text(
            "- name: download_policy\n  config:\n    allowed_networks: [\"%s\"]\n" % subnet)
        (root / "etc/ihandlers/download_policy.yaml").chmod(0o666)
        if not a.data_bind:
            docker("volume", "create", vdata, stdout=subprocess.DEVNULL)
        docker("volume", "create", vlog, stdout=subprocess.DEVNULL)
        docker("run", "--rm", "-v", "%s:/d" % vdata, "-v", "%s:/l" % vlog, "--entrypoint", "sh", "--user", "0",
               a.image, "-c", "cd /d && mkdir -p binaries bistreams rtp roots && "
               "chmod 777 . binaries bistreams rtp roots /l")
        if a.prefill:
            event("prefill-start", n=a.prefill, size=a.size)
            docker("run", "--rm", "--user", "2000:2000", "-v", "%s:/d" % vdata, "--entrypoint", "python3", a.image,
                   "-c", PREFILL, "/d/bistreams/2026-10-01", str(a.prefill), str(a.size))
            event("prefill-end")
        if a.store_prefill:
            event("store-prefill-start", n=a.store_prefill, size=a.store_size)
            docker("run", "--rm", "--user", "2000:2000", "-v", "%s:/d" % vdata, "--entrypoint", "python3", a.image,
                   "-c", STORE_PREFILL, "/d/binaries", str(a.store_prefill), str(a.store_size))
            event("store-prefill-end")
        if a.drop_caches:
            docker("run", "--rm", "--privileged", "--user", "0", "--entrypoint", "sh", a.image, "-c",
                   "sync; echo 2 > /proc/sys/vm/drop_caches")
            event("caches-dropped")

        # root in the container: the file capability of dionaea makes the loader ignore LD_PRELOAD for
        # another user (secure execution); dionaea drops to its user itself (-u / -g of the image's CMD)
        args = ["run", "-d", "--name", server, "--network", net, "--read-only", "--user", "0",
                "--memory", "1g", "--memory-swap", "1g", "--cpus", "1", "--pids-limit", "256",
                "--tmpfs", "/tmp:uid=2000,gid=2000,size=16m",
                "-v", "%s:/opt/dionaea/etc/dionaea:ro" % (root / "etc"),
                "-v", "%s:/opt/dionaea/var/dionaea" % vdata, "-v", "%s:/opt/dionaea/var/log" % vlog]
        if shim is not None:
            args += ["-e", "LD_PRELOAD=/shim/slowfs.so", "-e", "SLOWFS_ENTRY_US=" + a.entry_us,
                     "-e", "SLOWFS_BATCH=" + a.batch, "-e", "SLOWFS_STAT_US=" + a.stat_us,
                     "-e", "SLOWFS_LOG=/opt/dionaea/var/log/slowfs.log", "-v", "%s:/shim:ro" % shim]
        for name in ("ftp", "tftp", "www", "upnp"):
            args += ["-v", "%s:/opt/dionaea/var/dionaea/roots/%s:ro" % (root / "roots" / name, name)]
        event("server-start")
        docker(*args, a.image, stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + 900
        while docker("exec", server, "sh", "-c", "grep -q ':0015 ' /proc/net/tcp", check=False,
                     capture_output=True).returncode:
            if time.monotonic() > deadline:
                event("no-port-21")
                return 1
            time.sleep(0.5)
        event("server-listens")

        if a.stop_early:
            time.sleep(a.stop_early)
        else:
            mounts = ["-v", "%s:/tests:ro" % FUNCTIONAL, "-v", "%s:/work:ro" % LOAD, "-v", "%s:/out" % (root / "out"),
                      "-v", "%s:/logs:ro" % vlog, "-v", "%s:/data:ro" % vdata]
            cmd = ["python", "-u", "/work/replay_client.py", "--duration", str(int(a.minutes * 60)),
                   "--concurrency", "8", "--idle", "4", "--think-ms", "0", "--interval", "30", "--seed", "1",
                   "--settle", "30", "--unique-share", "0.15"]
            event("client-start")
            with (root / "client.log").open("w") as log:
                rc = subprocess.run(["docker", "run", "--rm", "--name", client, "--network", net, "--memory", "2g",
                                     "--cpus", "4", "--pids-limit", "512", "-e", "DIONAEA_HOST=" + server, *mounts,
                                     CLIENT_IMAGE, *cmd], stdout=log, stderr=subprocess.STDOUT).returncode
            event("client-end", rc=rc)
            if shim is not None:
                # stop while a count of the folder runs, if one does within 90 s (the old code walks every period)
                deadline = time.monotonic() + 90
                while time.monotonic() < deadline and not walking("streamcap"):
                    time.sleep(1)
        event("streamcap-walking", walking=shim is not None and walking("streamcap"))

        event("stop-start")
        t0 = time.monotonic()
        docker("stop", "-t", str(a.stop_timeout), server, stdout=subprocess.DEVNULL, check=False)
        state = json.loads(docker("inspect", server, capture_output=True).stdout)[0]["State"]
        stop = round(time.monotonic() - t0, 1)
        event("stop-end", seconds=stop, exit_code=state["ExitCode"])
        logs = docker("logs", server, capture_output=True, check=False)
        (root / "container.log").write_text(logs.stdout + logs.stderr)
        (root / "slowfs.log").write_text(slowfs_log())
        docker("run", "--rm", "-v", "%s:/d:ro" % vdata, "-v", "%s:/o" % root, "--entrypoint", "sh", "--user", "0",
               a.image, "-c", "cp /d/dionaea.log /d/dionaea-errors.log /o/ 2>/dev/null; chmod a+r /o/*.log",
               check=False)
    finally:
        docker("rm", "-f", server, client, check=False, capture_output=True)
        docker("network", "rm", net, check=False, capture_output=True)
        docker("volume", "rm", vlog, check=False, capture_output=True)
        if not a.data_bind:
            docker("volume", "rm", vdata, check=False, capture_output=True)
        if shim is not None:
            shutil.rmtree(shim, ignore_errors=True)

    # the result
    ev = {e["name"]: e for e in meta["events"]}
    listen = ev["server-listens"]["t"]
    counted = None
    log = root / "dionaea.log"
    if log.exists():
        m = re.search(r"bistreams in \S+ hold \d+ bytes in \d+ files \(counted in ([0-9.]+) s\)", log.read_text())
        counted = float(m.group(1)) if m else None
    walk_spans, late, store_late = [], [], []
    for name, points in sorted(walks_of((root / "slowfs.log").read_text()).items()):
        for index, (start, end, n) in enumerate(spans(points)):
            print("walk %-12s from %+7.1f s to %+7.1f s after the listen (%5.1f s, about %d entries)"
                  % (name, start - listen, end - listen, end - start, n))
            if name in ("streamcap", "store-count"):
                walk_spans.append((start - 1.0, end + 1.0))
            # a walk of the prefilled folder that begins after the first count ended: the old periodic count
            # (a refused dump may have today's folder of this run counted again, at most every 10 minutes)
            if name == "streamcap" and counted is not None and start - listen > counted + 5 and n >= a.prefill / 2:
                late.append(start - listen)
            # the store: binaries/ is counted once at the start, a later walk of it is a refusal that read it
            if name == "store-count" and index > 0 and a.store_prefill and n >= a.store_prefill / 2:
                store_late.append(start - listen)
    rows = []
    banner = root / "out" / "banner.csv"
    if banner.exists():
        for line in banner.read_text().splitlines()[1:]:
            at, value, _ = line.split(",", 2)
            rows.append((float(at), float(value)))
    inside = [v for at, v in rows if any(s <= at <= e for s, e in walk_spans)]
    outside = [v for at, v in rows if not any(s <= at <= e for s, e in walk_spans)]
    print("banner all       :", stats([v for _, v in rows]))
    print("banner in walks  :", stats(inside))
    print("banner outside   :", stats(outside))
    print("listens %.1f s after the start; first count %s" % (
        listen - ev["server-start"]["t"], "%.1f s" % counted if counted is not None else "not ended"))
    print("stop: %.1f s, exit code %d (a walk ran: %s)" % (
        ev["stop-end"]["seconds"], ev["stop-end"]["exit_code"], ev["streamcap-walking"]["walking"]))
    ok = ev["stop-end"]["seconds"] < a.max_stop and ev["stop-end"]["exit_code"] == 0 and not late and not store_late
    if late:
        print("walks of the prefilled folder after the first count, at", ["%+.0f s" % t for t in late])
    if store_late:
        print("walks of binaries/ after the first count, at", ["%+.0f s" % t for t in store_late])
    store = root / "dionaea.log"
    if a.store_prefill and store.exists():
        text = store.read_text(errors="replace")
        print("store: %d samples refused (warnings), %d stored" % (
            text.count("Not storing "), text.count("saving new file")))
    print("PASSED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
