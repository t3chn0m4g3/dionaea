#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Load test of dionaea's native stream processing (see README.md).

    tests/load/run.py [--image IMAGE] [--scenario normal|overload|all] [--artifacts DIR]

Starts dionaea on an internal Docker network as in T-Pot (uid/gid 2000,
read-only) with the limits of a small sensor (768 MiB without swap, 1 CPU, 128
pids), the emu processor active, and runs client.py in the client container of
the functional tests. Then the functional tests of the services run against
the same dionaea, it is stopped and its logs are checked. Exit 0: every
scenario passed; 1: a check failed (summary.json says which); 2: DIONAEA_RUN_ARGS
has another option than a read-only file mount or --ulimit nofile (runargs.py);
3: environment.
Python standard library and the docker CLI only.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from runargs import run_args

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
FUNCTIONAL = REPO / "tests" / "functional"
CLIENT_IMAGE = "dionaea-func-client:local"

LIMITS = ["--memory", "768m", "--memory-swap", "768m", "--cpus", "1", "--pids-limit", "128"]
# /tmp as in the T-Pot compose files: the files of the emulation (CreateFile, _lcreat) are made there
TMPFS = ["--tmpfs", "/tmp:uid=2000,gid=2000,size=16m"]
CLIENT_LIMITS = ["--memory", "1g", "--cpus", "2", "--pids-limit", "256"]
CLIENT_TIMEOUT = {"normal": 3600, "overload": 900}
# the functional tests of the services that run after the load
AFTER_TESTS = ["test_smoke.py", "test_smb_auth.py", "test_ftp.py", "test_tftp.py", "test_upload.py"]
BAD_LOG = re.compile(r"Traceback|LoaderError|Error loading module|Unable to start service|"
                     r"Assertion .*failed|Segmentation fault|-critical:")
# the whole line: reason, connection, protocol and address, nothing of the data (info since 0.12.3,
# a warning before)
OVERLOAD_LINE = re.compile(r"^\[[^]]+\] processor \S+-(?:warning|info): Stream processing limit reached "
                           r"\((stream data limit|job queue full|stream offsets)\), "
                           r"closing connection 0x[0-9a-f]+ \S+ [0-9a-fA-F.:]+:(\d+)$", re.M)
# the emu gives up at a limit or after its scan limit (the reason "scan limit"); "stream offsets"
# would be a bug
GIVE_UP_LINE = re.compile(r"^\[[^]]+\] processor \S+-(?:warning|info): emu scan stopped "
                          r"\((stream data limit|job queue full|scan limit)\), "
                          r"connection 0x[0-9a-f]+ \S+ [0-9a-fA-F.:]+:(\d+) goes on$", re.M)
# the summary warning of both, once a minute: the number, the reason and the address of the last one
SUMMARY_LINE = re.compile(r"^\[[^]]+\] processor \S+-warning: (scans stopped|connections closed) "
                          r"at a limit: \d+ connection\(s\) in the last minute, the last: (emu scan, )?"
                          r"(stream data limit|job queue full|stream offsets) \(\S+ [0-9a-fA-F.:]+:\d+\)$", re.M)


def odd_limit_lines(log):
    """The lines of the limits of the stream processing with more than their reason and address."""
    return [line for line in log.splitlines()
            if ("Stream processing limit reached" in line and not OVERLOAD_LINE.match(line))
            or ("scan stopped" in line and not GIVE_UP_LINE.match(line))
            or (re.match(r"^\[[^]]+\] processor \S+-warning: ", line) and " at a limit: " in line
                and not SUMMARY_LINE.match(line))]


def give_ups(load_log):
    """The (reason, port) of the emu scans stopped at a limit, and the ports of those done at their scan limit."""
    lines = GIVE_UP_LINE.findall(load_log)
    gave_up = [(reason, int(port)) for reason, port in lines if reason != "scan limit"]
    scan_limit = [int(port) for reason, port in lines if reason == "scan limit"]
    return gave_up, scan_limit


# the line probe.py logs when run.py asks for it, before the functional tests
LOAD_MARK = "load test mark %s"
MARK_TIMEOUT = 30


def load_lines(log, mark):
    """The lines of dionaea.log before the line of the mark (those of the load), None without it."""
    if mark is None:
        return None
    lines = log.splitlines()
    end = "-info: " + LOAD_MARK % mark
    for number, text in enumerate(lines):
        if text.endswith(end):
            return lines[:number]
    return None


def say(message):
    print("==> " + message, flush=True)


def docker(*args, **kwargs):
    kwargs.setdefault("check", True)
    kwargs.setdefault("text", True)
    return subprocess.run(["docker", *args], **kwargs)


def inspect(name):
    out = docker("inspect", name, capture_output=True, check=False)
    return json.loads(out.stdout)[0] if out.returncode == 0 else None


class Run:
    def __init__(self, scenario, image, root, keep=False):
        self.keep = keep
        self.scenario = scenario
        self.image = image
        self.root = root
        tag = "%d-%s" % (os.getpid(), scenario)
        self.server = "dionaea-load-%s" % tag
        self.client = "dionaea-load-%s-client" % tag
        self.network = "dionaea-load-%s" % tag
        self.summary = {"scenario": scenario, "image": image, "limits": LIMITS, "checks": []}

    def check(self, name, ok, **details):
        self.summary["checks"].append({"name": name, "ok": bool(ok), **details})
        say("%s %s %s" % ("PASS" if ok else "FAIL", name, json.dumps(details) if details else ""))
        if not ok:
            raise AssertionError(name)

    def prepare(self):
        for sub in ("etc", "log", "out", "data/binaries", "data/bistreams", "data/rtp",
                    "data/roots/ftp", "data/roots/tftp", "data/roots/www", "data/roots/upnp"):
            (self.root / sub).mkdir(parents=True, exist_ok=True)
        shutil.copytree(FUNCTIONAL / "config", self.root / "etc", dirs_exist_ok=True)
        cfg = self.root / "etc" / "dionaea.cfg"
        text = cfg.read_text()
        # no bistream files: 36,000 logins of 48 KiB would write about 1.7 GiB
        text = text.replace("processors=filter_streamdumper,filter_emu", "processors=filter_emu")
        text = text.replace("imports=dionaea.log,dionaea.services,dionaea.ihandlers",
                            "imports=dionaea.log,dionaea.services,dionaea.ihandlers,load_probe")
        assert "processors=filter_emu\n" in text and "load_probe" in text, "dionaea.cfg changed, adjust run.py"
        cfg.write_text(text)
        (self.root / "data/roots/ftp/functional-list.txt").write_text("ftp functional test file\n")
        (self.root / "data/roots/tftp/functional-test.txt").write_text("tftp functional test file\n")
        shutil.copy(HERE / "probe.py", self.root / "load_probe.py")
        for path in [self.root, *self.root.rglob("*")]:
            path.chmod(0o777 if path.is_dir() else 0o666)

    def start_server(self):
        docker("network", "create", "--internal", self.network, stdout=subprocess.DEVNULL)
        subnet = docker("network", "inspect", "--format", "{{(index .IPAM.Config 0).Subnet}}", self.network,
                        capture_output=True).stdout.strip()
        (self.root / "etc/ihandlers/download_policy.yaml").write_text(
            "- name: download_policy\n  config:\n    allowed_networks: [\"%s\"]\n" % subnet)
        args = ["run", "-d", "--name", self.server, "--network", self.network, "--read-only",
                "--user", "2000:2000", *LIMITS, *TMPFS,
                "-v", "%s:/opt/dionaea/etc/dionaea:ro" % (self.root / "etc"),
                "-v", "%s:/opt/dionaea/var/dionaea" % (self.root / "data"),
                "-v", "%s:/opt/dionaea/var/log" % (self.root / "log"),
                "-v", "%s:/opt/dionaea/lib/dionaea/python/load_probe.py:ro" % (self.root / "load_probe.py")]
        for name in ("ftp", "tftp", "www", "upnp"):
            args += ["-v", "%s:/opt/dionaea/var/dionaea/roots/%s:ro" % (self.root / "data/roots" / name, name)]
        # e.g. "--ulimit nofile=128", the allowed ones only (runargs.py, as replay.py and tests/functional/run.sh)
        args += run_args()
        docker(*args, self.image, stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + 90
        while not (self.root / "log/probe.jsonl").exists():
            state = inspect(self.server)
            if not state or not state["State"]["Running"]:
                raise AssertionError("dionaea exited during the start")
            if time.monotonic() > deadline:
                raise AssertionError("the probe did not start within 90 s")
            time.sleep(1)

    def container_state(self, name):
        state = inspect(self.server)
        details = {"running": state["State"]["Running"], "oom_killed": state["State"]["OOMKilled"],
                   "exit_code": state["State"]["ExitCode"], "restarts": state["RestartCount"]}
        self.summary.setdefault("container", {})[name] = details
        return details

    def run_client(self):
        mounts = ["-v", "%s:/work/client.py:ro" % (HERE / "client.py"), "-v", "%s:/out" % (self.root / "out"),
                  "-v", "%s:/logs:ro" % (self.root / "log"), "-v", "%s:/data:ro" % (self.root / "data")]
        with (self.root / "client.log").open("w") as log:
            try:
                rc = docker("run", "--rm", "--name", self.client, "--network", self.network, *CLIENT_LIMITS,
                            "-e", "DIONAEA_HOST=" + self.server, *mounts, CLIENT_IMAGE,
                            "python", "-u", "/work/client.py", self.scenario,
                            stdout=log, stderr=subprocess.STDOUT, check=False,
                            timeout=CLIENT_TIMEOUT[self.scenario]).returncode
            except subprocess.TimeoutExpired:
                rc = "timeout"
        result_file = self.root / "out/result.json"
        result = json.loads(result_file.read_text()) if result_file.exists() else {}
        self.summary["client"] = result
        state = self.container_state("after_load")
        self.check("no OOM kill, no restart, dionaea runs", state["running"] and not state["oom_killed"]
                   and state["restarts"] == 0, **state)
        self.check("load client", rc == 0 and result.get("pass") is True, rc=rc, error=result.get("error"),
                   elapsed_seconds=result.get("elapsed_seconds"))

    def mark_load_end(self):
        """The probe logs a mark into dionaea.log: the lines before it are those of the load."""
        mark = "%d-%s" % (os.getpid(), self.scenario)
        (self.root / "log/probe-mark").write_text(mark + "\n")
        deadline = time.monotonic() + MARK_TIMEOUT
        while time.monotonic() < deadline:
            try:
                lines = (self.root / "log/probe.jsonl").read_text(errors="replace").splitlines()[-5:]
            except OSError:
                # no file of the probe (yet): no mark, the check of the mark fails
                lines = []
            for text in lines:
                try:
                    if json.loads(text).get("mark") == mark:
                        return mark
                except ValueError:
                    pass
            time.sleep(0.5)
        return None

    def run_functional(self):
        self.summary["load_mark"] = self.mark_load_end()
        # keep the large log of the load, the functional tests read dionaea.json whole
        shutil.copy2(self.root / "log/dionaea.json", self.root / "out/load-dionaea.json")
        os.truncate(self.root / "log/dionaea.json", 0)
        with (self.root / "functional.log").open("w") as log:
            rc = docker("run", "--rm", "--name", self.client, "--network", self.network, *CLIENT_LIMITS,
                        "-v", "%s:/tests:ro" % FUNCTIONAL,
                        "-v", "%s:/dionaea/data:ro" % (self.root / "data"),
                        "-v", "%s:/dionaea/log:ro" % (self.root / "log"),
                        "-v", "%s:/src/dionaea:ro" % (REPO / "modules/python/dionaea"),
                        "-e", "DIONAEA_PY_SRC=/src/dionaea", "-e", "DIONAEA_HOST=" + self.server,
                        "-e", "DIONAEA_DATA_DIR=/dionaea/data", "-e", "DIONAEA_LOG_DIR=/dionaea/log",
                        CLIENT_IMAGE, "python", "-m", "pytest", "-p", "no:cacheprovider", "-q", *AFTER_TESTS,
                        stdout=log, stderr=subprocess.STDOUT, check=False, timeout=900).returncode
        tail = (self.root / "functional.log").read_text(errors="replace").strip().splitlines()[-1:]
        self.check("functional tests after the load (%s)" % ", ".join(AFTER_TESTS), rc == 0,
                   rc=rc, result=tail[0] if tail else "")
        state = self.container_state("after_functional")
        self.check("dionaea still runs after the functional tests", state["running"] and not state["oom_killed"]
                   and state["restarts"] == 0, **state)

    def stop_and_check_logs(self):
        # SIGINT, as T-Pot: the log files are buffered and written now
        docker("stop", "-t", "30", self.server, stdout=subprocess.DEVNULL, check=False)
        container_log = docker("logs", self.server, capture_output=True, check=False)
        (self.root / "container.log").write_text(container_log.stdout + container_log.stderr)
        texts = {"container.log": container_log.stdout + container_log.stderr}
        for name in ("dionaea.log", "dionaea-errors.log"):
            path = self.root / "data" / name
            texts[name] = path.read_text(errors="replace") if path.exists() else ""
        bad = {name: BAD_LOG.findall(text)[:3] for name, text in texts.items() if BAD_LOG.search(text)}
        self.check("no Traceback, assertion or crash in the logs", not bad, found=bad)
        log = texts["dionaea.log"]
        # the lines of the load, without those of the functional tests afterwards
        lines = load_lines(log, self.summary.get("load_mark"))
        self.check("the probe marked the end of the load in dionaea.log", lines is not None,
                   mark=self.summary.get("load_mark"))
        load_log = "\n".join(lines or [])
        overloads = OVERLOAD_LINE.findall(log)
        self.summary["overload_lines"] = len(overloads)
        # T-Pot has no processor that needs the whole history: no connection is closed
        self.check("no overload close", not overloads, lines=len(overloads))
        gave_up, scan_limit = give_ups(load_log)
        reasons = {}
        per_port = {}
        for reason, port in gave_up:
            reasons[reason] = reasons.get(reason, 0) + 1
            per_port[port] = per_port.get(port, 0) + 1
        self.summary.update(give_up_lines=len(gave_up), give_up_reasons=reasons, scan_limit_lines=len(scan_limit))
        client = self.summary["client"]
        uploads = set(client.get("smb_upload_ports", []))
        bursts = set(client.get("ports", []))
        self.check("the emu gives up at most once per connection",
                   set(per_port.values()) <= {1} and not set(per_port) & set(scan_limit),
                   repeated=[port for port, count in per_port.items() if count != 1][:5])
        if self.scenario == "normal":
            # the login connections send more than the emu scans: their scan stops at its limit (info)
            self.check("the emu gives up only for SMB uploads", set(per_port) <= uploads,
                       uploads=len(uploads), lines=len(gave_up), scan_limit=len(scan_limit), reasons=reasons,
                       other=sorted(set(per_port) - uploads)[:5])
        else:
            self.check("one give-up line per burst connection, none for the slow connections",
                       bursts <= set(per_port) and set(per_port) <= bursts | uploads
                       and not set(per_port) & set(client.get("slow_ports", [])),
                       connections=len(bursts), lines=len(gave_up), reasons=reasons,
                       missing=sorted(bursts - set(per_port))[:5],
                       other=sorted(set(per_port) - bursts - uploads)[:5])
        other = odd_limit_lines(log)
        self.check("limit lines carry only reason and address", not other, other=other[:3])

    def cleanup(self):
        docker("rm", "-f", self.client, capture_output=True, check=False)
        docker("rm", "-f", self.server, capture_output=True, check=False)
        docker("network", "rm", self.network, capture_output=True, check=False)

    def execute(self):
        started = time.monotonic()
        try:
            self.prepare()
            say("%s: dionaea %s as %s" % (self.scenario, self.image, self.server))
            self.start_server()
            say("%s: load client running, log in %s" % (self.scenario, self.root / "client.log"))
            self.run_client()
            self.run_functional()
            self.stop_and_check_logs()
            self.summary["pass"] = True
        except AssertionError as error:
            self.summary.update({"pass": False, "error": str(error)})
            if inspect(self.server):
                self.container_state("at_failure")
                if not self.keep:
                    # SIGINT writes the buffered log files (data/dionaea.log) for the analysis
                    docker("stop", "-t", "30", self.server, stdout=subprocess.DEVNULL, check=False)
        finally:
            self.summary["elapsed_seconds"] = round(time.monotonic() - started, 1)
            if inspect(self.server):
                log = docker("logs", "--tail", "200", self.server, capture_output=True, check=False)
                (self.root / "container-tail.log").write_text(log.stdout + log.stderr)
            if self.keep and not self.summary.get("pass"):
                say("--keep: %s and network %s left running" % (self.server, self.network))
            else:
                self.cleanup()
            (self.root / "summary.json").write_text(json.dumps(self.summary, indent=2) + "\n")
        return self.summary["pass"]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--image", help="test this image (default: build the Dockerfile of the checkout)")
    parser.add_argument("--scenario", choices=("normal", "overload", "all"), default="all")
    parser.add_argument("--artifacts", type=Path,
                        help="folder for config, data, logs and summary.json (default: a new temporary folder)")
    parser.add_argument("--keep", action="store_true", help="leave dionaea running after a failure (debugging)")
    args = parser.parse_args()
    try:
        run_args()
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2

    if shutil.which("docker") is None or docker("info", capture_output=True, check=False).returncode != 0:
        print("docker is not available", file=sys.stderr)
        return 3
    root = args.artifacts or Path(tempfile.mkdtemp(prefix="dionaea-load."))
    root = root.resolve()
    if root.exists() and any(root.iterdir()):
        print("%s is not empty" % root, file=sys.stderr)
        return 3
    image = args.image
    if image is None:
        image = "dionaea-load:%d" % os.getpid()
        say("building %s from %s" % (image, REPO / "Dockerfile"))
        docker("build", "-q", "-t", image, str(REPO), stdout=subprocess.DEVNULL)
    say("building the client image")
    docker("build", "-q", "-t", CLIENT_IMAGE, str(FUNCTIONAL / "client"), stdout=subprocess.DEVNULL)

    scenarios = ["normal", "overload"] if args.scenario == "all" else [args.scenario]
    results = {}
    for scenario in scenarios:
        results[scenario] = Run(scenario, image, root / scenario, args.keep).execute()
    (root / "summary.json").write_text(json.dumps({"image": image, "pass": all(results.values()),
                                                   "scenarios": results}, indent=2) + "\n")
    say("%s, artifacts in %s" % ("PASSED" if all(results.values()) else "FAILED", root))
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
