#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""replay.py: DIONAEA_RUN_ARGS cannot change the limits of an acceptance run.

The arguments of DIONAEA_RUN_ARGS come after the T-Pot limits in "docker run",
and docker takes the last value of an option: --memory 4g there quietly loosened
the run. Options of the limits are refused now (with = or a separate value), the
value is recorded in the summary.

    python3 tests/load/test_replay_args.py      (standard library only, no docker)
"""

import argparse
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import replay  # noqa: E402


class RunArgsTest(unittest.TestCase):
    def test_the_options_of_the_limits_are_refused(self):
        for value in ("--memory 4g", "--memory=4g", "-m 4g", "-m4g", "--memory-swap -1", "--memory-swap=-1",
                      "--cpus 4", "--cpus=4", "--pids-limit 0", "--pids-limit=-1",
                      "--cpu-quota=200000", "--oom-kill-disable", "--restart no", "--restart=no"):
            with self.subTest(value=value), self.assertRaises(ValueError) as error:
                replay.run_args(value)
            self.assertIn("DIONAEA_RUN_ARGS", str(error.exception))

    def test_the_options_of_the_user_privileges_and_read_only_are_refused(self):
        # the run is as T-Pot runs dionaea: uid/gid 2000, no extra capabilities, a read-only root
        for value in ("--privileged", "--privileged=true", "--user 0", "--user=0:0", "-u 0", "-u0",
                      "--cap-add NET_ADMIN", "--cap-add=ALL", "--read-only=false", "--read-only=0",
                      "--read-only=False", "--security-opt seccomp=unconfined",
                      "--security-opt=apparmor=unconfined", "--ulimit nofile=128 --privileged"):
            with self.subTest(value=value), self.assertRaises(ValueError) as error:
                replay.run_args(value)
            self.assertIn("DIONAEA_RUN_ARGS", str(error.exception))

    def test_a_cluster_of_short_flags_is_refused(self):
        # docker takes -tu0 as -t -u 0: no cluster, whatever is in it
        for value in ("-tu0", "-itu 0", "-du root", "-tm4g", "-ti", "-vt /x:/y", "-it"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                replay.run_args(value)

    def test_every_other_option_of_docker_run_is_refused(self):
        for value in ("--userns=host", "--userns host", "--pid=host", "--pid host", "--network host",
                      "--network=host", "--net=host", "--device /dev/mem", "--device=/dev/mem",
                      "--entrypoint sh", "--entrypoint=sh", "-e A=1", "--env=A=1", "--ipc=host",
                      "--uts=host", "--cgroupns=host", "--sysctl net.ipv4.ip_forward=1", "-p 21:21",
                      "--group-add 0", "--mount type=bind,src=/,dst=/host", "--rm", "--name x",
                      "--ulimit core=-1", "--ulimit=nproc=10", "--ulimit", "-v", "--volume"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                replay.run_args(value)

    def test_a_volume_is_a_file_mounted_read_only_into_the_modules_or_the_configuration(self):
        with tempfile.TemporaryDirectory() as folder:
            probe = Path(folder) / "leak_probe.py"
            probe.write_text("")
            for value in ("-v /:/host", "-v /:/opt/dionaea/lib/dionaea/python/x.py:ro", "--volume=/:/host",
                          "-v %s:/opt/dionaea/lib/dionaea/python/leak_probe.py" % probe,          # read-write
                          "-v %s:/opt/dionaea/lib/dionaea/python/leak_probe.py:rw" % probe,
                          "-v %s:/opt/dionaea/var/dionaea/x.py:ro" % probe,                      # not there
                          "-v %s:/opt/dionaea/lib/dionaea/python/../../../../etc/x:ro" % probe,
                          "-v %s:/host:ro" % probe, "-v %s/nothere.py:/opt/dionaea/etc/dionaea/a:ro" % folder,
                          "-v %s:/opt/dionaea/lib/dionaea/python/a.py:ro,z" % probe,
                          "-v%s:/opt/dionaea/lib/dionaea/python/a.py:ro" % probe):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    replay.run_args(value)

    def test_the_options_the_debugging_runs_need_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            probe = Path(folder) / "leak_probe.py"
            probe.write_text("")
            config = Path(folder) / "dionaea.cfg"
            config.write_text("")
            for value in ("--ulimit nofile=128", "--ulimit=nofile=128", "--ulimit nofile=128:256",
                          "-v %s:/opt/dionaea/lib/dionaea/python/leak_probe.py:ro" % probe,
                          "--volume %s:/opt/dionaea/lib/dionaea/python/leak_probe.py:ro" % probe,
                          "--volume=%s:/opt/dionaea/etc/dionaea/dionaea.cfg:ro" % config,
                          "--ulimit nofile=128 -v %s:/opt/dionaea/lib/dionaea/python/leak_probe.py:ro" % probe):
                with self.subTest(value=value):
                    self.assertEqual(replay.run_args(value), value.split())
            self.assertEqual(replay.run_args(""), [])

    def test_the_environment_is_read(self):
        with mock.patch.dict(os.environ, {"DIONAEA_RUN_ARGS": "--memory=8g"}):
            with self.assertRaises(ValueError):
                replay.run_args()
        with mock.patch.dict(os.environ, {"DIONAEA_RUN_ARGS": "--ulimit nofile=256"}):
            self.assertEqual(replay.run_args(), ["--ulimit", "nofile=256"])

    def test_the_summary_records_the_value(self):
        args = mock.Mock(quick=True, duration=5, concurrency=8, idle=4, interval=10, platform=None)
        with mock.patch.dict(os.environ, {"DIONAEA_RUN_ARGS": "--ulimit nofile=256"}):
            run = replay.Replay(args, "img", Path("/nonexistent"))
        self.assertEqual(run.summary["dionaea_run_args"], "--ulimit nofile=256")
        with mock.patch.dict(os.environ, {}, clear=True):
            run = replay.Replay(args, "img", Path("/nonexistent"))
        self.assertEqual(run.summary["dionaea_run_args"], "")

    def test_replay_stops_before_it_starts(self):
        env = dict(os.environ, DIONAEA_RUN_ARGS="--cpus=4", PATH=os.environ.get("PATH", ""))
        result = subprocess.run([sys.executable, str(HERE / "replay.py"), "--quick", "--config", "/nonexistent"],
                                env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("--cpus", result.stderr)
        self.assertNotIn("building", result.stdout)


class StartTest(unittest.TestCase):
    """leak.py and tftp_load.py build the replay from a plain namespace of their own"""

    def namespace(self, config):
        return argparse.Namespace(config=config, platform=None, quick=True, duration=1, concurrency=0, idle=0,
                                  interval=10)

    def test_the_namespace_of_leak_and_tftp_load(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "etc"
            (config / "ihandlers").mkdir(parents=True)
            (config / "dionaea.cfg").write_text("[module.python]\nimports=dionaea.log,dionaea.services\n")
            (config / "ihandlers/store.yaml").write_text("- name: store\n")
            run = replay.Replay(self.namespace(config), "img", Path(folder) / "run")
            self.assertIsNone(run.summary["inject_leak"])
            run.prepare()
            self.assertIn("imports=dionaea.log,dionaea.services,rss_probe\n",
                          (Path(folder) / "run/etc/dionaea.cfg").read_text())
            self.assertEqual(run.leak_env(), [])

    def test_the_wrapper_disables_thp_and_execs_the_command_of_the_image(self):
        entrypoint, args = replay.thp_wrapper(None, ["/opt/dionaea/sbin/dionaea", "-u", "dionaea"], native=True)
        self.assertEqual(entrypoint, "python3")
        self.assertEqual(args[0], "-c")
        self.assertEqual(args[2:], ["required", "/opt/dionaea/sbin/dionaea", "-u", "dionaea"])
        self.assertIn("prctl(41, 1, 0, 0, 0)", args[1])     # PR_SET_THP_DISABLE
        # an entrypoint of the image comes first, then its command
        self.assertEqual(replay.thp_wrapper(["/init"], ["-x"], native=True)[1][2:], ["required", "/init", "-x"])
        # under emulation a failed prctl does not stop the start
        self.assertEqual(replay.thp_wrapper(None, ["/init"], native=False)[1][2], "optional")
        with self.assertRaises(ValueError):
            replay.thp_wrapper(None, None, native=True)

    def wrapper(self, mode, result, *command):
        """THP_SCRIPT with a prctl that returns result (-1: EINVAL), as python3 -c of the image runs it"""
        stub = ("import ctypes\n"
                "class _Libc:\n"
                "    def prctl(self, *args):\n"
                "        if %d:\n"
                "            ctypes.set_errno(22)\n"
                "        return %d\n"
                "ctypes.CDLL = lambda *args, **kwargs: _Libc()\n" % (result != 0, result))
        return subprocess.run([sys.executable, "-c", stub + replay.THP_SCRIPT, mode, *command],
                              capture_output=True, text=True, timeout=30)

    def test_the_wrapper_finds_the_command_on_the_path(self):
        # an entrypoint without a path (as "dionaea" or "docker-entrypoint.sh") is looked up on PATH
        result = self.wrapper("required", 0, "echo", "started")
        self.assertEqual((result.returncode, result.stdout), (0, "started\n"), result.stderr)

    def test_a_failed_prctl_stops_a_native_start_with_its_reason(self):
        result = self.wrapper("required", -1, "echo", "started")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("PR_SET_THP_DISABLE: Invalid argument", result.stderr)

    def test_a_failed_prctl_under_emulation_starts_with_a_note(self):
        result = self.wrapper("optional", -1, "echo", "started")
        self.assertEqual((result.returncode, result.stdout), (0, "started\n"), result.stderr)
        self.assertIn("PR_SET_THP_DISABLE: Invalid argument", result.stderr)
        self.assertIn("not applicable", result.stderr)

    def test_the_reason_of_a_failed_start_is_in_the_error(self):
        args = argparse.Namespace(quick=True, duration=5, concurrency=8, idle=4, interval=10, platform=None)
        run = replay.Replay(args, "img", Path("/nonexistent"))
        logs = subprocess.CompletedProcess([], 0, stdout="", stderr="PR_SET_THP_DISABLE: Invalid argument\n")
        with mock.patch.object(replay, "docker", return_value=logs) as docker:
            message = run.start_failure()
        self.assertIn("dionaea exited during the start", message)
        self.assertIn("PR_SET_THP_DISABLE: Invalid argument", message)
        self.assertEqual(docker.call_args[0][:3], ("logs", "--tail", "20"))

    def test_native_is_the_architecture_of_the_docker_host(self):
        self.assertTrue(replay.same_arch("aarch64", "aarch64"))
        self.assertTrue(replay.same_arch("arm64", "aarch64"))
        self.assertTrue(replay.same_arch("x86_64", "amd64"))
        self.assertFalse(replay.same_arch("x86_64", "aarch64"))

    def test_an_unknown_architecture_is_an_error_not_emulation(self):
        # a failed probe must not turn the memory gates off on a native host
        for container, host in (("", "aarch64"), ("aarch64", ""), ("", ""), ("  ", "x86_64")):
            with self.subTest(container=container, host=host), self.assertRaises(replay.PlatformUnknown):
                replay.same_arch(container, host)

    def test_a_failed_probe_of_the_architecture_is_an_error(self):
        args = argparse.Namespace(quick=True, duration=5, concurrency=8, idle=4, interval=10, platform=None)
        run = replay.Replay(args, "img", Path("/nonexistent"))
        cases = [
            # docker run ... uname -m fails, docker info answers
            [subprocess.CompletedProcess([], 125, stdout="", stderr="no such image"),
             subprocess.CompletedProcess([], 0, stdout="aarch64\n", stderr="")],
            # uname answers, docker info fails
            [subprocess.CompletedProcess([], 0, stdout="aarch64\n", stderr=""),
             subprocess.CompletedProcess([], 1, stdout="aarch64\n", stderr="error")],
            # a non-zero exit with an answer is an error too
            [subprocess.CompletedProcess([], 1, stdout="x86_64\n", stderr=""),
             subprocess.CompletedProcess([], 0, stdout="aarch64\n", stderr="")],
        ]
        for outputs in cases:
            with self.subTest(outputs=outputs), mock.patch.object(replay, "docker", side_effect=outputs), \
                    self.assertRaises(replay.PlatformUnknown):
                run.platform_is_native()
        outputs = [subprocess.CompletedProcess([], 0, stdout="x86_64\n", stderr=""),
                   subprocess.CompletedProcess([], 0, stdout="aarch64\n", stderr="")]
        with mock.patch.object(replay, "docker", side_effect=outputs):
            self.assertFalse(run.platform_is_native())

    def test_a_probe_of_the_architecture_that_times_out_is_an_error(self):
        args = argparse.Namespace(quick=True, duration=5, concurrency=8, idle=4, interval=10, platform=None)
        run = replay.Replay(args, "img", Path("/nonexistent"))
        answer = subprocess.CompletedProcess([], 0, stdout="aarch64\n", stderr="")
        timeout = subprocess.TimeoutExpired(["docker"], 120)
        for outputs in ([timeout, answer], [answer, timeout]):
            with self.subTest(outputs=outputs), mock.patch.object(replay, "docker", side_effect=outputs), \
                    self.assertRaises(replay.PlatformUnknown) as error:
                run.platform_is_native()
            self.assertIn("timed out", str(error.exception))

    def test_a_probe_that_times_out_exits_with_3(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "etc"
            config.mkdir()
            (config / "dionaea.cfg").write_text("")
            argv = ["replay.py", "--quick", "--config", str(config), "--artifacts", str(Path(folder) / "out")]
            ok = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            timeout = subprocess.TimeoutExpired(["docker", "run"], 120)

            def start_server(run):
                # the start runs the probe of the architecture
                run.platform_is_native()

            def docker(*args, **kwargs):
                if args[:1] == ("run",) or args[:1] == ("info",) and "--format" in args:
                    raise timeout
                return ok
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(replay.shutil, "which", return_value="docker"), \
                    mock.patch.object(replay, "docker", side_effect=docker), mock.patch.object(replay, "say"), \
                    mock.patch.object(replay.Replay, "execute", start_server), mock.patch("sys.stderr"):
                self.assertEqual(replay.main(), 3)

    def test_an_unknown_architecture_exits_with_3(self):
        with tempfile.TemporaryDirectory() as folder:
            config = Path(folder) / "etc"
            config.mkdir()
            (config / "dionaea.cfg").write_text("")
            argv = ["replay.py", "--quick", "--config", str(config), "--artifacts", str(Path(folder) / "out")]
            ok = subprocess.CompletedProcess([], 0, stdout="", stderr="")
            unknown = replay.PlatformUnknown("uname -m failed")
            with mock.patch.object(sys, "argv", argv), \
                    mock.patch.object(replay.shutil, "which", return_value="docker"), \
                    mock.patch.object(replay, "docker", return_value=ok), mock.patch.object(replay, "say"), \
                    mock.patch.object(replay.Replay, "execute", side_effect=unknown), mock.patch("sys.stderr"):
                self.assertEqual(replay.main(), 3)

    def test_counts_that_could_not_be_read(self):
        # ls /proc/1/fd as uid 2000 counts 0 when dionaea is not dumpable: no samples, not a stable count
        self.assertFalse(replay.counted([(0.0, 0), (1.0, 0)]))
        self.assertFalse(replay.counted([]))
        self.assertTrue(replay.counted([(0.0, 0), (1.0, 63)]))

    def test_the_window_in_the_clock_of_the_probe(self):
        # the window of the samples is in the clock of the host, the probe has that of the container
        self.assertEqual(replay.probe_window(100.0, 200.0, "host", 2.5), (102.5, 202.5))
        # the client runs on the clock of the containers
        self.assertEqual(replay.probe_window(100.0, 200.0, "container", 2.5), (100.0, 200.0))

    def test_the_window_in_the_clock_of_the_host(self):
        # the samples of docker exec are taken by the host: a window of the client is moved back
        self.assertEqual(replay.host_window(100.0, 200.0, "container", 2.5), (97.5, 197.5))
        self.assertEqual(replay.host_window(100.0, 200.0, "host", 2.5), (100.0, 200.0))


class JudgeTest(unittest.TestCase):
    """The memory checks: on a native platform as they were, under emulation not applicable."""

    def checks(self, native, anon_huge=118784, quick=False):
        args = argparse.Namespace(quick=quick, duration=60, concurrency=8, idle=4, interval=30, platform=None)
        run = replay.Replay(args, "img", Path("/nonexistent"))
        run.native = native
        slopes = {"rss_floor": 3.0, "inuse": 2.0, "samples": 10, "minutes": 1, "floors_mib": [], "inuse_mib": []}
        with mock.patch.object(replay, "say"):
            run.check_memory(slopes, seconds=1800, anon_huge=anon_huge, thp={1}, ols=3.0, peak=900.0, hwm=900.0)
        return {item["name"].split(" ")[0] + " " + item["name"].split(" ")[1]: item for item in run.checks}

    def test_native_gates_fail(self):
        checks = self.checks(native=True)
        self.assertEqual(len(checks), 4)
        for item in checks.values():
            self.assertFalse(item["ok"], item["name"])
            self.assertTrue(item["gating"], item["name"])
            self.assertTrue(item["applicable"], item["name"])

    def test_under_emulation_the_memory_checks_do_not_apply(self):
        checks = self.checks(native=False)
        self.assertEqual(len(checks), 4)
        for item in checks.values():
            self.assertFalse(item["gating"], item["name"])
            self.assertFalse(item["applicable"], item["name"])
            self.assertIn("emulation", item["note"])

    def test_a_check_that_does_not_apply_is_reported_as_such(self):
        args = argparse.Namespace(quick=True, duration=5, concurrency=8, idle=4, interval=10, platform=None)
        run = replay.Replay(args, "img", Path("/nonexistent"))
        with mock.patch.object(replay, "say") as say:
            run.check("a criterion", False, gating=False, applicable=False)
        self.assertTrue(say.call_args[0][0].startswith("N/A a criterion"))


if __name__ == "__main__":
    unittest.main()
