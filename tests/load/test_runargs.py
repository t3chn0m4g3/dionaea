#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""runargs.py: one allow-list of DIONAEA_RUN_ARGS for replay.py, run.py and tests/functional/run.sh.

The arguments come after the limits and the options of "docker run" of dionaea, and docker
takes the last value of an option. replay.py refused everything but a read-only file mount
and --ulimit nofile; run.py and run.sh passed the value on as it was. All three take the
value through runargs.py now (run.sh by "python3 tests/load/runargs.py").

    python3 tests/load/test_runargs.py      (standard library only, no docker)
"""

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
RUN_SH = REPO / "tests" / "functional" / "run.sh"
sys.path.insert(0, str(HERE))

import replay  # noqa: E402
import run  # noqa: E402
import runargs  # noqa: E402

REFUSED = ("--privileged", "--memory=8g", "--user 0", "-e A=1", "--network host", "-tu0", "--ulimit core=-1")


class HelperTest(unittest.TestCase):
    def test_replay_takes_the_shared_allow_list(self):
        self.assertIs(replay.run_args, runargs.run_args)

    def test_the_allow_list(self):
        self.assertEqual(runargs.run_args("--ulimit nofile=128"), ["--ulimit", "nofile=128"])
        self.assertEqual(runargs.run_args(""), [])
        for value in REFUSED:
            with self.subTest(value=value), self.assertRaises(ValueError) as error:
                runargs.run_args(value)
            self.assertIn("DIONAEA_RUN_ARGS", str(error.exception))

    def cli(self, value):
        env = dict(os.environ, DIONAEA_RUN_ARGS=value)
        return subprocess.run([sys.executable, str(HERE / "runargs.py")], env=env, capture_output=True,
                              text=True, timeout=30)

    def test_the_command_prints_one_argument_per_line(self):
        with tempfile.TemporaryDirectory() as folder:
            probe = Path(folder) / "probe.py"
            probe.write_text("")
            value = "--ulimit nofile=128 -v %s:/opt/dionaea/lib/dionaea/python/probe.py:ro" % probe
            result = self.cli(value)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), value.split())

    def test_the_command_refuses_with_exit_2(self):
        for value in REFUSED:
            with self.subTest(value=value):
                result = self.cli(value)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, "")
                self.assertIn("DIONAEA_RUN_ARGS", result.stderr)


class RunPyTest(unittest.TestCase):
    def test_run_stops_before_it_starts(self):
        for value in REFUSED:
            with self.subTest(value=value), mock.patch.dict(os.environ, {"DIONAEA_RUN_ARGS": value}), \
                    mock.patch.object(sys, "argv", ["run.py"]), mock.patch.object(run, "docker") as docker, \
                    mock.patch("sys.stderr"):
                self.assertEqual(run.main(), 2)
                docker.assert_not_called()

    def test_the_server_gets_the_allowed_arguments(self):
        with tempfile.TemporaryDirectory() as folder:
            server = run.Run("normal", "img", Path(folder), False)
            calls = []

            def docker(*args, **kwargs):
                calls.append(args)
                return subprocess.CompletedProcess(args, 0, stdout="10.0.0.0/24\n", stderr="")
            (Path(folder) / "etc" / "ihandlers").mkdir(parents=True)
            (Path(folder) / "log").mkdir()
            (Path(folder) / "log" / "probe.jsonl").write_text("")
            with mock.patch.dict(os.environ, {"DIONAEA_RUN_ARGS": "--ulimit nofile=128"}), \
                    mock.patch.object(run, "docker", side_effect=docker):
                server.start_server()
        started = [c for c in calls if c[:2] == ("run", "-d")]
        self.assertEqual(len(started), 1)
        self.assertEqual(started[0][-3:], ("--ulimit", "nofile=128", "img"))


def stub_docker(folder):
    """a docker on PATH that records every call; "run -d" fails, so run.sh ends after it"""
    bin_dir = Path(folder) / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text('#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s"\n'
                      'if [ "$1" = run ] && [ "$2" = -d ]; then exit 1; fi\nexit 0\n' % (Path(folder) / "calls"))
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return bin_dir


class RunShTest(unittest.TestCase):
    def run_sh(self, folder, value, python_exit=None):
        bin_dir = stub_docker(folder)
        if python_exit is not None:
            # a python3 that fails in another way than the refusal of runargs.py (exit 2)
            python = bin_dir / "python3"
            python.write_text("#!/bin/sh\necho broken python >&2\nexit %d\n" % python_exit)
            python.chmod(python.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        env = dict(os.environ, PATH="%s:%s" % (bin_dir, os.environ.get("PATH", "")), TMPDIR=str(folder),
                   DIONAEA_RUN_ARGS=value, DIONAEA_IMAGE="img")
        result = subprocess.run(["bash", str(RUN_SH)], env=env, capture_output=True, text=True, timeout=60)
        calls = Path(folder, "calls")
        return result, calls.read_text().splitlines() if calls.exists() else []

    def test_run_sh_refuses_with_exit_2_before_docker(self):
        for value in REFUSED:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as folder:
                result, calls = self.run_sh(folder, value)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("DIONAEA_RUN_ARGS", result.stderr)
                self.assertEqual(calls, [])

    def test_run_sh_stops_with_exit_3_when_the_check_itself_fails(self):
        for code in (1, 127):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as folder:
                result, calls = self.run_sh(folder, "--ulimit nofile=128", python_exit=code)
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertIn("DIONAEA_RUN_ARGS could not be checked", result.stderr)
                self.assertEqual(calls, [])

    def test_run_sh_stops_with_exit_3_without_the_helper(self):
        # python3 answers a missing script with exit 2 as well: that is no refusal
        with tempfile.TemporaryDirectory() as folder:
            copy = Path(folder) / "repo" / "tests" / "functional"
            copy.mkdir(parents=True)
            (copy / "run.sh").write_text(RUN_SH.read_text())
            bin_dir = stub_docker(folder)
            env = dict(os.environ, PATH="%s:%s" % (bin_dir, os.environ.get("PATH", "")), TMPDIR=str(folder),
                       DIONAEA_RUN_ARGS="--ulimit nofile=128", DIONAEA_IMAGE="img")
            result = subprocess.run(["bash", str(copy / "run.sh")], env=env, capture_output=True, text=True,
                                    timeout=60)
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertIn("DIONAEA_RUN_ARGS could not be checked", result.stderr)
            self.assertFalse(Path(folder, "calls").exists())

    def test_run_sh_passes_the_allowed_arguments(self):
        with tempfile.TemporaryDirectory() as folder:
            probe = Path(folder) / "probe.py"
            probe.write_text("")
            value = "--ulimit nofile=128 -v %s:/opt/dionaea/lib/dionaea/python/probe.py:ro" % probe
            result, calls = self.run_sh(folder, value)
        started = [c for c in calls if c.startswith("run -d ")]
        self.assertEqual(len(started), 1, (calls, result.stderr))
        self.assertTrue(started[0].endswith(" " + value + " img"), started[0])


if __name__ == "__main__":
    unittest.main()
