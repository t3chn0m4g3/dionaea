# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The shell scripts of the harness (run.sh, host-checks/): what bash makes of them.

- An array that can be empty is expanded as ``${name[@]+"${name[@]}"}``: bash before 4.4
  (macOS ships 3.2) takes ``"${name[@]}"`` of an empty array for an unbound variable under
  ``set -u``, and run.sh ended before dionaea started.
- hc_main_pid (lib.sh) fails with a message when the container has no dionaea process: the
  host checks read /proc/<pid>/limits with it, an empty pid made that read end at EOF and
  ``set -e`` ended the check without a word.
- hc_count_warnings (42-bistream-cap.sh) reads its arguments only, not the variable mode of
  the loop that calls it.
"""

import os
import re
import stat
import subprocess
from pathlib import Path

FUNCTIONAL = Path(__file__).resolve().parents[1]
HOST_CHECKS = FUNCTIONAL / "host-checks"


def scripts():
    return sorted([FUNCTIONAL / "run.sh", *HOST_CHECKS.glob("*.sh"), *(FUNCTIONAL / "tools").glob("*.sh")])


def bash(script, env=None, cwd=None):
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                          env=dict(os.environ, **(env or {})), cwd=cwd)


def test_an_array_that_can_be_empty_is_expanded_for_old_bash():
    found = []
    for path in scripts():
        text = path.read_text()
        # arrays the script sets empty somewhere
        empty = set(re.findall(r"(?m)^\s*(?:local\s+)?([A-Za-z_][A-Za-z0-9_]*)=\(\)", text))
        for name in empty:
            guarded = '${%s[@]+"${%s[@]}"}' % (name, name)
            for number, line in enumerate(text.splitlines(), 1):
                rest = line.replace(guarded, "")
                if re.search(r"\$\{%s\[[@*]\]" % re.escape(name), rest):
                    found.append("%s:%d: %s" % (path.relative_to(FUNCTIONAL), number, line.strip()))
    assert not found, "expand as ${name[@]+\"${name[@]}\"} (bash < 4.4, set -u):\n" + "\n".join(found)


def stub_docker(tmp_path, output=""):
    """a docker on PATH that prints output for every call"""
    folder = tmp_path / "bin"
    folder.mkdir()
    (folder / "output").write_text(output)
    docker = folder / "docker"
    docker.write_text('#!/bin/sh\ncat "%s"\n' % (folder / "output"))
    docker.chmod(docker.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return {"PATH": "%s:%s" % (folder, os.environ.get("PATH", "")), "DIONAEA_CONTAINER": "dionaea-test"}


def test_hc_main_pid_fails_with_a_message_without_a_dionaea_process(tmp_path):
    result = bash('set -Eeuo pipefail; . "%s/lib.sh"; pid="$(hc_main_pid)"; echo "pid=[$pid]"' % HOST_CHECKS,
                  env=stub_docker(tmp_path))
    assert result.returncode != 0, result.stdout
    assert "pid=" not in result.stdout
    assert "FAIL: no dionaea process in dionaea-test" in result.stderr


def test_hc_main_pid_is_the_lowest_pid(tmp_path):
    result = bash('set -Eeuo pipefail; . "%s/lib.sh"; pid="$(hc_main_pid)"; echo "pid=[$pid]"' % HOST_CHECKS,
                  env=stub_docker(tmp_path, "17\n9\n"))
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "pid=[9]"


def test_the_host_checks_take_the_pid_so_that_a_failure_ends_them():
    # a plain assignment: set -e ends the check with the message of hc_main_pid (local or a pipe would not)
    for path in HOST_CHECKS.glob("*.sh"):
        for line in path.read_text().splitlines():
            if "hc_main_pid" in line and not line.lstrip().startswith(("#", "hc_main_pid()")):
                assert re.fullmatch(r'\s*pid="\$\(hc_main_pid\)"', line), "%s: %s" % (path.name, line)


def count_warnings():
    """the definition of hc_count_warnings of 42-bistream-cap.sh"""
    text = (HOST_CHECKS / "42-bistream-cap.sh").read_text()
    match = re.search(r"(?ms)^hc_count_warnings\(\) \{.*?^\}", text)
    assert match, "no hc_count_warnings in 42-bistream-cap.sh"
    return match.group(0)


def test_hc_count_warnings_reads_its_arguments_only(tmp_path):
    log = tmp_path / "dionaea.log"
    log.write_text("x Not dumping the streams of 3 connections, limit reached\n")
    script = ('set -Eeuo pipefail; . "%s/lib.sh"; %s\n'
              'hc_count_warnings size "%s" "Not dumping the streams of" 1 2 refused') % (
        HOST_CHECKS, count_warnings(), log)
    result = bash(script)
    assert result.returncode == 0, result.stderr
    assert "size: 1 warning(s) about refused dumps in 2 minute(s)" in result.stdout


def test_hc_count_warnings_fails_outside_its_bounds(tmp_path):
    log = tmp_path / "dionaea.log"
    log.write_text("")
    script = 'set -Eeuo pipefail; . "%s/lib.sh"; %s\nhc_count_warnings files "%s" "Not dumping" 1 2 refused' % (
        HOST_CHECKS, count_warnings(), log)
    result = bash(script)
    assert result.returncode != 0
    assert "FAIL: dionaea.log has 0 warnings about refused dumps in 2 minute(s) (expected 1 to 3)" in result.stderr
