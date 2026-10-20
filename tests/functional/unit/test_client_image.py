# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""client/Dockerfile builds the same client image every time.

The base image by its digest, the Debian packages from the snapshot of the base image's
date with their versions, the Python packages from requirements files with the hashes of
every file pip may take (``pip install --require-hashes``).
"""

import re
from pathlib import Path

CLIENT = Path(__file__).resolve().parents[1] / "client"


def dockerfile():
    # the instructions, continuation lines joined
    return re.sub(r"\\\n\s*", " ", (CLIENT / "Dockerfile").read_text())


def requirements(name):
    """{package: [hashes]} of a requirements file of the client image."""
    entries = {}
    text = re.sub(r"\\\n\s*", " ", (CLIENT / name).read_text())
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        spec = line.split()[0]
        assert re.fullmatch(r"[A-Za-z0-9_.-]+==[A-Za-z0-9_.+-]+", spec), "%s: %s is not pinned" % (name, spec)
        entries[spec] = re.findall(r"--hash=sha256:([0-9a-f]{64})", line)
    return entries


def test_the_base_image_is_pinned_by_its_digest():
    froms = re.findall(r"(?m)^FROM\s+(\S+)", dockerfile())
    assert froms, "no FROM"
    for image in froms:
        assert re.search(r"@sha256:[0-9a-f]{64}$", image), "%s is not pinned by a digest" % image


def test_debian_packages_come_from_a_snapshot_with_their_versions():
    text = dockerfile()
    # the archive of one day, also for the security updates
    snapshots = set(re.findall(r"snapshot\.debian\.org/archive/(debian(?:-security)?)/(\d{8}T\d{6}Z)", text))
    assert {kind for kind, _ in snapshots} == {"debian", "debian-security"}, snapshots
    assert len({stamp for _, stamp in snapshots}) == 1, snapshots
    installs = re.findall(r"apt-get install ([^&;]*)", text)
    assert installs, "no apt-get install"
    for install in installs:
        packages = [word for word in install.split() if not word.startswith("-")]
        assert packages, install
        for package in packages:
            assert re.fullmatch(r"[a-z0-9][a-z0-9.+-]*=[A-Za-z0-9.+:~-]+", package), \
                "%s has no version" % package


def test_pip_takes_only_hashed_files_of_the_requirements():
    installs = re.findall(r"pip install ([^&;]*)", dockerfile())
    assert installs, "no pip install"
    for install in installs:
        words = install.split()
        assert "--require-hashes" in words and "--no-deps" in words, install
        files = [words[i + 1] for i, word in enumerate(words) if word in ("-r", "--requirement")]
        assert files, "%s installs no requirements file" % install
        # the values of these options are no packages
        values = {i + 1 for i, word in enumerate(words)
                  if word in ("-r", "--requirement", "--only-binary", "--no-binary")}
        assert not [w for i, w in enumerate(words) if not w.startswith("-") and i not in values], \
            "%s names a package outside a requirements file" % install
    for name in ("requirements.txt", "requirements-build.txt"):
        entries = requirements(name)
        assert entries, name
        for spec, hashes in entries.items():
            assert hashes, "%s: %s has no hash" % (name, spec)


def test_the_requirements_have_the_packages_of_the_tests():
    names = {spec.split("==")[0].lower() for spec in requirements("requirements.txt")}
    assert {"pytest", "impacket", "pymysql", "pyftpdlib", "paho-mqtt"} <= names, names
    direct = (CLIENT / "requirements.in").read_text()
    for spec in re.findall(r"(?m)^([A-Za-z0-9_.-]+==\S+)", direct):
        assert spec.lower() in {s.lower() for s in requirements("requirements.txt")}, \
            "%s of requirements.in is not in requirements.txt" % spec


def test_the_build_fails_when_the_snapshot_is_not_set():
    # the sed of debian.sources must have hit both URIs: a base image with other sources ends the build
    text = dockerfile()
    run = next(step for step in re.findall(r"(?m)^RUN (.*)$", text) if "debian.sources" in step)
    commands = [c.strip() for c in run.split("&&")]
    sed = next(i for i, c in enumerate(commands) if c.startswith("sed "))
    update = next(i for i, c in enumerate(commands) if "apt-get" in c and "update" in c)
    guards = " ".join(commands[sed + 1:update])
    for kind in ("debian", "debian-security"):
        assert re.search(r"grep -q[^&]*snapshot\.debian\.org/archive/%s/" % kind, guards), guards
    assert re.search(r"! grep -q[^&]*deb\.debian\.org", guards), guards


def test_the_lock_is_made_by_its_script_with_a_fixed_date():
    script = (CLIENT / "lock.sh").read_text()
    date = re.search(r'(?m)^LOCK_DATE="(\d{4}-\d\d-\d\dT[\d:]+Z)"$', script)
    assert date and '--exclude-newer "${LOCK_DATE}"' in script, "the lock depends on the day it is made"
    assert "lock.sh" in (CLIENT / "requirements.in").read_text()
    for name in ("requirements.txt", "requirements-build.txt"):
        assert "lock.sh" in (CLIENT / name).read_text(), name
