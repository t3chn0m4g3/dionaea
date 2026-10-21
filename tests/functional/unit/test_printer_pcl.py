# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""printer.py: a PCL print job goes through the store like every other sample.

The job used to be written by the service itself to download.dir/print-<time>.pcl with
the mode of the umask, past the store (mode, size cap). Now it is an UploadFile
(temporary file, 0600, bound in size) that is reported as dionaea.download.complete
when the connection ends; store.py names, protects and counts it.
"""

import contextlib
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
        path = getattr(self, "path", None)
        data = Path(path).read_bytes() if path and os.path.exists(path) else None
        FakeIncident.reported.append((self.name, dict(vars(self)), data))


class FakeConnection:
    def __init__(self, proto="tcp"):
        self.remote = types.SimpleNamespace(host="198.51.100.9", port=4711)


class FakeDionaea:
    download_dir = None

    def config(self):
        return {"dionaea": {"download.dir": FakeDionaea.download_dir, "download.suffix": ".tmp"}}


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


def _load_file(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def _stand_ins():
    names = ("dionaea", "dionaea.core", "dionaea.exception", "dionaea.logtext", "dionaea.upload")
    saved = {name: sys.modules.get(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = []
    package.ServiceLoader = type("ServiceLoader", (), {})
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    core.incident = FakeIncident
    core.g_dionaea = FakeDionaea()
    exception = types.ModuleType("dionaea.exception")
    exception.ServiceConfigError = type("ServiceConfigError", (Exception,), {})
    sys.modules.update({"dionaea": package, "dionaea.core": core, "dionaea.exception": exception})
    # the real logtext and upload (stdlib only)
    sys.modules["dionaea.logtext"] = _load_file("dionaea.logtext", _src_root() / "logtext.py")
    sys.modules["dionaea.upload"] = _load_file("dionaea.upload", _src_root() / "upload.py")
    try:
        yield
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


with _stand_ins():
    printer = _load_file("printer_under_test", _src_root() / "printer.py")


@pytest.fixture(autouse=True)
def clear_reported():
    """upload.py takes dionaea.core when it makes and completes a file, so the stand-ins stay for the test."""
    FakeIncident.reported.clear()
    with _stand_ins():
        yield


def left_over(download_dir):
    """What is left in download.dir and in its folder of the temporary files (.incoming)."""
    incoming = download_dir / ".incoming"
    names = [p.name for p in download_dir.iterdir() if p != incoming]
    if incoming.is_dir():
        names += [".incoming/" + p.name for p in incoming.iterdir()]
    return names


@pytest.fixture
def con(tmp_path):
    FakeDionaea.download_dir = str(tmp_path)
    con = printer.Printerd()
    con.download_dir = str(tmp_path)
    return con


def test_pcl_is_reported_to_the_store_when_the_connection_ends(con, tmp_path):
    assert con.process_pcl(b"\x1bE first ") == 9
    assert con.process_pcl(b"second") == 6
    # no file named print-*.pcl is made by the service
    assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".pcl")] == []
    con.handle_disconnect()
    complete = [e for e in FakeIncident.reported if e[0] == "dionaea.download.complete"]
    assert len(complete) == 1
    _, attrs, data = complete[0]
    assert data == b"\x1bE first second"
    assert attrs["con"] is con
    assert attrs["url"].startswith("printer://198.51.100.9/print-") and attrs["url"].endswith(".pcl")
    # the temporary file is gone after the report, store.py has linked it by then
    assert left_over(tmp_path) == []


def test_the_temp_file_is_never_executable(con, tmp_path):
    con.process_pcl(b"\x1bE data")
    mode = os.stat(con.pcl_upload.name).st_mode & 0o7777
    assert mode & 0o177 == 0
    con.handle_disconnect()


def test_the_print_incident_is_still_reported(con):
    con.process_pcl(b"\x1bE data")
    names = [e[0] for e in FakeIncident.reported]
    assert names == ["dionaea.modules.python.printer.print"]
    con.handle_disconnect()


def test_a_job_larger_than_the_bound_is_cut_not_unbounded(con, tmp_path, monkeypatch):
    monkeypatch.setattr(printer, "MAX_PCL_SIZE", 100)
    assert con.process_pcl(b"\x1bE" + b"a" * 60) == 62
    assert con.process_pcl(b"b" * 60) == 60  # taken from the socket, not stored
    assert con.process_pcl(b"c" * 60) == 60
    con.handle_disconnect()
    complete = [e for e in FakeIncident.reported if e[0] == "dionaea.download.complete"]
    assert len(complete) == 1 and len(complete[0][2]) <= 100
    assert left_over(tmp_path) == []


def test_a_disconnect_without_a_job_is_fine(con, tmp_path):
    con.handle_disconnect()
    assert FakeIncident.reported == []
    assert left_over(tmp_path) == []


def test_the_cut_jobs_of_many_connections_are_one_warning_a_minute(tmp_path, monkeypatch, caplog, summaries):
    """A job above the bound is cut with an info line; one warning a minute sums them up."""
    import logging
    monkeypatch.setattr(printer, "MAX_PCL_SIZE", 100)
    clock = summaries(printer.CUT)
    FakeDionaea.download_dir = str(tmp_path)
    with caplog.at_level(logging.INFO, logger="printer"):
        for _ in range(4):
            con = printer.Printerd()
            con.download_dir = str(tmp_path)
            con.process_pcl(b"\x1bE" + b"a" * 200)
            con.process_pcl(b"b" * 200)
            con.handle_disconnect()
            clock.advance(1)
        infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO and "is cut" in r.getMessage()]
        assert len(infos) == 4
        assert infos[0].startswith("print job from 198.51.100.9 is cut: write of 202 bytes at offset 0")
        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings == [("print jobs cut: 1 job(s) in the last minute, the last: 198.51.100.9, "
                            "write of 202 bytes at offset 0, limit is 100")]
        clock.advance(60)
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings[1:] == [("print jobs cut: 3 job(s) in the last minute, the last: 198.51.100.9, "
                            "write of 202 bytes at offset 0, limit is 100")]
