# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""smb/rpcservices.py spoolss.handle_WritePrinter: the fragments of a print job.

The data of a job sent in fragments (first, middle, last) is kept on the connection
until its last fragment, then written as a download. The data of a job is kept for
that job only: the next job of the connection starts empty. A job above the
max_upload_size of the SMB service is dropped with an info line (one warning a minute sums
them up for all connections), its fragments are not kept (con.printer is None until the
first fragment of the next job). A fragment is added in the time of its own length.

rpcservices.py is loaded with stand-ins of dionaea.core (it needs the binding).
"""

import contextlib
import importlib.util
import logging
import os
import struct
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest


class FakeIncident:
    reported = []

    def __init__(self, name):
        self.name = name

    def report(self):
        with open(self.path, "rb") as f:
            FakeIncident.reported.append((self.name, f.read()))


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins(download_dir):
    names = [name for name in sys.modules if name == "dionaea" or name.startswith("dionaea.")]
    saved = {name: sys.modules.pop(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(_src_root())]
    core = types.ModuleType("dionaea.core")
    core.incident = FakeIncident
    config = {"dionaea": {"download.dir": str(download_dir), "download.suffix": ".tmp"}}
    core.g_dionaea = SimpleNamespace(config=lambda: config)
    smb = types.ModuleType("dionaea.smb")
    smb.__path__ = [str(_src_root() / "smb")]
    sys.modules.update({"dionaea": package, "dionaea.core": core, "dionaea.smb": smb})
    try:
        spec = importlib.util.spec_from_file_location("dionaea.smb.rpcservices", _src_root() / "smb" / "rpcservices.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["dionaea.smb.rpcservices"] = module
        spec.loader.exec_module(module)
        yield module
    finally:
        for name in [n for n in sys.modules if n == "dionaea" or n.startswith("dionaea.")]:
            sys.modules.pop(name, None)
        sys.modules.update(saved)


@pytest.fixture
def rpc(tmp_path):
    FakeIncident.reported.clear()
    with _stand_ins(tmp_path) as module:
        yield module


def connection(max_upload_size=32 * 1024 * 1024):
    return SimpleNamespace(printer=b"", remote=SimpleNamespace(host="198.51.100.9"),
                           config=SimpleNamespace(max_upload_size=max_upload_size))


def job(data):
    """the stub of a WritePrinter: the printer handle, cbBuf and the data"""
    return b"\x00" * 20 + struct.pack("<L", len(data)) + data


def fragments(stub, size):
    """the stub in fragments of size bytes: first (1), middle (0) ..., last (2)"""
    parts = [stub[i:i + size] for i in range(0, len(stub), size)]
    flags = [1] + [0] * (len(parts) - 2) + [2]
    return [SimpleNamespace(PacketFlags=f, StubData=p) for f, p in zip(flags, parts)]


def write(rpc, con, requests):
    return [rpc.spoolss.handle_WritePrinter(con, p) for p in requests]


def test_a_job_in_fragments_is_one_download(rpc):
    con = connection()
    replies = write(rpc, con, fragments(job(b"%!PS-Adobe first job"), 8))
    assert replies[:-1] == [None] * (len(replies) - 1)
    assert struct.unpack("<LL", replies[-1]) == (len(b"%!PS-Adobe first job"), 0)
    assert FakeIncident.reported == [("dionaea.download.complete", b"%!PS-Adobe first job")]


def test_the_next_job_of_the_connection_starts_empty(rpc):
    con = connection()
    write(rpc, con, fragments(job(b"first job"), 8))
    assert con.printer == b""
    write(rpc, con, fragments(job(b"second job, other data"), 8))
    assert [data for _, data in FakeIncident.reported] == [b"first job", b"second job, other data"]
    assert con.printer == b""


def test_a_job_above_max_upload_size_is_dropped(rpc, caplog):
    con = connection(max_upload_size=64)
    with caplog.at_level(logging.WARNING, logger="rpcservices"):
        replies = write(rpc, con, fragments(job(b"x" * 1000), 16))
    assert replies == [None] * len(replies)
    assert FakeIncident.reported == []
    # nothing of the dropped job is kept after its last fragment
    assert con.printer == b""
    warnings = [r for r in caplog.records if r.name == "rpcservices" and r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "max_upload_size" in warnings[0].getMessage()
    # the connection goes on: a job within the limit after it
    write(rpc, con, fragments(job(b"small"), 8))
    assert FakeIncident.reported == [("dionaea.download.complete", b"small")]


def test_the_dropped_jobs_of_many_connections_are_one_warning_a_minute(rpc, caplog, summaries):
    clock = summaries(rpc.PRINT_DROPPED)
    with caplog.at_level(logging.INFO, logger="rpcservices"):
        for _ in range(6):
            write(rpc, connection(max_upload_size=64), fragments(job(b"x" * 1000), 16))
            clock.advance(1)
        infos = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO and "dropped" in r.getMessage()]
        assert infos == ["print job of 198.51.100.9 dropped: its fragments are above max_upload_size (64 bytes)"] * 6
        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings == [("print jobs dropped above max_upload_size: 1 job(s) in the last minute, "
                            "the last: 198.51.100.9, 64 bytes")]
        clock.advance(60)
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings[1:] == [("print jobs dropped above max_upload_size: 5 job(s) in the last minute, "
                            "the last: 198.51.100.9, 64 bytes")]


def test_the_fragments_of_a_job_are_kept_up_to_max_upload_size(rpc):
    con = connection(max_upload_size=256)
    for _ in range(1000):
        rpc.spoolss.handle_WritePrinter(con, SimpleNamespace(PacketFlags=0, StubData=b"y" * 100))
        assert con.printer is None or len(con.printer) <= 256


def test_a_job_of_32_mib_in_1_kib_fragments_is_one_download(rpc):
    # every fragment is added in the time of its own length
    import time

    data = bytes(range(256)) * (32 * 4096)
    data = data[:32 * 1024 * 1024 - 24]
    con = connection()
    requests = fragments(job(data), 1024)
    started = time.perf_counter()
    write(rpc, con, requests)
    seconds = time.perf_counter() - started
    assert FakeIncident.reported == [("dionaea.download.complete", data)]
    assert seconds < 2, seconds
