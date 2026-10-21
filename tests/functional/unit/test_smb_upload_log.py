# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""smb.py: the lines of a connection at the limit of open files and of an upload that is not
kept are info, with their detail; one warning a minute of each sums them up for all
connections (LogSummary of logtext.py).

The methods of smbd and the summaries are taken from the source with ast (smb.py needs
dionaea.core); logtext and upload are the real modules.
"""

import ast
import importlib.util
import logging
import os
import sys
import types
from pathlib import Path


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


def _module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeIncident:
    def __init__(self, name):
        self.name = name

    def report(self):
        pass


def load():
    logtext = _module("dionaea.logtext", _src_root() / "logtext.py")
    saved = {name: sys.modules.get(name) for name in ("dionaea", "dionaea.core", "dionaea.logtext")}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(_src_root())]
    core = types.ModuleType("dionaea.core")
    core.incident = FakeIncident
    sys.modules.update({"dionaea": package, "dionaea.core": core, "dionaea.logtext": logtext})
    try:
        upload = _module("dionaea.upload", _src_root() / "upload.py")
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module
    source = _src_root() / "smb" / "smb.py"
    tree = ast.parse(source.read_text(), filename=str(source))
    nodes = [node for node in tree.body
             if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call)
             and getattr(node.value.func, "id", "") == "LogSummary"]
    nodes += [node for node in tree.body
              if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "MAX_OPEN_FIDS" for t in node.targets)]
    smbd = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "smbd")
    nodes += [node for node in smbd.body
              if isinstance(node, ast.FunctionDef) and node.name in ("new_fid", "open_upload", "write_upload")]
    namespace = {"LogSummary": logtext.LogSummary, "log_text": logtext.log_text, "smblog": logging.getLogger("SMB"),
                 "UploadFile": upload.UploadFile, "UploadError": upload.UploadError,
                 "UploadTooLarge": upload.UploadTooLarge, "DEFAULT_MAX_UPLOAD_SIZE": upload.DEFAULT_MAX_UPLOAD_SIZE,
                 "upload_url": upload.upload_url, "is_pipe_name": lambda name: False, "incident": FakeIncident,
                 "STATUS_DISK_FULL": 0xC000007F, "STATUS_UNSUCCESSFUL": 0xC0000001}
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    namespace["upload_module"] = upload
    return namespace


smb = load()


class Node:
    host = "192.0.2.9"
    port = 49152


class Connection:
    def __init__(self, max_upload_size=1000):
        self.fids = {}
        self.state = {}
        self.remote = Node()
        self.config = types.SimpleNamespace(max_upload_size=max_upload_size)
        for name in ("new_fid", "open_upload", "write_upload"):
            setattr(self, name, smb[name].__get__(self))


class Response:
    FID = 0x4000


def _lines(caplog, level):
    return [r.getMessage() for r in caplog.records if r.name == "SMB" and r.levelno == level]


def test_connections_at_the_limit_of_open_files_are_one_warning_a_minute(caplog, summaries):
    clock = summaries(smb["FID_LIMIT"])
    caplog.set_level(logging.INFO, logger="SMB")
    for _ in range(4):
        con = Connection()
        con.fids = {fid: None for fid in range(smb["MAX_OPEN_FIDS"])}
        # once per connection, as often as the client asks
        assert con.new_fid() is None
        assert con.new_fid() is None
        clock.advance(1)
    assert _lines(caplog, logging.INFO) == ["32 files are open, no more allowed"] * 4
    assert _lines(caplog, logging.WARNING) == [
        "connections at the limit of open files: 1 connection(s) in the last minute, the last: 32 files, 192.0.2.9"]
    clock.advance(60)
    assert _lines(caplog, logging.WARNING)[1:] == [
        "connections at the limit of open files: 3 connection(s) in the last minute, the last: 32 files, 192.0.2.9"]


def test_uploads_above_the_limit_are_dropped_with_one_warning_a_minute(tmp_path, monkeypatch, caplog, summaries):
    # the file of the upload in tmp_path (without dionaea.core: no download.dir)
    upload = smb["upload_module"]
    monkeypatch.setitem(smb, "UploadFile", lambda prefix, max_size: upload.UploadFile(
        prefix, max_size=max_size, download_dir=str(tmp_path), suffix=".tmp"))
    clock = summaries(smb["UPLOAD_DROPPED"])
    caplog.set_level(logging.INFO, logger="SMB")
    for _ in range(5):
        con = Connection(max_upload_size=1000)
        con.open_upload(Response(), "\\a.exe", "C$")
        assert con.write_upload(Response.FID, b"x" * 100, 5000) == (0, 0xC000007F)
        clock.advance(1)
    dropped = "upload dropped: write of 100 bytes at offset 5000, limit is 1000 (192.0.2.9)"
    assert _lines(caplog, logging.INFO).count(dropped) == 5
    assert _lines(caplog, logging.WARNING) == [
        ("uploads dropped: 1 upload(s) in the last minute, the last: write of 100 bytes at offset 5000, limit is 1000 "
         "(192.0.2.9)")]
    clock.advance(60)
    assert _lines(caplog, logging.WARNING)[1:] == [
        ("uploads dropped: 4 upload(s) in the last minute, the last: write of 100 bytes at offset 5000, limit is 1000 "
         "(192.0.2.9)")]


def test_an_upload_without_a_file_or_that_can_not_be_written_is_one_warning_a_minute(monkeypatch, caplog, summaries):
    clock = summaries(smb["UPLOAD_NO_FILE"], smb["UPLOAD_FAILED"])
    caplog.set_level(logging.INFO, logger="SMB")

    def no_file(*args, **kwargs):
        raise OSError(24, "Too many open files")

    with monkeypatch.context() as m:
        m.setitem(smb, "UploadFile", no_file)
        for _ in range(3):
            con = Connection()
            con.open_upload(Response(), "\\b.exe", "C$")
            assert con.fids == {Response.FID: None}
    infos = _lines(caplog, logging.INFO)
    assert infos.count("unable to create a file for an upload: [Errno 24] Too many open files (192.0.2.9)") == 3

    class Broken:
        def write(self, data, offset):
            raise smb["UploadError"]("unable to write to x: [Errno 28] No space left on device")

        def discard(self):
            pass

    for _ in range(3):
        con = Connection()
        con.fids[Response.FID] = Broken()
        assert con.write_upload(Response.FID, b"y", 0) == (0, 0xC0000001)
    infos = _lines(caplog, logging.INFO)
    assert infos.count("upload failed: unable to write to x: [Errno 28] No space left on device (192.0.2.9)") == 3
    assert _lines(caplog, logging.WARNING) == [
        ("uploads not stored, no file could be made: 1 upload(s) in the last minute, "
         "the last: [Errno 24] Too many open files (192.0.2.9)"),
        ("uploads failed: 1 upload(s) in the last minute, "
         "the last: unable to write to x: [Errno 28] No space left on device (192.0.2.9)")]
    clock.advance(60)
    assert len(_lines(caplog, logging.WARNING)) == 4
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


def test_the_texts_of_a_client_stay_on_their_line(caplog, summaries):
    summaries(smb["UPLOAD_FAILED"])
    caplog.set_level(logging.INFO, logger="SMB")

    class Broken:
        def write(self, data, offset):
            raise smb["UploadError"]("name\n\x1b[2J" + "z" * 400)

        def discard(self):
            pass

    con = Connection()
    con.fids[Response.FID] = Broken()
    con.write_upload(Response.FID, b"y", 0)
    (warning,) = _lines(caplog, logging.WARNING)
    cut = ("name??[2J" + "z" * 400)[:256] + "..."
    assert warning == "uploads failed: 1 upload(s) in the last minute, the last: " + cut + " (192.0.2.9)"
    # the info line too
    (info,) = _lines(caplog, logging.INFO)
    assert info == "upload failed: " + cut + " (192.0.2.9)"
