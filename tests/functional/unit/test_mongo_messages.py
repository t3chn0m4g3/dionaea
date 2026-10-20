# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""mongo.py with stand-ins of the core and of bson: what ends a connection, what does not.

A message that the parser or BSON can not read closes the connection with one info line; an error
of the service itself (its handlers, the reply) is no malformed message of the client and goes on
to the binding, which logs it with its traceback. test_mongo.py has the functional tests.
"""

import contextlib
import importlib.util
import logging
import os
import struct
import sys
import types
from pathlib import Path

import pytest


class FakeNode:
    def __init__(self, host="", port=0):
        self.host = host
        self.port = port


class FakeConnection:
    def __init__(self, proto="tcp"):
        self.sent = []
        self.closed = False
        self.remote = FakeNode("198.51.100.9", 50123)
        self.local = FakeNode("192.0.2.1", 27017)

    def send(self, data):
        self.sent.append(bytes(data))

    def close(self):
        self.closed = True


class BSONError(Exception):
    pass


def _fake_bson():
    """decode_all of the documents of fake_document(), encode of a dict as its repr"""
    module = types.ModuleType("bson")
    errors = types.ModuleType("bson.errors")
    errors.BSONError = BSONError
    module.errors = errors

    def decode_all(data):
        docs = []
        while data:
            if len(data) < 4:
                raise BSONError("short document")
            size = struct.unpack("<i", data[:4])[0]
            if size < 5 or size > len(data):
                raise BSONError("bad length")
            docs.append({"raw": data[4:size]})
            data = data[size:]
        return docs

    module.decode_all = decode_all
    module.BSON = types.SimpleNamespace(encode=lambda doc: repr(sorted(doc)).encode())
    return module, errors


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins():
    names = [name for name in sys.modules if name in ("bson", "bson.errors") or name == "dionaea"
             or name.startswith("dionaea.")]
    saved = {name: sys.modules.pop(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(_src_root())]
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    core.incident = object
    core.g_dionaea = None
    bson, errors = _fake_bson()
    sys.modules.update({"dionaea": package, "dionaea.core": core, "bson": bson, "bson.errors": errors})
    for sub in ("smb", "mongo"):
        module = types.ModuleType("dionaea." + sub)
        module.__path__ = [str(_src_root() / sub)]
        sys.modules["dionaea." + sub] = module
    try:
        yield
    finally:
        for name in [n for n in sys.modules if n in ("bson", "bson.errors") or n == "dionaea"
                     or n.startswith("dionaea.")]:
            sys.modules.pop(name, None)
        sys.modules.update(saved)


with _stand_ins():
    spec = importlib.util.spec_from_file_location("dionaea.mongo.mongo", _src_root() / "mongo" / "mongo.py")
    mongo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mongo)


def document(payload=b"\x10isMaster\x00\x01\x00\x00\x00"):
    return struct.pack("<i", 4 + len(payload) + 1) + payload + b"\x00"


def op_query(request_id=1, doc=None):
    body = struct.pack("<i", 0) + b"admin.$cmd\x00" + struct.pack("<ii", 0, -1) + (document() if doc is None else doc)
    return struct.pack("<iiii", 16 + len(body), request_id, 0, 2004) + body


def op_command(request_id=1, docs=None):
    body = b"test\x00isMaster\x00" + b"".join(docs if docs is not None else [document(), document()])
    return struct.pack("<iiii", 16 + len(body), request_id, 0, 2010) + body


def test_a_query_is_answered():
    con = mongo.mongod()
    data = op_query(7)
    assert con.handle_io_in(data) == len(data)
    assert len(con.sent) == 1 and struct.unpack("<iiii", con.sent[0][:16])[2:] == (7, 1)
    assert not con.closed


@pytest.mark.parametrize("data", [
    op_query(doc=struct.pack("<i", 100) + b"\x10isMaster\x00"),   # a document longer than the message
    op_query(doc=b""),                                              # no document at all
    op_command(docs=[document()]),                                  # OP_COMMAND without its arguments
    op_command(docs=[b"\x01\x00"]),
], ids=["long-document", "no-document", "command-one-document", "command-short"])
def test_a_message_the_parser_can_not_read_closes_with_one_info_line(data, caplog):
    con = mongo.mongod()
    with caplog.at_level(logging.DEBUG, logger="mongo"):
        assert con.handle_io_in(data) == len(data)
    assert con.closed and con.sent == []
    lines = [r for r in caplog.records if "malformed MongoDB message" in r.getMessage()]
    assert len(lines) == 1 and lines[0].levelno == logging.INFO, caplog.text


@pytest.mark.parametrize("handler, data", [("_handle_query", op_query()), ("_handle_command", op_command())],
                         ids=["query", "command"])
def test_an_error_of_the_service_is_no_malformed_message(monkeypatch, handler, data):
    # a bug of the service goes on to the binding (a Traceback in the errors log), it does not close the
    # connection as if the client had sent garbage
    def broken(self, *args, **kwargs):
        raise KeyError("a bug of the handler")
    monkeypatch.setattr(mongo.mongod, handler, broken)
    con = mongo.mongod()
    with pytest.raises(KeyError):
        con.handle_io_in(data)
    assert not con.closed
