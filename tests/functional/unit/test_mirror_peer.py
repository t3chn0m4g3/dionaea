# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""mirror.py: the connect-back (mirrorc) and the client connection (mirrord).

A client that closes before the connect-back is established leaves mirrorc without
its peer (mirrord.handle_disconnect sets it to None). Its handle_established then
did ``self.peer.peer = self`` on None (AttributeError in the event loop); now the
connect-back is closed instead, nothing is mirrored to a client that is gone.
"""

import contextlib
import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest


class FakeTimeouts:
    sustain = 0


class FakeAccounting:
    limit = 0


class FakeStream:
    def __init__(self):
        self.accounting = FakeAccounting()


class FakeNode:
    def __init__(self, host="", port=0):
        self.host = host
        self.port = port


class FakeConnection:
    def __init__(self, proto="tcp"):
        self.transport = proto
        self.sent = []
        self.closed = False
        self.timeouts = FakeTimeouts()
        self._in = FakeStream()
        self._out = FakeStream()
        self.remote = FakeNode("198.51.100.7", 40000)
        self.local = FakeNode("192.0.2.1", 42)

    def bind(self, host, port, iface=""):
        return True

    def listen(self):
        return True

    def connect(self, host, port, iface=""):
        self.remote = FakeNode(host, port)

    def send(self, data):
        assert not self.closed, "send on a closed connection"
        self.sent.append(bytes(data))

    def close(self):
        # a connection that connects is only marked; its disconnect comes from the core later
        self.closed = True


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins():
    names = ("dionaea", "dionaea.core", "dionaea.mirror_policy")
    saved = {name: sys.modules.get(name) for name in names}
    package = types.ModuleType("dionaea")
    # the real mirror_policy (stdlib only) is found here
    package.__path__ = [str(_src_root())]
    package.ServiceLoader = type("ServiceLoader", (), {})
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    sys.modules.update({"dionaea": package, "dionaea.core": core})
    try:
        yield
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


with _stand_ins():
    spec = importlib.util.spec_from_file_location("mirror_under_test", _src_root() / "mirror.py")
    mirror = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mirror)


class AllowAll:
    def __init__(self):
        self.released = []

    def allow(self, remote, local):
        return True, None

    def release(self, source):
        self.released.append(source)


@pytest.fixture
def policy(monkeypatch):
    p = AllowAll()
    monkeypatch.setattr(mirror, "policy", p)
    return p


def client(policy):
    d = mirror.mirrord("tcp")
    d.handle_established()
    assert isinstance(d.peer, mirror.mirrorc)
    return d


def test_connect_back_mirrors_once_established(policy):
    d = client(policy)
    back = d.peer
    back.handle_established()
    assert back.peer is d and d.peer is back
    d.handle_io_in(b"abc")
    assert back.sent == [b"abc"]
    back.handle_io_in(b"xyz")
    assert d.sent == [b"xyz"]


def test_client_gone_before_the_connect_back_is_established(policy):
    d = client(policy)
    back = d.peer
    # the client closes first: mirrord gives the place back and drops the connect-back
    d.handle_disconnect()
    assert back.peer is None
    assert back.closed
    assert policy.released == ["198.51.100.7"]

    # the connect-back is established afterwards: no AttributeError, it is closed
    back.handle_established()
    assert back.closed
    assert back.peer is None
    # its own end gives the place back once only
    back.handle_disconnect()
    assert policy.released == ["198.51.100.7"]
