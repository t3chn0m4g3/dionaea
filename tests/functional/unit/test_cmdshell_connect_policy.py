# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import contextlib
import importlib.util
import os
import sys
import types
from pathlib import Path


ROOT = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
    Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


class FakeIncident:
    reported = []

    def __init__(self, origin):
        self.origin = origin

    def __setattr__(self, key, value):
        if isinstance(value, FakeConnection) and value.released:
            raise ReferenceError("the object requested does not exist")
        object.__setattr__(self, key, value)

    def report(self):
        FakeIncident.reported.append(self.origin)


class FakeConnection:
    instances = []

    def __init__(self, proto="tcp"):
        self.proto = proto
        self.local = types.SimpleNamespace(host="192.0.2.9")
        self.timeouts = types.SimpleNamespace(listen=0, connecting=0, idle=0, sustain=0)
        self._in = types.SimpleNamespace(accounting=types.SimpleNamespace(limit=0))
        self.released = False
        self._status = "none"
        self.connect_calls = []
        FakeConnection.instances.append(self)

    def bind(self, host, port, iface=""):
        self.local.host = host
        return True

    def connect(self, host, port, iface="", download=False):
        self.connect_calls.append((host, port, iface, download))
        if host == "127.0.0.1":
            self._status = "close"
        elif host == "127.0.0.2":
            self.released = True
        else:
            self._status = "connecting"

    @property
    def status(self):
        if self.released:
            raise ReferenceError("the object requested does not exist")
        return self._status

    def close(self):
        self.released = True

    def send(self, data):
        return len(data)


class FakeIHandler:
    def __init__(self, path):
        self.path = path


class FakeIcd:
    def __init__(self, origin, con, host, port):
        self.origin = origin
        self.con = con
        self._values = {"host": host, "port": port}

    def get(self, name):
        return self._values[name]


@contextlib.contextmanager
def _stand_ins():
    names = [name for name in sys.modules if name == "dionaea" or name.startswith("dionaea.")]
    saved = {name: sys.modules.pop(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(ROOT)]
    package.IHandlerLoader = object
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    core.ihandler = FakeIHandler
    core.incident = FakeIncident
    sys.modules.update({"dionaea": package, "dionaea.core": core})
    try:
        yield
    finally:
        for name in [n for n in sys.modules if n == "dionaea" or n.startswith("dionaea.")]:
            sys.modules.pop(name, None)
        sys.modules.update(saved)


with _stand_ins():
    spec = importlib.util.spec_from_file_location("dionaea.cmd", ROOT / "cmd.py")
    cmd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cmd)


def _handler():
    FakeIncident.reported.clear()
    FakeConnection.instances.clear()
    return cmd.cmdshellhandler("dionaea.service.shell.*")


def test_shell_connect_uses_download_policy_guard():
    h = _handler()
    parent = FakeConnection()
    h.handle_incident(FakeIcd("dionaea.service.shell.connect", parent, "198.51.100.77", 4444))
    child = [c for c in FakeConnection.instances if c is not parent][-1]
    assert child.connect_calls == [("198.51.100.77", 4444, "", True)]
    assert FakeIncident.reported == ["dionaea.connection.link"]


def test_shell_connect_refused_in_connect_reports_no_link():
    h = _handler()
    parent = FakeConnection()
    h.handle_incident(FakeIcd("dionaea.service.shell.connect", parent, "127.0.0.1", 4444))
    child = [c for c in FakeConnection.instances if c is not parent][-1]
    assert child.connect_calls == [("127.0.0.1", 4444, "", True)]
    assert child.status == "close"
    assert not child.released
    assert FakeIncident.reported == []


def test_shell_connect_released_in_connect_reports_no_link():
    h = _handler()
    parent = FakeConnection()
    h.handle_incident(FakeIcd("dionaea.service.shell.connect", parent, "127.0.0.2", 4444))
    child = [c for c in FakeConnection.instances if c is not parent][-1]
    assert child.connect_calls == [("127.0.0.2", 4444, "", True)]
    assert child.released
    assert FakeIncident.reported == []
