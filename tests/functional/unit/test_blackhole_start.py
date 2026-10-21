# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""blackhole.py: every port of the config gets its connection (and its config) before the first
bind, so a port with a transport the core does not have (TransportError of the binding) stops the
start before any socket is opened: no listener of the other ports is left that the service
could not stop. Without services in the config the service starts nothing."""

import contextlib
import importlib.util
import logging
import os
import sys
import types
from pathlib import Path

import pytest


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


class TransportError(ValueError):
    """dionaea.core.TransportError (binding.pyx)"""


class FakeConnection:
    """dionaea.core.connection: tcp, udp and tls only; bind and listen are recorded."""
    calls = []

    def __init__(self, proto=None):
        if proto not in ("tcp", "udp", "tls"):
            raise TransportError("unknown transport %r, the core has tcp, udp and tls" % proto)
        self.proto = proto

    def apply_config(self, config):
        FakeConnection.calls.append(("config", self.proto))

    def bind(self, addr, port, iface=None):
        FakeConnection.calls.append(("bind", self.proto, port))
        return True

    def listen(self):
        FakeConnection.calls.append(("listen", self.proto))
        return True


@contextlib.contextmanager
def _stand_ins():
    names = ("dionaea", "dionaea.core", "dionaea.exception")
    saved = {name: sys.modules.get(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = []
    package.ServiceLoader = type("ServiceLoader", (), {})
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    core.TransportError = TransportError
    exception = types.ModuleType("dionaea.exception")
    exception.ServiceConfigError = type("ServiceConfigError", (Exception,), {})
    sys.modules.update({"dionaea": package, "dionaea.core": core, "dionaea.exception": exception})
    try:
        spec = importlib.util.spec_from_file_location("blackhole_under_test", _src_root() / "blackhole.py")
        blackhole = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(blackhole)
        yield blackhole
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


@pytest.fixture
def blackhole():
    FakeConnection.calls = []
    with _stand_ins() as module:
        yield module


def test_a_port_with_an_unknown_transport_stops_the_start_before_any_bind(blackhole):
    config = {"services": [{"port": 4434, "protocol": "tcp"}, {"port": 4433, "protocol": "dtls"},
                           {"port": 4435, "protocol": "udp"}]}
    with pytest.raises(TransportError):
        blackhole.BlackholeService.start("192.0.2.1", config=config)
    assert [call for call in FakeConnection.calls if call[0] in ("bind", "listen")] == []


def test_every_port_is_bound_and_listens(blackhole):
    config = {"services": [{"port": 4434, "protocol": "tcp"}, {"port": 53}, {"port": "x"}]}
    daemons = blackhole.BlackholeService.start("192.0.2.1", config=config)
    assert [d.proto for d in daemons] == ["tcp", "tcp"]
    assert [call for call in FakeConnection.calls if call[0] == "bind"] == [("bind", "tcp", 4434), ("bind", "tcp", 53)]
    assert len([call for call in FakeConnection.calls if call[0] == "listen"]) == 2


def test_without_services_nothing_starts(blackhole, caplog):
    with caplog.at_level(logging.WARNING, logger="blackhole"):
        assert blackhole.BlackholeService.start("192.0.2.1", config={}) == []
    assert [r.getMessage() for r in caplog.records] == ["No services configured"]
