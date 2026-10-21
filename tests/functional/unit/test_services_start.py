# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""services.py: a service that asks for a transport the core does not have (dtls, ...) does not
start, with one warning line that names the service and the transport and no traceback; the other
services start. Any other exception of a start is a warning with its traceback, as before."""

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


@contextlib.contextmanager
def _stand_ins():
    names = ("dionaea", "dionaea.core")
    saved = {name: sys.modules.get(name) for name in names}
    core = types.ModuleType("dionaea.core")
    core.g_dionaea = None
    core.ihandler = type("ihandler", (), {"__init__": lambda self, path: None})
    core.TransportError = TransportError
    package = types.ModuleType("dionaea")
    package.__path__ = []
    package.ServiceLoader = []
    package.load_config_from_files = lambda patterns: []
    package.load_submodules = lambda: None
    package.core = core
    sys.modules.update({"dionaea": package, "dionaea.core": core})
    try:
        spec = importlib.util.spec_from_file_location("services_under_test", _src_root() / "services.py")
        services = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(services)
        yield services, package
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def _service(name, start):
    return type(name, (), {"name": name, "start": classmethod(lambda cls, addr, iface=None, config=None: start())})


@pytest.fixture
def services():
    with _stand_ins() as loaded:
        yield loaded


def _start(services, loaders):
    module, package = services
    package.ServiceLoader[:] = loaders
    module.ServiceLoader[:] = loaders
    module.g_service_configs = [{"name": loader.name} for loader in loaders]
    slave = module.slave(addresses={"lo": ["127.0.0.1"], "eth0": ["192.0.2.1", "2001:db8::1"]})
    slave.start()
    return slave


def _unknown_transport():
    raise TransportError("unknown transport 'dtls', the core has tcp, udp and tls")


def _broken():
    raise RuntimeError("broken")


def test_a_service_with_an_unknown_transport_does_not_start_with_one_line(services, caplog):
    blackhole = _service("blackhole", _unknown_transport)
    echo = _service("echo", lambda: "daemon")
    with caplog.at_level(logging.INFO, logger="services"):
        slave = _start(services, [blackhole, echo])
    # one line, not one per address
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert [r.getMessage() for r in warnings] == [
        "Unable to start service blackhole: unknown transport 'dtls', the core has tcp, udp and tls"]
    assert warnings[0].exc_info is None
    for addr in ("127.0.0.1", "192.0.2.1", "2001:db8::1"):
        assert slave.daemons[addr][blackhole] == []
        assert slave.daemons[addr][echo] == ["daemon"]


def test_another_exception_of_a_start_keeps_its_traceback(services, caplog):
    broken = _service("broken", _broken)
    with caplog.at_level(logging.INFO, logger="services"):
        _start(services, [broken])
    warnings = [r for r in caplog.records if r.levelno >= logging.WARNING]
    # tried on every address, each with its traceback
    assert [r.getMessage() for r in warnings] == ["Unable to start service broken"] * 3
    assert all(r.exc_info is not None for r in warnings)


def test_a_refused_config_leaves_another_config_of_the_same_service(services, caplog):
    """refused is per config entry: a second entry of the same service starts on every address."""
    module, package = services

    class Blackhole:
        name = "blackhole"
        started = []

        @classmethod
        def start(cls, addr, iface=None, config=None):
            if config.get("bad"):
                _unknown_transport()
            cls.started.append(addr)
            return "daemon"

    package.ServiceLoader[:] = [Blackhole]
    module.g_service_configs = [{"name": "blackhole", "config": {"bad": True}},
                                {"name": "blackhole", "config": {}}]
    slave = module.slave(addresses={"lo": ["127.0.0.1"], "eth0": ["192.0.2.1", "2001:db8::1"]})
    with caplog.at_level(logging.INFO, logger="services"):
        slave.start()
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings == ["Unable to start service blackhole: unknown transport 'dtls', the core has tcp, udp and tls"]
    assert Blackhole.started == ["127.0.0.1", "192.0.2.1", "2001:db8::1"]
    for addr in ("127.0.0.1", "192.0.2.1", "2001:db8::1"):
        assert slave.daemons[addr][Blackhole] == ["daemon"]
