# This file is part of the dionaea honeypot
# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: CC0-1.0

"""Credential retention uses the actual handler without the native binding."""

import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


@pytest.fixture
def handler(monkeypatch):
    package = ModuleType("dionaea")
    package.IHandlerLoader = type("IHandlerLoader", (), {})
    core = ModuleType("dionaea.core")
    core.ihandler = type("ihandler", (), {"__init__": lambda self, path: None})
    exception = ModuleType("dionaea.exception")
    exception.LoaderError = RuntimeError
    for name, module in (("dionaea", package), ("dionaea.core", core), ("dionaea.exception", exception)):
        monkeypatch.setitem(sys.modules, name, module)
    root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
    spec = importlib.util.spec_from_file_location("log_json_under_test", root / "log_json.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.LogJsonHandler("*", config={"handlers": []})


def login(handler, con, index, protocol="smb"):
    event = SimpleNamespace(con=con, username=("user-%d" % index).encode(), password=b"",
                            domain="DOMAIN", workstation="CLIENT-%d" % index,
                            dialect="NT LM 0.12", ntlm_version="NTLMv2")
    getattr(handler, "handle_incident_dionaea_modules_python_%s_login" % protocol)(event)


@pytest.mark.parametrize("protocol", ["smb", "ftp", "mysql", "mssql"])
@pytest.mark.parametrize("count", [999, 1000, 1001])
@pytest.mark.parametrize("flat", [False, True])
def test_first_credentials_are_retained(handler, protocol, count, flat):
    con = object()
    handler.attacks[con] = {"connection": {}}
    for index in range(count):
        login(handler, con, index, protocol)
    data = handler.attacks[con]
    expected = ["user-%d" % index for index in range(min(count, 1000))]
    if flat:
        handler._flatten_data(data)
        assert data["credentials"]["username"] == expected
        assert data["credentials"]["password"] == [""] * len(expected)
    else:
        assert [entry["username"] for entry in data["credentials"]] == expected
        assert all(entry["password"] == "" for entry in data["credentials"])
    if protocol == "smb":
        assert data["smb"]["workstation"] == "CLIENT-%d" % (count - 1)
        credentials = data["credentials"]
        assert (credentials["workstation"][-1] if flat else credentials[-1]["workstation"]) == (
            "CLIENT-%d" % (min(count, 1000) - 1))


def test_limit_is_shared_but_connections_are_independent(handler):
    first, second = object(), object()
    handler.attacks = {first: {"connection": {}}, second: {"connection": {}}}
    for index in range(1001):
        login(handler, first, index, ("smb", "ftp", "mysql", "mssql")[index % 4])
    login(handler, second, 1001)
    assert len(handler.attacks[first]["credentials"]) == 1000
    assert len(handler.attacks[second]["credentials"]) == 1


def test_full_list_skips_preparing_credentials(handler, monkeypatch):
    con = object()
    handler.attacks[con] = {"connection": {}, "credentials": [{}] * 1000}

    def fail(value):
        pytest.fail("Full credential list must be checked before preparing values")

    monkeypatch.setattr(handler, "_prepare_value", fail)
    login(handler, con, 1000, "ftp")
    assert len(handler.attacks[con]["credentials"]) == 1000


def test_unknown_connection_is_ignored(handler):
    login(handler, object(), 0)
    assert handler.attacks == {}
