# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: CC0-1.0

import importlib.util
import ipaddress
import os
import sys
import types
from pathlib import Path

import pytest

root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
    Path(__file__).resolve().parents[3] / "modules/python/dionaea")
package = types.ModuleType("download_policy_test")
package.__path__ = [str(root)]
sys.modules[package.__name__] = package
spec = importlib.util.spec_from_file_location(package.__name__ + ".download_policy", root / "download_policy.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


@pytest.mark.parametrize("address", ["127.0.0.1", "::1", "169.254.169.254", "fe80::1",
                                     "10.1.2.3", "172.16.0.1", "192.168.0.1", "fd00::1",
                                     "100.64.0.1", "0.0.0.0", "::", "224.0.0.1", "ff02::1",
                                     "::ffff:127.0.0.1", "::ffff:169.254.169.254", "localhost", ""])
def test_production_denies_internal_destinations(address):
    assert not policy.allowed(address)


@pytest.mark.parametrize("address", ["8.8.8.8", "2606:4700:4700::1111", "::ffff:8.8.8.8"])
def test_public_destinations(address, monkeypatch):
    monkeypatch.setattr(policy, "is_local_address", lambda _: False)
    assert policy.allowed(address)


def test_lab_allowlist_is_explicit_and_never_overrides_local_or_gateway(monkeypatch):
    monkeypatch.setattr(policy, "is_local_address", lambda address: address == "10.0.0.2")
    networks = [ipaddress.ip_network("10.0.0.0/24"), ipaddress.ip_network("127.0.0.0/8")]
    assert policy.allowed("10.0.0.3", networks, ["10.0.0.1"])
    for address in ["10.0.0.1", "10.0.0.2", "127.0.0.1", "10.0.1.3"]:
        assert not policy.allowed(address, networks, ["10.0.0.1"])
