# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""dionaea/mirror_policy.py: when the mirror service may connect back.

The module imports no ``dionaea.core``, so it runs without the binding.
"""

import importlib.util
import os
from pathlib import Path

import pytest


def _load():
    root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
    spec = importlib.util.spec_from_file_location("mirror_policy_under_test", root / "mirror_policy.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = _load()

ROUTE4 = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
"""

ROUTE6 = (
    "fd000000000000000000000000000000 40 00000000000000000000000000000000 "
    "00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
    "00000000000000000000000000000000 00 00000000000000000000000000000000 "
    "00 fd0000000000000000000000000000fe 00000400 00000001 00000000 00000003 eth0\n"
    "00000000000000000000000000000000 00 00000000000000000000000000000000 "
    "00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n"
)


@pytest.fixture
def routes(tmp_path):
    r4 = tmp_path / "route"
    r6 = tmp_path / "ipv6_route"
    r4.write_text(ROUTE4)
    r6.write_text(ROUTE6)
    return str(r4), str(r6)


def test_default_gateways_from_proc_files(routes):
    gws = policy.default_gateways(*routes)
    assert gws == {"172.17.0.1", "fd00::fe"}


def test_default_gateways_missing_files(tmp_path):
    assert policy.default_gateways(str(tmp_path / "x"), str(tmp_path / "y")) == set()


@pytest.mark.parametrize("host", [
    "8.8.8.8", "1.1.1.1", "93.184.216.34", "2001:4860:4860::8888", "2606:4700::1111",
    "::ffff:8.8.8.8", "::ffff:93.184.216.34",
])
def test_public_addresses_are_mirrored(host):
    assert policy.refusal_reason(host, own=("10.0.0.5",), gateways=()) is None


@pytest.mark.parametrize("host", [
    "127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1",
    "169.254.1.1", "fe80::1", "fe80::1%eth0", "::ffff:169.254.0.5",
    "10.0.0.1", "172.16.5.4", "172.31.255.255", "192.168.1.1",
    "::ffff:10.1.2.3", "::ffff:192.168.0.9", "::ffff:172.17.0.2",
    "fc00::1", "fd12:3456::7", "::ffff:100.64.0.1",
    "0.0.0.0", "::", "::ffff:0.0.0.0",
    "224.0.0.1", "ff02::1", "255.255.255.255",
    "100.64.0.1", "192.0.2.1",
])
def test_non_public_addresses_are_refused(host):
    assert policy.refusal_reason(host, own=(), gateways=()) is not None


@pytest.mark.parametrize("host", ["", "not an address", "1.2.3", None])
def test_unparsable_addresses_are_refused(host):
    assert policy.refusal_reason(host, own=(), gateways=()) is not None


def test_own_addresses_are_refused_in_every_form():
    own = ("8.8.4.4", "2001:4860:4860::8844")
    assert policy.refusal_reason("8.8.4.4", own=own, gateways=()) == "own address"
    assert policy.refusal_reason("::ffff:8.8.4.4", own=own, gateways=()) == "own address"
    assert policy.refusal_reason("2001:4860:4860::8844", own=own, gateways=()) == "own address"
    # own address given in the mapped form
    assert policy.refusal_reason("8.8.4.4", own=("::ffff:8.8.4.4",), gateways=()) == "own address"
    assert policy.refusal_reason("8.8.8.8", own=own, gateways=()) is None


def test_gateway_is_refused(routes):
    # a gateway on a public network (the host's router seen from a host-network container)
    gws = {"8.8.4.4", "2001:4860:4860::1"}
    assert policy.refusal_reason("8.8.4.4", own=(), gateways=gws) == "default gateway"
    assert policy.refusal_reason("::ffff:8.8.4.4", own=(), gateways=gws) == "default gateway"
    assert policy.refusal_reason("2001:4860:4860::1", own=(), gateways=gws) == "default gateway"
    assert policy.refusal_reason("8.8.8.8", own=(), gateways=gws) is None


def test_gateway_is_read_from_the_route_files(routes):
    p = policy.MirrorPolicy(route4=routes[0], route6=routes[1])
    assert "172.17.0.1" in p.gateways()


def test_gateway_cache_is_refreshed_after_the_ttl(tmp_path):
    r4 = tmp_path / "route"
    r4.write_text(ROUTE4)
    now = [1000.0]
    p = policy.MirrorPolicy(route4=str(r4), route6=str(tmp_path / "none"), ttl=60, clock=lambda: now[0])
    assert p.gateways() == {"172.17.0.1"}
    r4.write_text(ROUTE4.replace("010011AC", "020011AC"))
    now[0] += 30
    assert p.gateways() == {"172.17.0.1"}
    now[0] += 31
    assert p.gateways() == {"172.17.0.2"}


def test_a_local_address_is_refused_by_the_bind_probe():
    # 127.0.0.1 is local on every host; the probe is for addresses of interfaces
    assert policy.is_local_address("127.0.0.1")
    assert not policy.is_local_address("8.8.8.8")


def test_one_mirror_per_source_at_a_time():
    t = policy.MirrorTracker()
    assert t.acquire("8.8.8.8")
    assert not t.acquire("8.8.8.8")
    assert not t.acquire("::ffff:8.8.8.8")  # same source, other notation
    assert t.acquire("8.8.4.4")
    t.release("8.8.8.8")
    assert t.acquire("8.8.8.8")


def test_release_is_idempotent_and_ignores_unknown_sources():
    t = policy.MirrorTracker()
    t.release("8.8.8.8")
    assert t.acquire("8.8.8.8")
    t.release("8.8.8.8")
    t.release("8.8.8.8")
    assert t.acquire("8.8.8.8")


def test_a_stale_mirror_does_not_block_its_source_forever():
    now = [0.0]
    t = policy.MirrorTracker(max_age=300, clock=lambda: now[0])
    assert t.acquire("8.8.8.8")
    now[0] += 299
    assert not t.acquire("8.8.8.8")
    now[0] += 2
    assert t.acquire("8.8.8.8")


def test_decide_combines_policy_and_tracker():
    p = policy.MirrorPolicy(route4="/nonexistent", route6="/nonexistent")
    p.add_own("8.8.4.4")
    ok, reason = p.allow("8.8.8.8", "8.8.4.4")
    assert ok and reason is None
    ok, reason = p.allow("8.8.8.8", "8.8.4.4")
    assert not ok and reason == "mirror already active for this source"
    p.release("8.8.8.8")
    assert p.allow("8.8.8.8", "8.8.4.4")[0]
    ok, reason = p.allow("10.0.0.1", "8.8.4.4")
    assert not ok and reason
    # the local address of the connection is its own address, too
    ok, reason = p.allow("8.8.4.4", "8.8.4.4")
    assert not ok and reason == "own address"
    # a refused source took no slot
    ok, _ = p.allow("10.0.0.1", "8.8.4.4")
    p.release("10.0.0.1")
