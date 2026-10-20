# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2026 T-Pot contributors
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""When the mirror service may connect back to a client.

The mirror service (port 42) connects back to the address of every client on
the same port. That is meant for clients on the internet. It must not happen
for addresses that lead back to the honeypot itself or into its own network:
behind docker-proxy a client on the host or an IPv6 client arrives with the
address of the bridge gateway, and the connect-back would reach the mirror
service itself.

This module imports nothing of dionaea (no ``dionaea.core``), so it can be
tested with plain python3 (tests/functional/unit/test_mirror_policy.py).
"""

import ipaddress
import socket
import struct
import time

ROUTE4 = "/proc/net/route"
ROUTE6 = "/proc/net/ipv6_route"

RTF_GATEWAY = 0x2


def normalize(host):
    """ip_address of host (IPv4-mapped IPv6 as IPv4, scope id dropped), None if it is no address."""
    if not isinstance(host, str):
        return None
    host = host.strip().split("%", 1)[0]
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def default_gateways(route4=ROUTE4, route6=ROUTE6):
    """Set of the default gateways (text) from /proc/net/route and /proc/net/ipv6_route."""
    gateways = set()
    try:
        with open(route4, encoding="ascii", errors="replace") as f:
            for line in list(f)[1:]:
                fields = line.split()
                # Iface Destination Gateway Flags ... (hex, little endian)
                if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & RTF_GATEWAY:
                    gw = int(fields[2], 16)
                    if gw:
                        gateways.add(socket.inet_ntoa(struct.pack("<L", gw)))
    except (OSError, ValueError, struct.error):
        pass
    try:
        with open(route6, encoding="ascii", errors="replace") as f:
            for line in f:
                fields = line.split()
                # dest prefixlen src prefixlen next_hop metric refcnt use flags iface
                if len(fields) >= 10 and fields[0] == "0" * 32 and int(fields[1], 16) == 0:
                    if int(fields[4], 16):
                        gateways.add(str(ipaddress.IPv6Address(bytes.fromhex(fields[4]))))
    except (OSError, ValueError):
        pass
    return gateways


def is_local_address(host):
    """True if host is an address of this machine (a bind() to it works)."""
    address = normalize(host)
    if address is None:
        return False
    family = socket.AF_INET if address.version == 4 else socket.AF_INET6
    try:
        s = socket.socket(family, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        s.bind((str(address), 0))
        return True
    except OSError:
        return False
    finally:
        s.close()


def refusal_reason(host, own=(), gateways=()):
    """Why the mirror must not connect back to host, None if it may.

    own: addresses of this honeypot, gateways: default gateways (text).
    """
    address = normalize(host)
    if address is None:
        return "no valid address"
    for name in ("is_unspecified", "is_loopback", "is_link_local", "is_multicast"):
        if getattr(address, name):
            return name[3:].replace("_", " ")
    if address in {a for a in map(normalize, own) if a is not None}:
        return "own address"
    if address in {a for a in map(normalize, gateways) if a is not None}:
        return "default gateway"
    # RFC 1918, ULA, CGNAT, documentation, reserved, broadcast, ...
    if not address.is_global:
        return "not a public address"
    return None


class MirrorTracker:
    """At most one mirror per source address at a time."""

    def __init__(self, max_age=300, clock=time.monotonic):
        self.max_age = max_age
        self.clock = clock
        self.active = {}

    def acquire(self, host):
        """True if host had no mirror (now it has one), False if one is active."""
        key = normalize(host)
        if key is None:
            return False
        now = self.clock()
        started = self.active.get(key)
        # a mirror whose end was missed must not block its source forever
        if started is not None and now - started < self.max_age:
            return False
        self.active[key] = now
        return True

    def release(self, host):
        key = normalize(host)
        if key is not None:
            self.active.pop(key, None)


class MirrorPolicy:
    """The decision of the mirror service: address filter and one mirror per source."""

    def __init__(self, route4=ROUTE4, route6=ROUTE6, ttl=60, clock=time.monotonic, max_age=300):
        self.route4 = route4
        self.route6 = route6
        self.ttl = ttl
        self.clock = clock
        self.own = set()
        self.tracker = MirrorTracker(max_age=max_age, clock=clock)
        self._gateways = set()
        self._read = None

    def add_own(self, host):
        """An address the honeypot is bound to."""
        address = normalize(host)
        if address is not None:
            self.own.add(str(address))

    def gateways(self):
        """Default gateways, read from /proc at most every ttl seconds."""
        now = self.clock()
        if self._read is None or now - self._read >= self.ttl:
            self._gateways = default_gateways(self.route4, self.route6)
            self._read = now
        return self._gateways

    def allow(self, remote, local=None):
        """(True, None) and the source is taken, or (False, reason)."""
        own = set(self.own)
        if local:
            own.add(local)
        reason = refusal_reason(remote, own, self.gateways())
        if reason is None and is_local_address(remote):
            reason = "own address"
        if reason is None and not self.tracker.acquire(remote):
            reason = "mirror already active for this source"
        return (reason is None, reason)

    def release(self, remote):
        self.tracker.release(remote)
