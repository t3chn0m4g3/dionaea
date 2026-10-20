# This file is part of the dionaea honeypot
# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: GPL-2.0-or-later

"""Destination policy for attacker supplied downloads, after DNS resolution."""

from .mirror_policy import is_local_address, normalize


def allowed(address, networks=(), gateways=()):
    ip = normalize(address)
    if ip is None or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return False
    if ip in {normalize(gateway) for gateway in gateways} or is_local_address(str(ip)):
        return False
    return ip.is_global or any(ip.version == network.version and ip in network for network in networks)
