# This file is part of the dionaea honeypot
# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: GPL-2.0-or-later

"""Configure the resolved-address policy for download clients."""


from dionaea import IHandlerLoader
from dionaea.core import ihandler

from .download_policy import allowed
from .mirror_policy import default_gateways
import ipaddress


class DownloadPolicyLoader(IHandlerLoader):
    name = "download_policy"

    @classmethod
    def start(cls, config=None):
        return DownloadPolicy(config or {})


class DownloadPolicy(ihandler):
    def __init__(self, config):
        self.networks = tuple(ipaddress.ip_network(value) for value in config.get("allowed_networks", []))
        super().__init__("dionaea.download.resolve")

    def handle_incident(self, icd):
        icd.allow = int(allowed(icd.address, self.networks, default_gateways()))
