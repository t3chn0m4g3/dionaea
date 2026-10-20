# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2006-2009 Michael P. Soulier
# SPDX-FileCopyrightText: 2009  Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import ServiceLoader
from dionaea.core import connection
from dionaea.mirror_policy import MirrorPolicy
import logging

logger = logging.getLogger('mirror')
logger.setLevel(logging.DEBUG)

# which clients get a mirror (see mirror_policy.py): no connect-back to
# private, loopback or link-local addresses, to the honeypot itself or its
# default gateway, and one mirror per source at a time
policy = MirrorPolicy()


class MirrorService(ServiceLoader):
    name = "mirror"

    @classmethod
    def start(cls, addr, iface=None, config=None):
        policy.add_own(addr)
        daemon = mirrord('tcp', addr, 42, iface)
        return daemon


class mirrorc(connection):
    def __init__(self, peer=None):
        logger.debug("mirror connection %s %s" %
                     ( peer.remote.host, peer.local.host))
        connection.__init__(self,peer.transport)
        self.peer = peer
        self.source = peer.remote.host
        self.bind(peer.local.host,0)
        self.connect(peer.remote.host,peer.local.port)
#		self.connect('',peer.local.port)

    def release(self):
        # the source may get its next mirror, once per mirror
        if self.source is not None:
            policy.release(self.source)
            self.source = None

    def handle_established(self):
        if self.peer is None:
            # the client closed before the connect-back was established
            self.close()
            return
        self.peer.peer = self

    def handle_io_in(self, data):
        if self.peer:
            self.peer.send(data)
        return len(data)

    def handle_error(self, err):
        self.release()
        if self.peer:
            self.peer.peer = None
            self.peer.close()

    def handle_disconnect(self):
        self.release()
        if self.peer:
            self.peer.close()
        if self.peer:
            self.peer.peer = None
        return 0

class mirrord(connection):
    def __init__(self, proto=None, host=None, port=None, iface=None):
        connection.__init__(self,proto)
        if host:
            self.bind(host, port, iface)
            self.listen()
        self.peer=None

    def handle_established(self):
        allowed, reason = policy.allow(self.remote.host, self.local.host)
        if allowed:
            try:
                self.peer=mirrorc(self)
            except Exception:
                policy.release(self.remote.host)
                raise
        else:
            # the connection stays, it takes data like a sink
            logger.debug("mirror to %s refused: %s" % (self.remote.host, reason))
        self.timeouts.sustain = 60
        self._in.accounting.limit  = 100*1024
        self._out.accounting.limit = 100*1024

    def handle_io_in(self, data):
        if self.peer:
            self.peer.send(data)
        return len(data)

    def handle_error(self, err):
        logger.debug("mirrord connection error?, should not happen")
        if self.peer:
            self.peer.release()
            self.peer.peer = None

    def handle_disconnect(self):
        if self.peer:
            self.peer.release()
            self.peer.close()
        if self.peer:
            self.peer.peer = None
        return 0
