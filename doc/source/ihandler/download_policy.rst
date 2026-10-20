..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2026 T-Pot contributors

    SPDX-License-Identifier: GPL-2.0-or-later

download_policy
===============

The download clients (the curl module for HTTP and HTTPS, the FTP and TFTP
downloads of the python module) ask this ihandler about every address they are
about to connect to: after the DNS lookup, and for every HTTP redirect. A public
address is taken. Loopback, link-local, multicast, unspecified and local
addresses and the default gateways are refused, also when they are in
``allowed_networks``; a private address is taken only when a network of
``allowed_networks`` holds it (an isolated lab network). Without this ihandler
every address is refused.

Configuration
-------------

**allowed_networks**

    Networks in CIDR notation whose private addresses a download may connect to.
    Default: ``[]``, public addresses only.

Log lines
---------

A download whose target the filter refused is one info line, and nothing else::

    download target refused by the filter: <url>

A target counts as refused when the filter refused every address of it (of the
last redirect for HTTP); when an address of it was tried and failed, the
download failed.

A download that fails (no connection, no answer, an error of the server, a
transfer that ends early) is one info line with its reason::

    download failed: <url> (<reason>)

and at most one warning a minute sums the failures up::

    downloads: <N> failed in the last minute, the last: <url> (<reason>)

The first failure after a minute without a warning of this kind is in one at
once, the ones after it when the minute of that warning ends. So a log of the
levels ``warning,error`` (T-Pot's ``dionaea-errors.log``) shows within a minute
that downloads fail, with one line a minute however many there are; the
failures of the last minute before dionaea stops are only in the info lines.

The url and the reason are those of the client: in the lines every byte outside
the printable ASCII range (``0x20`` to ``0x7e``) is a ``?``, and each is cut at 256
characters with ``...`` behind.

Example config
--------------

.. literalinclude:: ../../../conf/ihandlers/download_policy.yaml
   :language: yaml
   :caption: ihandlers/download_policy.yaml
