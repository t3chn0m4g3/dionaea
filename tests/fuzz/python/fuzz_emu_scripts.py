#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""atheris target of the stager patterns of emu_scripts (emu_scripts/handler.py).

The ihandler hands a downloaded file of any size to the handlers in turn
(PowerShell, VBScript, RawURL). The rule of handler.py: no exception, and a file
is searched in the time of its own length. Every file is run as it is and
repeated up to 256 KiB; -timeout reports a file that takes longer. A handler returns None or a list of str URLs.
"""

import sys

import atheris

import standins

REPEATED_SIZE = 256 * 1024

handler = standins.load("emu_scripts_handler", "emu_scripts/handler.py")
atheris.instrument_all()
HANDLERS = (handler.PowerShell(), handler.VBScript(), handler.RawURL())


def scan(data):
    for h in HANDLERS:
        urls = h.run(data)
        assert urls is None or (isinstance(urls, list) and all(isinstance(u, str) for u in urls)), urls


def target(data):
    scan(data)
    if data:
        scan(data * max(1, min(1 << 16, REPEATED_SIZE // len(data))))


def TestOneInput(data):
    standins.run(target, data)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
