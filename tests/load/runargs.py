#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""DIONAEA_RUN_ARGS: the extra arguments of "docker run" of dionaea in the test tools.

replay.py (and leak.py, tftp_load.py through it), run.py and tests/functional/run.sh take
the value through run_args(). run.sh runs this file:

    python3 tests/load/runargs.py

prints the arguments of DIONAEA_RUN_ARGS one per line (exit 0), or the reason it refuses
them (exit 2). Python standard library only.
"""

import os
import re
import sys

# DIONAEA_RUN_ARGS (debugging: a probe module, a configuration that imports it, a lower fd limit) may
# have these options of "docker run" only, each with its value: the arguments come after the limits and
# the options of the run, and docker takes the last value, so any other option could loosen the limits,
# the user, the privileges, the read-only root or the isolation of the run (--pid / --network / --userns
# host, a device, a mount of the host). A volume is a file of the host mounted read-only to a file of the
# python modules or of the configuration of dionaea, --ulimit sets nofile only.
VOLUME_OPTIONS = ("-v", "--volume")
ULIMIT_OPTIONS = ("--ulimit",)
VOLUME_TARGETS = ("/opt/dionaea/lib/dionaea/python/", "/opt/dionaea/etc/dionaea/")


def run_args(value=None):
    """DIONAEA_RUN_ARGS (or value) as arguments of "docker run"; ValueError for anything but a read-only file
    mount into the modules or the configuration of dionaea and --ulimit nofile (see VOLUME_OPTIONS)."""
    if value is None:
        value = os.environ.get("DIONAEA_RUN_ARGS", "")
    args = value.split()
    i = 0
    while i < len(args):
        name, equals, setting = args[i].partition("=")
        if name not in VOLUME_OPTIONS + ULIMIT_OPTIONS or (equals and name == "-v"):
            # also -m4g, -u0, -tu0 (a cluster of short flags), a value without its option
            raise ValueError("DIONAEA_RUN_ARGS may have only -v / --volume FILE:%s...:ro and --ulimit nofile=N "
                             "(the limits of the run, uid/gid 2000 and the read-only root stay): %s"
                             % ("|".join(VOLUME_TARGETS), args[i]))
        if not equals:
            i += 1
            if i == len(args):
                raise ValueError("DIONAEA_RUN_ARGS: %s without its value" % name)
            setting = args[i]
        if name in VOLUME_OPTIONS:
            _check_volume(setting)
        elif not re.fullmatch(r"nofile=\d+(:\d+)?", setting):
            raise ValueError("DIONAEA_RUN_ARGS: --ulimit sets nofile only: %s" % setting)
        i += 1
    return args


def _check_volume(setting):
    """FILE:TARGET:ro, FILE a regular file of the host, TARGET a file below one of VOLUME_TARGETS."""
    parts = setting.split(":")
    if len(parts) != 3 or parts[2] != "ro":
        raise ValueError("DIONAEA_RUN_ARGS: a volume is SOURCE:TARGET:ro: %s" % setting)
    source, target = parts[0], parts[1]
    if not os.path.isfile(source):
        raise ValueError("DIONAEA_RUN_ARGS: the source of a volume is a file of the host: %s" % setting)
    if os.path.normpath(target) != target or not target.startswith(VOLUME_TARGETS):
        raise ValueError("DIONAEA_RUN_ARGS: a volume goes below %s: %s" % (" or ".join(VOLUME_TARGETS), setting))


def main():
    try:
        args = run_args()
    except ValueError as error:
        print(error, file=sys.stderr)
        return 2
    # the arguments of value.split() have no white space
    for arg in args:
        print(arg)
    return 0


if __name__ == "__main__":
    sys.exit(main())
