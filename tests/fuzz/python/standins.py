# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Stand-ins of the C binding of dionaea (dionaea.core) for the Python fuzz targets.

The services are loaded from modules/python/dionaea (DIONAEA_PY_SRC) as the unit
tests under tests/functional/unit do: the package dionaea and the packages of
the services without their __init__ (they need the binding), dionaea.core with
a connection, an incident and g_dionaea that behave as those of binding.pyx
where the services can tell: send takes str or bytes only, an incident takes
an int that fits a C long and a str that is valid UTF-8, and the binding
catches what handle_io_in raises (which is what the targets look for).

The log handler of dionaea (dionaea/log.py) is on the root logger at DEBUG: it
formats every record and hands the message to the binding as UTF-8; the stand-in
does the same and drops the line.
"""

import contextlib
import hashlib
import importlib.util
import logging
import os
import sys
import tempfile
import traceback
import types
from pathlib import Path

SRC = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
    Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")

LONG_MIN, LONG_MAX = -(1 << 63), (1 << 63) - 1


class Node:
    def __init__(self, host, port):
        self.host = host
        self.port = port


class Timeouts:
    idle = 0
    sustain = 0
    listen = 0
    connecting = 0
    handshake = 0


class Accounting:
    limit = 0


class Direction:
    def __init__(self):
        self.accounting = Accounting()


class Connection:
    """connection of binding.pyx as the services see it"""

    def __init__(self, proto="tcp", *args, **kwargs):
        self.transport = proto
        self.sent = []
        self.closed = False
        self.timeouts = Timeouts()
        self.remote = Node("198.51.100.9", 50123)
        self.local = Node("192.0.2.1", 445)
        self._in = Direction()
        self._out = Direction()

    def send(self, data, local=None, remote=None):
        if isinstance(data, str):
            data = data.encode("utf-8")
        elif not isinstance(data, bytes):
            raise ValueError("requires text/bytes input, got %s" % type(data))
        self.sent.append(data)

    def close(self):
        self.closed = True

    def processors(self):
        pass

    def bind(self, *args, **kwargs):
        pass

    def listen(self, *args, **kwargs):
        pass


class Incident:
    """incident of binding.pyx: the values it takes, the reports in Incident.reported"""

    reported = []

    def __init__(self, origin=None):
        object.__setattr__(self, "origin", origin)
        object.__setattr__(self, "values", {})

    def __setattr__(self, key, value):
        if isinstance(value, Connection):
            pass
        elif isinstance(value, int):
            if not LONG_MIN <= value <= LONG_MAX:
                raise OverflowError("Python int too large to convert to C long")
        elif isinstance(value, str):
            value.encode("utf-8")
        elif not isinstance(value, (bytes, list, dict)) and value is not None:
            # the binding sets nothing for other types
            return
        self.values[key] = value

    def __getattr__(self, key):
        try:
            return self.__dict__["values"][key]
        except KeyError:
            raise AttributeError("%s does not exist" % key) from None

    def set(self, key, value):
        self.__setattr__(key, value)

    def get(self, key):
        return self.__getattr__(key)

    def report(self):
        if len(Incident.reported) < 1000:
            Incident.reported.append((self.origin, dict(self.values)))


class LogHandler(logging.Handler):
    """DionaeaLogHandler of dionaea/log.py without the binding (dlhfn encodes the message as UTF-8)"""

    def __init__(self):
        logging.Handler.__init__(self, logging.DEBUG)

    def emit(self, record):
        self.format(record).encode("utf-8")


class Dionaea:
    def __init__(self, download_dir):
        self._config = {"dionaea": {"download.dir": download_dir, "download.suffix": ".tmp"}}

    def config(self):
        return self._config


DOWNLOAD_DIR = tempfile.mkdtemp(prefix="dionaea-fuzz-")


def install():
    """dionaea, dionaea.core and the service packages as stand-ins in sys.modules"""
    package = types.ModuleType("dionaea")
    package.__path__ = [str(SRC)]
    core = types.ModuleType("dionaea.core")
    core.connection = Connection
    core.incident = Incident
    core.g_dionaea = Dionaea(DOWNLOAD_DIR)
    core.__all__ = ["connection", "incident", "g_dionaea"]
    sys.modules["dionaea"] = package
    sys.modules["dionaea.core"] = core
    root = logging.getLogger("")
    root.setLevel(logging.DEBUG)
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.addHandler(LogHandler())
    for sub in ("smb", "mqtt", "mongo"):
        module = types.ModuleType("dionaea." + sub)
        module.__path__ = [str(SRC / sub)]
        sys.modules["dionaea." + sub] = module
        setattr(package, sub, module)


def load(name, path):
    """the module name (dotted, below dionaea) from the file path below SRC"""
    spec = importlib.util.spec_from_file_location(name, SRC / path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def clean_downloads():
    """the files the services wrote (uploads, payloads) since the last call"""
    for root, _dirs, files in os.walk(DOWNLOAD_DIR):
        for name in files:
            with contextlib.suppress(OSError):
                os.unlink(os.path.join(root, name))


def reads(data):
    """(cuts, stream) of the input of a service target: a byte n (modulo 9), n cuts of 3 bytes (big endian), the
    stream. A seed is b"\\x00" and the stream."""
    count = data[0] % 9 if data else 0
    cuts = [int.from_bytes(data[1 + 3 * i:4 + 3 * i], "big") for i in range(count)]
    return cuts, data[1 + 3 * count:]


def feed(con, data, cuts):
    """data in reads cut at cuts, as the binding: what handle_io_in did not take comes again in front of the next
    read. Returns what is left in the buffer. Checks the value handle_io_in returns."""
    pending = b""
    start = 0
    for cut in sorted(cuts) + [len(data)]:
        if cut < start:
            continue
        pending += data[start:cut]
        start = cut
        if not pending:
            continue
        taken = con.handle_io_in(pending)
        if not isinstance(taken, int) or not 0 <= taken <= len(pending):
            raise AssertionError("handle_io_in returned %r for %d bytes" % (taken, len(pending)))
        pending = pending[taken:]
        if con.closed:
            break
    return pending


FAILURES = os.environ.get("FUZZ_FAILURES")
_seen = set()


def _signature(error):
    """the type of the error, the innermost frame of it in a service (not in the shared dissector of
    smb/include) and the innermost frame of it in the sources of dionaea"""
    frames = [f for f in traceback.extract_tb(error.__traceback__) if str(SRC) in f.filename]

    def where(frame):
        return "%s:%d" % (os.path.relpath(frame.filename, SRC), frame.lineno)

    services = [f for f in frames if "/smb/include/" not in f.filename]
    parts = [type(error).__name__]
    if services:
        parts.append(where(services[-1]))
    if frames and (not services or frames[-1] is not services[-1]):
        parts.append(where(frames[-1]))
    return " ".join(parts)


def run(target, data):
    """target(data); with FUZZ_FAILURES=folder an error is written there once per signature (the input and its
    traceback) and the run goes on, so one run collects all of them; else it is raised (libFuzzer stops)."""
    if FAILURES is None:
        target(data)
        return
    try:
        target(data)
    except Exception as error:
        signature = _signature(error)
        if signature in _seen:
            return
        _seen.add(signature)
        name = hashlib.sha1(signature.encode()).hexdigest()[:12]
        os.makedirs(FAILURES, exist_ok=True)
        with open(os.path.join(FAILURES, name + ".input"), "wb") as f:
            f.write(data)
        with open(os.path.join(FAILURES, name + ".txt"), "w") as f:
            f.write(signature + "\n\n" + "".join(traceback.format_exception(error)))
        sys.stderr.write("FAILING INPUT %s %s\n" % (name, signature))
