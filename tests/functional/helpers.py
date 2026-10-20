# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Plain helper functions for the functional tests (no pytest fixtures)."""

import json
import socket
import sqlite3
import time
from pathlib import Path


def read_json_events(path):
    """Return all complete JSON lines of a dionaea.json as a list of dicts.

    Lines that are not (yet) valid JSON, e.g. a line dionaea is writing right
    now, are skipped.
    """
    path = Path(path)
    events = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return events
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except ValueError:
            continue
    return events


def wait_for_json_event(path, predicate, timeout=30.0, interval=0.5):
    """Wait until an entry of the JSON log matches predicate(event).

    Returns the first matching event, raises TimeoutError otherwise.
    """
    deadline = time.monotonic() + timeout
    while True:
        for event in read_json_events(path):
            try:
                if predicate(event):
                    return event
            except (AttributeError, KeyError, TypeError):
                continue
        if time.monotonic() >= deadline:
            raise TimeoutError(
                "no entry in %s matched within %.0fs" % (path, timeout)
            )
        time.sleep(interval)


def query_sqlite(path, sql, params=()):
    """Run a read-only query on dionaea.sqlite and return the rows as dicts."""
    con = sqlite3.connect("file:%s?mode=ro" % Path(path).as_posix(), uri=True, timeout=10)
    con.row_factory = sqlite3.Row
    try:
        return [dict(row) for row in con.execute(sql, params)]
    finally:
        con.close()


def wait_for_port(host, port, timeout=60.0, interval=0.5):
    """Wait until host:port accepts a TCP connection, raise TimeoutError otherwise."""
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=3):
                return
        except OSError as exc:
            last_error = exc
            time.sleep(interval)
    raise TimeoutError("%s:%d not reachable within %.0fs: %s" % (host, port, timeout, last_error))


def recv_line(sock, timeout=10.0):
    """Read one line (up to and including LF) from a connected socket."""
    deadline = time.monotonic() + timeout
    data = b""
    while not data.endswith(b"\n"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("no complete line within %.0fs, got %r" % (timeout, data))
        sock.settimeout(remaining)
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode("utf-8", errors="replace")


def binaries_names(binaries_dir):
    """The names in binaries/ and, as ``.incoming/<name>``, in its folder of the temporary files of samples."""
    binaries_dir = Path(binaries_dir)
    names = [p.name for p in binaries_dir.iterdir()]
    incoming = binaries_dir / ".incoming"
    if incoming.is_dir():
        names += [".incoming/" + p.name for p in incoming.iterdir()]
    return names


def temp_names(binaries_dir, prefixes):
    """The temporary files of samples (by their prefix) in binaries/ and binaries/.incoming."""
    return sorted(n for n in binaries_names(binaries_dir) if n.rsplit("/", 1)[-1].startswith(prefixes))
