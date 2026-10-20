# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Read-only measuring point of the load test, loaded into dionaea.

run.py mounts this file as a python module of dionaea (dionaea.cfg
``imports=...,load_probe``). A thread writes one JSON line per second to
/opt/dionaea/var/log/probe.jsonl:

    timestamp   time.time()
    rss_kib     VmRSS of the dionaea process
    smb         one entry per open smbd connection of log_json: client port,
                credentials kept (count) and their characters (text_chars)
    stats       g_dionaea.processor_stats() (stream data, jobs, overloads),
                null for an image without it (before the stream limits)
    mark        once, the text run.py put into /opt/dionaea/var/log/probe-mark: the probe
                logs "load test mark <text>" at info first (dionaea.log has the lines
                in their order, so the lines before it are those of the load)

It changes nothing in dionaea.
"""

import json
import logging
import threading
import time
from pathlib import Path

OUT = Path("/opt/dionaea/var/log/probe.jsonl")
MARK = Path("/opt/dionaea/var/log/probe-mark")

logger = logging.getLogger("load-probe")

stopping = threading.Event()
worker = None


def _smb_rows():
    from dionaea.ihandlers import g_handlers
    from dionaea.log_json import LogJsonHandler

    rows = []
    for group in (g_handlers or {}).values():
        for handler in group:
            if not isinstance(handler, LogJsonHandler):
                continue
            for _con, data in list(handler.attacks.items()):
                if data.get("connection", {}).get("protocol") != "smbd":
                    continue
                credentials = data.get("credentials", [])
                if isinstance(credentials, dict):
                    # flattened when the connection ends
                    count = len(credentials.get("username", []))
                    chars = sum(len(v) for values in credentials.values() for v in values if isinstance(v, str))
                else:
                    count = len(credentials)
                    chars = sum(len(v) for item in list(credentials) for v in item.values() if isinstance(v, str))
                rows.append({"port": data.get("src_port"), "count": count, "text_chars": chars})
    return rows


def _stats():
    from dionaea.core import g_dionaea

    get = getattr(g_dionaea, "processor_stats", None)
    return get() if get is not None else None


def _rss_kib():
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return None


def snapshot():
    return {"timestamp": time.time(), "rss_kib": _rss_kib(), "smb": _smb_rows(), "stats": _stats()}


def take_mark(path=MARK):
    """The text of the mark file, logged at info, and the file removed; None without one."""
    try:
        text = path.read_text().strip()
        path.unlink()
    except OSError:
        return None
    logger.info("load test mark %s", text)
    return text


def line(row, mark):
    """The JSON line of a snapshot, with the mark logged before it."""
    if mark is not None:
        row = dict(row, mark=mark)
    return json.dumps(row)


def _run():
    with OUT.open("a", buffering=1) as out:
        while not stopping.wait(1):
            mark = take_mark()
            out.write(line(snapshot(), mark) + "\n")


def new():
    pass


def start():
    global worker
    worker = threading.Thread(target=_run, name="load-probe", daemon=True)
    worker.start()


def stop():
    stopping.set()
    if worker is not None:
        worker.join(timeout=5)
