# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Memory probe of leak.py, loaded into dionaea (dionaea.cfg imports=...,leak_probe).

leak.py drops command files into /opt/dionaea/var/log/probe-cmd/ (``<n>-<command>``),
a thread of the probe runs them and writes /opt/dionaea/var/log/probe-<command>.json:

    snap-<name>      after gc.collect(): VmRSS, mallinfo2() of glibc (heap in use, free in
                     the arenas), sqlite3_memory_used() (page caches of the sqlite logs, they
                     fill up to their cache_size), the objects the GC tracks per type, and with tracemalloc
                     the lines whose allocations grew since the last snap
    config-<n>       g_dionaea.config() n times: growth of the objects and of the heap
    trace            tracemalloc.start(25)

It changes nothing in dionaea.
"""

import ctypes
import gc
import json
import threading
import time
import tracemalloc
from collections import Counter
from pathlib import Path

CMD = Path("/opt/dionaea/var/log/probe-cmd")
OUT = Path("/opt/dionaea/var/log")
stopping = threading.Event()
state = {"types": None, "snapshot": None}


class Mallinfo2(ctypes.Structure):
    _fields_ = [(name, ctypes.c_size_t) for name in ("arena", "ordblks", "smblks", "hblks", "hblkhd", "usmblks",
                                                     "fsmblks", "uordblks", "fordblks", "keepcost")]


def mallinfo():
    try:
        libc = ctypes.CDLL("libc.so.6")
        libc.mallinfo2.restype = Mallinfo2
        info = libc.mallinfo2()
        return {name: getattr(info, name) for name, _ in Mallinfo2._fields_}
    except (OSError, AttributeError) as error:
        return {"error": str(error)}


def sqlite_memory():
    """Bytes sqlite has allocated (all connections of the process: page caches, statements)."""
    try:
        lib = ctypes.CDLL("libsqlite3.so.0")
        lib.sqlite3_memory_used.restype = ctypes.c_int64
        return lib.sqlite3_memory_used()
    except (OSError, AttributeError):
        return None


def status():
    values = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        if line.startswith(("VmRSS:", "RssAnon:", "VmHWM:")):
            values[line.split(":")[0]] = int(line.split()[1])
    return values


def type_name(obj):
    cls = type(obj)
    module = cls.__dict__.get("__module__") if isinstance(cls, type) else None
    if not isinstance(module, str):
        module = "builtins"
    name = getattr(cls, "__qualname__", "?")
    return "%s.%s" % (module, name if isinstance(name, str) else "?")


def snap(name):
    gc.collect()
    types = Counter(type_name(obj) for obj in gc.get_objects())
    out = {"name": name, "time": time.time(), "status": status(), "mallinfo": mallinfo(), "sqlite": sqlite_memory(),
           "objects": sum(types.values()), "types_top": types.most_common(20)}
    if state["types"] is not None:
        out["types_grown"] = (types - state["types"]).most_common(20)
    state["types"] = types
    if tracemalloc.is_tracing():
        snapshot = tracemalloc.take_snapshot().filter_traces([tracemalloc.Filter(False, tracemalloc.__file__)])
        out["traced_bytes"] = tracemalloc.get_traced_memory()[0]
        if state["snapshot"] is not None:
            out["lines_grown"] = [[str(stat.traceback[0]), stat.size_diff, stat.count_diff]
                                  for stat in snapshot.compare_to(state["snapshot"], "lineno")[:20]]
        state["snapshot"] = snapshot
    return out


def config_check(count):
    from dionaea.core import g_dionaea
    g_dionaea.config()
    gc.collect()
    objects, heap = len(gc.get_objects()), mallinfo().get("uordblks", 0)
    for _ in range(count):
        g_dionaea.config()
    gc.collect()
    return {"calls": count, "objects_grown": len(gc.get_objects()) - objects,
            "heap_grown_bytes": mallinfo().get("uordblks", 0) - heap}


def run(command):
    if command == "trace":
        tracemalloc.start(25)
        return
    kind, _, name = command.partition("-")
    if kind == "snap":
        result = snap(name)
    elif kind == "config":
        result = config_check(int(name))
    else:
        result = {"error": "unknown command %s" % command}
    path = OUT / ("probe-%s.json" % command)
    tmp = OUT / ("probe-%s.tmp" % command)
    tmp.write_text(json.dumps(result, indent=1))
    tmp.rename(path)


def _commands():
    try:
        return sorted(CMD.iterdir())
    except OSError:
        # the folder is a bind mount: a listing can fail now and then, the next one works
        return []


def _loop():
    CMD.mkdir(exist_ok=True)
    while not stopping.wait(0.5):
        for path in _commands():
            command = path.name.split("-", 1)[1] if "-" in path.name else path.name
            try:
                path.unlink()
            except OSError:
                continue
            try:
                run(command)
            except Exception as error:   # the probe must never stop dionaea, nor itself
                try:
                    (OUT / "probe-error.txt").write_text("%s: %r\n" % (command, error))
                except OSError:
                    pass


def new():
    pass


def start():
    threading.Thread(target=_loop, name="leak-probe", daemon=True).start()


def stop():
    stopping.set()
