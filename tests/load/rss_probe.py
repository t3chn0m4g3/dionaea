# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The 1 s memory probe of replay.py (test only: never in the image or in T-Pot's configuration).

replay.py mounts this file into the python modules of dionaea, adds it to the imports of its copy
of the configuration and mounts its out/ folder at /probe. A thread writes one line per second to
/probe/rss_probe.csv:

    epoch,rss_kib,inuse_bytes,cost_us,anon_huge_kib

rss_kib is the resident set of the process (the second field of /proc/self/statm, the counter of
VmRSS), inuse_bytes what glibc has handed out (mallinfo2: uordblks + hblkhd, the arenas and the
mmapped chunks), cost_us the time the sample took, anon_huge_kib AnonHugePages of
/proc/self/smaps_rollup, read once a minute (empty otherwise): replay.py turns THP off for
dionaea and fails the run if it is not 0. With LEAK_INJECT=<malloc|mmap>:<MiB per 10 min>
in the environment (replay.py --inject-leak) the thread also leaks memory at that rate, through
malloc (glibc in use and RSS grow) or anonymous mmap (only RSS grows): the test of the gates.
"""

import ctypes
import mmap
import os
import threading
import time

OUT = "/probe/rss_probe.csv"
stopping = threading.Event()


class Mallinfo2(ctypes.Structure):
    _fields_ = [(name, ctypes.c_size_t) for name in ("arena", "ordblks", "smblks", "hblks", "hblkhd", "usmblks",
                                                     "fsmblks", "uordblks", "fordblks", "keepcost")]


class Leak:
    """Allocates rate MiB / 10 min, every 10 s a piece, touches every page and never frees it."""

    def __init__(self, spec, libc):
        kind, _, rate = spec.partition(":")
        if kind not in ("malloc", "mmap"):
            raise ValueError("LEAK_INJECT: malloc or mmap, not %r" % kind)
        self.kind = kind
        self.piece = int(float(rate or 2) * (1 << 20) / 60)
        self.libc = libc
        self.kept = []
        self.next_at = time.monotonic()

    def step(self, now):
        if now < self.next_at:
            return
        self.next_at += 10
        if self.kind == "malloc":
            address = self.libc.malloc(self.piece)
            if address:
                ctypes.memset(address, 0x5a, self.piece)
                self.kept.append(address)
        else:
            area = mmap.mmap(-1, self.piece, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
            area.write(b"\x5a" * self.piece)
            self.kept.append(area)


def anon_huge_kib():
    with open("/proc/self/smaps_rollup") as rollup:
        for line in rollup:
            if line.startswith("AnonHugePages:"):
                return int(line.split()[1])
    return ""


def _loop():
    libc = ctypes.CDLL("libc.so.6")
    libc.mallinfo2.restype = Mallinfo2
    libc.malloc.restype = ctypes.c_void_p
    libc.malloc.argtypes = [ctypes.c_size_t]
    page_kib = os.sysconf("SC_PAGE_SIZE") // 1024
    leak = Leak(os.environ["LEAK_INJECT"], libc) if os.environ.get("LEAK_INJECT") else None
    statm = os.open("/proc/self/statm", os.O_RDONLY)
    new = not os.path.exists(OUT)
    with open(OUT, "a", buffering=1) as out:
        if new:
            out.write("epoch,rss_kib,inuse_bytes,cost_us,anon_huge_kib\n")
        next_at = time.monotonic()
        tick = 0
        while not stopping.wait(max(0.0, next_at - time.monotonic())):
            next_at += 1
            start = time.perf_counter()
            rss_kib = int(os.pread(statm, 128, 0).split()[1]) * page_kib
            info = libc.mallinfo2()
            huge = anon_huge_kib() if tick % 60 == 0 else ""
            tick += 1
            cost = int((time.perf_counter() - start) * 1e6)
            out.write("%.3f,%d,%d,%d,%s\n" % (time.time(), rss_kib, info.uordblks + info.hblkhd, cost, huge))
            if leak is not None:
                leak.step(time.monotonic())


def new():
    pass


def start():
    # replay.py starts dionaea through a python wrapper (PR_SET_THP_DISABLE): its exec of dionaea gains
    # cap_net_bind_service, which makes the process non-dumpable, so /proc/1/fd is root's and the samples
    # of replay.py (docker exec as uid 2000) see no fd. Started by docker directly dionaea stays dumpable;
    # this puts that back.
    try:
        ctypes.CDLL(None).prctl(4, 1, 0, 0, 0)    # PR_SET_DUMPABLE
    except (OSError, AttributeError):
        pass
    threading.Thread(target=_loop, name="rss-probe", daemon=True).start()


def stop():
    stopping.set()
