<!--
SPDX-FileCopyrightText: none
SPDX-License-Identifier: CC0-1.0
-->

# Slow share: the streamcap count

On a Docker Desktop bind mount (T-Pot's mac_win edition) every file request of
a container goes through one serial queue of the virtiofs device on the host.
A count of all of `bistreams/` by the counting thread of the streamdumper limits
(`src/streamcap.c`), a cold walk of 188,000 dumps, keeps that queue busy for 2
to 9 minutes, and every file request of the event loop (sqlite, logs, new
dumps) comes behind it. The same holds for the store's `DirQuota`
(`binaries/`). Both count once at the start, beside the event loop, and then
look only at the folders.

`slowfs.so` models such a share on any Linux, without macOS: an `LD_PRELOAD`
shim that serves file requests one at a time.

- The queue is a FIFO ticket lock that every file request below takes.
- `readdir`: every `SLOWFS_BATCH`-th entry (default 128) of a thread is one
  getdents request that holds the queue for `SLOWFS_BATCH * SLOWFS_ENTRY_US`
  (default 500 µs per entry: READDIRPLUS, one host lookup per entry).
- `fstatat` / `stat` / `lstat` hold it for `SLOWFS_STAT_US` (default 20 µs).
- `open` / `openat`, `pwrite`, `write` to regular files, `fsync`, `fdatasync`
  have no cost of their own, but wait while a batch is served.
- `SLOWFS_LOG=FILE` writes `time tid thread entries` per 2,000 directory
  entries of a thread: which thread walks, and when.

It reproduces the time a walk takes, the banner latency behind it and the time
of a stop during a walk. It only delays: it does not reproduce the 10 s banner
timeouts of virtiofs.

## Build

The shim must be built against the glibc of the dionaea image (Linux only):

    gcc -O2 -shared -fPIC -o slowfs.so slowfs.c -ldl -lpthread

`repro.py` does this itself, in an image with gcc on the base of the last
stage of `./Dockerfile` (`dionaea-slowfs-builder:local`, cached) or in the
image of `--builder-image`, and mounts the result into the dionaea container
with `LD_PRELOAD=/shim/slowfs.so`. dionaea runs as root in the container there
and drops to its user itself: with the file capability of the binary the loader
ignores `LD_PRELOAD` for another user (secure execution).

## Run

Needs Docker and Python 3 (standard library); the client image of the
functional tests is built if it is missing.

    tests/load/slowfs/repro.py --image IMAGE                     # 190,000 dumps, 5 min of load, then the stop
    tests/load/slowfs/repro.py --image IMAGE --stop-early 30     # the stop during the first count
    tests/load/slowfs/repro.py --image IMAGE --prefill 60000 --entry-us 2000 --batch 256   # a colder share
    tests/load/slowfs/repro.py --image IMAGE --prefill 1000 --store-prefill 16000 --store-max-size 63 --minutes 11
                                                                 # the store at its cap while samples come
    tests/load/slowfs/coldstop.sh IMAGE DIR                      # Docker Desktop: a cold bind mount, no shim

`repro.py` starts dionaea with the T-Pot limits (streamdumper 2048 MiB /
200,000 dumps, store 1024 MiB) on a Docker named volume, prefills
`bistreams/2026-10-01`, runs the replay client of `tests/load` (8 workers and
the FTP banner every 0.5 s), and stops dionaea with `docker stop -t 10` while a
count runs (if one does within 90 s). `--data-bind DIR` puts the data folder on
a host folder (the virtiofs bind mount on Docker Desktop), `--no-shim` runs
without the shim, `--drop-caches` drops the dentries and inodes of the Docker
VM first (privileged), `--artifacts DIR` keeps config, logs, `slowfs.log`,
`out/banner.csv` and `meta.json` in DIR (default: a new temp folder).

It prints the walks of the `streamcap` and `store-count` threads, the banner
latency inside and outside them, when dionaea listened and how long its first
count took, and the stop. Exit 0 (`PASSED`): the stop took less than
`--max-stop` seconds (2; dionaea's own stop without a walk took 0.6 to 0.8 s
on Docker Desktop) with exit code 0, and the prefilled folder was not walked again
after the first count. A refused dump may have today's folder of
the run counted again (at most every 10 minutes): that walk is listed, but does
not fail the run. 1: not so; 3: no Docker, or a used artifacts folder.

The numbers on Docker Desktop (arm64, 190,000 dumps, 0.5 ms per entry, 5
minutes of load): dionaea listened after 1.3 s, counted once (141 s, beside the
event loop, banner max 0.17 s), did not walk again after it, and stopped in
0.2 s with exit 0: `PASSED`. A count before the listen and every minute takes
126 s to the listen and 148 s per walk in the same model. With `--stop-early 30` (the stop during the first count) it stopped
in 0.1 to 1.6 s with exit 0 in 13 runs; without the shim and without a walk the
stop took 0.6 to 0.8 s, so the spread is that of `docker stop` on Docker
Desktop, not the wait for the count.

The store at its cap (`--store-prefill 16000 --store-max-size 63`: 16,000
samples of 4 KiB in `binaries/`, room for a few dozen more, 11 minutes of
load): the `store-count` thread must read `binaries/` once, at the start. With
the temporary files in `binaries/.incoming` (they do not change the mtime of
`binaries/`): 58 samples stored, 11,329 refused, one walk (the first count,
7.6 s), `PASSED`. With the temporary files in `binaries/` itself every sample
changes its mtime and a refused sample has the folder counted again (7.7 s per
walk in the model).
