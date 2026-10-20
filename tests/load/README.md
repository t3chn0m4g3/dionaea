<!--
SPDX-FileCopyrightText: none
SPDX-License-Identifier: CC0-1.0
-->

# Load test of the stream processing

dionaea runs as in T-Pot (uid/gid 2000, read-only, a 16 MiB tmpfs on /tmp) with the limits of a small
sensor: 768 MiB without swap, 1 CPU, 128 pids, on an internal Docker network,
the emu processor active (`filter_emu`: smbd, epmapper, nfqmirrord, mssqld; the
streamdumper is off, 36,000 logins would write about 1.7 GiB of bistreams).
The client runs in the client image of the functional tests. The host needs
Docker and Python 3 (standard library).

    tests/load/run.py                          # build ./Dockerfile, both scenarios
    tests/load/run.py --image IMAGE            # test an image
    tests/load/run.py --scenario normal|overload|all --artifacts DIR
    tests/load/run.py --keep                   # leave dionaea running after a failure
    DIONAEA_RUN_ARGS="..." tests/load/run.py   # more arguments for docker run of dionaea

Exit 0: every scenario passed, 1: a check failed, 2: `DIONAEA_RUN_ARGS` has an
option that is not allowed (see the replay below), 3: no Docker or a used
artifacts folder. `DIR/summary.json` has the result, `DIR/<scenario>/` the
config, data, logs, `summary.json` (every check with its numbers),
`client.log`, `out/result.json` (the numbers of the client) and
`log/probe.jsonl`.

`probe.py` is loaded into dionaea as a python module (`load_probe`) and writes
one line per second: RSS, the credentials log_json keeps per smbd connection,
and `g_dionaea.processor_stats()` (stream data stored and its peak, requests
refused by the limits of an instance and of the process, waiting and refused
jobs, overload closes, instances the emu gave up). It is read only, but for one
line: before the functional tests run.py has it log a mark (`load test mark
<pid>-<scenario>`, info), and the lines of `dionaea.log` before the mark are those of
the load (the log has the time in seconds, a split by time put the lines of that
second on the wrong side). `python3 tests/load/test_run_log_split.py` tests it
(standard library, no docker).

Both scenarios upload x86 code over SMB1 beside the load (6 MiB at full speed,
data that costs libemu as much as x86 code: random bytes with a near call every
2400 bytes, see *Limits*). smbd is behind the emu, which can not keep up with
it: it gives up for that connection or stops at its scan limit, and the upload
must be stored (binaries/<md5>, 0440).

## normal

3 cycles of 4 SMB1 connections with 3000 NTLM logins each (36,000 in all;
user name, domain and workstation of 8192 characters each), FTP and HTTP uploads
every 3 s beside them, the FTP banner every 0.5 s. Pass:

- no OOM kill, no restart, no Traceback, assertion, critical or crash in the logs
- every SMB upload of x86 code stored; the emu gives up (one warning) only for
  them, the login connections only reach its scan limit (an info)
- RSS after the credential limit (1000 per connection) grows at most 16 MiB or
  10 % within a cycle, idle RSS at most 32 MiB from the first cycle to the
  last
- JSON has 1000 credentials per connection, SQLite every login
- the stream data stays within 32 MiB / 32768 chunks, at most 32 jobs wait,
  no job and nothing of the process limit is refused, no connection is
  closed for overload
- after each cycle no stream data and no job is left
- the FTP banner always within 5 s, every upload stored (binaries/<md5>, 0440)
- afterwards FTP, SMB and an upload work, and the functional tests of the
  services (smoke, SMB auth, FTP, TFTP, upload) pass against the same dionaea

## overload

Three rounds. In each, 4 connections (one per worker) send a window the emu
needs seconds for (a GetPC candidate every 128 bytes, plus filler: 960 KiB, below
the limit of an instance), then 48 connections send bursts: 960 KiB each, then
on to 6 MiB, and an SMB upload of x86 code runs beside them. Pass:

- the emu gives up once for every burst connection, with exactly one line in
  dionaea.log (reason, connection, protocol, address, nothing of the data);
  every burst connection stays open and sends everything, none is closed
- the SMB upload is stored
- the 4 slow connections stay open and are scanned to the end
- the job queue (32 waiting, jobs refused), the 1 MiB of an instance and the
  32 MiB of the process were all reached; the stream data never above
  32 MiB / 32768 chunks
- once the connections are gone no stream data and no job is left
- RSS below 512 MiB in every round, the last round not more than 32 MiB
  above the rounds before (the allocator keeps what the first rounds took)
- the FTP banner within 5 s during the load; afterwards FTP, SMB and an
  upload work, the functional tests pass, no crash or Traceback

## Limits of the test

The numbers hold for this sensor size. libemu tries every GetPC candidate (a
call with a displacement of at most 512, fnstenv) and builds a new Windows
environment for each, so the scan rate depends on the data. Measured with
`emu_shellcode_test()` in the windows of `modules/emu/detect.c` (64 KiB new
data plus 300 bytes of overlap), one core:

| data | arm64 (Apple M, native) | amd64 (emulated by Docker Desktop) |
| --- | --- | --- |
| random bytes | 81 MB/s | 56 MB/s |
| x86-64 `libc.so.6` (2.1 MB) | 1.2 MB/s | 0.6 MB/s |
| x86-64 `libcrypto.so.3` (first 4 MiB) | 0.9 MB/s | 0.45 MB/s |
| the x86-like data of the SMB uploads (first 4 MiB) | 0.55 MB/s | 0.5 MB/s |
| a GetPC every 128 bytes | 2.1 s per 64 KiB window | 3.3 s per window |

The amd64 column ran under emulation (not measured on native amd64 hardware).
The emu scans the first 4 MiB of a connection (`EMU_SCAN_LIMIT`) or until a
limit of the stream processing (the 1 MiB of its instance, the limits of the
process, a full job queue), and the connection goes on; exploit shellcode comes
in the first requests. Only a processor that needs the whole history (xmatch,
not in the T-Pot config) closes the connection at a limit.

# Synthetic accelerated replay

The last test before a release. Instead of watching a sensor for a day, the
benign scenarios of the functional tests run in a loop at the highest rate
dionaea takes, for an hour: about 275,000 connections (4,600 a minute, 240,000
scenarios) on the arm64 image, the connections of many days of a sensor. It shows
whether dionaea stays stable: memory, file descriptors, threads, the event loop, the
files it writes.

    tests/load/replay.py                                # dionaea:local, 60 minutes
    tests/load/replay.py --quick                        # 5 minutes, sample every 10 s
    tests/load/replay.py --image IMAGE --duration 120 --concurrency 12 --artifacts DIR
    tests/load/replay.py --platform linux/amd64 --quick # an amd64 image under emulation (see below)
    tests/load/replay.py --only ftp_session,http_get    # a part of the mix (debugging)
    tests/load/replay.py --unique-share 0               # uploads from the pool only (default 0.15 new samples)
    tests/load/replay.py --inject-leak malloc|mmap [--leak-rate 2]   # a test of the memory gates (fails)

The host needs Docker and Python 3 (standard library); the client container is
the one of the functional tests. Exit 0: every criterion passed, 1: one failed,
3: no Docker or a used artifacts folder. `--quick` judges the same criteria, but
the slope of the RSS and the growth of fds and threads are only reported (five
minutes are too short for a slope; the start of dionaea is no leak).

dionaea runs as in T-Pot: the configuration of `docker/dionaea/dist/etc` of the
tpotce checkout (`--config DIR`, or the folder `DIONAEA_CONFIG_DIR` names;
read, never written), uid/gid 2000, `--read-only` with a 16 MiB tmpfs on `/tmp`, the service roots read-only,
1 GiB memory without swap, 256 pids, 1 CPU, `--restart always`, `max_size` of the
store as in T-Pot's `store.yaml`, streamdumper and emu active. The only change:
the download policy allows the test network, which is `--internal`, so nothing
leaves it. Downloads (shellshock header, MySQL `xpdl3`, the shellcode that runs
`tftp -i <client> GET <script>`, whose script points at an HTTP URL) go to a TFTP
and an HTTP server in the client container.

## The mix

`replay_client.py` runs `--concurrency` workers (default 8), each picks a
scenario by weight at random, with no pause (`--think-ms` adds one), and
`--idle` threads (default 4) with idle and slow connections. It uses the
protocol clients of `tests/functional` (imported, not copied) and the SMB1 client
of `client.py`; the shellcode and the transaction sequences are those of
`test_emu.py` and `test_smb_trans.py`. A sample is one of 48 files of a pool
(stored once, as a botnet's binary) or, at 15 %, a new one.

| weight | scenario |
| --- | --- |
| 10, 3, 6, 2 | FTP: session (login, commands, passive LIST / RETR), active LIST, malformed commands (501 / 425 / 550), USER / PASS without argument |
| 8 | FTP STOR (passive or active, stored as binaries/<md5>) |
| 8, 2, 3 | HTTP GET, HTTPS GET, POST of a form |
| 5, 4 | HTTP multipart upload, request with a shellshock header (download from the client) |
| 5 | TFTP RRQ (file, missing file, outside the root) |
| 7, 4 | SMB1 login with IPC$, SMB1 upload to C$ (15 % x86-like data through the emu) |
| 5, 2 | SMB2 negotiate and NTLMSSP v1 / v2 to STATUS_LOGON_FAILURE (raw and impacket) |
| 4, 1 | SMB1 TRANSACTION / TRANSACTION2 / NT_TRANSACT with their *_SECONDARY, orphan secondary |
| 6, 4 | MySQL (SET, SHOW, SELECT, dumpfile, xpdl3, blocked internal URL, refused SQLite statements), MSSQL login and queries |
| 3, 2, 3 | MQTT connect / publish / subscribe, Mongo isMaster, epmap bind |
| 7, 2 | the emu: the shellcode of the functional tests on 445 and 135 (WinExec, PE export lookup, no GetPC, behind scan windows); the chain shellcode -> TFTP script -> HTTP payload |
| 3, 6 | the mirror port (42), port scans (connect, close or reset) |
| in the background | idle connections (3 to 25 s) and slow ones (a request in single bytes) |

## What it checks

dionaea is sampled every 30 s (`docker exec` reads `/proc/1/status`, `/proc/1/fd`
and the cgroup, `docker stats` the CPU), the FTP banner every 0.5 s by the client.
Memory is also sampled every second from inside: `rss_probe.py` (test only, never
in the image or in T-Pot's configuration) is mounted into the python modules of
dionaea, added to the imports of the run's copy of `dionaea.cfg`, and writes
`out/rss_probe.csv` (epoch, RSS in KiB from `/proc/self/statm`, glibc in use in
bytes, the time the sample took, and once a minute AnonHugePages of
`/proc/self/smaps_rollup`). A sample costs about 0.1 ms (p99 1 to 3 ms,
`mallinfo2()` takes the lock of every arena), `probe_cost_us` in the summary.
dionaea starts through a wrapper of the test: `--entrypoint python3` with a
`-c` script in the python of the image, which calls
`prctl(PR_SET_THP_DISABLE, 1, 0, 0, 0)` and execs the entrypoint and command of
the image (`docker image inspect`, a command without a path is looked up on `PATH`); the flag survives `execve`, dionaea is pid 1
with its file capabilities as before, and the image stays as it is (a python
of the image instead of a static helper: nothing to build per platform). The
summary has `thp_disabled` (`THP_enabled: 0` in `/proc/1/status` of every
sample) and `anon_huge_max_kib`. The probe's clock is that of the containers;
the window of the load comes from the client (the same clock) or, without it,
from the samples of the host, then it is moved by the offset of the clock of
the containers measured at the start (`probe_clock_offset_s`). The samples of
`docker exec` and `docker stats` are in the clock of the host: they are judged in
the window moved back by the offset, the banner probes of the client in the
clock of the containers.
With `--inject-leak malloc` or `mmap` the probe also allocates `--leak-rate` MiB
per 10 minutes (default 2) every 10 s and keeps it, through malloc (RSS and glibc
in use grow) or anonymous mmap (only RSS grows); the gates have to fail then.

- no restart, no OOM kill, dionaea runs (`RestartCount`, `OOMKilled`, `StartedAt`)
- no Traceback, LoaderError, Error loading module, assertion, critical or segmentation
  fault in the container log, `dionaea.log` and `dionaea-errors.log`; the report names
  each kind of Traceback with its last frames
- memory over the second half of the load, from the 1 s probe (below), each at
  most 1 MiB per 10 minutes: the Theil-Sen slope (the median of the slopes of all
  pairs) of the per-minute minimum of RSS, and that of the per-minute median of
  glibc's bytes in use (`mallinfo2`: `uordblks + hblkhd`); a minute counts with
  30 samples or more, the probe has to sample 90 % of the seconds and dionaea
  must have no transparent huge pages (AnonHugePages 0, see below). Maximum
  RSS (and `VmHWM`) below 768 MiB. The least squares slope of the 30 s samples
  is only reported (`rss_slope_ols_mib_per_10min`).
  Why: libemu builds an instruction graph of about 385 bytes per byte of a
  window with a GetPC candidate (24 MiB for 64 KiB). Without a trim the glibc
  arena of each of the four emu workers kept it after the scan, so RSS was a
  flat floor with peaks of up to 30 MiB, and the least squares slope of the 30 s
  samples had a standard error of about the threshold (runs without a leak
  failed it 14 to 26 % of the time). The emu worker trims after such a scan now
  (`modules/emu/trim.c`, at most every 5 s, and once more when it goes idle):
  the floor is about 93 MiB instead of 163, but RSS spreads between it and the
  peaks (93 to 180 MiB) and no slope of the 30 s samples is reliable any more
  (39 % above 1 MiB / 10 min with the samples of a run without a leak shuffled
  in time). RSS still touches the floor within every minute, and glibc in use
  (about 24 MiB, plus the graphs of running scans) does not depend on what the
  allocator keeps. The RSS floor sees a leak outside malloc (mmap), glibc in use
  one inside it that RSS hides under the spread. With THP on ("always", as on
  Docker Desktop) the level of the floor wandered by about 3 MiB for 10 to 30
  minutes (AnonHugePages collapse and split, the trim splits them more), and the
  RSS floor gate failed 13 to 15 % of the 60 minute runs without a leak (with
  AnonHugePages taken out 1.58 -> 0.51 and 1.88 -> 0.08): that case is out of
  scope, so the replay turns THP off for dionaea. `python3
  tests/load/test_rss_slope.py` checks both on synthesised shapes (standard
  library, no docker), `--inject-leak` on a real run (below)
- the fd and the thread count do not grow in the second half (growth of the
  regression line above 16 fds / 10 %, 4 threads / 10 %, and the later half of the
  samples above the earlier)
- p99 of the banner latency below 1 s (a timeout counts as 10 s)
- `binaries/` at most `max_size`
- `dionaea.json` valid JSON line by line, with every event type of the reference
  session (`fixtures/log_0.11.1.json`) and of the services of the mix
- the sqlite tables grow: connections never fall, no stall of four samples, 0.5 to 4
  rows per connection of the client, `PRAGMA integrity_check` ok, logins, downloads and
  emu_profiles are filled
- harness checks: every scenario worked at least once, at most 5 % of the scenarios
  failed, every upload is in `binaries/<md5>` (0440) a minute later, nothing is mirrored
  back, the emu chain made the servers of the client answer
- after a quiet period of 30 s: FTP banner, SMB1 login, SMB2 negotiate, TFTP RRQ, an FTP,
  an HTTP and an SMB upload (stored, 0440) still work

`DIR/summary.json` has the numbers (with `checks`, the Tracebacks by kind, the
counts of the client per scenario), `DIR/result.md` the table, `DIR/samples.csv` and
`samples.json` the samples (RSS, VmHWM, fds, threads, cgroup memory, CPU),
`DIR/out/banner.csv` every banner probe, `DIR/out/client.jsonl` what the client sees of
the data every 30 s, `DIR/client.log`, `container.log` and the data of dionaea
(`data/`, `log/`). The data of an hour are large: 2.4 GB of bistreams (216,000 files, the
streamdumper of the T-Pot configuration), 160 MiB of `binaries/`, 116 MB of `dionaea.json`.


`DIONAEA_RUN_ARGS` adds arguments to `docker run` of dionaea (debugging, e.g. a probe
module and a configuration that imports it). They come after the limits and the
options of the run, and docker takes the last value of an option, so only these are
taken: `-v` / `--volume SOURCE:TARGET:ro` with a file of the host as the source and a
file below `/opt/dionaea/lib/dionaea/python/` or `/opt/dionaea/etc/dionaea/` as the
target, read-only, and `--ulimit nofile=N[:M]` (also with `=`). Everything else is
refused with exit 2 before anything starts: the options of the limits, `--user`,
`--privileged`, `--cap-add`, `--security-opt`, `--read-only=false`, `--pid`,
`--network`, `--userns`, `--device`, `--entrypoint`, `-e`, a mount of the host, a
cluster of short flags (`-tu0` is `-t -u 0`), a value without its option. The value
is recorded as `dionaea_run_args` in `summary.json`. The same holds for
`tftp_load.py` and `leak.py`, which start dionaea through the replay, for `run.py`
and for `tests/functional/run.sh`: the allow-list is `runargs.py`, which run.sh runs
as `python3 tests/load/runargs.py` (one argument per line, exit 2 with the reason).
`python3 tests/load/test_replay_args.py` and `python3 tests/load/test_runargs.py` test
this (standard library, no docker).

## Under emulation

`--platform linux/amd64` on an arm64 host (or an image of the other architecture)
runs dionaea under qemu-user (Docker Desktop; where amd64 gives "exec format error",
`docker run --privileged --rm tonistiigi/binfmt --install amd64` first). The replay
finds out at the start: `uname -m` of the image against the architecture of
`docker info` (`native`, `container_arch`, `host_arch` in `summary.json`). When either
fails, answers nothing or does not answer in time (120 s for `uname -m`, 60 s for
`docker info`) the run stops with exit 3: it is never taken for emulated, which would
turn the memory gates off on a native host.

- On a native platform a failed `prctl(PR_SET_THP_DISABLE)` stops the start, and
  the error names it (`PR_SET_THP_DISABLE: <the text of errno>`).
- Under emulation qemu-user answers the prctl with EINVAL. The wrapper says so in
  the container log and starts dionaea anyway; THP stays as the kernel has it
  (AnonHugePages of 100 MiB and more), and RSS and glibc in use are those of the
  emulator with its translation cache. The THP check (the probe's check of the second
  half and AnonHugePages), the two memory gates and the max RSS backstop are then
  reported as not applicable (`n/a` in `result.md`, `"applicable": false` in the
  checks of `summary.json`) and never fail the run. Every other criterion holds as on
  a native run: no restart, no Traceback, the fd and thread counts, the banner
  latency, `binaries/`, `dionaea.json`, the sqlite tables, the scenarios of the client
  and the checks after the run.

# TFTP sessions under load

    tests/load/tftp_load.py --image IMAGE                   # 60 s, 20 clients x 4 threads
    tests/load/tftp_load.py --image IMAGE --duration 120 --clients 30 --artifacts DIR

dionaea runs as in the replay (T-Pot configuration and limits). Every client
container is one source address; its threads send read requests for a file of
`roots/tftp` at `--rate` a second per client (default 1,200, 24,000 a second in
all) without waiting for a reply, and acknowledge nothing, so every session waits for
its idle timeout (3 s); every fourth request is for a missing file.
dionaea is sampled every 2 s (its
connected UDP sockets in `/proc/net/udp` are the sessions). Pass:

- at most 64 sessions at a time, at most 4 of one source address; a read request
  beyond that is answered with a TFTP ERROR ("Too many sessions") from the server
  socket and makes no session (`tftp.py`, `MAX_SESSIONS`, `MAX_SESSIONS_PER_SOURCE`)
- fds at most the idle count + 2 x 64 + 16 (a session has its socket and the file it
  sends), RSS at most 64 MiB above the idle RSS
- no restart, no OOM kill, no Traceback; the clients got DATA and "Too many sessions"
- the ERROR replies of the server socket (a refused or a write request) and of the
  sessions (a missing file, a path outside the root, a mode other than octet) are rate
  limited in the same buckets: at most 10 a second per source address
  (burst 20) and 200 a second in all (burst 200); above that a request gets no reply,
  a limited source is logged once a minute (`tftp.py`, `ERRORS_*`, `TftpErrorLimiter`)
- 15 s after the load no session is left (idle timeout 3 s, sustain 120 s), and a
  TFTP read request and the FTP banner are answered

`DIR/summary.json` has every sample and check, `DIR/out/<client>.json` the replies
each client counted, `DIR/container.log` the log of dionaea.

# Memory per scenario

    tests/load/leak.py --image IMAGE                          # ftp_stor, smb1_upload, http_multipart, mysql_session
    tests/load/leak.py --image IMAGE --scenarios ftp_stor --warm 500 --step 1000 --steps 3 --trace

Does a connection leave anything behind? For every scenario a fresh dionaea as in
the replay, with `leak_probe.py` loaded (a thread that runs commands leak.py drops
into `log/probe-cmd/`). The scenario of `replay_client.py` (`leak_client.py`) runs
`--warm` times, one connection at a time, then `--steps` times `--step` times; after
each part the probe collects the garbage and counts the objects the GC tracks (per
type), the heap glibc has in use and free (`mallinfo2`), what sqlite has allocated
(`sqlite3_memory_used`) and, with `--trace`, the lines whose Python allocations grew
(tracemalloc). Pass:

- the objects grow by at most 0.01 per scenario
- the heap in use outside sqlite grows by at most 0.1 KiB per scenario in the last
  step: the page cache of `dionaea.sqlite` (2 MiB by default) fills over the first
  thousands of uploads, which is no leak
- 2,000 calls of `g_dionaea.config()` leave no object behind

The RSS and
the free memory of the arenas are only reported: the RSS moves in steps of 2 to 4 MiB
while the heap in use stays flat (free memory malloc keeps, not live data), and after
the working set is built glibc keeps about 100 MiB free in its arenas.

## Slow share: the streamcap count

    tests/load/slowfs/repro.py --image IMAGE [--stop-early S] [--data-bind DIR] [--no-shim]

A Docker Desktop bind mount serves the file requests of a container one at a
time, and a count of 188,000 bistreams takes minutes; the file requests of the
event loop come behind it. `slowfs/slowfs.so` (LD_PRELOAD) models such a share on any
Linux; `slowfs/README.md` says how it is built and what it reproduces.
