# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Load client, runs in the client container next to dionaea (see README.md).

    python client.py normal     3 cycles x 4 SMB1 connections x 3000 NTLM logins
                                with 8192 character fields, uploads beside them
    python client.py overload   many connections send fast bursts while the
                                emu workers are busy

SMB1 uploads of x86 code (6 MiB, more than the emu keeps and scans) run beside
both: the emu gives up or stops its scan, the upload is stored.

Paths in the container: /logs (dionaea's var/log: dionaea.json, dionaea.sqlite,
probe.jsonl), /data (var/dionaea: binaries/), /out (result.json). DIONAEA_HOST
names the server. Every check that fails raises; result.json has the numbers.
"""

import concurrent.futures
import ftplib
import hashlib
import http.client
import io
import json
import os
import random
import socket
import sqlite3
import statistics
import struct
import sys
import threading
import time
from pathlib import Path

HOST = os.environ.get("DIONAEA_HOST", "dionaea-load-server")
OUT = Path("/out")
LOG = Path("/logs")
DATA = Path("/data")

# Limits of the stream processing (include/bistream.h, include/threads.h)
STREAM_GLOBAL_BYTES = 32 * 1024 * 1024
STREAM_GLOBAL_CHUNKS = 32768
JOBS_MAX_WAITING = 32

# Pass criteria of the normal run (the tolerances of the earlier load test)
CYCLES = 3
CONNECTIONS = 4
LOGINS = 3000                         # per connection and cycle: 36,000 in all
CHECKPOINTS = ((0, 1000), (1000, 2000), (2000, 3000))
JSON_CREDENTIALS = 1000               # log_json keeps the first 1000 per connection
FIELD_CHARS = 8192
RSS_CYCLE_GROWTH_KIB = 16 * 1024      # after the credential limit: 16 MiB or 10 %
RSS_CYCLE_GROWTH_SHARE = 0.10
RSS_IDLE_GROWTH_KIB = 32 * 1024       # idle after a cycle, against the first cycle
BANNER_MAX_SECONDS = 5.0              # FTP banner during the load: the eventloop runs
UPLOAD_INTERVAL = 3.0
SMB_UPLOAD_BYTES = 6 * 1024 * 1024    # > 1 MiB of an emu instance, > the 4 MiB the emu scans
SMB_WARMUP = 10                       # SMB uploads before the cycles: the allocator settles (about 80 MiB)

# Overload run
SLOW_CONNECTIONS = 4                          # one per worker (THREADS_MAX_WORKERS)
SLOW_WINDOW = 64 * 1024              # a slow first window (a GetPC candidate every 128 bytes)
SLOW_BYTES = 960 * 1024            # in all: below the 1 MiB of an instance
OVERLOAD_CONNECTIONS = 48             # > 32 waiting jobs
BURST_FIRST = 960 * 1024              # phase A: 32 waiting x 960 KiB + the slow connections > 32 MiB
BURST_BYTES = 6 * 1024 * 1024         # in all per connection: beyond every limit of the emu
OVERLOAD_SECONDS = 90
OVERLOAD_ROUNDS = 3
OVERLOAD_RSS_CEILING_KIB = 512 * 1024  # peak of a round (container limit 768 MiB)
OVERLOAD_RSS_ROUND_KIB = 32 * 1024    # peak of the last round against the rounds before

report = {"checks": []}
start = time.monotonic()


def check(name, ok, **details):
    report["checks"].append({"name": name, "ok": bool(ok), **details})
    print(json.dumps({"check": name, "ok": bool(ok), **details}), flush=True)
    assert ok, (name, details)


# ---------------------------------------------------------------- probe data

def probe_rows(after=None):
    rows = []
    path = LOG / "probe.jsonl"
    if not path.exists():
        return rows
    with path.open() as file:
        for line in file:
            try:
                row = json.loads(line)
            except ValueError:
                continue  # a line being written
            if after is None or row["timestamp"] >= after:
                rows.append(row)
    return rows


def wait_row(predicate, after, timeout=40, what="probe row"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for row in reversed(probe_rows(after)):
            if predicate(row):
                return row
        time.sleep(0.25)
    raise AssertionError("no %s within %d s" % (what, timeout))


def stats_bounds(name, rows):
    """The stored stream data and the waiting jobs stay within the limits."""
    rows = [row for row in rows if row.get("stats") is not None]
    check("%s: probe has processor_stats" % name, rows, rows=len(rows))
    peak = {
        "stream_bytes": max(row["stats"]["stream_bytes"] for row in rows),
        "stream_chunks": max(row["stats"]["stream_chunks"] for row in rows),
        "stream_peak_bytes": rows[-1]["stats"]["stream_peak_bytes"],
        "stream_peak_chunks": rows[-1]["stats"]["stream_peak_chunks"],
        "jobs_waiting": max(row["stats"]["jobs_waiting"] for row in rows),
        "jobs_peak_waiting": rows[-1]["stats"]["jobs_peak_waiting"],
        "jobs_refused": rows[-1]["stats"]["jobs_refused"],
        "stream_refused_instance": rows[-1]["stats"].get("stream_refused_instance"),
        "stream_refused_global": rows[-1]["stats"].get("stream_refused_global"),
        "overloads": rows[-1]["stats"]["overloads"],
        "gave_up": rows[-1]["stats"].get("gave_up"),
    }
    check("%s: stream data within 32 MiB / 32768 chunks" % name,
          peak["stream_peak_bytes"] <= STREAM_GLOBAL_BYTES and peak["stream_peak_chunks"] <= STREAM_GLOBAL_CHUNKS,
          **peak)
    check("%s: at most 32 waiting jobs" % name, peak["jobs_peak_waiting"] <= JOBS_MAX_WAITING,
          jobs_peak_waiting=peak["jobs_peak_waiting"])
    return peak


def released(name, after):
    """No stream data and no job is left once the connections are gone."""
    row = wait_row(lambda row: row.get("stats") is not None and row["stats"]["stream_bytes"] == 0
                   and row["stats"]["stream_chunks"] == 0 and row["stats"]["jobs_waiting"] == 0,
                   after, what="released reservations")
    check("%s: reservations released" % name, True, stats=row["stats"])
    return row


# ---------------------------------------------------------------- services

def banner(timeout=20):
    begin = time.monotonic()
    with socket.create_connection((HOST, 21), timeout=timeout) as sock:
        sock.settimeout(timeout)
        data = sock.recv(64)
    assert data.startswith(b"220"), data
    return time.monotonic() - begin


class BannerProbe(threading.Thread):
    """FTP banner every 0.5 s: dionaea's eventloop answers while the load runs."""

    def __init__(self):
        super().__init__(daemon=True)
        self.stop = threading.Event()
        self.latencies = []
        self.errors = []

    def run(self):
        while not self.stop.is_set():
            try:
                self.latencies.append(banner())
            except Exception as error:
                self.errors.append(repr(error))
            self.stop.wait(0.5)

    def summary(self):
        values = sorted(self.latencies) or [0.0]
        return {"samples": len(self.latencies), "errors": self.errors[:5], "error_count": len(self.errors),
                "median_s": round(statistics.median(values), 4),
                "p95_s": round(values[int(0.95 * (len(values) - 1))], 4), "max_s": round(values[-1], 4)}


def upload(tag, index):
    """FTP STOR is captured (binaries/<md5>, mode 0440), an HTTP POST is answered."""
    content = ("load-upload-%s-%d\n" % (tag, index)).encode() * 80
    md5 = hashlib.md5(content).hexdigest()
    with ftplib.FTP() as ftp:
        ftp.connect(HOST, 21, timeout=20)
        ftp.login("load", "secret")
        ftp.storbinary("STOR load-%s-%d.bin" % (tag, index), io.BytesIO(content))
        ftp.quit()
    boundary = "LOADBOUNDARY"
    body = (("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"load.bin\"\r\n"
             "Content-Type: application/octet-stream\r\n\r\n" % boundary).encode()
            + content + ("\r\n--%s--\r\n" % boundary).encode())
    con = http.client.HTTPConnection(HOST, 81, timeout=20)
    con.request("POST", "/upload.php", body, {"Content-Type": "multipart/form-data; boundary=" + boundary})
    response = con.getresponse()
    assert response.status < 500, response.status
    response.read()
    con.close()
    path = DATA / "binaries" / md5
    deadline = time.monotonic() + 15
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert path.read_bytes() == content, md5
    assert path.stat().st_mode & 0o777 == 0o440, oct(path.stat().st_mode)
    return md5


def x86_like(size, seed=5):
    """Data that costs the emu as much as x86 code (tests/functional/test_upload.py).

    Random bytes with a near call every 2400 bytes, each a GetPC candidate
    libemu runs: about 0.5 MB/s per core (libcrypto.so.3 of x86-64 Linux: 0.9).
    Seed 5 has no shellcode hit in the windows of the emu.
    """
    rnd = random.Random(seed)
    data = bytearray(rnd.randbytes(size))
    for offset in range(1200, size - 5, 2400):
        data[offset] = 0xE8
        data[offset + 1:offset + 5] = struct.pack("<i", rnd.randint(16, 512))
    return bytes(data)


X86 = x86_like(SMB_UPLOAD_BYTES)


def smb_upload(tag, index, ports=None):
    """An SMB1 upload of x86 code at full speed is stored (binaries/<md5>, 0440).

    smbd is behind filter_emu; the emu can not keep up with it and gives up or
    stops after its scan limit, the connection goes on to SMB_COM_CLOSE. The
    file differs from the others only after the part the emu scans.
    """
    from impacket.smb import SMB_DIALECT
    from impacket.smbconnection import SMBConnection

    content = X86 + ("load-smb-%s-%d\n" % (tag, index)).encode()
    md5 = hashlib.md5(content).hexdigest()
    conn = SMBConnection(HOST, HOST, sess_port=445, preferredDialect=SMB_DIALECT, timeout=60)
    try:
        if ports is not None:
            ports.append(conn.getSMBServer().get_socket().getsockname()[1])
        conn.login("load", "secret")
        tid = conn.connectTree("C$")
        fid = conn.createFile(tid, "\\load-smb-%s-%d.bin" % (tag, index))
        for offset in range(0, len(content), 60000):
            conn.writeFile(tid, fid, content[offset:offset + 60000], offset)
        conn.closeFile(tid, fid)
    finally:
        conn.close()
    path = DATA / "binaries" / md5
    deadline = time.monotonic() + 30
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert path.read_bytes() == content, md5
    assert path.stat().st_mode & 0o777 == 0o440, oct(path.stat().st_mode)
    return md5


class Uploads(threading.Thread):
    """FTP and HTTP uploads every UPLOAD_INTERVAL, with smb=True also an SMB upload of x86 code."""

    def __init__(self, tag, smb=False):
        super().__init__(daemon=True)
        self.tag = tag
        self.smb = smb
        self.stop = threading.Event()
        self.done = []
        self.smb_done = []
        self.smb_ports = []
        self.errors = []

    def run(self):
        index = 0
        while not self.stop.is_set():
            try:
                self.done.append(upload(self.tag, index))
                if self.smb:
                    self.smb_done.append(smb_upload(self.tag, index, self.smb_ports))
            except Exception as error:
                self.errors.append(repr(error))
            index += 1
            self.stop.wait(UPLOAD_INTERVAL)


# ---------------------------------------------------------------- SMB1

def exact(sock, size):
    data = b""
    while len(data) < size:
        part = sock.recv(size - len(data))
        assert part, "SMB connection closed"
        data += part
    return data


class SMB:
    """SMB1 NEGOTIATE + SESSION_SETUP with NTLMSSP, as the earlier load test."""

    def __init__(self):
        self.sock = socket.create_connection((HOST, 445), timeout=60)
        self.port = self.sock.getsockname()[1]
        self.mid = 0
        dialect = b"\x02NT LM 0.12\0"
        self.request(0x72, b"\0" + struct.pack("<H", len(dialect)) + dialect, 0)

    def request(self, command, body, status):
        self.mid = (self.mid + 1) & 0xFFFF
        header = (b"\xffSMB" + bytes([command]) + b"\0" * 4 + b"\x18" + struct.pack("<H", 0x4801)
                  + b"\0" * 12 + struct.pack("<HHHH", 0, 1234, 0, self.mid))
        data = header + body
        self.sock.sendall(b"\0" + len(data).to_bytes(3, "big") + data)
        reply_header = exact(self.sock, 4)
        assert reply_header[0] == 0
        reply = exact(self.sock, int.from_bytes(reply_header[1:], "big"))
        assert reply[:4] == b"\xffSMB" and reply[4] == command
        assert struct.unpack_from("<I", reply, 5)[0] == status, (command, reply[:32].hex())

    def setup(self, token, status):
        body = (b"\x0c" + struct.pack("<BBHHHHIHIIH", 255, 0, 0, 65535, 50, 0, 0, len(token), 0,
                                      0x8000E3FD, len(token) + 2) + token + b"\0\0")
        self.request(0x73, body, status)

    def logins(self, cycle, worker, first, last):
        for index in range(first, last):
            name = ("load-%d-%d-%04d-" % (cycle, worker, index)).ljust(FIELD_CHARS, "U")
            values = (b"X" * 24, b"Y" * 24, ("D" * FIELD_CHARS).encode("utf-16-le"), name.encode("utf-16-le"),
                      ("W" * FIELD_CHARS).encode("utf-16-le"), b"")
            token = b"NTLMSSP\0" + struct.pack("<I", 3)
            offset = 64
            for value in values:
                token += struct.pack("<HHI", len(value), len(value), offset)
                offset += len(value)
            token += struct.pack("<I", 1) + b"".join(values)
            self.setup(b"NTLMSSP\0" + struct.pack("<II", 1, 1), 0xC0000016)
            self.setup(token, 0)
        self.request(0x2B, b"\1" + struct.pack("<HH", 1, 4) + b"abcd", 0)  # ECHO

    def close(self):
        self.sock.close()


# ---------------------------------------------------------------- normal

def json_events(cycle, ports):
    """The JSON entries of the cycle, read line by line (each about 24 MB)."""
    found = {}
    with (LOG / "dionaea.json").open() as file:
        for line in file:
            event = json.loads(line)
            user = event.get("credentials", {}).get("username", [""])
            if (event.get("connection", {}).get("protocol") == "smbd" and event.get("src_port") in ports
                    and user and user[0].startswith("load-%d-" % cycle)):
                creds = event["credentials"]
                assert len(user) == JSON_CREDENTIALS
                assert all(len(value) == FIELD_CHARS for key in ("username", "domain", "workstation")
                           for value in creds[key])
                assert creds["password"] == [""] * JSON_CREDENTIALS
                assert "-0999-" in user[-1][:30]
                found[event["src_port"]] = True
    return found


def sqlite_logins(cycle):
    """Logins of the cycle in dionaea.sqlite.

    Read without locks (immutable): a shared lock of this reader made the
    commits of log_sqlite fail with "database is locked" (it sets no busy
    timeout). A read that meets a write in progress is repeated.
    """
    for attempt in range(10):
        try:
            with sqlite3.connect("file:%s?mode=ro&immutable=1" % (LOG / "dionaea.sqlite"), uri=True) as db:
                return db.execute("SELECT count(*) FROM logins JOIN connections USING(connection) "
                                  "WHERE connection_protocol='smbd' AND login_username LIKE ?",
                                  ("load-%d-%%" % cycle,)).fetchone()[0]
        except sqlite3.DatabaseError:
            if attempt == 9:
                raise
            time.sleep(1)


def at_limit(row, ports):
    """Every connection of ports is open and kept JSON_CREDENTIALS credentials."""
    kept = [i for i in row["smb"] if i["port"] in ports]
    return sorted(i["port"] for i in kept) == sorted(ports) and all(i["count"] == JSON_CREDENTIALS for i in kept)


def normal():
    load_start = time.time()
    baseline = wait_row(lambda row: True, None, what="first probe row")
    report["baseline"] = baseline
    # the first uploads take memory once (buffers of smbd and the emu, glibc arenas);
    # the RSS tolerances of the cycles are about what the logins keep
    warmup_ports = []
    warmup = [smb_upload("warmup", index, warmup_ports) for index in range(SMB_WARMUP)]
    time.sleep(2)
    report["warmup"] = wait_row(lambda row: True, time.time() - 2, what="probe row after the warm-up")
    check("SMB uploads of x86 code before the load", len(set(warmup)) == SMB_WARMUP,
          uploads=len(warmup), rss_kib=report["warmup"]["rss_kib"])
    uploads = Uploads("normal", smb=True)
    uploads.smb_ports.extend(warmup_ports)
    probe = BannerProbe()
    uploads.start()
    probe.start()
    cycles = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONNECTIONS) as pool:
            for cycle in range(CYCLES):
                clients = [SMB() for _ in range(CONNECTIONS)]
                ports = [client.port for client in clients]
                checkpoints = []
                try:
                    for lower, upper in CHECKPOINTS:
                        futures = [pool.submit(client.logins, cycle, index, lower, upper)
                                   for index, client in enumerate(clients)]
                        for future in futures:
                            future.result(timeout=600)
                        time.sleep(2)
                        row = wait_row(lambda row, ports=ports: at_limit(row, ports),
                                       time.time() - 3, what="checkpoint of cycle %d" % cycle)
                        checkpoints.append({"logins_per_connection": upper, "rss_kib": row["rss_kib"],
                                            "stats": row["stats"],
                                            "text_chars": sum(i["text_chars"] for i in row["smb"]
                                                              if i["port"] in ports)})
                        print(json.dumps({"cycle": cycle, "logins": upper, "rss_kib": row["rss_kib"],
                                          "stats": row["stats"]}), flush=True)
                finally:
                    for client in clients:
                        client.close()
                rss = [point["rss_kib"] for point in checkpoints]
                allowed = max(RSS_CYCLE_GROWTH_KIB, int(rss[0] * RSS_CYCLE_GROWTH_SHARE))
                check("cycle %d: RSS after the credential limit" % cycle, max(rss[1:]) - rss[0] <= allowed,
                      rss_kib=rss, growth_kib=max(rss[1:]) - rss[0], allowed_kib=allowed)
                chars = [point["text_chars"] for point in checkpoints]
                check("cycle %d: retained credentials constant" % cycle, len(set(chars)) == 1, text_chars=chars)
                closed_at = time.time()
                idle = wait_row(lambda row, ports=ports: not any(i["port"] in ports for i in row["smb"]),
                                closed_at, what="closed records freed")
                check("cycle %d: closed connection records freed" % cycle, True)
                if idle.get("stats") is not None:
                    idle = released("cycle %d" % cycle, closed_at)
                events = json_events(cycle, ports)
                check("cycle %d: JSON has 1000 credentials per connection" % cycle, len(events) == CONNECTIONS,
                      connections=len(events))
                count = sqlite_logins(cycle)
                check("cycle %d: SQLite has every login" % cycle, count == CONNECTIONS * LOGINS, logins=count)
                cycles.append({"cycle": cycle, "ports": ports, "checkpoints": checkpoints,
                               "idle_rss_kib": idle["rss_kib"], "idle_stats": idle.get("stats")})
    finally:
        uploads.stop.set()
        probe.stop.set()
        uploads.join(timeout=60)
        probe.join(timeout=30)
    report["cycles"] = cycles
    idle = [cycle["idle_rss_kib"] for cycle in cycles]
    check("RSS across cycles", max(idle[1:]) - idle[0] <= RSS_IDLE_GROWTH_KIB, idle_rss_kib=idle,
          growth_kib=max(idle[1:]) - idle[0], allowed_kib=RSS_IDLE_GROWTH_KIB)
    check("uploads during the load", uploads.done and not uploads.errors, uploads=len(uploads.done),
          errors=uploads.errors[:5])
    check("SMB uploads of x86 code during the load", uploads.smb_done and len(uploads.smb_done) == len(uploads.done),
          smb_uploads=len(uploads.smb_done), uploads=len(uploads.done))
    report["smb_upload_ports"] = uploads.smb_ports
    latency = probe.summary()
    report["banner"] = latency
    check("FTP banner during the load", latency["samples"] > 0 and latency["error_count"] == 0
          and latency["max_s"] <= BANNER_MAX_SECONDS, limit_s=BANNER_MAX_SECONDS, **latency)
    peak = stats_bounds("normal", probe_rows(load_start))
    # only the SMB uploads reach a limit (the 1 MiB of their emu instance), and the emu gives up
    check("normal: no overload close, the emu gives up only for SMB uploads",
          peak["overloads"] == 0 and peak["jobs_refused"] == 0 and not peak["stream_refused_global"]
          and peak["gave_up"] is not None and peak["gave_up"] <= len(uploads.smb_done) + SMB_WARMUP,
          overloads=peak["overloads"], jobs_refused=peak["jobs_refused"], gave_up=peak["gave_up"],
          smb_uploads=len(uploads.smb_done) + SMB_WARMUP, stream_refused_instance=peak["stream_refused_instance"],
          stream_refused_global=peak["stream_refused_global"])
    report["peak"] = peak
    afterwards("normal")
    report["total_logins"] = CYCLES * CONNECTIONS * LOGINS


# ---------------------------------------------------------------- overload

def nbt_frames(body):
    """NetBIOS frames of a type smbd ignores (0x86), so the connection stays open."""
    out = b""
    for start in range(0, len(body), 60000):
        part = body[start:start + 60000]
        out += bytes([0x86]) + len(part).to_bytes(3, "big") + part
    return out


def slow_stream():
    """A window the emu takes seconds for, then filler it scans fast.

    call $+5 / pop esi / ret every 128 bytes: a GetPC candidate libemu runs
    (some milliseconds each) and drops (too short to be reported); ret (0xc3)
    has none.
    """
    piece = b"\xe8\x00\x00\x00\x00\x5e\xc3"
    slow = (piece + b"\xc3" * (128 - len(piece))) * (SLOW_WINDOW // 128)
    return nbt_frames(slow + b"\xc3" * (SLOW_BYTES - len(slow) - 4 * 17))


def burst(sock, barriers, data, results, index):
    """Phase A: BURST_FIRST bytes (below the limit of an instance), phase B: on to BURST_BYTES."""
    entry = {"index": index, "sent": 0, "closed": False, "how": None}
    results[index] = entry
    view = memoryview(data)

    def send(until, deadline):
        while not entry["closed"] and entry["sent"] < until and time.monotonic() < deadline:
            part = view[entry["sent"] % len(data):][:min(65536, until - entry["sent"])]
            try:
                sock.sendall(part)
            except OSError as error:
                entry.update(closed=True, how=type(error).__name__)
                break
            entry["sent"] += len(part)

    try:
        with sock:
            entry["port"] = sock.getsockname()[1]
            barriers[0].wait(timeout=60)
            deadline = time.monotonic() + OVERLOAD_SECONDS
            send(BURST_FIRST, deadline)
            barriers[1].wait(timeout=OVERLOAD_SECONDS)
            send(BURST_BYTES, deadline)
            if not entry["closed"]:
                # dionaea may have closed it without a send failing yet
                sock.settimeout(3)
                try:
                    entry["closed"] = sock.recv(1) == b""
                    entry["how"] = "eof" if entry["closed"] else "data"
                except socket.timeout:
                    entry["how"] = "open"
                except OSError as error:
                    entry.update(closed=True, how=type(error).__name__)
    except Exception as error:
        entry["error"] = repr(error)


def overload_round(number, baseline):
    """One round: slow connections, then the bursts. Returns its peak RSS."""
    name = "overload %d" % number
    round_start = time.time()
    counted_before = wait_row(lambda row: True, None)["stats"]

    slow_conns = []
    for _ in range(SLOW_CONNECTIONS):
        sock = socket.create_connection((HOST, 445), timeout=30)
        sock.sendall(slow_stream())
        slow_conns.append(sock)
    time.sleep(1)

    data = nbt_frames(b"\xc3" * (4 * 1024 * 1024))
    barriers = [threading.Barrier(OVERLOAD_CONNECTIONS), threading.Barrier(OVERLOAD_CONNECTIONS)]
    results = [None] * OVERLOAD_CONNECTIONS
    # one after the other, so the accept queue of the service (20) never overflows
    socks = []
    for _ in range(OVERLOAD_CONNECTIONS):
        socks.append(socket.create_connection((HOST, 445), timeout=30))
        time.sleep(0.02)
    threads = [threading.Thread(target=burst, args=(sock, barriers, data, results, index), daemon=True)
               for index, sock in enumerate(socks)]
    # an SMB upload of x86 code while the job queue is full and the limits are reached
    smb = {"ports": []}

    def smb_during():
        try:
            smb["md5"] = smb_upload("overload", number, smb["ports"])
        except Exception as error:
            smb["error"] = repr(error)

    uploader = threading.Thread(target=smb_during, daemon=True)
    for thread in threads:
        thread.start()
    time.sleep(0.2)
    uploader.start()
    for thread in threads:
        thread.join(timeout=OVERLOAD_SECONDS + 120)
    uploader.join(timeout=120)
    report.setdefault("connections", []).extend(results)
    errors = [entry for entry in results if entry is None or "error" in entry]
    check("%s: every connection was made" % name, not errors, errors=errors[:5])
    full = [entry for entry in results if entry["sent"] >= BURST_BYTES and not entry["closed"]]
    check("%s: every burst connection stays open and sends everything" % name, len(full) == OVERLOAD_CONNECTIONS,
          open=len(full), connections=OVERLOAD_CONNECTIONS,
          other=[entry for entry in results if entry not in full][:5])
    check("%s: SMB upload of x86 code stored" % name, "md5" in smb, error=smb.get("error"), md5=smb.get("md5"))
    report.setdefault("ports", []).extend(entry["port"] for entry in results)
    report.setdefault("smb_upload_ports", []).extend(smb["ports"])
    for entry in results:
        try:
            socks[entry["index"]].close()
        except OSError:
            pass

    # the slow connections were within the limits: open, their data scanned to the end
    report.setdefault("slow_ports", []).extend(sock.getsockname()[1] for sock in slow_conns)
    scanned = wait_row(lambda row: row.get("stats") is not None
                       and row["stats"]["stream_bytes"] <= SLOW_CONNECTIONS * 300
                       and row["stats"]["jobs_waiting"] == 0,
                       time.time(), timeout=180, what="slow connections scanned")
    still_open = []
    for sock in slow_conns:
        sock.settimeout(1)
        try:
            still_open.append(sock.recv(1) != b"")
        except socket.timeout:
            still_open.append(True)
        except OSError:
            still_open.append(False)
        sock.close()
    check("%s: the slow connections stay open and are scanned" % name, all(still_open),
          open=still_open, stats=scanned["stats"])

    idle = released(name, time.time())
    rows = probe_rows(round_start)
    peak = stats_bounds(name, rows)
    report.setdefault("peaks", []).append(peak)
    before = counted_before
    refused_instance = peak["stream_refused_instance"] - before["stream_refused_instance"]
    refused_global = peak["stream_refused_global"] - before["stream_refused_global"]
    check("%s: stream limits of the instances and of the process reached" % name,
          refused_instance > 0 and refused_global > 0, stream_refused_instance=refused_instance,
          stream_refused_global=refused_global, stream_peak_bytes=peak["stream_peak_bytes"])
    jobs_refused = peak["jobs_refused"] - before["jobs_refused"]
    check("%s: job queue full" % name, jobs_refused > 0 and peak["jobs_waiting"] == JOBS_MAX_WAITING,
          jobs_refused=jobs_refused, jobs_waiting=peak["jobs_waiting"])
    closes = idle["stats"]["overloads"] - before["overloads"]
    gave_up = idle["stats"]["gave_up"] - before["gave_up"]
    # every burst reaches a limit; the upload may (its first data in a full queue) or not
    check("%s: the emu gave up once per burst connection, nothing was closed" % name,
          closes == 0 and OVERLOAD_CONNECTIONS <= gave_up <= OVERLOAD_CONNECTIONS + 1,
          overloads=closes, gave_up=gave_up)
    rss_peak = max(row["rss_kib"] for row in rows)
    check("%s: RSS below the ceiling" % name, rss_peak <= OVERLOAD_RSS_CEILING_KIB,
          baseline_kib=baseline["rss_kib"], peak_kib=rss_peak, idle_kib=idle["rss_kib"],
          ceiling_kib=OVERLOAD_RSS_CEILING_KIB)
    return rss_peak


def overload():
    """Bursts while the workers are busy, until the limits and the job queue are reached.

    In each of OVERLOAD_ROUNDS rounds, first SLOW_CONNECTIONS connections each send a
    window the emu needs seconds for (plus filler, below the limit of an
    instance), so every worker is busy. Then OVERLOAD_CONNECTIONS connections
    send fast bursts: 32 jobs wait, the others are refused (queue full). In
    phase A each sends BURST_FIRST bytes, below its own 1 MiB: together with
    what the slow connections keep they cross the 32 MiB of the process. In phase B
    each goes on to BURST_BYTES, beyond its 1 MiB. The emu gives up once per
    burst connection, with one log line, and the connection stays open; an SMB
    upload of x86 code beside them is stored. The slow connections stay open, are
    scanned to the end and closed by the client. The last round must not need
    more memory than the rounds before (OVERLOAD_RSS_ROUND_KIB): what a round
    takes is given back.
    """
    # an image without processor_stats (before the stream limits) fails at the first check
    baseline = wait_row(lambda row: True, None, what="first probe row")
    report["baseline"] = baseline
    probe = BannerProbe()
    probe.start()
    peaks = [overload_round(number, baseline) for number in range(1, OVERLOAD_ROUNDS + 1)]
    probe.stop.set()
    probe.join(timeout=30)
    # the allocator settles within the first rounds; the last one must not need more
    growth = peaks[-1] - max(peaks[:-1])
    check("overload: RSS of the last round", growth <= OVERLOAD_RSS_ROUND_KIB,
          peak_kib=peaks, growth_kib=growth, allowed_kib=OVERLOAD_RSS_ROUND_KIB)
    report["banner"] = probe.summary()
    check("overload: FTP banner during the load", report["banner"]["error_count"] == 0
          and report["banner"]["max_s"] <= BANNER_MAX_SECONDS, limit_s=BANNER_MAX_SECONDS, **report["banner"])
    afterwards("overload")


def afterwards(name):
    """New connections and uploads work once the load is over."""
    check("%s: FTP answers afterwards" % name, banner() < BANNER_MAX_SECONDS)
    client = SMB()
    client.request(0x2B, b"\1" + struct.pack("<HH", 1, 4) + b"abcd", 0)
    client.close()
    check("%s: SMB answers afterwards" % name, True)
    md5 = upload(name + "-after", 0)
    check("%s: upload afterwards" % name, True, md5=md5)


def main():
    scenario = sys.argv[1] if len(sys.argv) > 1 else "normal"
    report["scenario"] = scenario
    try:
        {"normal": normal, "overload": overload}[scenario]()
        report["pass"] = True
    except BaseException as error:
        report.update({"pass": False, "error": repr(error)})
        raise
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - start, 2)
        (OUT / "result.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
