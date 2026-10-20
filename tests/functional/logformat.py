# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The reference session and the comparison of the log formats.

constraint of the project: the keys and the value types of dionaea.json, the
columns of the tables of dionaea.sqlite and the timestamp format of a new
release stay as they were in the release before (T-Pot reads them: Logstash,
ewsposter). New keys are allowed.

run_session() talks to services that work in dionaea 0.11.1 (the image of
T-Pot 24.04.1) and 0.12; the shape of every entry of dionaea.json it causes
is recorded per event type (``<protocol>/<connection type>``) in
fixtures/log_0.11.1.json (tools/record_fixture.sh), and compare() checks a
later release against that.
"""

import re
import socket
import struct
import time

FIXTURE_VERSION = 1


# --- the reference session --------------------------------------------------


def _recv_some(sock, size=4096, timeout=5.0):
    sock.settimeout(timeout)
    try:
        return sock.recv(size)
    except OSError:
        return b""


def _session_ftp(host, ports):
    with socket.create_connection((host, 21), timeout=10) as sock:
        ports.add(sock.getsockname()[1])
        _recv_some(sock)
        for command in (b"USER reference", b"PASS secret", b"SYST", b"PWD", b"TYPE I", b"FEAT", b"QUIT"):
            sock.sendall(command + b"\r\n")
            _recv_some(sock)


def _session_mysql(host, ports):
    with socket.create_connection((host, 3306), timeout=10) as sock:
        ports.add(sock.getsockname()[1])
        _recv_some(sock)  # greeting
        # CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION
        body = struct.pack("<IIB23x", 0x8201, 1 << 24, 33) + b"reference\x00" + b"\x00"
        sock.sendall(struct.pack("<I", len(body))[:3] + b"\x01" + body)
        _recv_some(sock)


def _session_mssql(host, ports):
    from impacket import tds

    class PlainMSSQL(tds.MSSQL):
        # the prelogin answer of dionaea offers encryption, which it cannot do
        def set_tls_context(self):
            pass

    ms = PlainMSSQL(host, 1433)
    try:
        ms.connect()
        ports.add(ms.socket.getsockname()[1])
        ms.login(None, "reference", "secret")
    except Exception:
        pass
    finally:
        try:
            ms.disconnect()
        except Exception:
            pass


def _session_smb(host, ports):
    from impacket.smb import SMB_DIALECT
    from impacket.smbconnection import SMBConnection
    try:
        conn = SMBConnection(host, host, sess_port=445, timeout=10, preferredDialect=SMB_DIALECT)
        ports.add(conn.getSMBServer().get_socket().getsockname()[1])
        try:
            conn.login("reference", "secret", "WORKGROUP")
        except Exception:
            pass
        conn.close()
    except Exception:
        pass


def _session_mqtt(host, ports):
    clientid, user, password = b"reference", b"reference", b"secret"
    payload = b"".join(struct.pack("!H", len(item)) + item for item in (clientid, user, password))
    body = b"\x00\x04MQTT\x04" + bytes([0xC2]) + struct.pack("!H", 60) + payload
    with socket.create_connection((host, 1883), timeout=10) as sock:
        ports.add(sock.getsockname()[1])
        sock.sendall(b"\x10" + bytes([len(body)]) + body)
        _recv_some(sock)
        sock.sendall(b"\xe0\x00")  # DISCONNECT


def _session_epmap(host, ports):
    from impacket.dcerpc.v5 import epm, transport
    rpc = transport.DCERPCTransportFactory("ncacn_ip_tcp:%s[135]" % host)
    dce = rpc.get_dce_rpc()
    try:
        dce.connect()
        ports.add(rpc.get_socket().getsockname()[1])
        dce.bind(epm.MSRPC_UUID_PORTMAP)
    except Exception:
        pass
    finally:
        try:
            dce.disconnect()
        except Exception:
            pass


def _session_http(host, ports):
    with socket.create_connection((host, 81), timeout=10) as sock:
        ports.add(sock.getsockname()[1])
        sock.sendall(b"GET /index.html HTTP/1.1\r\nHost: reference\r\n"
                     b"User-Agent: reference\r\nConnection: close\r\n\r\n")
        _recv_some(sock, timeout=3)


SESSIONS = (
    _session_ftp,
    _session_mysql,
    _session_mssql,
    _session_smb,
    _session_mqtt,
    _session_epmap,
    _session_http,
)


def run_session(host):
    """Run the reference session, return the set of source ports of its connections."""
    ports = set()
    for session in SESSIONS:
        try:
            session(host, ports)
        except OSError:
            # a service that does not answer: the log entry of the connection is still written
            pass
    return ports


# --- shape of a log entry -----------------------------------------------------


def json_type(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    return type(value).__name__


def event_type(event):
    connection = event.get("connection", {})
    return "%s/%s" % (connection.get("protocol"), connection.get("type"))


def collect_paths(value, path, found):
    """Add path -> {json types} of value and everything below it to found."""
    found.setdefault(path, set()).add(json_type(value))
    if isinstance(value, dict):
        for key, item in value.items():
            collect_paths(item, "%s.%s" % (path, key) if path else key, found)
    elif isinstance(value, list):
        for item in value:
            collect_paths(item, path + "[]", found)


def shape_of(events):
    """{event type: {path: sorted list of json types}} of the entries (all values of a path merged)."""
    shapes = {}
    for event in events:
        found = shapes.setdefault(event_type(event), {})
        for key, value in event.items():
            collect_paths(value, key, found)
    return {
        etype: {path: sorted(types) for path, types in sorted(paths.items())}
        for etype, paths in sorted(shapes.items())
    }


def timestamp_pattern(timestamp):
    return re.sub(r"\d", "d", timestamp)


def timestamp_patterns(events):
    return sorted({timestamp_pattern(event["timestamp"]) for event in events if "timestamp" in event})


def sqlite_columns(query):
    """{table: {column: declared type}} of dionaea.sqlite, query(sql) returns a list of dicts."""
    tables = {}
    for row in query("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"):
        name = row["name"]
        tables[name] = {
            col["name"]: (col["type"] or "").upper()
            for col in query("PRAGMA table_info('%s')" % name.replace("'", "''"))
        }
    return dict(sorted(tables.items()))


def build_fixture(events, tables, image, image_id):
    return {
        "fixture_version": FIXTURE_VERSION,
        "recorded_with": {"image": image, "image_id": image_id},
        "timestamp_patterns": timestamp_patterns(events),
        "events": shape_of(events),
        "sqlite": tables,
    }


# --- comparison -----------------------------------------------------------------


def compare(fixture, events, tables):
    """Problems of the shapes of events / tables compared with the fixture (empty list: fine).

    Missing event types, missing paths, other value types, other timestamp
    formats and missing or retyped columns are problems; new paths, new event
    types, new columns and new tables are not.
    """
    problems = []
    shapes = shape_of(events)
    for etype, paths in fixture["events"].items():
        if etype not in shapes:
            problems.append("event type %s is missing" % etype)
            continue
        for path, types in paths.items():
            new_types = shapes[etype].get(path)
            if new_types is None:
                problems.append("%s: key %s is missing" % (etype, path))
            elif new_types != types:
                problems.append("%s: key %s has the types %s, was %s" % (etype, path, new_types, types))

    allowed = set(fixture["timestamp_patterns"])
    # isoformat() leaves the fraction out when the microseconds are 0
    allowed |= {p.split(".")[0] for p in fixture["timestamp_patterns"]}
    for event in events:
        timestamp = event.get("timestamp")
        if timestamp is None:
            continue
        if timestamp_pattern(timestamp) not in allowed:
            problems.append("timestamp %r does not look like %s" % (timestamp, sorted(fixture["timestamp_patterns"])))
            break

    for table, columns in fixture["sqlite"].items():
        if table not in tables:
            problems.append("sqlite table %s is missing" % table)
            continue
        for column, ctype in columns.items():
            if column not in tables[table]:
                problems.append("sqlite %s: column %s is missing" % (table, column))
            elif tables[table][column] != ctype:
                problems.append("sqlite %s: column %s is %s, was %s" % (table, column, tables[table][column], ctype))
    return problems


def events_of_ports(events, ports):
    return [e for e in events if e.get("src_port") in ports]


def expected_types(fixture):
    return sorted(fixture["events"])


def wait_for_events(read_events, ports, wanted_types, timeout=40.0):
    """Wait until every event type of wanted_types has an entry of the session, return them all."""
    deadline = time.monotonic() + timeout
    while True:
        ours = events_of_ports(read_events(), ports)
        have = {event_type(e) for e in ours}
        if set(wanted_types) <= have or time.monotonic() >= deadline:
            return ours
        time.sleep(0.5)


def wait_for_ports(read_events, ports, timeout=40.0):
    """Wait until every source port of the session has an entry (or the timeout is over)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ports <= {e.get("src_port") for e in read_events()}:
            return
        time.sleep(0.5)
