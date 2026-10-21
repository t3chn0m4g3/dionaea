# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""mqtt.py: the packets of a connection are framed by their fixed header, not by the reads.

handle_io_in took every read as one packet. A read is no packet boundary: the TCP
read of dionaea asks the kernel how much is queued (SIOCINQ) and reads one byte more,
so when the next segment arrives in between, its first byte comes with the read before
(PUBLISH + 0xE0, then 0x00 alone). The lone 0x00 matched no packet type, ``x`` stayed
None and ``x.show()`` raised AttributeError (a Traceback in the replay, 6 in 6,150
sessions). Packets that came in one read were lost behind the first.

The test feeds the stream as the binding does: what handle_io_in did not take stays
in the buffer and comes again in front of the next read.
"""

import contextlib
import importlib.util
import logging
import os
import struct
import sys
import types
from pathlib import Path

import pytest


class FakeIncident:
    reported = []

    def __init__(self, name):
        self.name = name

    def report(self):
        FakeIncident.reported.append((self.name, {k: v for k, v in vars(self).items() if k not in ("name", "con")}))


class FakeTimeouts:
    idle = 0


class FakeNode:
    def __init__(self, host="", port=0):
        self.host = host
        self.port = port


class FakeConnection:
    def __init__(self, proto="tcp"):
        self.sent = []
        self.closed = False
        self.timeouts = FakeTimeouts()
        self.remote = FakeNode("198.51.100.9", 50123)

    def send(self, data):
        self.sent.append(bytes(data))

    def close(self):
        self.closed = True

    def processors(self):
        pass


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins():
    names = [name for name in sys.modules if name == "dionaea" or name.startswith("dionaea.")]
    saved = {name: sys.modules.pop(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(_src_root())]
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    core.incident = FakeIncident
    core.__all__ = ["connection", "incident"]
    sys.modules.update({"dionaea": package, "dionaea.core": core})
    # the packages without their __init__ (the services of smb and mqtt need dionaea itself)
    for sub in ("smb", "mqtt"):
        module = types.ModuleType("dionaea." + sub)
        module.__path__ = [str(_src_root() / sub)]
        sys.modules["dionaea." + sub] = module
    try:
        yield
    finally:
        for name in [n for n in sys.modules if n == "dionaea" or n.startswith("dionaea.")]:
            sys.modules.pop(name, None)
        sys.modules.update(saved)


with _stand_ins():
    spec = importlib.util.spec_from_file_location("dionaea.mqtt.mqtt", _src_root() / "mqtt" / "mqtt.py")
    mqtt = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mqtt)


def connect_packet(clientid=b"replay-1", user=b"admin", password=b"secret"):
    payload = b"".join(struct.pack("!H", len(item)) + item for item in (clientid, user, password))
    body = b"\x00\x04MQTT\x04" + bytes([0xC2]) + struct.pack("!H", 60) + payload
    return b"\x10" + bytes([len(body)]) + body


def publish_packet(topic=b"sensors/1", message=b"hello"):
    return b"\x30" + bytes([2 + len(topic) + len(message)]) + struct.pack("!H", len(topic)) + topic + message


def subscribe_packet(topic=b"sensors/2", packet_id=1):
    return (b"\x82" + bytes([2 + 2 + len(topic) + 1]) + struct.pack("!H", packet_id)
            + struct.pack("!H", len(topic)) + topic + b"\x00")


DISCONNECT = b"\xe0\x00"
PINGREQ = b"\xc0\x00"


def feed(con, reads):
    """The binding: bytes handle_io_in leaves stay in front of the next read."""
    pending = b""
    for data in reads:
        pending += data
        taken = con.handle_io_in(pending)
        assert 0 <= taken <= len(pending)
        pending = pending[taken:]
    return pending


@pytest.fixture(autouse=True)
def clear():
    FakeIncident.reported.clear()


def names():
    return [name.rsplit(".", 1)[-1] for name, _ in FakeIncident.reported]


def test_the_first_byte_of_the_next_packet_in_the_read_before():
    # PUBLISH + 0xE0 in one read, the 0x00 of the DISCONNECT in the next
    con = mqtt.mqttd()
    rest = feed(con, [connect_packet(), publish_packet() + DISCONNECT[:1], DISCONNECT[1:]])
    assert rest == b""
    assert names() == ["connect", "publish"]
    assert FakeIncident.reported[1][1]["publishtopic"] == b"sensors/1"
    assert FakeIncident.reported[1][1]["publishmessage"] == b"hello"


def test_a_packet_split_in_the_middle_is_taken_when_it_is_whole():
    con = mqtt.mqttd()
    packet = connect_packet()
    assert feed(con, [packet[:5], packet[5:17]]) == packet[:17]
    assert names() == []
    rest = feed(con, [packet[:5], packet[5:17], packet[17:]])
    assert rest == b""
    assert names() == ["connect"]
    # the same fields as the packet in one read
    whole = mqtt.MQTT_Connect(packet)
    assert FakeIncident.reported[0][1]["clientid"] == whole.ClientID
    assert len(con.sent) == 1 and con.sent[0][:1] == b"\x20"   # one CONNACK


def test_packets_in_one_read_are_all_taken():
    con = mqtt.mqttd()
    rest = feed(con, [connect_packet() + subscribe_packet(packet_id=7) + publish_packet(b"t/x", b"m") + PINGREQ
                      + DISCONNECT])
    assert rest == b""
    assert names() == ["connect", "subscribe", "publish"]
    assert FakeIncident.reported[1][1]["subscribemessageid"] == 7
    kinds = [packet[:1] for packet in con.sent]
    assert kinds == [b"\x20", b"\x90", b"\xd0"]   # CONNACK, SUBACK, PINGRESP


@pytest.mark.parametrize("header", [b"\x00\x00", b"\x20\x02\x00\x00", b"\x40\x02\x00\x01", b"\x50\x02\x00\x01",
                                    b"\x60\x02\x00\x01", b"\x70\x02\x00\x01",
                                    b"\xf0\x00"])
def test_a_packet_of_another_type_is_no_error(header):
    con = mqtt.mqttd()
    rest = feed(con, [connect_packet(), header, PINGREQ])
    assert rest == b""
    assert names() == ["connect"]
    assert con.sent[-1][:1] == b"\xd0"   # the connection goes on: PINGRESP


def test_a_partial_header_waits():
    con = mqtt.mqttd()
    assert con.handle_io_in(b"\x10") == 0
    assert names() == []


def test_a_remaining_length_of_more_than_four_bytes_closes():
    con = mqtt.mqttd()
    data = b"\x30\xff\xff\xff\xff\x01" + b"x" * 10
    assert con.handle_io_in(data) == len(data)
    assert con.closed
    assert names() == []


def test_a_packet_beyond_the_bound_is_not_buffered():
    con = mqtt.mqttd()
    length = mqtt.MAX_PACKET_SIZE + 1
    encoded = bytearray()
    while True:
        byte, length = length % 128, length // 128
        encoded.append(byte | (0x80 if length else 0))
        if not length:
            break
    data = b"\x30" + bytes(encoded) + b"x" * 100
    assert con.handle_io_in(data) == len(data)
    assert con.closed


def publish_of_length(total):
    """A PUBLISH packet of total bytes (fixed header included)."""
    for header_len in (2, 3, 4, 5):
        remaining = total - header_len
        encoded, n = bytearray(), remaining
        while True:
            byte, n = n % 128, n // 128
            encoded.append(byte | (0x80 if n else 0))
            if not n:
                break
        if 1 + len(encoded) == header_len:
            topic = b"t"
            body = struct.pack("!H", len(topic)) + topic
            return b"\x30" + bytes(encoded) + body + b"x" * (remaining - len(body))
    raise AssertionError(total)


def test_the_bound_is_64_kib():
    # a connection buffers up to a packet for its 120 s idle timeout
    assert mqtt.MAX_PACKET_SIZE == 64 * 1024


def test_a_packet_of_64_kib_is_taken():
    con = mqtt.mqttd()
    data = publish_of_length(64 * 1024)
    assert len(data) == 64 * 1024
    assert con.handle_io_in(data) == len(data)
    assert not con.closed
    assert names() == ["publish"]


def test_a_packet_above_64_kib_closes_before_it_is_buffered():
    con = mqtt.mqttd()
    data = publish_of_length(64 * 1024 + 1)
    # the header alone says it: closed at once, nothing waits for the rest
    assert con.handle_io_in(data[:8]) == 8
    assert con.closed
    assert names() == []


def oversized_lines(caplog):
    """The info lines of the packets above the limit (the warning is the summary of them)."""
    return [r.getMessage() for r in caplog.records
            if r.name == "mqtt" and r.levelno == logging.INFO and "above the limit" in r.getMessage()]


@pytest.fixture(autouse=True)
def oversized_clock(summaries):
    return summaries(mqtt.OVERSIZED)


def test_a_packet_above_64_kib_logs_its_topic_and_size_not_its_payload(caplog):
    caplog.set_level(logging.INFO, logger="mqtt")
    con = mqtt.mqttd()
    topic = b"factory/line-7/plc"
    payload = b"SECRET-PAYLOAD-" * 5000
    remaining = 2 + len(topic) + len(payload)
    assert remaining > mqtt.MAX_PACKET_SIZE
    encoded, n = bytearray(), remaining
    while True:
        byte, n = n % 128, n // 128
        encoded.append(byte | (0x80 if n else 0))
        if not n:
            break
    data = b"\x30" + bytes(encoded) + struct.pack("!H", len(topic)) + topic + payload
    # the first read carries the topic and the start of the payload
    assert con.handle_io_in(data[:4096]) == 4096
    assert con.closed
    lines = oversized_lines(caplog)
    assert len(lines) == 1, caplog.text
    assert "factory/line-7/plc" in lines[0]
    assert str(1 + len(encoded) + remaining) in lines[0]
    assert "198.51.100.9" in lines[0]
    assert "SECRET" not in caplog.text


def test_the_topic_of_a_subscribe_above_64_kib_is_logged(caplog):
    caplog.set_level(logging.INFO, logger="mqtt")
    con = mqtt.mqttd()
    remaining = 70000
    encoded, n = bytearray(), remaining
    while True:
        byte, n = n % 128, n // 128
        encoded.append(byte | (0x80 if n else 0))
        if not n:
            break
    data = b"\x82" + bytes(encoded) + struct.pack("!H", 7) + struct.pack("!H", 5) + b"a/b/c" + b"\x00"
    assert con.handle_io_in(data) == len(data)
    assert con.closed
    lines = oversized_lines(caplog)
    assert len(lines) == 1 and "a/b/c" in lines[0], caplog.text


def test_an_oversized_packet_without_its_topic_yet_is_logged_with_its_size(caplog):
    caplog.set_level(logging.INFO, logger="mqtt")
    con = mqtt.mqttd()
    data = publish_of_length(64 * 1024 + 1)
    # only the fixed header and one byte of the topic length
    assert con.handle_io_in(data[:5]) == 5
    assert con.closed
    lines = oversized_lines(caplog)
    assert len(lines) == 1 and str(64 * 1024 + 1) in lines[0], caplog.text


def test_a_topic_of_control_bytes_is_logged_escaped(caplog):
    caplog.set_level(logging.INFO, logger="mqtt")
    con = mqtt.mqttd()
    topic = b"x\n\x1b[31mtwo lines"
    remaining = 100000
    encoded, n = bytearray(), remaining
    while True:
        byte, n = n % 128, n // 128
        encoded.append(byte | (0x80 if n else 0))
        if not n:
            break
    data = b"\x30" + bytes(encoded) + struct.pack("!H", len(topic)) + topic
    con.handle_io_in(data)
    lines = oversized_lines(caplog)
    assert len(lines) == 1
    assert "\n" not in lines[0] and "\x1b" not in lines[0]


# --- MQTT 5: the properties in front of the topic filter of a SUBSCRIBE -----------------


def varint(n):
    encoded = bytearray()
    while True:
        byte, n = n % 128, n // 128
        encoded.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(encoded)


def connect5(clientid=b"v5-client"):
    # protocol level 5, clean start, keep alive 60, no properties (length 0)
    body = b"\x00\x04MQTT\x05\x02" + struct.pack("!H", 60) + b"\x00" + struct.pack("!H", len(clientid)) + clientid
    return b"\x10" + varint(len(body)) + body


def subscribe5(topic, packet_id=9, properties=b"\x0b\x07"):
    # properties: subscription identifier 7 by default
    body = struct.pack("!H", packet_id) + varint(len(properties)) + properties + struct.pack("!H", len(topic)) \
        + topic + b"\x01"
    return b"\x82" + varint(len(body)) + body


def subscriptions():
    return [(fields["subscribemessageid"], fields["subscribetopic"]) for name, fields in FakeIncident.reported
            if name.endswith(".subscribe")]


@pytest.mark.parametrize("properties", [b"", b"\x0b\x07", b"\x26\x00\x01k\x00\x01v" * 3],
                         ids=["none", "subscription-id", "user-properties"])
def test_the_topic_of_an_mqtt5_subscribe_is_logged(properties):
    con = mqtt.mqttd()
    assert feed(con, [connect5(), subscribe5(b"plc/+/status", 9, properties)]) == b""
    assert subscriptions() == [(9, b"plc/+/status")]


def test_an_mqtt311_subscribe_after_a_level_5_connection_elsewhere_is_unchanged():
    assert feed(mqtt.mqttd(), [connect5()]) == b""
    con = mqtt.mqttd()
    assert feed(con, [connect_packet(), subscribe_packet(b"sensors/2", 3)]) == b""
    assert subscriptions() == [(3, b"sensors/2")]


def test_a_long_subscribe_has_its_topic_and_id():
    # a remaining length of two bytes (the parser of the packet read one)
    topic = b"t/" + b"x" * 300
    con = mqtt.mqttd()
    subscribe = (b"\x82" + varint(2 + 2 + len(topic) + 1) + struct.pack("!H", 0x1234)
                 + struct.pack("!H", len(topic)) + topic + b"\x00")
    assert feed(con, [connect_packet(), subscribe]) == b""
    assert subscriptions() == [(0x1234, topic)]


def test_the_packets_above_the_limit_of_many_connections_are_one_warning_a_minute(caplog, oversized_clock):
    caplog.set_level(logging.INFO, logger="mqtt")
    for _ in range(5):
        con = mqtt.mqttd()
        assert con.handle_io_in(publish_of_length(64 * 1024 + 1)[:5]) == 5
        assert con.closed
        oversized_clock.advance(1)
    assert len(oversized_lines(caplog)) == 5
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings == ["MQTT packets above the limit, connections closed: 1 connection(s) in the last minute, "
                        "the last: %d bytes (type 3) from 198.51.100.9:%s" % (64 * 1024 + 1, con.remote.port)]
    oversized_clock.advance(60)
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings[1:] == ["MQTT packets above the limit, connections closed: 4 connection(s) in the last minute, "
                            "the last: %d bytes (type 3) from 198.51.100.9:%s" % (64 * 1024 + 1, con.remote.port)]


def test_packet_topic_skips_the_properties_of_level_5():
    data = subscribe5(b"a/b", 1, b"\x0b\x07")
    assert mqtt.packet_topic(data, 5) == b"a/b"
    # the properties are not complete yet
    assert mqtt.packet_topic(data[:5], 5) is None


def test_an_oversized_mqtt5_subscribe_logs_its_topic(caplog):
    caplog.set_level(logging.INFO, logger="mqtt")
    con = mqtt.mqttd()
    feed(con, [connect5()])
    body = struct.pack("!H", 7) + b"\x02\x0b\x07" + struct.pack("!H", 5) + b"a/b/c" + b"\x01" * 70000
    con.handle_io_in(b"\x82" + varint(len(body)) + body)
    assert con.closed
    lines = oversized_lines(caplog)
    assert len(lines) == 1 and "'a/b/c'" in lines[0], caplog.text


# --- PUBLISH: remaining length of more than one byte, MQTT 5 properties ------------------


def publish(topic, message, qos=0, packet_id=None, properties=None):
    """A PUBLISH packet; properties (bytes) for MQTT 5."""
    body = struct.pack("!H", len(topic)) + topic
    if qos:
        body += struct.pack("!H", packet_id)
    if properties is not None:
        body += varint(len(properties)) + properties
    body += message
    return bytes([0x30 | (qos << 1)]) + varint(len(body)) + body


def publications():
    return [(fields["publishtopic"], fields["publishmessage"]) for name, fields in FakeIncident.reported
            if name.endswith(".publish")]


# payload format indicator 1, message expiry 60, a user property
PROPERTIES = b"\x01\x01\x02\x00\x00\x00\x3c\x26\x00\x01k\x00\x01v"


@pytest.mark.parametrize("size", [5, 200, 20000], ids=["small", "over-127", "over-16k"])
@pytest.mark.parametrize("qos", [0, 1, 2])
@pytest.mark.parametrize("level", [4, 5])
def test_the_topic_and_message_of_a_publish(level, qos, size):
    con = mqtt.mqttd()
    topic, message = b"plant/line-%d/temp" % size, bytes(range(256)) * (size // 256) + b"m" * (size % 256)
    packet = publish(topic, message, qos, 0x0a0b if qos else None, PROPERTIES if level == 5 else None)
    feed(con, [connect5() if level == 5 else connect_packet(), packet, PINGREQ])
    assert publications() == [(topic, message)]
    if qos == 1:
        assert b"\x40\x02\x0a\x0b" in con.sent        # PUBACK with the packet identifier
    elif qos == 2:
        assert b"\x50\x02\x0a\x0b" in con.sent        # PUBREC
    assert con.sent[-1][:1] == b"\xd0"


def test_a_level_5_publish_without_properties():
    con = mqtt.mqttd()
    feed(con, [connect5(), publish(b"t", b"msg", properties=b"")])
    assert publications() == [(b"t", b"msg")]


@pytest.mark.parametrize("flags", [0x01, 0x08, 0x09], ids=["retain", "dup", "dup-retain"])
def test_a_qos_0_publish_with_retain_or_dup_is_logged(flags):
    con = mqtt.mqttd()
    packet = bytearray(publish(b"t/r", b"retained"))
    packet[0] |= flags
    feed(con, [connect_packet(), bytes(packet), PINGREQ])
    assert publications() == [(b"t/r", b"retained")]
    assert con.sent[-1][:1] == b"\xd0"


# --- the replies: CONNACK and SUBACK carry the property length at protocol level 5 -------


def test_the_connack_of_an_mqtt5_connect_has_the_property_length():
    # MQTT 5.0 3.2.2.3: acknowledge flags, reason code, property length (a varint 0)
    con = mqtt.mqttd()
    feed(con, [connect5()])
    assert con.sent == [b"\x20\x03\x00\x00\x00"]


def test_the_connack_of_an_mqtt311_connect_is_unchanged():
    con = mqtt.mqttd()
    feed(con, [connect_packet()])
    assert con.sent == [b"\x20\x02\x00\x00"]


def test_the_suback_of_an_mqtt5_subscribe_has_the_property_length():
    # MQTT 5.0 3.9.2.1: packet identifier, property length (0), a reason code per topic filter (QoS 1 granted)
    con = mqtt.mqttd()
    feed(con, [connect5(), subscribe5(b"plc/+/status", 0x0102)])
    assert con.sent[1] == b"\x90\x04\x01\x02\x00\x01"


@pytest.mark.parametrize("properties", [b"", b"\x0b\x07"], ids=["none", "subscription-id"])
@pytest.mark.parametrize("qos", [0, 1, 2])
def test_the_suback_of_an_mqtt5_subscribe_grants_the_qos_of_its_options(properties, qos):
    # the reason code is the QoS granted: the requested one of the subscription options, not a byte of the
    # topic (the parser of 3.1.1 reads the properties as the topic length)
    con = mqtt.mqttd()
    packet = bytearray(subscribe5(b"plc/+/status", 0x0102, properties))
    packet[-1] = qos | 0x04     # no local
    feed(con, [connect5(), bytes(packet)])
    assert con.sent[1] == b"\x90\x04\x01\x02\x00" + bytes([qos])


# --- the SUBACK has one return code per topic filter, its remaining length counts them ------


def subscribe_many(filters, packet_id=0x0102, level=4, properties=b""):
    """A SUBSCRIBE of [(topic, options byte)]; MQTT 5 with the properties in front of the filters."""
    body = struct.pack("!H", packet_id)
    if level == 5:
        body += varint(len(properties)) + properties
    for topic, options in filters:
        body += struct.pack("!H", len(topic)) + topic + bytes([options])
    return b"\x82" + varint(len(body)) + body


def suback(con):
    packets = [p for p in con.sent if p[:1] == b"\x90"]
    assert len(packets) == 1, con.sent
    packet = packets[0]
    # the remaining length is what follows the fixed header
    length = mqtt.packet_length(packet)
    assert length == len(packet), (length, packet)
    return packet


def test_the_suback_of_an_mqtt311_subscribe_counts_its_return_code():
    # MQTT 3.1.1 3.9: packet identifier, a return code per topic filter (it said 2 and sent 3 bytes)
    con = mqtt.mqttd()
    feed(con, [connect_packet(), subscribe_packet(b"sensors/2", 0x0102)])
    assert suback(con) == b"\x90\x03\x01\x02\x00"


@pytest.mark.parametrize("level", [4, 5])
def test_the_suback_has_a_return_code_per_topic_filter(level):
    con = mqtt.mqttd()
    filters = [(b"a/1", 0), (b"b/+", 1), (b"c/#", 2)]
    feed(con, [connect5() if level == 5 else connect_packet(), subscribe_many(filters, 0x0a0b, level)])
    head = b"\x90\x06\x0a\x0b\x00" if level == 5 else b"\x90\x05\x0a\x0b"
    assert suback(con) == head + b"\x00\x01\x02"


def test_an_mqtt311_filter_with_a_qos_of_3_or_reserved_bits_fails():
    # 3.1.1 3.8.3.1: QoS 3 and the reserved bits are malformed: 0x80 (failure) for that filter
    con = mqtt.mqttd()
    feed(con, [connect_packet(), subscribe_many([(b"a", 3), (b"b", 0x05), (b"c", 1)])])
    assert suback(con) == b"\x90\x05\x01\x02\x80\x80\x01"


def test_an_mqtt5_filter_keeps_its_options_and_grants_its_qos():
    # MQTT 5 3.8.3.1: no local (0x04), retain as published (0x08), retain handling (0x30) beside the QoS
    con = mqtt.mqttd()
    filters = [(b"a", 0x2d), (b"b", 0x06), (b"c", 0x03)]
    feed(con, [connect5(), subscribe_many(filters, level=5, properties=b"\x0b\x07")])
    assert suback(con) == b"\x90\x06\x01\x02\x00\x01\x02\x80"


def test_a_suback_of_many_filters_has_a_long_remaining_length():
    con = mqtt.mqttd()
    filters = [(b"t/%03d" % i, i % 3) for i in range(200)]
    feed(con, [connect_packet(), subscribe_many(filters)])
    packet = suback(con)
    assert packet[1:3] == varint(2 + 200)
    assert packet[5:] == bytes(i % 3 for i in range(200))


# a packet whose body ends before the fields of its type: CONNECT (its remaining length in two bytes,
# 0x80 0x00), PUBLISH (QoS 0, 1, 2), PUBREL, SUBSCRIBE (with the flags of 3.1.1 and without)
@pytest.mark.parametrize("packet", [b"\x10\x80\x00", b"\x30\x01\x00", b"\x32\x01\x00", b"\x34\x01\x00",
                                    b"\x62\x01\x00", b"\x82\x01\x00", b"\x80\x01\x00"],
                         ids=["connect", "publish", "publish-qos1", "publish-qos2", "pubrel", "subscribe",
                              "subscribe-no-flags"])
def test_a_packet_the_parser_can_not_read_closes_with_one_info_line(packet, caplog):
    # MQTT 3.1.1 4.8 and 5.0 4.13: a malformed packet closes the network connection; nothing escapes
    # handle_io_in, the line names the packet type and the client, none of the bytes
    con = mqtt.mqttd()
    with caplog.at_level(logging.INFO, logger="mqtt"):
        rest = feed(con, [packet + PINGREQ])
    assert rest == b""
    assert con.closed
    assert con.sent == []
    lines = [r for r in caplog.records if r.name == "mqtt" and r.levelno >= logging.INFO]
    assert len(lines) == 1, [r.getMessage() for r in lines]
    assert lines[0].levelno == logging.INFO
    assert "malformed MQTT packet (type %d)" % (packet[0] >> 4) in lines[0].getMessage()
    assert "198.51.100.9:50123" in lines[0].getMessage()


def test_a_packet_the_parser_can_not_read_ends_the_packets_after_it():
    con = mqtt.mqttd()
    rest = feed(con, [connect_packet() + b"\x30\x01\x00" + publish_packet()])
    assert rest == b""
    assert con.closed
    assert names() == ["connect"]
