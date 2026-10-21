#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""atheris target of the MQTT service (mqtt/mqtt.py): the stream of a client, cut into reads.

handle_io_in frames the packets by their fixed header (packet_length), handle_packet
dissects them (mqtt/include/packets.py) and reads the fields by the protocol level
(publish_fields, subscribe_fields, suback). Nothing may escape handle_io_in, it
returns what it took (0 to the length of its input), and what it leaves in the
buffer is at most one packet below MAX_PACKET_SIZE.
"""

import sys

import atheris

import standins

standins.install()
mqtt = standins.load("dionaea.mqtt.mqtt", "mqtt/mqtt.py")
atheris.instrument_all()


def target(data):
    cuts, stream = standins.reads(data)
    standins.Incident.reported.clear()
    con = mqtt.mqttd()
    con.handle_established()
    rest = standins.feed(con, stream, cuts)
    if not con.closed:
        # a partial fixed header, or a partial packet within the limit
        assert len(rest) < 5 or len(rest) < mqtt.MAX_PACKET_SIZE, len(rest)
    # the helpers on the whole stream, as the handler calls them on a packet
    for level in (4, 5):
        mqtt.publish_fields(stream, level)
        mqtt.subscribe_fields(stream, level)
        mqtt.suback(stream, level)
        mqtt.packet_topic(stream, level)
    mqtt.connect_level(stream)


def TestOneInput(data):
    standins.run(target, data)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
