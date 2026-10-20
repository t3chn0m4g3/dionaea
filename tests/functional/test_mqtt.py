# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The MQTT service (port 1883) with MQTT 5 and MQTT 3.1.1 clients (paho-mqtt).

The CONNACK and the SUBACK of protocol level 5 have a property length (MQTT 5.0 3.2.2.3 and
3.9.2.1); without it an MQTT 5 client read the reason code as the property length and the
connection ended. The client connects, subscribes with QoS 1 and publishes with QoS 1, and
the subscription and the publication are in dionaea.sqlite. An MQTT 3.1.1 client gets a SUBACK whose
remaining length counts its return codes, one per topic filter.
"""

import queue
import uuid

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties

PORT = 1883


def test_an_mqtt5_client_connects_subscribes_and_publishes(dionaea_host, wait_for_rows):
    events = queue.Queue()
    name = "func-v5-%s" % uuid.uuid4().hex[:8]
    topic = "plant/%s/status" % name
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=name, protocol=mqtt.MQTTv5)
    client.on_connect = lambda c, u, flags, reason, properties: events.put(("connect", reason.value))
    client.on_subscribe = lambda c, u, mid, reasons, properties: events.put(("subscribe", [r.value for r in reasons]))
    client.on_publish = lambda c, u, mid, reason, properties: events.put(("publish", reason.value))
    client.on_disconnect = lambda c, u, flags, reason, properties: events.put(("disconnect", reason.value))
    properties = Properties(PacketTypes.CONNECT)
    properties.SessionExpiryInterval = 0
    client.connect(dionaea_host, PORT, keepalive=30, clean_start=True, properties=properties)
    client.loop_start()
    try:
        assert events.get(timeout=10) == ("connect", 0)
        client.subscribe(topic, qos=1)
        assert events.get(timeout=10) == ("subscribe", [1])
        client.publish(topic, b"running", qos=1)
        assert events.get(timeout=10) == ("publish", 0)
    finally:
        client.disconnect()
        client.loop_stop()
    assert wait_for_rows("SELECT * FROM mqtt_subscribe_commands WHERE CAST(mqtt_subscribe_command_topic AS TEXT) = ?",
                         (topic,), timeout=15)
    assert wait_for_rows("SELECT * FROM mqtt_publish_commands WHERE CAST(mqtt_publish_command_topic AS TEXT) = ? "
                         "AND CAST(mqtt_publish_command_message AS TEXT) = 'running'", (topic,), timeout=15)


def test_an_mqtt311_client_gets_a_return_code_per_topic_filter(dionaea_host):
    # MQTT 3.1.1 3.9: the SUBACK said 2 bytes and sent 3, so paho read no return code
    events = queue.Queue()
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="func-v311-%s" % uuid.uuid4().hex[:8],
                         protocol=mqtt.MQTTv311)
    client.on_connect = lambda c, u, flags, reason, properties: events.put(("connect", reason.value))
    client.on_subscribe = lambda c, u, mid, reasons, properties: events.put(("subscribe", [r.value for r in reasons]))
    client.connect(dionaea_host, PORT, keepalive=30)
    client.loop_start()
    try:
        assert events.get(timeout=10) == ("connect", 0)
        client.subscribe([("plant/a/status", 0), ("plant/b/status", 1), ("plant/c/#", 2)])
        assert events.get(timeout=10) == ("subscribe", [0, 1, 2])
        # the connection goes on: a second subscription is answered as well
        client.subscribe("plant/d/status", qos=1)
        assert events.get(timeout=10) == ("subscribe", [1])
    finally:
        client.disconnect()
        client.loop_stop()
