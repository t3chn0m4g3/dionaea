# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2015 Tan Kean Siong
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea.core import *
from dionaea.logtext import log_text, log_unreadable

import datetime
import logging
import binascii
import os
import struct
import tempfile

from dionaea.mqtt.include.packets import *

logger = logging.getLogger('mqtt')

# what the packet classes raise for a packet whose body does not hold the fields of its type
MALFORMED = (AttributeError, IndexError, KeyError, TypeError, ValueError, struct.error)


class MalformedPacket(Exception):
	"""A packet of the client the packet classes can not read (not an error of the service)."""


def read_packet(cls, data):
	"""The packet cls of the bytes data; MalformedPacket if they do not hold its fields."""
	try:
		return cls(data)
	except MALFORMED as e:
		raise MalformedPacket(e.__class__.__name__) from e

# the largest packet (fixed header and remaining length) a connection buffers, for up
# to its idle timeout (120 s): larger ones close the connection
MAX_PACKET_SIZE = 64 * 1024


def packet_length(data):
	"""Length of the first packet of data (fixed header + remaining length).

	None while the fixed header is not complete, -1 if the remaining length
	has more than the four bytes MQTT allows.
	"""
	multiplier = 1
	remaining = 0
	for i in range(1, 5):
		if i >= len(data):
			return None
		byte = data[i]
		remaining += (byte & 0x7f) * multiplier
		if byte & 0x80 == 0:
			return 1 + i + remaining
		multiplier *= 128
	return -1


def _varint(data, pos):
	"""(value, end) of the variable byte integer at pos, None while it is not complete or longer than 4 bytes."""
	value = 0
	for i in range(4):
		if pos + i >= len(data):
			return None
		byte = data[pos + i]
		value += (byte & 0x7f) << (7 * i)
		if byte & 0x80 == 0:
			return value, pos + i + 1
	return None


def _subscribe_parts(data, level):
	"""(packet identifier, first topic filter, where its subscription options are) of a SUBSCRIBE, else None."""
	header = _varint(data, 1)
	if header is None or data[0] >> 4 != 8:
		return None
	start = header[1]
	if len(data) < start + 2:
		return None
	packet_id = int.from_bytes(data[start:start + 2], "big")
	start += 2
	if level == 5:
		properties = _varint(data, start)
		if properties is None:
			return None
		start = properties[1] + properties[0]
	if len(data) < start + 2:
		return None
	size = int.from_bytes(data[start:start + 2], "big")
	topic = data[start + 2:start + 2 + size]
	if len(topic) < size:
		return None
	return packet_id, topic, start + 2 + size


def subscribe_fields(data, level=4):
	"""(packet identifier, first topic filter) of a SUBSCRIBE, as far as data has it, else None.

	With protocol level 5 the properties (a variable byte length and the
	properties) come between the packet identifier and the topic filter.
	"""
	parts = _subscribe_parts(data, level)
	return None if parts is None else parts[:2]


def _varint_bytes(n):
	"""n as a variable byte integer"""
	encoded = bytearray()
	while True:
		byte, n = n % 128, n // 128
		encoded.append(byte | (0x80 if n else 0))
		if not n:
			return bytes(encoded)


# a return code (reason code with MQTT 5) of a SUBACK for a topic filter that is refused
SUBACK_FAILURE = 0x80


def suback(data, level=4):
	"""The SUBACK of a whole SUBSCRIBE packet: its packet identifier, with MQTT 5 a property length of 0, and
	one return code per topic filter (MQTT 3.1.1 3.9, MQTT 5.0 3.9): the QoS the filter asks for, 0x80 for
	options that are malformed (QoS 3, reserved bits, with MQTT 5 retain handling 3). None if data is no
	SUBSCRIBE with at least one whole topic filter."""
	parts = _subscribe_parts(data, level)
	if parts is None:
		return None
	packet_id, _, pos = parts
	codes = bytearray()
	while True:
		if pos >= len(data):
			return None
		options = data[pos]
		if level == 5:
			bad = options & 0x03 == 3 or options & 0xc0 or options & 0x30 == 0x30
		else:
			bad = options & 0x03 == 3 or options & 0xfc
		codes.append(SUBACK_FAILURE if bad else options & 0x03)
		pos += 1
		if pos == len(data):
			break
		# the next topic filter
		if pos + 2 > len(data):
			return None
		pos += 2 + int.from_bytes(data[pos:pos + 2], "big")
	body = packet_id.to_bytes(2, "big") + (b"\x00" if level == 5 else b"") + bytes(codes)
	return b"\x90" + _varint_bytes(len(body)) + body


def packet_topic(data, level=4):
	"""The topic of a PUBLISH, the first topic filter of a SUBSCRIBE, as far as data has it.

	None for other packet types and while the topic is not complete. The payload is
	never read. level is the protocol level of the connection (5: MQTT 5).
	"""
	if len(data) < 2:
		return None
	kind = data[0] >> 4
	if kind == 8:
		fields = subscribe_fields(data, level)
		return None if fields is None else fields[1]
	if kind != 3:
		return None
	header = _varint(data, 1)
	if header is None:
		return None
	start = header[1]
	if len(data) < start + 2:
		return None
	size = int.from_bytes(data[start:start + 2], "big")
	topic = data[start + 2:start + 2 + size]
	if len(topic) < size:
		return None
	return topic


def publish_fields(data, level=4):
	"""(topic, packet identifier or None, message) of a whole PUBLISH packet, None if it is malformed.

	The remaining length is a variable byte integer; a packet identifier is there
	with QoS 1 and 2; with protocol level 5 the properties (a variable byte length
	and the properties) come before the message, they are not part of it.
	"""
	header = _varint(data, 1)
	if header is None or data[0] >> 4 != 3:
		return None
	remaining, start = header
	end = start + remaining
	if len(data) < end or end < start + 2:
		return None
	size = int.from_bytes(data[start:start + 2], "big")
	pos = start + 2 + size
	if pos > end:
		return None
	topic = data[start + 2:pos]
	packet_id = None
	if (data[0] >> 1) & 3:
		if pos + 2 > end:
			return None
		packet_id = int.from_bytes(data[pos:pos + 2], "big")
		pos += 2
	if level == 5:
		properties = _varint(data[:end], pos)
		if properties is None or properties[1] + properties[0] > end:
			return None
		pos = properties[1] + properties[0]
	return topic, packet_id, data[pos:end]


def connect_level(data):
	"""The protocol level of a CONNECT (3: MQTT 3.1, 4: 3.1.1, 5: MQTT 5), None if data has none."""
	header = _varint(data, 1)
	if header is None:
		return None
	start = header[1]
	if len(data) < start + 2:
		return None
	size = int.from_bytes(data[start:start + 2], "big")
	if len(data) <= start + 2 + size:
		return None
	return data[start + 2 + size]


def printable(value, limit=256):
	"""Attacker bytes for a log line: control characters escaped, at most limit characters."""
	text = bytes(value[:limit]).decode("utf-8", "backslashreplace")
	text = "".join(c if c.isprintable() else "\\x%02x" % ord(c) if ord(c) < 0x100 else "\\u%04x" % ord(c) for c in text)
	return text + ("..." if len(value) > limit else "")


class mqttd(connection):
	def __init__ (self):
		connection.__init__(self,"tcp")
		self.buf = b''
		# protocol level of the CONNECT of the client (MQTT 5 has properties in its packets)
		self.protocol_level = 4

	def handle_established(self):
		self.timeouts.idle = 120
		self.processors()

	def handle_io_in(self, data):
		"""Take every complete packet of data, leave a partial one in the buffer.

		A read is no packet boundary: a packet can come in pieces, several can come
		in one read, and the read before can carry the first byte of the next one.
		"""
		offset = 0
		while offset < len(data):
			length = packet_length(data[offset:offset + 5])
			if length is None:
				break
			if length < 0:
				logger.info("Bad MQTT Packet, remaining length malformed")
				self.close()
				return len(data)
			if length > MAX_PACKET_SIZE:
				# the topic and the size, never the payload
				topic = packet_topic(data[offset:], self.protocol_level)
				logger.warning("MQTT packet of %d bytes (type %d, topic %s) from %s:%s is above the limit of %d bytes, closing the connection",
					length, data[offset] >> 4,
					"unknown" if topic is None else "'%s'" % printable(topic),
					self.remote.host, self.remote.port, MAX_PACKET_SIZE)
				self.close()
				return len(data)
			if offset + length > len(data):
				break
			try:
				self.handle_packet(data[offset:offset + length])
			except MalformedPacket as e:
				# MQTT 3.1.1 4.8, MQTT 5.0 4.13: a malformed packet closes the network connection
				logger.info("malformed MQTT packet (type %d) from %s:%s, closing the connection: %s",
					data[offset] >> 4, self.remote.host, self.remote.port, e)
				self.close()
				return len(data)
			offset += length
		return offset

	def handle_packet(self, data):
		l=0
		size = 0
		chunk = b''

		if len(data) > l:
			p = None
			x = None
			try:

				if len(data) > 0:
					p = MQTT_ControlMessage_Type(data);
					p.show()

					self.pendingPacketType = p.ControlPacketType
					logger.debug("MQTT Control Packet Type {}".format(self.pendingPacketType))

				if len(data) == 0:
					logger.info("Bad MQTT Packet, Length = 0")

			except Exception as e:
				log_unreadable(logger, "Unable to read the type of an MQTT packet", e)
				return l

			if self.pendingPacketType == MQTT_CONTROLMESSAGE_TYPE_CONNECT:
				level = connect_level(data)
				if level is not None:
					self.protocol_level = level
				x = read_packet(MQTT_Connect, data)

				i = incident("dionaea.modules.python.mqtt.connect")
				i.con = self
				i.clientid = x.ClientID
				i.willtopic = x.WillTopic
				i.willmessage = x.WillMessage
				i.username = x.Username
				i.password = x.Password
				i.report()

			elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISH) == 48) &
				((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) > 0) ) :
				x = read_packet(MQTT_Publish, data)
				self.report_publish(data, x)

			elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISH) == 48) &
				((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_QoS2) > 0) ) :
				x = read_packet(MQTT_Publish, data)
				self.report_publish(data, x)

			elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISHREL) == 96) &
				((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) > 0) ) :
				x = read_packet(MQTT_Publish_Release, data)

			elif self.pendingPacketType >> 4 == MQTT_CONTROLMESSAGE_TYPE_PUBLISH >> 4:
				# QoS 0, also with the RETAIN or DUP flag
				x = read_packet(MQTT_Publish, data)
				self.report_publish(data, x)

			elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_SUBSCRIBE) == 128) &
				((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) > 0) ) :
				x = read_packet(MQTT_Subscribe, data)
				self.report_subscribe(data, x)

			elif self.pendingPacketType == MQTT_CONTROLMESSAGE_TYPE_SUBSCRIBE:
				x = read_packet(MQTT_Subscribe, data)
				self.report_subscribe(data, x)

			elif self.pendingPacketType == MQTT_CONTROLMESSAGE_TYPE_PINGREQ:
				x = read_packet(MQTT_PingRequest, data)

			elif self.pendingPacketType == MQTT_CONTROLMESSAGE_TYPE_DISCONNECT:
				x = read_packet(MQTT_DisconnectReq, data)

			self.buf = b''
			if x is None:
				logger.info("Unknown Packet Type for MQTT %s", log_text(self.pendingPacketType))
				return len(data)
			x.show()

			r = None
			r = self.process( self.pendingPacketType, x, data)

			if r:
				r.show()
				self.send(r.build())

		return len(data)

	def report_publish(self, data, x):
		"""The incident of a PUBLISH: topic and message, read by the protocol level."""
		i = incident("dionaea.modules.python.mqtt.publish")
		i.con = self
		fields = publish_fields(data, self.protocol_level)
		if fields is None:
			# malformed: what the packet parser read
			i.publishtopic = x.Topic
			i.publishmessage = x.Message
		else:
			i.publishtopic, packet_id, i.publishmessage = fields
			if packet_id is not None:
				# the identifier the acknowledgement carries
				x.PacketIdentifier = packet_id
		i.report()

	def report_subscribe(self, data, x):
		"""The incident of a SUBSCRIBE: packet identifier and first topic filter, read by the protocol level."""
		i = incident("dionaea.modules.python.mqtt.subscribe")
		i.con = self
		fields = subscribe_fields(data, self.protocol_level)
		if fields is None:
			# not complete: what the packet parser read
			i.subscribemessageid = x.PacketIdentifier
			i.subscribetopic = x.Topic
		else:
			i.subscribemessageid, i.subscribetopic = fields
		i.report()

	def process(self, PacketType, p, data=b""):
		r =''
		rp = None

		if PacketType == MQTT_CONTROLMESSAGE_TYPE_CONNECT:
			# MQTT 5 replies carry a property length, a client of that level can not read them without it
			r = MQTT5_ConnectACK() if self.protocol_level == 5 else MQTT_ConnectACK()

		elif PacketType == MQTT_CONTROLMESSAGE_TYPE_DISCONNECT:
			r = ''

		elif PacketType == MQTT_CONTROLMESSAGE_TYPE_PINGREQ:
			r = MQTT_PingResponse()

		elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_SUBSCRIBE) == 128) &
			((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) > 0) ) :
			# from the bytes of the packet, by the protocol level: the parser of the packet reads one topic
			# filter in the layout of 3.1.1
			reply = suback(data, self.protocol_level)
			if reply is None:
				logger.info("SUBSCRIBE without a whole topic filter from %s:%s, no SUBACK",
							self.remote.host, self.remote.port)
			else:
				r = Raw(reply)

		# mqtt-v3.1.1-os.pdf - page 36
		# For "Publish" Packet, the Response will be varied with the QoS level:
		# - QoS level 0 - No response packet
		# - QoS level 1 - PUBACK packet
		# - QoS level 2 - PUBREC packet

		elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISH) == 48) &
			((PacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) == 2) ) :
			l = p.getlayer(MQTT_Publish)
			packetidentifier = l.PacketIdentifier
			if (packetidentifier is not None):
				r = MQTT_PublishACK_Identifier()
				r.PacketIdentifier = packetidentifier

		elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISH) == 48) &
			((PacketType & MQTT_CONTROLMESSAGE_TYPE_QoS2) == 4) ) :
			l = p.getlayer(MQTT_Publish)
			packetidentifier = l.PacketIdentifier
			if (packetidentifier is not None):
				r = MQTT_PublishACK_Identifier()
				r.HeaderFlags = MQTT_CONTROLMESSAGE_TYPE_PUBLISHRCV
				r.PacketIdentifier = packetidentifier

		elif (  ((self.pendingPacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISH) == 48) &
			((PacketType & MQTT_CONTROLMESSAGE_TYPE_QoS1) == 0) ) :
			r = ''

		elif (PacketType & MQTT_CONTROLMESSAGE_TYPE_PUBLISHREL) == 96:
			l = p.getlayer(MQTT_Publish_Release)
			packetidentifier = l.PacketIdentifier
			if (packetidentifier is not None):
				r = MQTT_PublishACK_Identifier()
				r.PacketIdentifier = packetidentifier
				r.HeaderFlags = MQTT_CONTROLMESSAGE_TYPE_PUBLISHCOM
		else:
			logger.info("Unknown Packet Type for MQTT %s", log_text(PacketType))

		return r

	def handle_timeout_idle(self):
		return False

	def handle_disconnect(self):
		return False
