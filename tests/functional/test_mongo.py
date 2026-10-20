# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The MongoDB service (port 27017): what a scanner sends first, and frames that are no message.

- isMaster as OP_QUERY on admin.$cmd (the handshake of old drivers and of most scanners) gets
  an OP_REPLY with one document, ismaster true, responseTo the request id
- isMaster and buildInfo as OP_COMMAND on test get an OP_COMMANDREPLY
- the connection is in dionaea.json (mongod)
- a header whose messageLength is below the 16 bytes of the header itself, a messageLength
  above what the service takes, and a query whose document is no BSON end the connection
  and leave the service answering
"""

import socket
import struct

import pytest

PORT = 27017
HEADER = struct.Struct("<iiii")


def bson_document(*elements):
    """A BSON document of (name, value) with an int32 or a boolean value."""
    body = b""
    for name, value in elements:
        if isinstance(value, bool):
            body += b"\x08" + name.encode() + b"\x00" + (b"\x01" if value else b"\x00")
        else:
            body += b"\x10" + name.encode() + b"\x00" + struct.pack("<i", value)
    body += b"\x00"
    return struct.pack("<i", 4 + len(body)) + body


def message(request_id, opcode, body):
    return HEADER.pack(HEADER.size + len(body), request_id, 0, opcode) + body


def op_query(request_id, collection, document):
    return message(request_id, 2004, struct.pack("<i", 0) + collection + b"\x00" + struct.pack("<ii", 0, -1)
                   + document)


def op_command(request_id, database, command, document):
    # OP_COMMAND: database, commandName, metadata, commandArgs
    return message(request_id, 2010, database + b"\x00" + command + b"\x00" + document + bson_document())


class Replies:
    """The messages of the server on sock, whole, as they come (several can come in one read)."""

    def __init__(self, sock):
        self.sock = sock
        self.data = b""

    def next(self, timeout=10):
        """(header fields, body) of the next message"""
        self.sock.settimeout(timeout)
        while len(self.data) < HEADER.size or len(self.data) < HEADER.unpack_from(self.data)[0]:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise AssertionError("the connection closed after %d bytes" % len(self.data))
            self.data += chunk
        length, request_id, response_to, opcode = HEADER.unpack_from(self.data)
        body, self.data = self.data[HEADER.size:length], self.data[length:]
        return (length, request_id, response_to, opcode), body


def recv_message(sock, timeout=10):
    return Replies(sock).next(timeout)


def closed_soon(sock, timeout=5):
    """The server closes the connection (EOF or a reset) within timeout seconds."""
    sock.settimeout(timeout)
    try:
        while sock.recv(4096):
            pass
    except ConnectionResetError:
        pass
    except socket.timeout:
        return False
    return True


def assert_answers(host):
    """The service still answers an isMaster at once."""
    with socket.create_connection((host, PORT), timeout=10) as sock:
        sock.sendall(op_query(7, b"admin.$cmd", bson_document(("isMaster", 1))))
        (_, _, response_to, opcode), _ = recv_message(sock, timeout=5)
    assert (response_to, opcode) == (7, 1)


def test_is_master_as_op_query(dionaea_host, wait_for_event):
    with socket.create_connection((dionaea_host, PORT), timeout=10) as sock:
        port = sock.getsockname()[1]
        sock.sendall(op_query(4242, b"admin.$cmd", bson_document(("isMaster", 1))))
        (length, _, response_to, opcode), body = recv_message(sock)
    assert opcode == 1 and response_to == 4242, (opcode, response_to)
    # OP_REPLY: responseFlags, cursorID, startingFrom, numberReturned, then the documents
    flags, cursor, starting, returned = struct.unpack_from("<iqii", body)
    assert (cursor, starting, returned) == (0, 0, 1)
    document = body[20:]
    assert struct.unpack_from("<i", document)[0] == len(document)
    assert b"\x08ismaster\x00\x01" in document
    assert b"maxWireVersion\x00" in document
    event = wait_for_event(lambda e: e.get("connection", {}).get("protocol") == "mongod"
                           and e.get("src_port") == port, timeout=30)
    assert event["dst_port"] == PORT


@pytest.mark.parametrize("command, key", [(b"isMaster", b"\x08ismaster\x00\x01"),
                                          (b"buildInfo", b"versionArray\x00")])
def test_a_command_as_op_command(dionaea_host, command, key):
    with socket.create_connection((dionaea_host, PORT), timeout=10) as sock:
        sock.sendall(op_command(9, b"test", command, bson_document((command.decode(), 1))))
        (_, _, response_to, opcode), body = recv_message(sock)
    assert (response_to, opcode) == (9, 2011)
    assert key in body


@pytest.mark.parametrize("length", [0, 8, 15, -1, -2147483648])
def test_a_header_shorter_than_itself_ends_the_connection(dionaea_host, length):
    with socket.create_connection((dionaea_host, PORT), timeout=10) as sock:
        sock.sendall(HEADER.pack(length, 1, 0, 2004) + b"\x00" * 16)
        assert closed_soon(sock), "dionaea kept the connection of a messageLength of %d" % length
    assert_answers(dionaea_host)


def test_a_message_above_the_limit_ends_the_connection(dionaea_host):
    with socket.create_connection((dionaea_host, PORT), timeout=10) as sock:
        # a header that announces 2 GiB: nothing of it is buffered
        sock.sendall(HEADER.pack(0x7fffffff, 1, 0, 2004) + b"\x00" * 64)
        assert closed_soon(sock), "dionaea waits for a message of 2 GiB"
    assert_answers(dionaea_host)


def test_a_query_whose_document_is_no_bson_ends_the_connection(dionaea_host):
    with socket.create_connection((dionaea_host, PORT), timeout=10) as sock:
        # a document whose length says more than it has
        sock.sendall(op_query(3, b"admin.$cmd", struct.pack("<i", 100) + b"\x10isMaster\x00"))
        assert closed_soon(sock)
    assert_answers(dionaea_host)


def test_the_service_answers_several_messages_of_one_read(dionaea_host):
    with socket.create_connection((dionaea_host, PORT), timeout=10) as sock:
        sock.sendall(b"".join(op_query(i, b"admin.$cmd", bson_document(("isMaster", 1))) for i in (1, 2, 3)))
        replies = Replies(sock)
        got = [replies.next()[0][2] for _ in range(3)]
    assert got == [1, 2, 3]
