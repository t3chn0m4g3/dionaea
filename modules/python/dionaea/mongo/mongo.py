# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2017 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os
import re
import struct
import tempfile
from datetime import datetime
from decimal import Decimal

try:
    import bson
    import bson.errors
except ImportError:
    bson = None

from dionaea.core import incident, connection, g_dionaea
from . import packets
from dionaea.smb.include.packet import Raw


logger = logging.getLogger('mongo')

# a message is its header (16 bytes) and its body; the first messages of a client (isMaster,
# buildInfo, a query) are a few hundred bytes, a larger one is not waited for (MAX_MESSAGE_SIZE)
HEADER_SIZE = 16
MAX_MESSAGE_SIZE = 64 * 1024
# what the parsers raise for a message that is not what its header says
MALFORMED = (AttributeError, IndexError, KeyError, TypeError, ValueError, struct.error) + (
    (bson.errors.BSONError,) if bson is not None else ())


class MalformedMessage(Exception):
    """A message of the client the parser or BSON can not read (not an error of the service)."""


class mongod(connection):
    shared_config_values = [
        "config",
    ]

    def __init__(self):
        connection.__init__(self, "tcp")
        if bson is None:
            logger.warning("Unable to load 'bson' module. Some functions might be very limited.")
        self.config = None
        self.state = ""

    def _handle_command(self, database, command_name, metadata, command_args, input_docs):
        database = database.strip(b"\x00")
        command_name = command_name.strip(b"\x00")
        # print(database)
        # print(command_name)
        # print(metadata)
        result = None
        if database == b"admin":
            result = self._handle_command_db_admin(command_name, metadata, command_args, input_docs)
        elif database == b"test":
            result = self._handle_command_db_test(command_name, metadata, command_args, input_docs)

        if result is None:
            logger.error("not found")
            # We need at least two documents(metadata and commandReply)
            return [{}, {}]
        return result

    def _handle_command_db_admin(self, command_name, metadata, command_args, input_docs):
        if command_name == b"buildinfo":
            return [self._handle_get_build_info(), {}]
        elif command_name == b"getLog":
            return [{
                'ok': 1.0,
                'log': [],
                'totalLinesWritten': 0
            }, {}]
        elif command_name == b"replSetGetStatus":
            return [{
                'ok': 0.0,
                'codeName': 'NoReplicationEnabled',
                'code': 76,
                'errmsg': 'not running with --replSet'
            }, {}]
        elif command_name == b"whatsmyuri":
            return [{
                "ok": 1.0,
                "you": "%s:%s" % (self.local.host, self.local.port)
            }, {}]

    def _handle_command_db_test(self, command_name, metadata, command_args, input_docs):
        if command_name == b"buildInfo":
            return [self._handle_get_build_info(), {}]
        elif command_name == b"isMaster":
            return [{
                'ok': 1.0,
                'ismaster': True,
                'maxBsonObjectSize': 16777216,
                'readOnly': False,
                'minWireVersion': 0,
                'maxMessageSizeBytes': 48000000,
                'maxWriteBatchSize': 1000,
                'maxWireVersion': 5,
                'localTime': datetime.now()
            }, {}]
        return None

    def _handle_get_build_info(self):
        return {
            'storageEngines': ['devnull', 'ephemeralForTest', 'mmapv1', 'wiredTiger'],
            'buildEnvironment': {
                'ccflags': '-fno-omit-frame-pointer -fno-strict-aliasing -ggdb -pthread -Wall -Wsign-compare -Wno-unknown-pragmas -Winvalid-pch -Werror -O2 -Wno-unused-local-typedefs -Wno-unused-function -Wno-deprecated-declarations -Wno-unused-but-set-variable -Wno-missing-braces -fstack-protector-strong -fno-builtin-memcmp',
                'cxx': '/opt/mongodbtoolchain/v2/bin/g++: g++ (GCC) 5.4.0', 'distarch': 'x86_64',
                'cxxflags': '-Woverloaded-virtual -Wno-maybe-uninitialized -std=c++11',
                'linkflags': '-pthread -Wl,-z,now -rdynamic -Wl,--fatal-warnings -fstack-protector-strong -fuse-ld=gold -Wl,--build-id -Wl,-z,noexecstack -Wl,--warn-execstack -Wl,-z,relro',
                'target_os': 'linux', 'cc': '/opt/mongodbtoolchain/v2/bin/gcc: gcc (GCC) 5.4.0', 'distmod': 'debian81',
                'target_arch': 'x86_64'
            },
            'version': '3.4.4',
            'gitVersion': '888390515874a9debd1b6c5d36559ca86b44babd',
            'javascriptEngine': 'mozjs',
            'maxBsonObjectSize': 16777216,
            'debug': False,
            'openssl': {
                'compiled': 'OpenSSL 1.0.1t  3 May 2016',
                'running': 'OpenSSL 1.0.1t  3 May 2016'
            },
            'versionArray': [3, 4, 4, 0],
            'sysInfo': 'deprecated',
            'ok': 1.0,
            'bits': 64,
            'modules': [],
            'allocator': 'tcmalloc'
        }

    def _handle_query(self, fullCollectionName, query, field_selectors):
        fullCollectionName = fullCollectionName.strip(b"\x00")
        db_name, sep, col_name = fullCollectionName.partition(b".")
        # print(db_name, col_name)
        if db_name == b"admin":
            if col_name == b"$cmd":
                return [{
                    "ismaster": True,
                    "maxBsonObjectSize": 16 * 1024 * 1024,
                    "maxMessageSizeBytes": 48000000,
                    "maxWriteBatchSize": 1000,
                    "localTime": datetime.now(),
                    "maxWireVersion": 5,
                    "minWireVersion": 0,
                    "readOnly": False,
                    "ok": 1
                }]
        else:
            if col_name == b"$cmd":
                return [{
                    "cursor": {
                        "id": 0,
                        "ns": db_name,
                        "firstBatch": {}
                    },
                    "ok": 1
                }]
            else:
                return []
        return []

    def handle_established(self):
        self.processors()

    def handle_io_in(self, data):
        offset = 0
        while len(data) - offset >= HEADER_SIZE:
            h = packets.MsgHeader(data[offset:offset + HEADER_SIZE])
            if not HEADER_SIZE <= h.messageLength <= MAX_MESSAGE_SIZE:
                # shorter than its own header or above the limit
                logger.info("MongoDB message of %d bytes from %s:%s, closing the connection",
                            h.messageLength, self.remote.host, self.remote.port)
                self.close()
                return len(data)
            if len(data) - offset < h.messageLength:
                break
            try:
                self._handle_message(h, data[offset:offset + h.messageLength])
            except MalformedMessage as e:
                logger.info("malformed MongoDB message (opCode %d) from %s:%s, closing the connection: %s",
                            h.opCode, self.remote.host, self.remote.port, e)
                self.close()
                return len(data)
            offset = offset + h.messageLength

        return offset

    @staticmethod
    def _parse(h, body):
        """(message, its documents) of OP_QUERY / OP_COMMAND; MalformedMessage if they can not be read"""
        try:
            if h.opCode == 2004:
                msg = packets.MsgQuery(body)
                docs = bson.decode_all(msg.payload.load) if bson else []
            else:
                msg = packets.MsgCommand(body)
                docs = bson.decode_all(msg.payload.load)
        except MALFORMED as e:
            raise MalformedMessage(e.__class__.__name__) from e
        if h.opCode == 2010 and len(docs) < 2:
            # the metadata and the arguments of the command
            raise MalformedMessage("%d documents" % len(docs))
        return msg, docs

    def _handle_message(self, h, data):
        """One whole message (header and body) of the client: OP_QUERY and OP_COMMAND are answered."""
        if h.opCode not in (2004, 2010):
            return
        msg, docs = self._parse(h, data[HEADER_SIZE:])
        if h.opCode == 2004:
            query = docs[0] if docs else None
            res = self._handle_query(fullCollectionName=msg.fullCollectionName, query=query, field_selectors=docs[1:])
            reply = packets.MsgReply(numberReturned=len(res))
            opcode = 1
        else:
            res = self._handle_command(msg.database, msg.commandName, docs[0], docs[1], docs[1:])
            reply = packets.MsgCommandReply()
            opcode = 2011

        payload = b""
        for doc in res:
            payload += bson.BSON.encode(doc)
        pkg = packets.MsgHeader(responseTo=h.requestID, opCode=opcode) / reply / Raw(payload)
        pkg.show()
        self.send(pkg.build())
