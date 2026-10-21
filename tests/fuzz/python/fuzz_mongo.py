#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""atheris target of the MongoDB service (mongo/mongo.py) with the bson of the image (pymongo 4.16).

handle_io_in frames the messages by their header, _parse reads OP_QUERY and OP_COMMAND
and their documents; a message they can not read closes the connection
(MalformedMessage). Nothing may escape handle_io_in, it returns what it took, and
what it leaves in the buffer is less than one message of MAX_MESSAGE_SIZE.
"""

import sys

import atheris

import standins

standins.install()
mongo = standins.load("dionaea.mongo.mongo", "mongo/mongo.py")
assert mongo.bson is not None, "bson is needed"
atheris.instrument_all()


def target(data):
    cuts, stream = standins.reads(data)
    con = mongo.mongod()
    con.handle_established()
    rest = standins.feed(con, stream, cuts)
    if not con.closed:
        assert len(rest) < mongo.MAX_MESSAGE_SIZE, len(rest)


def TestOneInput(data):
    standins.run(target, data)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
