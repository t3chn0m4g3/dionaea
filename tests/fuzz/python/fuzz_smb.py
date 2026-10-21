#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""atheris target of the SMB service (smb/smb.py, smb2.py, ntlm.py and the dissector of smb/include).

The stream of a client, cut into reads, goes through smbd.handle_io_in as the
binding hands it over: the NetBIOS framing, SMB1 messages dissected by
NBTSession (smbfields.py, packet.py) and answered by process(), SMB2 NEGOTIATE
and SESSION_SETUP with NTLMSSP (smb2.py, ntlm.py). handle_message catches what a
malformed request raises (ValueError, IndexError, KeyError, AttributeError,
TypeError, struct.error, UnicodeError); anything else that escapes handle_io_in
is a failing input. handle_io_in returns what it took, and what it leaves in the buffer
is less than one message (MAX_MESSAGE). The service runs with a max_upload_size of
4 KiB, so the uploads and print jobs of an input reach it; the fragments of a print
job are kept up to it.
"""

import sys

import atheris

import standins

MAX_UPLOAD_SIZE = 4096

standins.install()
smb = standins.load("dionaea.smb.smb", "smb/smb.py")
atheris.instrument_all()


def target(data):
    cuts, stream = standins.reads(data)
    standins.Incident.reported.clear()
    con = smb.smbd()
    con.apply_config({"max_upload_size": MAX_UPLOAD_SIZE})
    con.handle_established()
    try:
        rest = standins.feed(con, stream, cuts)
    finally:
        standins.clean_downloads()
    if not con.closed:
        assert len(rest) < smb.MAX_MESSAGE + 4, len(rest)
    # the per connection state stays within its limits
    assert len(con.fids) <= smb.MAX_OPEN_FIDS, len(con.fids)
    assert len(con.trees) <= smb.MAX_TREES, len(con.trees)
    assert len(con.uids) <= smb.MAX_SESSIONS, len(con.uids)
    assert con.printer is None or len(con.printer) <= MAX_UPLOAD_SIZE, len(con.printer)


def TestOneInput(data):
    standins.run(target, data)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
