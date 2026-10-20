# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter & Mark Schloesser
# SPDX-FileCopyrightText: 2010 Markus Koetter & Tan Kean Siong
# SPDX-FileCopyrightText: 2011 Markus Koetter
# SPDX-FileCopyrightText: 2015 Katarina Durechova
# SPDX-FileCopyrightText: 2017 Tan Kean Siong
# SPDX-FileCopyrightText: 2016-2017 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea.core import incident, connection, g_dionaea

import struct
import hashlib
import logging
import os
from uuid import UUID, uuid4

from .include.smbfields import *
from .rpcservices import __shares__, STYPE_DEVICE, STYPE_DISKTREE, STYPE_IPC, STYPE_PRINTQ, STYPE_SPECIAL
from .include.packet import Raw
from .ntlm import Exchange, filetime, legacy_password, negotiate_token, variant
from .smb2 import SMB2, MAX_MESSAGE
from dionaea.util import calculate_doublepulsar_opcode, xor
from dionaea.logtext import log_text
from dionaea.upload import (
    DEFAULT_MAX_UPLOAD_SIZE,
    UploadError,
    UploadFile,
    UploadTooLarge,
    incoming_file,
    upload_url,
)


smblog = logging.getLogger('SMB')

STATE_START = 0
STATE_SESSIONSETUP = 1
STATE_TREECONNECT = 2
STATE_NTCREATE = 3
STATE_NTWRITE = 4
STATE_NTREAD = 5

registered_services = {}

# Per connection: files (and pipes) a client can have open at the same time,
# and the bytes kept for a DCERPC fragment that is not complete yet (the
# fragment length is a 16 bit value)
MAX_OPEN_FIDS = 32
# Per connection: trees (TREE_CONNECT_ANDX) and sessions (SESSION_SETUP_ANDX) that are kept
MAX_TREES = 32
# the share a tree keeps, in characters: the name is the client's (any length for a name that ends in
# "share", CVE-2017-7494), Windows takes paths of shares of at most 256 characters
MAX_SHARE_LENGTH = 256
MAX_SESSIONS = 16
MAX_DCERPC_BUFFER = 65536 + 1024

STATUS_UNSUCCESSFUL = 0xc0000001
STATUS_ACCESS_DENIED = 0xc0000022
STATUS_BAD_NETWORK_NAME = 0xc00000cc
STATUS_INVALID_PARAMETER = 0xc000000d
STATUS_DISK_FULL = 0xc000007f
STATUS_TOO_MANY_OPENED_FILES = 0xc000011f

# Transactions are sent in pieces: the first request carries the start, the
# *_SECONDARY requests the rest. Nothing of them is kept (no totals, offsets
# or displacements are used), dionaea only knows that a transaction was started.
TRANS_SECONDARIES = frozenset((
    SMB_COM_TRANSACTION_SECONDARY, SMB_COM_TRANSACTION2_SECONDARY, SMB_COM_NT_TRANSACT_SECONDARY,
))
# the start of a session, or its end, leaves no transaction pending
TRANS_ENDS = frozenset((
    SMB_COM_NEGOTIATE, SMB_COM_SESSION_SETUP_ANDX, SMB_COM_LOGOFF_ANDX, SMB_COM_TREE_DISCONNECT,
))


# Names of the named pipes of the services in rpcservices.py: a write to them is DCERPC, not a file
PIPE_NAMES = frozenset((
    "atsvc", "browser", "eventlog", "initshutdown", "lsarpc", "lsass", "netlogon", "ntsvcs",
    "samr", "spoolss", "srvsvc", "svcctl", "wkssvc", "winreg", "epmapper", "plugplay",
    "protected_storage", "trkwks", "w32time", "scerpc", "msgsvc",
))


# The UID of a new session: a Windows server counts them for all its connections in
# steps of 0x0800. The n-th UID is step (n % 31 + 1) * 0x0800 plus round n // 31:
# 0x0800, 0x1000, ..., 0xf800, then 0x0801, ..., 0xf801, 0x0802, ...; every value
# from 0x0800 to 0xfffe once in 63,487 sessions (31 * 0x0800 = 63,488 steps, of which the
# last is 0xffff and skipped; 0 and 0xffff never), then again.
_uid_counter = [0]
UID_STEPS = 31
UID_ROUNDS = 0x0800


def new_uid(in_use=()):
    """The UID of a new session, not one of in_use."""
    while True:
        n = _uid_counter[0]
        _uid_counter[0] = (n + 1) % (UID_STEPS * UID_ROUNDS)
        uid = (n % UID_STEPS + 1) * 0x0800 + n // UID_STEPS
        if uid != 0xffff and uid not in in_use:
            return uid


# Reply of a TREE_CONNECT_ANDX per type of share (MS-CIFS 2.2.4.55.2): Service, NativeFileSystem
TREE_SERVICES = {
    STYPE_DISKTREE: ("A:", "NTFS"),
    STYPE_PRINTQ: ("LPT1:", ""),
    STYPE_DEVICE: ("COMM", ""),
    STYPE_IPC: ("IPC", ""),
}
# what a Windows server gives an administrator in an extended tree connect reply (and a guest)
MAXIMAL_SHARE_ACCESS = 0x001f01ff


def is_admin_share(name, share_type):
    """True for an administrative share: ADMIN$, C$, ... (special, or a name ending in $ but IPC$ and PRINT$)."""
    if share_type & STYPE_SPECIAL and share_type & 0x3 != STYPE_IPC:
        return True
    return name.endswith("$") and name.upper() not in ("IPC$", "PRINT$")


def share_name(path):
    """The share of the path of a TREE_CONNECT_ANDX (\\\\server\\share, str), as the client sent it."""
    return path.split("\x00")[0].replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]


def is_pipe_name(name):
    """True if name is the name of a pipe of a service, as \\srvsvc or \\PIPE\\srvsvc."""
    name = name.replace("/", "\\").lower().lstrip("\\")
    if name.startswith("pipe\\"):
        name = name[len("pipe\\"):]
    return name in PIPE_NAMES


def decode_smb_name(raw, unicode_names):
    """
    File name from a field of a request, str.

    :param raw: Value of the field (bytes, UTF-16LE with SMB_FLAGS2_UNICODE, else the OEM code page)
    :param unicode_names: True if the client uses unicode names
    """
    if isinstance(raw, str):
        name = raw
    elif unicode_names:
        name = raw.decode("utf-16-le", errors="replace")
    else:
        name = raw.decode("utf-8", errors="replace")
    return name.split("\x00")[0]

def register_rpc_service(service):
    uuid = service.uuid
    registered_services[uuid] = service


class smbd(connection):
    shared_config_values = [
        "config", "server_guid", "server_start"
    ]

    def __init__ (self, proto="tcp", config=None):
        connection.__init__(self,"tcp")
        self.state = {
            'lastcmd': None,
            'readcount': 0,
            'stop': False,
        }
        self.buf = b''
        self.buf2 = b''  # ms17-010 SMB_COM_TRANSACTION2
        self.outbuf = None
        self.fids = {}
        # TID -> share of the trees of the client; UID of a session -> True while it is
        # anonymous (or a guest): no login yet, or one with an empty user name or "guest"
        self.trees = {}
        self.uids = {}
        self.smb_message = None
        self.next_tid = 0x0800
        self.printer = b'' # spoolss file "queue"

        self.config = None
        self.server_guid = uuid4().bytes_le
        self.server_start = filetime()
        self.ntlm = Exchange()
        self.smb2 = SMB2(self)
        # a SMB_COM_TRANSACTION, _TRANSACTION2 or _NT_TRANSACT was started
        # and the connection has not been through TRANS_ENDS since
        self.trans = False
        # process() has nothing to answer on purpose (the continuation of a transaction)
        self.no_answer = False

    def apply_config(self, config=None):
        # Avoid import loops
        from .extras import SmbConfig
        self.config = SmbConfig(config=config)
        # Set the global OS_TYPE value
        # ToDo: This is a quick and dirty hack
        from . import rpcservices
        rpcservices.__shares__ = self.config.shares
        rpcservices.OS_TYPE = self.config.os_type

    def handle_established(self):
        #		self.timeouts.sustain = 120
        self.timeouts.idle = 120
#		self._in.accounting.limit  = 2000*1024
#		self._out.accounting.limit = 2000*1024
        self.processors()

    def handle_io_in(self, data):
        """Process every complete NetBIOS session message of the input.

        A client may send several requests at once (the MS17-010 exploits send
        their *_SECONDARY packets in bursts, and TCP puts them into one read).
        Each message is cut out by its own length, so the rest of the buffer is
        neither taken as the data of the first request nor left unprocessed until
        more data arrives. Returns the number of bytes used; an incomplete
        message stays in the buffer.
        """
        done = 0
        while len(data) - done >= 4:
            # Direct TCP uses the full 24-bit length, not the NBT 17-bit mask.
            size = 4 + int.from_bytes(data[done + 1:done + 4], "big")
            if size > MAX_MESSAGE + 4:
                smblog.info("SMB message exceeds limit")
                self.close()
                return len(data)
            if len(data) - done < size:
                # we probably do not have the whole packet yet
                smblog.info('=== SMB did not get enough data')
                break
            used = self.handle_message(data[done:done + size])
            if used is None:
                # the connection has no more use for the input
                return len(data)
            done += used
        return done

    def report_login(self, login, dialect):
        icd = incident("dionaea.modules.python.smb.login")
        icd.con = self
        icd.password = ""
        icd.dialect = dialect
        for name, value in login.items():
            setattr(icd, name, value)
        icd.report()

    def handle_message(self, data):
        try:
            if data[0] == 0x85 and len(data) == 4:
                return len(data)
            if data[0] == 0 and data[4:8] == b"\xfeSMB":
                self.smb2.process(data[4:])
                return len(data)
            if self.smb2.active:
                raise ValueError("SMB1 message after SMB2 negotiation")
            return self.handle_smb1_message(data)
        except (ValueError, IndexError, KeyError, AttributeError, TypeError, struct.error, UnicodeError) as e:
            smblog.warning("Invalid SMB request: %s", log_text(e))
            if self.smb2.active or data[4:8] != b"\xffSMB":
                self.close()
                return None
            return len(data)

    def handle_smb1_message(self, data):
        """One complete NetBIOS session message; returns its length, None if the rest of the input is to be dropped.

        self.smb_message holds the message only while it is handled, on every path."""
        try:
            return self._handle_smb1_message(data)
        finally:
            self.smb_message = None

    def _handle_smb1_message(self, data):
        if data[0] == 0:
            if len(data) < 39 or data[4:8] != b"\xffSMB":
                raise ValueError("invalid SMB1 header")
            # Session setup and negotiation have bounded security/dialect data.
            # Transaction secondaries deliberately keep their permissive handling
            # for exploit capture (their declared counts need not match the body).
            if data[8] in (SMB_COM_NEGOTIATE, SMB_COM_SESSION_SETUP_ANDX):
                words = data[36]
                bytecount_at = 37 + words * 2
                if bytecount_at + 2 > len(data):
                    raise ValueError("truncated SMB1 parameters")
                count = struct.unpack_from("<H", data, bytecount_at)[0]
                if bytecount_at + 2 + count > len(data):
                    raise ValueError("SMB1 byte count outside message")
                if data[8] == SMB_COM_SESSION_SETUP_ANDX:
                    if words not in (12, 13):
                        raise ValueError("unsupported SMB1 session setup")
                    blobsize = struct.unpack_from("<H", data, 51)[0]
                    if words == 13:
                        blobsize += struct.unpack_from("<H", data, 53)[0]
                    if blobsize > count:
                        raise ValueError("SMB1 security data outside message")
        # the SMB message (without the NetBIOS header), for the requests of a chain
        self.smb_message = data[4:]
        p = NBTSession(data, _ctx=self)

        if p.TYPE == 0x81:
            self.send(NBTSession(TYPE=0x82).build())
            return len(data)
        elif p.TYPE != 0:
            # we currently do not handle anything else
            return len(data)

        if p.haslayer(SMB_Header) and p[SMB_Header].Start != b'\xffSMB':
            # not really SMB Header -> bail out
            smblog.error('=== not really SMB')
            self.close()
            return None

        p.show()
        r = None

        # this is one of the things you have to love, it violates the spec, but
        # has to work ...
        if p.haslayer(SMB_Sessionsetup_ESEC_AndX_Request) and p.getlayer(SMB_Sessionsetup_ESEC_AndX_Request).WordCount == 13:
            smblog.debug("recoding session setup request!")
            p.getlayer(SMB_Header).decode_payload_as(
                SMB_Sessionsetup_AndX_Request2)
            x = p.getlayer(SMB_Sessionsetup_AndX_Request2)
            x.show()

        r = self.process(p)
        smblog.debug("packet: %s" % p.summary())

        if p.haslayer(Raw):
            smblog.debug("p.haslayer(Raw): %s" % p.getlayer(Raw).build())
            p.show()

#		i = incident("dionaea.module.python.smb.info")
#		i.con = self
#		i.direction = 'in'
#		i.data = p.summary()
#		i.report()

        if self.state['stop']:
            smblog.info("faint death.")
            return None

        if r:
            smblog.debug("response: %s" % r.summary())
            r.show()

#			i = incident("dionaea.module.python.smb.info")
#			i.con = self
#			i.direction = 'out'
#			i.data = r.summary()
#			i.report()

#			r.build()
            #r.show2()
            self.send(r.build())
        elif not self.no_answer:
            smblog.error('process() returned None.')

        # a rest that is not parsed (junk, or a failed dissection) is inside
        # the message, which ends where its length says
        return len(data)

    def process(self, p):
        r = ''
        rp = None
#		self.state['readcount'] = 0
        # if self.state == STATE_START and p.getlayer(SMB_Header).Command ==
        # 0x72:
        rstatus = 0
        # the reply carries the TID and the UID of the request, but the TID of a new tree
        # and the UID of a new session (as a Windows server)
        reply_tid = None
        reply_uid = None
        # the request of a chain behind the first one (AndX), parsed: (request, chained header)
        chained = None
        smbh = p.getlayer(SMB_Header)
        Command = smbh.Command

        icd = incident("dionaea.modules.python.smb.command")
        # the client chooses the command byte, not every value has a name
        icd.command = SMB_Commands.get(Command, "0x%02x" % Command)
        icd.con = self
        icd.report()

        self.no_answer = False
        if Command in TRANS_ENDS:
            self.trans = False
        if Command == SMB_COM_NEGOTIATE:
            requests = p.getlayer(SMB_Negociate_Protocol_Request_Counts).Requests
            dialects = [request.BufferData.rstrip(b"\0") for request in requests]
            if b"NT LM 0.12" not in dialects and (b"SMB 2.???" in dialects or b"SMB 2.002" in dialects):
                self.smb2.negotiate(0x02ff if b"SMB 2.???" in dialects else 0x0202)
                self.no_answer = True
                return None
            # Negociate Protocol -> Send response that supports minimal features in NT LM 0.12 dialect
            # (could be randomized later to avoid detection - but we need more dialects/options support)
            r = SMB_Negociate_Protocol_Response(
                OemDomainName=self.config.oem_domain_name + "\0",
                ServerName=self.config.server_name + "\0",
                ServerGUID=self.server_guid, SecurityBlob=negotiate_token()
            )
            # we have to select dialect
            c = 0
            tmp = p.getlayer(SMB_Negociate_Protocol_Request_Counts)
            while c < len(tmp.Requests):
                request = tmp.Requests[c]
                if request.BufferData.decode('ascii').find('NT LM 0.12') != -1:
                    break
                c += 1

            r.DialectIndex = c

#			r.Capabilities = r.Capabilities & ~CAP_EXTENDED_SECURITY
            if not p.Flags2 & SMB_FLAGS2_EXT_SEC:
                r.Capabilities = r.Capabilities & ~CAP_EXTENDED_SECURITY

        # elif self.state == STATE_SESSIONSETUP and
        # p.getlayer(SMB_Header).Command == 0x73:
        elif Command == SMB_COM_SESSION_SETUP_ANDX:
            if p.haslayer(SMB_Sessionsetup_ESEC_AndX_Request):
                r = SMB_Sessionsetup_ESEC_AndX_Response(
                    NativeOS=self.config.native_os + "\0",
                    NativeLanManager=self.config.native_lan_manager + "\0",
                    PrimaryDomain=self.config.primary_domain
                )
                sb = p.getlayer(SMB_Sessionsetup_ESEC_AndX_Request).SecurityBlob
                r.SecurityBlob, login = self.ntlm.process(sb, self.config)
                r.Action = 0
                reply_uid = self.session_uid(smbh.UID)
                if login is None:
                    rstatus = 0xc0000016  # STATUS_MORE_PROCESSING_REQUIRED
                else:
                    self.report_login(login, "NT LM 0.12")
                    self.session_login(reply_uid, login.get("username", ""))
            elif p.haslayer(SMB_Sessionsetup_AndX_Request2):
                setup = p.getlayer(SMB_Sessionsetup_AndX_Request2)
                unicode_names = bool(p.Flags2 & SMB_FLAGS2_UNICODE)
                username = decode_smb_name(setup.Account, unicode_names)
                self.report_login(dict(
                    username=username,
                    domain=decode_smb_name(setup.PrimaryDomain, unicode_names),
                    workstation="", ntlm_version=variant(setup.UnicodePassword),
                    password=legacy_password(setup.Password, setup.UnicodePassword, unicode_names),
                ), "NT LM 0.12")
                r = SMB_Sessionsetup_AndX_Response2(
                    NativeOS=self.config.native_os + "\0",
                    NativeLanManager=self.config.native_lan_manager + "\0",
                    PrimaryDomain=self.config.primary_domain + "\0"
                )
                reply_uid = self.session_uid(smbh.UID)
                self.session_login(reply_uid, username)
                if setup.AndXCommand == SMB_COM_TREE_CONNECT_ANDX:
                    # a TREE_CONNECT_ANDX chained behind it (the only chain dionaea answers)
                    chained = self.chained_tree_connect(setup, smbh, reply_uid)
            else:
                smblog.warning("Unknown Session Setup Type used")

        elif Command == SMB_COM_TREE_CONNECT_ANDX:
            h = p.getlayer(SMB_Treeconnect_AndX_Request)
            r, rstatus, reply_tid = self.tree_connect(h, smbh, smbh.UID, 32)
        elif Command == SMB_COM_TREE_DISCONNECT:
            self.trees.pop(smbh.TID, None)
            r = SMB_Treedisconnect()
        elif Command == SMB_COM_CLOSE:
            r = p.getlayer(SMB_Close)
            if p.FID in self.fids:
                upload = self.fids.pop(p.FID)
                if upload is not None:
                    # the client has closed the file: it is complete
                    upload.complete(self, upload_url("smb", self.remote.host, upload.client_name, upload.share))
                    r = SMB_Close_Response()
        elif Command == SMB_COM_LOGOFF_ANDX:
            self.uids.pop(smbh.UID, None)
            r = SMB_Logoff_AndX()
        elif Command == SMB_COM_NT_CREATE_ANDX:
            # FIXME return NT_STATUS_OBJECT_NAME_NOT_FOUND=0xc0000034
            # for writes on IPC$
            # this is used to distinguish between file shares and devices by nmap smb-enum-shares
            # requires mapping of TreeConnect ids to names/objects
            r = SMB_NTcreate_AndX_Response()
            h = p.getlayer(SMB_NTcreate_AndX_Request)
            r.FID = self.new_fid()
            if r.FID is None:
                r.FID = 0
                rstatus = STATUS_TOO_MANY_OPENED_FILES
            elif h.FileAttributes & (SMB_FA_HIDDEN|SMB_FA_SYSTEM|SMB_FA_ARCHIVE|SMB_FA_NORMAL):
                # if a normal file is requested, provide a file
                filename = decode_smb_name(h.Filename, smbh.Flags2 & SMB_FLAGS2_UNICODE)
                self.open_upload(r, filename, self.trees.get(smbh.TID))
            elif h.FileAttributes & SMB_FA_DIRECTORY:
                pass
            else:
                self.fids[r.FID] = None
        elif Command == SMB_COM_OPEN_ANDX:
            h = p.getlayer(SMB_Open_AndX_Request)
            r = SMB_Open_AndX_Response()
            r.FID = self.new_fid()
            if r.FID is None:
                r.FID = 0
                rstatus = STATUS_TOO_MANY_OPENED_FILES
            else:
                filename = decode_smb_name(h.FileName, smbh.Flags2 & SMB_FLAGS2_UNICODE)
                self.open_upload(r, filename, self.trees.get(smbh.TID))

        elif Command == SMB_COM_ECHO:
            r = p.getlayer(SMB_Header).payload
        elif Command == SMB_COM_WRITE_ANDX:
            r = SMB_Write_AndX_Response()
            h = p.getlayer(SMB_Write_AndX_Request)
            r.CountLow = h.DataLenLow
            if self.fids.get(h.FID) is not None:
                smblog.debug("WRITE FILE!")
                offset = h.Offset
                if h.WordCount == 14:
                    # 64 bit offset, the high part is only there with the longer form of the request
                    offset |= h.HighOffset << 32
                written, rstatus = self.write_upload(h.FID, h.Data, offset)
                # Low 16 bits of written
                r.CountLow = written & 0xffff
                # High 16 bits of written
                r.CountHigh = (written >> 16) & 0xffff
            else:
                self.buf += h.Data
#				self.process_dcerpc_packet(p.getlayer(SMB_Write_AndX_Request).Data)
                if len(self.buf) > MAX_DCERPC_BUFFER:
                    # not a DCERPC fragment, do not keep what the client sends without limit
                    smblog.warning("dropping %i bytes written to a pipe", len(self.buf))
                    self.buf = b''
                if len(self.buf) >= 10:
                    # we got the dcerpc header
                    inpacket = DCERPC_Header(self.buf[:10])
                    smblog.debug("got header")
                    inpacket = DCERPC_Header(self.buf)
                    smblog.debug("FragLen %i len(self.buf) %i" %
                                 (inpacket.FragLen, len(self.buf)))
                    if inpacket.FragLen == len(self.buf):
                        outpacket = self.process_dcerpc_packet(self.buf)
                        if outpacket is not None:
                            outpacket.show()
                            self.outbuf = outpacket.build()
                        self.buf = b''
        elif Command == SMB_COM_WRITE:
            h = p.getlayer(SMB_Write_Request)
            count = h.CountOfBytesToWrite
            if self.fids.get(h.FID) is not None:
                smblog.debug("WRITE FILE!")
                count, rstatus = self.write_upload(h.FID, h.Data, h.WriteOffsetInBytes)
            r = SMB_Write_Response(CountOfBytesWritten = count)
        elif Command == SMB_COM_READ_ANDX:
            r = SMB_Read_AndX_Response()
            h = p.getlayer(SMB_Read_AndX_Request)
            # self.outbuf should contain response buffer now
            if not self.outbuf:
                if self.state['stop']:
                    smblog.debug('drop dead!')
                else:
                    smblog.error('dcerpc processing failed. bailing out.')
                return rp

            rdata = SMB_Data()
            outbuf = self.outbuf
            outbuflen = len(outbuf)
            smblog.debug("MaxCountLow %i len(outbuf) %i readcount %i" %(
                h.MaxCountLow, outbuflen, self.state['readcount']) )
            if h.MaxCountLow < outbuflen-self.state['readcount']:
                rdata.ByteCount = h.MaxCountLow
                newreadcount = self.state['readcount']+h.MaxCountLow
            else:
                newreadcount = 0
                self.outbuf = None

            rdata.Bytes = outbuf[
                self.state['readcount'] : self.state['readcount'] + h.MaxCountLow ]
            rdata.ByteCount = len(rdata.Bytes)+1
            r.DataLenLow = len(rdata.Bytes)
            smblog.debug("readcount %i len(rdata.Bytes) %i" %
                         (self.state['readcount'], len(rdata.Bytes)) )
            r /= rdata

            self.state['readcount'] = newreadcount

        elif Command == SMB_COM_TRANSACTION:
            self.trans = True
            h = p.getlayer(SMB_Trans_Request)
            r = SMB_Trans_Response()
            rdata = SMB_Data()

            TransactionName = h.TransactionName
            if type(TransactionName) == bytes:
                if smbh.Flags2 & SMB_FLAGS2_UNICODE:
                    TransactionName = TransactionName.decode('utf-16')
                else:
                    TransactionName = TransactionName.decode('ascii')

            if TransactionName[-1] == '\0':
                TransactionName = TransactionName[:-1]

#			print("'{}' == '{}' => {} {} {}".format(TransactionName, '\\PIPE\\',
#				TransactionName == '\\PIPE\\', type(TransactionName) == type('\\PIPE\\'),
#				len(TransactionName)) )


            if TransactionName == '\\PIPE\\LANMAN':
                # [MS-RAP].pdf - Remote Administration Protocol
                rapbuf = bytes(h.Param)
                rap = RAP_Request(rapbuf)
                rap.show()
                rout = RAP_Response()
                coff = 0
                if rap.Opcode == RAP_OP_NETSHAREENUM:
                    (InfoLevel,ReceiveBufferSize) = struct.unpack(
                        "<HH",rap.Params)
                    print("InfoLevel {} ReceiveBufferSize {}".format(
                        InfoLevel, ReceiveBufferSize) )
                    if InfoLevel == 1:
                        l = len(__shares__)
                        rout.OutParams = struct.pack("<HH", l, l)
                    rout.OutData = b""
                    comments = []
                    for i in __shares__:
                        rout.OutData += struct.pack("<13sxHHH",
                                                    i, # NetworkName
                                                    # Pad
                                                    # Type
                                                    __shares__[i][
                                                        'type'] & 0xff,
                                                    # RemarkOffsetLow
                                                    coff + len(__shares__)*20,
                                                    0x0101) # RemarkOffsetHigh
                        comments.append(__shares__[i]['comment'])
                        coff += len(__shares__[i]['comment']) + 1
                    rout.show()
                outpacket = rout
                self.outbuf = outpacket.build()
                dceplen = len(self.outbuf) + coff

                r.TotalParamCount = 8 # Status|Convert|Count|Available
                r.TotalDataCount = dceplen

                r.ParamCount = 8 # Status|Convert|Count|Available
                r.ParamOffset = 56

                r.DataCount = dceplen
                r.DataOffset = 64

                rdata.ByteCount = dceplen
                rdata.Bytes = self.outbuf + \
                    b''.join(c.encode('ascii') + b'\x00' for c in comments)


            elif TransactionName == '\\PIPE\\':
                if socket.htons(h.Setup[0]) == TRANS_NMPIPE_TRANSACT:
                    outpacket = self.process_dcerpc_packet(
                        p.getlayer(DCERPC_Header))

                    if not outpacket:
                        if self.state['stop']:
                            smblog.debug('drop dead!')
                        else:
                            smblog.error('dcerpc processing failed. bailing out.')
                        return rp
                    self.outbuf = outpacket.build()
                    dceplen = len(self.outbuf)

                    r.TotalDataCount = dceplen
                    r.DataCount = dceplen

                    rdata.ByteCount = dceplen
                    rdata.Bytes = self.outbuf

                if socket.htons(h.Setup[0]) == TRANS_NMPIPE_PEEK:
                    SetupCount = h.SetupCount
                    if SetupCount > 0:
                        smblog.info('MS17-010 - SMB RCE exploit scanning..')
                        r = SMB_Trans_Response_Simple()
                        # returned #STATUS_INSUFF_SERVER_RESOURCE as we not being patched
                        rstatus = 0xc0000205  # STATUS_INSUFF_SERVER_RESOURCES

            r /= rdata
        elif Command == SMB_COM_TRANSACTION2:
            self.trans = True
            h = p.getlayer(SMB_Trans2_Request)
            if h.Setup[0] == SMB_TRANS2_SESSION_SETUP:
                smblog.info('Possible DoublePulsar connection attempts..')
                # determine DoublePulsar opcode and command
                # https://zerosum0x0.blogspot.sg/2017/04/doublepulsar-initial-smb-backdoor-ring.html
                # The opcode list is as follows:
                # 0x23 = ping
                # 0xc8 = exec
                # 0x77 = kil
                op = calculate_doublepulsar_opcode(h.Timeout)
                op2 = hex(op)[-2:]
                oplist = [('23','ping'), ('c8','exec'), ('77','kill')]
                for fid,command in oplist:
                    if op2 == fid:
                        smblog.info("DoublePulsar request opcode: %s command: %s" % (op2, command))
                if op2 != '23' and op2 != 'c8' and op2 != '77':
                    smblog.info("unknown opcode: %s" % op2)

                # make sure the payload size not larger than 10MB
                if len(self.buf2) > 10485760:
                    self.buf2 = b''
                elif len(self.buf2) == 0 and h.DataCount == 4096:
                    self.buf2 = self.buf2 + h.Data
                elif len(self.buf2) != 0 and h.DataCount == 4096:
                    self.buf2 = self.buf2 + h.Data
                elif len(self.buf2) != 0 and h.DataCount < 4096:
                    smblog.info('DoublePulsar payload receiving..')
                    self.buf2 = self.buf2 + h.Data
                    key = bytearray([0x52, 0x73, 0x36, 0x5E])
                    xor_output = xor(self.buf2, key)
                    hash_buf2 = hashlib.md5(self.buf2);
                    smblog.info('DoublePulsar payload - MD5 (before XOR decryption): %s' % (hash_buf2.hexdigest()))
                    hash_xor_output = hashlib.md5(xor_output);
                    smblog.info('DoublePulsar payload - MD5 (after XOR decryption ): %s' % (hash_xor_output.hexdigest()))

                    # payload = some data(shellcode or code to load the executable) + executable itself
                    # try to locate the executable and remove the prepended data
                    # now, we will have the executable itself
                    offset = 0
                    for i, c in enumerate(xor_output):
                        if ((xor_output[i] == 0x4d and xor_output[i + 1] == 0x5a) and xor_output[i + 2] == 0x90):
                            offset = i
                            smblog.info('DoublePulsar payload - MZ header found...')
                            break

                    # save the captured payload/gift/evil/buddy to disk
                    smblog.info('DoublePulsar payload - Save to disk')

                    dionaea_config = g_dionaea.config().get("dionaea")
                    download_dir = dionaea_config.get("download.dir")
                    download_suffix = dionaea_config.get("download.suffix", ".tmp")

                    fp = incoming_file("smb-", suffix=download_suffix, download_dir=download_dir)
                    fp.write(xor_output[offset:])
                    fp.close()
                    self.buf2 = b''
                    xor_output = b''

                    icd = incident("dionaea.download.complete")
                    icd.path = fp.name
                    # We need the url for logging
                    icd.url = ""
                    icd.con = self
                    icd.report()
                    os.unlink(fp.name)

                r = SMB_Trans2_Response()
                rstatus = 0xc0000002  # STATUS_NOT_IMPLEMENTED
            elif h.Setup[0] == SMB_TRANS2_FIND_FIRST2:
                r = SMB_Trans2_FIND_FIRST2_Response()
            else:
                r = SMB_Trans2_Response()

        elif Command == SMB_COM_DELETE:
            h = p.getlayer(SMB_Delete_Request)
            r = SMB_Delete_Response()
        elif Command in TRANS_SECONDARIES:
            # MS17-010 / EternalBlue starts with an SMB_COM_NT_TRANSACT and goes on with
            # SMB_COM_TRANSACTION2_SECONDARY, so the kinds, the order and the displacements
            # of the pieces are not checked. A continuation is not answered, as a
            # server does until the transaction is complete; without a transaction
            # before it, it is an error.
            if self.trans:
                self.no_answer = True
            else:
                r = SMB_Trans2_Response()
                # the answer to a continuation has the command and the ids of the request
                r.smb_cmd = Command
                rstatus = STATUS_INVALID_PARAMETER
        elif Command == SMB_COM_NT_TRANSACT:
            self.trans = True
            h = p.getlayer(SMB_NT_Trans_Request)
            r = SMB_NT_Trans_Response()
            rstatus = 0x00000000  # STATUS_SUCCESS
        else:
            smblog.error('...unknown SMB Command. bailing out.')
            p.show()

        if r:
            smbh = SMB_Header(Status=rstatus)
            smbh.Command = r.smb_cmd
            smbh.Flags2 = p.getlayer(SMB_Header).Flags2
#			smbh.Flags2 = p.getlayer(SMB_Header).Flags2 & ~SMB_FLAGS2_EXT_SEC
            smbh.MID = p.getlayer(SMB_Header).MID
            smbh.PID = p.getlayer(SMB_Header).PID
            smbh.TID = p.getlayer(SMB_Header).TID if reply_tid is None else reply_tid
            smbh.UID = p.getlayer(SMB_Header).UID if reply_uid is None else reply_uid
            if chained is not None:
                r = self.chain_tree_connect(r, smbh, chained)
            # Deception for DoublePulsar, we fix the XOR key first as 0x5273365E
            # WannaCry will use the XOR key to encrypt and deliver next payload, so we can decode easily later
            if Command == SMB_COM_TRANSACTION2:
                h = p.getlayer(SMB_Trans2_Request)
                if h.Setup[0] == SMB_TRANS2_SESSION_SETUP:
                    smbh.MID = p.getlayer(SMB_Header).MID + 16
                    smbh.Signature = 0x000000009cf9c567
            rp = NBTSession()/smbh/r

        if Command in SMB_Commands:
            self.state['lastcmd'] = SMB_Commands[
                p.getlayer(SMB_Header).Command]
        else:
            self.state['lastcmd'] = "UNKNOWN"
        return rp

    def process_dcerpc_packet(self, buf):
        if not isinstance(buf, DCERPC_Header):
            smblog.debug("got buf, make DCERPC_Header")
            dcep = DCERPC_Header(buf)
        else:
            dcep = buf

        outbuf = None

        smblog.debug("data")
        try:
            dcep.show()
        except:
            return None
        if dcep.AuthLen > 0:
            #			print(dcep.getlayer(Raw).underlayer.load)
            #			dcep.getlayer(Raw).underlayer.decode_payload_as(DCERPC_Auth_Verfier)
            dcep.show()

        if dcep.PacketType == 11: #bind
            outbuf = DCERPC_Header()/DCERPC_Bind_Ack()
            outbuf.CallID = dcep.CallID
            c = 0
            outbuf.CtxItems = [DCERPC_Ack_CtxItem()
                               for i in range(len(dcep.CtxItems))]
            while c < len(dcep.CtxItems): #isinstance(tmp, DCERPC_CtxItem):
                tmp = dcep.CtxItems[c]
                ctxitem = outbuf.CtxItems[c]
                service_uuid = UUID(bytes_le=tmp.UUID)
                transfersyntax_uuid = UUID(bytes_le=tmp.TransferSyntax)
                ctxitem.TransferSyntax = tmp.TransferSyntax #[:16]
                ctxitem.TransferSyntaxVersion = tmp.TransferSyntaxVersion
                if str(transfersyntax_uuid) == '8a885d04-1ceb-11c9-9fe8-08002b104860':
                    if service_uuid.hex in registered_services:
                        service = registered_services[service_uuid.hex]
                        smblog.info("Found a registered UUID (%s). Accepting Bind for %s" %
                                    (service_uuid , service.__class__.__name__))
                        self.state['uuid'] = service_uuid.hex
                        # Copy Transfer Syntax to CtxItem
                        ctxitem.AckResult = 0
                        ctxitem.AckReason = 0
                    else:
                        smblog.warning(
                            "Attempt to register %s failed, UUID does not exist or is not implemented",
                            service_uuid
                        )
                else:
                    smblog.warning(
                        "Attempt to register %s failed, TransferSyntax %s is unknown",
                        service_uuid,
                        transfersyntax_uuid
                    )
                i = incident("dionaea.modules.python.smb.dcerpc.bind")
                i.con = self
                i.uuid = str(service_uuid)
                i.transfersyntax = str(transfersyntax_uuid)
                i.report()
                c += 1
            outbuf.NumCtxItems = c
            outbuf.FragLen = len(outbuf.build())
            smblog.debug("dce reply")
            outbuf.show()
        elif dcep.PacketType == 0: #request
            resp = None
            if 'uuid' in self.state:
                service = registered_services[self.state['uuid']]
                resp = service.processrequest(service, self, dcep.OpNum, dcep)
                i = incident("dionaea.modules.python.smb.dcerpc.request")
                i.con = self
                i.uuid = str(UUID(bytes=bytes.fromhex(self.state['uuid'])))
                i.opnum = dcep.OpNum
                i.report()
            else:
                smblog.info("DCERPC Request without pending action")
            if not resp:
                self.state['stop'] = True
            outbuf = resp
        else:
            # unknown DCERPC packet -> logcrit and bail out.
            smblog.error('unknown DCERPC packet. bailing out.')
        return outbuf

    def handle_timeout_idle(self):
        return False

    def new_fid(self):
        """The next free file id, None if the client has too many files open."""
        if len(self.fids) >= MAX_OPEN_FIDS:
            # once per connection, a client can ask as often as it likes
            if not self.state.get('fid_limit_logged'):
                self.state['fid_limit_logged'] = True
                smblog.warning("%i files are open, no more allowed", len(self.fids))
            return None
        fid = 0x4000
        while fid in self.fids:
            fid += 0x200
        return fid

    def session_uid(self, uid):
        """The UID of the session of a SESSION_SETUP_ANDX with uid: that one if the session is known, else a new one."""
        if uid in self.uids:
            return uid
        if len(self.uids) >= MAX_SESSIONS:
            del self.uids[next(iter(self.uids))]
        uid = new_uid(self.uids)
        self.uids[uid] = True
        return uid

    def session_login(self, uid, username):
        """The session uid logged in as username: an empty name or guest stays anonymous."""
        if uid in self.uids:
            self.uids[uid] = not username or username.lower() == "guest"

    def share_type(self, share):
        """The type (STYPE_*) of a share of the config (smb.yaml shares, names in any case), None if there is none."""
        for name, options in self.config.shares.items():
            if name.lower() == share.lower():
                return options["type"]
        return None

    def tree_connect(self, h, smbh, uid, offset):
        """
        The reply to a TREE_CONNECT_ANDX as a Windows server with the shares of the config gives it.

        A share that is not in the config gets STATUS_BAD_NETWORK_NAME (except one whose name
        ends in "share", CVE-2017-7494), an administrative share (ADMIN$, C$, ...)
        STATUS_ACCESS_DENIED for an anonymous or guest session; otherwise a new TID, and the
        Service and NativeFileSystem of the type of the share.

        :param h: The request (SMB_Treeconnect_AndX_Request)
        :param uid: UID of the session of the request
        :param offset: Where the response starts in the reply, from the start of the SMB header
        :return: (response, status, TID or None)
        """
        unicode_names = smbh.Flags2 & SMB_FLAGS2_UNICODE
        share = share_name(decode_smb_name(h.Path, unicode_names))
        share_type = self.share_type(share)
        if share_type is None and share.lower().endswith("share"):
            # support for CVE-2017-7494 Samba SMB RCE
            smblog.info('Possible CVE-2017-7494 Samba SMB RCE attempts..')
            share_type = STYPE_DISKTREE
        if share_type is None:
            return SMB_Treeconnect_AndX_Response2(), STATUS_BAD_NETWORK_NAME, None
        if is_admin_share(share, share_type) and self.uids.get(uid, True):
            return SMB_Treeconnect_AndX_Response2(), STATUS_ACCESS_DENIED, None

        if h.Flags & 0x08:
            # TREE_CONNECT_ANDX_EXTENDED_RESPONSE
            r = SMB_Treeconnect_AndX_Response_Extended(
                MaximalShareAccessRights=MAXIMAL_SHARE_ACCESS, GuestMaximalShareAccessRights=0)
        else:
            r = SMB_Treeconnect_AndX_Response()
        service, file_system = TREE_SERVICES.get(share_type & 0x3, TREE_SERVICES[STYPE_DISKTREE])
        r.Service = service + "\0"
        r.NativeFileSystem = file_system + "\0"
        # a unicode NativeFileSystem is word-aligned from the start of the SMB header
        end_of_service = offset + 1 + 2 * r.WordCount + 2 + len(r.Service)
        r.Padding = b"\0" if unicode_names and end_of_service % 2 else b""
        return r, 0, self.new_tree(share)

    def new_tree(self, share):
        """The TID of a new tree of the client on share (the oldest one is forgotten when there are too many);
        the tree keeps at most MAX_SHARE_LENGTH characters of the share, which go into the url of an upload."""
        if len(self.trees) >= MAX_TREES:
            del self.trees[next(iter(self.trees))]
        tid = self.next_tid
        while tid in self.trees or tid in (0, 0xffff):
            tid = (tid + 1) % 0x10000
        self.next_tid = (tid + 1) % 0x10000
        self.trees[tid] = share[:MAX_SHARE_LENGTH]
        return tid

    def chained_tree_connect(self, setup, smbh, uid):
        """The TREE_CONNECT_ANDX behind a SESSION_SETUP_ANDX (at its AndXOffset), None if it is not there."""
        message = self.smb_message
        offset = setup.AndXOffset
        if message is None or offset < 32 or offset >= len(message):
            return None
        try:
            request = SMB_Treeconnect_AndX_Request(message[offset:], _underlayer=smbh)
            request.Path
        except (ValueError, IndexError, KeyError, AttributeError, TypeError, struct.error, UnicodeError) as e:
            smblog.info("chained TREE_CONNECT_ANDX not parsed: %s", e)
            return None
        return request, uid

    def chain_tree_connect(self, r, smbh, chained):
        """
        The reply of a SESSION_SETUP_ANDX (r) with the reply of the TREE_CONNECT_ANDX chained to it, as Windows
        gives it: one message, the session setup response points at the tree connect response (AndXOffset), the
        header has the new TID, and the status of the tree connect if it failed.
        """
        request, uid = chained
        r.AndXCommand = SMB_COM_TREE_CONNECT_ANDX
        offset = len((SMB_Header(Flags2=smbh.Flags2) / r).build())
        r.AndXOffset = offset
        tree, status, tid = self.tree_connect(request, smbh, uid, offset)
        if tid is not None:
            smbh.TID = tid
        if status:
            smbh.Status = status
        return r / tree

    def open_upload(self, response, filename, share=None):
        """
        The client opened a file: collect what it writes, offer it as a download.

        :param share: Share of the tree of the request, None if the TID is not known
        """
        if is_pipe_name(filename):
            # a service, the writes are DCERPC
            self.fids[response.FID] = None
            return
        try:
            upload = UploadFile("smb-", max_size=getattr(self.config, "max_upload_size", DEFAULT_MAX_UPLOAD_SIZE))
        except OSError as e:
            smblog.error("unable to create a file for an upload: %s", e)
            self.fids[response.FID] = None
            return
        upload.client_name = filename
        upload.share = share
        self.fids[response.FID] = upload

        url = upload_url("smb", self.remote.host, filename, share)
        i = incident("dionaea.download.offer")
        i.con = self
        i.url = url
        i.report()
        smblog.info("OPEN FILE! %s" % url)

    def write_upload(self, fid, data, offset):
        """
        Write data of a client into its open file.

        :return: Number of bytes written and the status of the response
        """
        upload = self.fids[fid]
        try:
            return upload.write(data, offset), 0
        except UploadTooLarge as e:
            # a file this large is not what the service is for: drop it, the client gets the errors
            smblog.warning("upload dropped: %s", e)
            upload.discard()
            return 0, STATUS_DISK_FULL
        except UploadError as e:
            smblog.warning("upload failed: %s", e)
            upload.discard()
            return 0, STATUS_UNSUCCESSFUL

    def handle_disconnect(self):
        # files that were not closed by the client are dropped
        for upload in self.fids.values():
            if upload is not None:
                upload.discard()
        self.fids.clear()
        return 0

class epmapper(smbd):
    def __init__ (self):
        connection.__init__(self,"tcp")
        smbd.__init__(self)

    def handle_io_in(self,data):
        try:
            p = DCERPC_Header(data)
        except:
            t = traceback.format_exc()
            smblog.error(t)
            return len(data)

        if len(data) < p.FragLen:
            smblog.debug("epmapper - not enough data")
            return 0

        smblog.debug("packet: %s" % p.summary())

        r = self.process_dcerpc_packet(p)

        if self.state['stop']:
            smblog.info("faint death.")
            return len(data)

        if not r or r is None:
            smblog.error('dcerpc processing failed. bailing out.')
            return len(data)

        smblog.debug("response: %s" % r.summary())
        r.show()
        self.send(r.build())

        if p.haslayer(Raw):
            smblog.debug("p.haslayer(Raw): %s" % p.getlayer(Raw).build())
            p.show()

        return len(data)


from . import rpcservices
import inspect
services = inspect.getmembers(rpcservices, inspect.isclass)
for name, servicecls in services:
    if not name == 'RPCService' and issubclass(servicecls, rpcservices.RPCService):
        register_rpc_service(servicecls())
