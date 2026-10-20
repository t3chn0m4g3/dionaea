..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

SMB
===

The main protocol offerd by dionaea is SMB. SMB has a decent history of
remote exploitable bugs, and is a very popular target for worms.
dionaeas SMB implementation makes use of an python3 adapted version of
scapy. As scapys own version of SMB was pretty limited, almost
everything but the Field declarations had to be rewritten. The SMB
emulation written for dionaea is used by the mwcollectd
<http://code.mwcollect.org> low interaction honeypot too.
Besides the known attacks on SMB dionaea supports uploading files to smb
shares.
Adding new DCE remote procedure calls is a good start to get into
dionaea code, you can use:

.. code-block:: sql

    SELECT
            COUNT(*),
            dcerpcrequests.dcerpcrequest_uuid,
            dcerpcservice_name,
            dcerpcrequest_opnum
    FROM
            dcerpcrequests
            JOIN dcerpcservices ON(dcerpcrequests.dcerpcrequest_uuid == dcerpcservices.dcerpcservice_uuid)
            LEFT OUTER JOIN dcerpcserviceops ON(dcerpcserviceops.dcerpcserviceop_opnum = dcerpcrequest_opnum AND dcerpcservices.dcerpcservice = dcerpcserviceops.dcerpcservice )
    WHERE
            dcerpcserviceop_name IS NULL
    GROUP BY
            dcerpcrequests.dcerpcrequest_uuid,dcerpcservice_name,dcerpcrequest_opnum
    ORDER BY
            COUNT(*) DESC;


to identify potential usefull targets of unknown dcerpc calls using the
data you gathered and stored in your logsql database. Patches are
appreciated.

Authentication and SMB2
-----------------------

SMB1 accepts both extended-security NTLMSSP/SPNEGO logins and legacy
session setup. SMB2 dialects 2.02 and 2.10 support negotiation and
NTLMSSP/SPNEGO session setup. After recording an SMB2 authenticate message,
the server replies with ``STATUS_LOGON_FAILURE``. SMB2 file operations and
compound requests are not implemented; use SMB1 to capture uploads.

NTLM challenges include computer and domain names from the existing SMB
configuration, a current timestamp, and a random challenge. The server GUID
is shared by connections of one listener and changes when it restarts.
Messages are limited to 128 KiB; malformed authentication data closes the
connection without logging a traceback.

A login reports ``dionaea.modules.python.smb.login`` with the connection,
username, domain, workstation, dialect and ``ntlm_version``. The latter is
``NTLMv1``, ``NTLMv2`` or ``unknown`` and describes the authentication
response, not the operating system version in an NTLM Version field.
Passwords are recorded as empty strings. JSON adds the SMB metadata to
``credentials`` and ``smb``; SQLite adds a row to the existing ``logins``
table without changing its schema. Legacy logins without an identifiable
NTLM response are recorded as ``unknown``.

Uploads
-------

A file that a client writes to a share (SMB1: ``NT_CREATE_ANDX`` or
``OPEN_ANDX``, ``WRITE``, ``WRITE_ANDX``, ``CLOSE``) is stored like a download:
``<download.dir>/<md5>`` and a row in the table ``downloads`` of the sqlite log,
the hashes are in the ``downloads`` key of the connection in ``log_json``. The
file is complete when the client closes it. Pipes of the DCERPC services
(``\\srvsvc``, ``\\lsarpc``, ...) are no files.

The url of an upload (and of the matching entry in ``offers``) is
``smb://<address of the client>/<share>/<file name>``: the share of the tree
the file was opened on (``C$``, ``DATA``, ...; the last part of the path of the
``TREE_CONNECT_ANDX``), the name is what the client sent; both are percent
encoded (``$`` stays; a part of only dots, ``.`` or ``..``, is percent encoded too)
and cut to 255 characters. A file opened on a TID dionaea
did not give out has the url ``smb://<address of the client>/<file name>``.

Shares
------

A ``TREE_CONNECT_ANDX`` is answered as a Windows host with the shares of
``shares`` in ``smb.yaml`` (the T-Pot persona: ``ADMIN$``, ``C$``, ``IPC$``,
``Printer``; names in any case) answers it:

* a share that is not configured: ``STATUS_BAD_NETWORK_NAME`` (``0xc00000cc``),
  no tree; except a name that ends in ``share``, which is taken as a disk share
  (CVE-2017-7494, a Samba exploit, is logged);
* an administrative share (``ADMIN$``, ``C$``, ``<drive>$``, a share of type
  ``special``; not ``IPC$`` and ``PRINT$``) for an anonymous session (empty user
  name, a null session) or a guest (user name ``guest``):
  ``STATUS_ACCESS_DENIED`` (``0xc0000022``), as a Windows host where the guest
  account is disabled; any other user name counts as an administrator (dionaea
  accepts every login);
* otherwise a new TID, ``Service`` and ``NativeFileSystem`` by the type of the
  share (MS-CIFS 2.2.4.55.2): disk ``A:`` / ``NTFS``, ``ipc`` ``IPC`` / empty,
  ``printq`` ``LPT1:`` / empty; ``NativeFileSystem`` in Unicode (word-aligned) when
  the client uses Unicode. An extended response (``TREE_CONNECT_ANDX_EXTENDED_RESPONSE``)
  gives ``MaximalShareAccessRights`` ``0x001f01ff`` and ``GuestMaximalShareAccessRights`` 0.

``IPC$`` is open to every session, also to a null session (the MS17-010
scanners and exploits use it).

AndX chains: a ``TREE_CONNECT_ANDX`` chained behind a ``SESSION_SETUP_ANDX``
(without extended security) is answered in the same reply as Windows does: the
session setup response points at the tree connect response (``AndXOffset``), the
header carries the new UID and TID, or the error of the tree connect. Every other
chain is answered for its first command only, as before.

Like a Windows server, dionaea gives a session a UID in the reply to
``SESSION_SETUP_ANDX`` and a tree a TID in the reply to ``TREE_CONNECT_ANDX``
(both counted from ``0x0800``); every other reply carries the TID and the UID of
its request. A
connection keeps up to 32 trees and 16 sessions; the TID and the UID of a
request are not checked (a request on an unknown tree is answered as before).

A client can have 32 files open per connection. A file larger than
``max_upload_size`` (bytes, default 33554432 = 32 MiB, counted by the highest
offset written) is dropped when the first write beyond the limit arrives: that
write and all later writes to the file fail (``STATUS_DISK_FULL``) and the file
is not recorded. An empty file is not recorded, nor is a file that is mostly
holes (more than 1 MiB larger than the data written into it, e.g. 100 bytes at
an offset of 32 MiB). Files the client did not close
are dropped when the connection ends.

The commands of the client are logged in ``log_json`` as ``smb.commands`` (the
name of the command, no arguments; a command without a name as ``0x<hex>``).

Example config
--------------

The default port is `445`; it can be changed via the `port` stanza.

.. literalinclude:: ../../../conf/services/smb.yaml
    :language: yaml
    :caption: services/smb.yaml
