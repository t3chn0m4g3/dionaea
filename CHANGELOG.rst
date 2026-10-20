..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2016-2020 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

Changelog
=========

0.12.1 - (`master`_)
--------------------

**libemu**

* The emulated MUL and IMUL compute the full product and set CF and OF as x86 does:
  MUL when the upper half of the product is not 0, IMUL when the product does not fit
  the destination size. This holds for every form of IMUL, also 0F AF and 69, which
  the CPU does not dispatch.
* The emulated fwrite and WriteFile write at most 1 MiB per call. A longer write writes
  nothing and returns 0, WriteFile with 0 bytes written; fwrite computes size * count
  in 64 bits.
* The emulated send records an empty byte argument when it returns -1 for more than
  64 KiB; recv writes at most the 4096 bytes it hands the emulated program.
* fwrite, WriteFile, _lwrite, send, sendto and recv return their error value when
  their copy of the buffer can not be allocated; the emulation goes on at the return
  address.

**emu**

* Profiles of long byte arguments are written in full; an empty byte argument is an
  empty string.

**tests**

* ``tests/libemu/test_mul.c`` runs MUL and IMUL on instruction bytes and checks EDX:EAX,
  CF and OF; ``test_w32_hooks.c`` the copies of the hooks above with a profile;
  ``tests/processor/test_profile.c`` the JSON of byte arguments.
* The TLS clients of the tests (the early close scenario, the HTTPS request of the
  replay) ask for TLS 1.2 at least; ``tests/load/test_tls_minimum.py`` checks it.

0.12.0 - (2026-10-20)
---------------------

**build and runtime**

* Build and run on Ubuntu 26.04 with bundled libemu; preserve its licence. The libdasm
  of libemu is the public domain libdasm 1.4 (``LicenseRef-PublicDomain-libdasm``), not
  the 2-clause BSD libdasm 1.6.
* Replace embedded Windows DLL bytes with independently generated PE32 export
  tables; preserve API addresses and hooks. Test PEB/export resolution and
  ordinal lookup without DLL-array sanitizer suppressions.
* Remove loudmouth/libnl and repair the Python 3.14, OpenSSL and curl paths.
* Use RelWithDebInfo; dionaea stays idle when stdin is closed, when no file descriptor is
  free and when a mirror connect-back ends.
* Repair TFTP service loading, active FTP data connections and download handlers.
* HTTP downloads work with current curl; they were broken in the prior T-Pot image.

**authentication, downloads and uploads**

* SMB2 2.02/2.10 negotiation and SPNEGO/NTLMSSP authentication capture, followed
  by STATUS_LOGON_FAILURE. No SMB2 file operations.
* SMB1 extended security uses the same bounded NTLM parsing and TargetInfo.
  Mixed dialect offers retain SMB1 file capture; explicit SMB2 offers upgrade.
* Record SMB usernames, domain, workstation, dialect and NTLMv1/NTLMv2/unknown
  authentication variants. Store readable legacy passwords; keep NTLM password
  fields empty. Existing JSON field types, SQLite schemas and timestamps remain.
* Confine client SQL to the configured MySQL emulation database; deny SQLite
  attachments, VACUUM INTO, PRAGMAs other than ``table_info`` and file/extension functions.
* Check resolved HTTP/FTP/TFTP download destinations before connecting, including
  HTTP redirects. Private destinations require an explicit lab allowlist;
  loopback, local addresses, link-local and gateways are always blocked.
* A download whose target the download target filter refused is one info line,
  ``download target refused by the filter: <url>``. Any other download that does not
  complete (HTTP, FTP, TFTP) is one info line with its reason, ``download failed: <url>
  (<reason>)``, and at most one warning a minute sums them up, ``downloads: <N> failed in
  the last minute, the last: <url> (<reason>)``: the first at once, the others when that
  minute ends (see the ``download_policy`` docs). They replace the warning of every
  download (``DOWNLOAD FAIL``, ``Download destination denied``). The url and the reason
  in these lines are printable ASCII (``?`` for any other byte), at most 256 characters
  each.
* Quarantine FTP, HTTP, TFTP, SMB and printer uploads; never serve them through
  another connection. Samples are stored read-only at 0440. An optional total
  store cap refuses storage while retaining the hash incident and log entry.
* A print job over 32 MiB is stored as a truncated sample (at most its first 32 MiB,
  an md5 that is not that of the whole job); FTP, SMB and HTTP uploads over their limit
  are dropped; uploads whose transfer ends early are stored as far as they came. The
  ``store`` and ``printer`` docs list the cases.
* Optional streamdumper limits ``config.max_size`` (MiB) and ``config.max_files``
  for all bistreams: a connection over a limit gets no dump and goes on, an open
  dump stops (closed, valid) at ``max_size``, one warning per minute and kind;
  the folder is counted once at the start, beside the eventloop, then only its
  date folders are looked at every minute (a removed or replaced one is counted
  again, and at a refused connection the ones dionaea did not make whose mtime
  changed, at most every 10 minutes; today's folder counts as dionaea's after
  a restart too; one that can not be read is tried again, backed off); a count
  ends at once when dionaea stops. The dumps of the connections that are still
  open when dionaea stops are closed as valid dumps (ending in ``')]``).
* The environment variables ``DIONAEA_STREAMDUMPER_MAX_SIZE`` (MiB) and
  ``DIONAEA_STREAMDUMPER_MAX_FILES`` replace ``config.max_size`` and
  ``config.max_files`` when set (decimal digits; an invalid value is a warning and
  the config holds). One line per limit at the start names the value in effect and
  its source, ``streamdumper: max_size <N> MiB (from <SOURCE>)`` and
  ``streamdumper: max_files <N> (from <SOURCE>)``, ``<SOURCE>`` the variable or
  ``dionaea.cfg`` (see the ``streamdumper`` docs).
* The environment variable ``DIONAEA_STORE_MAX_SIZE`` (MiB) replaces ``max_size`` of
  the store handler when set, with the same rules; its line at the start is
  ``store: max_size <N> MiB (from <SOURCE>)``, ``<SOURCE>`` the variable or
  ``store.yaml`` (see the ``store`` docs). ``max_size`` of the store goes up to 2^40 MiB,
  as that of the streamdumper; a larger value is a warning.
* An ihandler that can not start is logged as an error, the other ihandlers start; a
  handler whose ``start()`` raises is removed, no incident reaches it.
* dionaea handles SIGTERM, SIGINT and SIGHUP before its services listen: a stop right
  after the start (dionaea as PID 1 of a container) ends it at once, with exit code 0 and
  its log files written.
* A log file whose levels have neither debug nor info (``errors.levels=warning,error``) is
  written per line, so a warning is in it at once; the other log files keep their buffer.
* emu ``CreateFile`` / ``_lcreat`` and curl downloads and uploads fail on their own when no
  temp file can be made (no free file descriptor, a full disk); dionaea goes on.
* A temp file (streamdumper, emu) closes its descriptor exactly once.

**stream processing and limits**

* The emu scans only the first 4 MiB of a connection, in windows of 64 KiB (plus
  300 bytes of overlap). At a limit it gives up for that connection with one warning; the
  connection and its uploads go on. xmatch and unicode, which need the whole
  stream, close the connection at the limits.
* The emu worker gives the memory of libemu's instruction graph back after a scan
  that built one (``malloc_trim``, glibc only, at most every 5 s; a trim the limit
  skipped follows once the emu is idle): the RSS floor under load is about 93 MiB
  instead of 163 (the graphs of running scans come on top of it, up to about 180 MiB).
* libemu's prefix map is a constant table shared by the emu workers.
* Stream data is bounded: 1 MiB per processor instance, 32 MiB per process; the
  threadpool has 4 workers and at most 32 waiting jobs, more are refused, never
  waited for. The last stream chunk grows by doubling.
* At the stop the buffered rows of log_sqlite are committed before dionaea waits
  for the threadpool (module api ``flush``), waiting processor jobs are dropped.
* TFTP: at most 64 server sessions, 4 per source address (``::ffff:a.b.c.d`` is
  the IPv4 address). A read request over that gets a ``Too many sessions`` ERROR
  reply; ERROR replies of the server socket and of the sessions (file missing, path
  outside the root, mode) are rate-limited per source and in all, in the same buckets.
* MQTT frames packets by their fixed header; a packet over 64 KiB closes the
  connection, logged with its size, type, source and topic (never the payload).
* MQTT keeps the protocol level of the CONNECT: the topic filter of an MQTT 5
  SUBSCRIBE is read behind its properties, and the packet identifier and topic of a
  SUBSCRIBE with a remaining length of more than one byte (over 127 bytes) are right;
  both were logged wrong (``subscribetopic`` / ``subscribemessageid``, same keys and types).
* The CONNACK and the SUBACK of MQTT 5 carry their property length (0), which an MQTT 5
  client needs to read them. The SUBACK (3.1.1 and 5) has one return code per topic filter,
  the QoS the filter asks for (``0x80`` for malformed options), and a remaining length that
  counts them: the SUBACK of 3.1.1 said 2 bytes and sent 3, so a client read no return code.
* The topic and message of a PUBLISH are read by its remaining length (a variable byte
  integer), its QoS (packet identifier) and, with MQTT 5, behind its properties: the
  message of a PUBLISH over 127 bytes was cut or shifted, MQTT 5 properties were part of
  it (``publishtopic`` / ``publishmessage``, same keys and types). The PUBACK / PUBREC
  carries the packet identifier of the PUBLISH. A QoS 0 PUBLISH with the RETAIN or DUP
  flag is logged (it was taken for an unknown packet).
* log_sqlite commits once a second from a timer of the loop, not per incident:
  rows are in ``dionaea.sqlite`` up to 1 s after the event (``dionaea.json`` at
  once). Readers that poll the database, such as ewsposter, see them that late.
* The store counts ``download.dir`` once, beside the event loop, and again when
  the folder was replaced, or at a refused sample when the folder changed since
  (samples removed from outside, at most every 10 minutes); a ``max_size`` below
  one byte is one byte, not unlimited. The temporary files of samples (all
  services, curl, the copy of an emulation sample) are in ``download.dir/.incoming``
  (0700, emptied at the start), so they do not change ``download.dir``: a full
  folder is not read again while samples come.

**fixes**

* The ``recv failed`` line of a TCP connection names the connection (address and port).
* Lines a client causes are logged at info or debug instead of warning, so
  ``dionaea-errors.log`` (``warning,error``) is much quieter: the TFTP session messages
  (ERR packets, unsupported modes and options, paths outside the root, missing files), the
  FTP command and bounce lines, ``SMB message exceeds limit``, epmapper, ``no attack data``
  of log_json, ``no attackid`` of logsql, ``getpeername failed`` with ``ENOTCONN`` and
  ``recv failed`` with ``ECONNRESET`` / ``EPIPE``.
* Warnings that name a text of a client (the url of a curl download or upload, a file name
  of TFTP, an FTP argument, an HTTP header, a PJL line, SMB and MySQL data) write it as
  printable ASCII (``?`` for any other byte), at most 256 characters
  (``src/log_text.c``, ``dionaea/logtext.py``).
* UDP: a connection that closed itself while it handled a datagram (a TFTP session at its
  last ACK or after its ERROR reply) is not read any more.
* MySQL: the values of a result row carry no trailing NUL byte.
* TLS: a failed send closes the connection after ``connection_send`` returns.
* A TCP connection reads its receive queue in pieces of a fixed size.
* Python: the modules stop with the GIL held;
  ``g_dionaea.config()`` releases every value it returns;
  ``connection.__init__`` checks the defaults of a class once, not per wrapper.
* mirror: a client that closes before the connect-back is established no
  longer raises ``AttributeError``.
* TLS: the certificate made for a listener gives back its references to the key and
  the certificate (a listener that was freed kept them).
* MongoDB: a message shorter than its 16 byte header, above 64 KiB, or with a body or
  BSON that can not be read closes the connection with one info line.

**python/binding**

* ``dionaea.core.timer(callback, after, repeat=0)``: a timer of the event loop.
* ``g_dionaea.processor_stats()``: read-only counters of the stream processing
  (bytes, chunks, waiting and refused jobs, overloads, gave_up).

**tests**

* Functional tests in containers (``tests/functional``), C unit tests of the stream
  processing (``tests/processor``) and load tools (``tests/load``: the load test,
  a replay of the functional scenarios, ``tftp_load.py``), all with the T-Pot
  runtime (uid/gid 2000, read-only, a 16 MiB tmpfs on ``/tmp``). The client image of the
  tests is pinned (base image digest, Debian snapshot, pip hashes); the replay of an image
  of another architecture (emulated) reports the THP check and the memory gates as not
  applicable.

**python/ftp**

* Uploads (``STOR``) are captured: stored like a download (``<download.dir>/<md5>``, table
  ``downloads``) with the url ``ftp://<client>/<file name>``, no longer written into the root
  of the service (from vertebarbe/dionaea)
* Uploads larger than ``max_upload_size`` (default 32 MiB) are dropped, answer ``552``
* A full disk or quota (``ENOSPC``, ``EDQUOT``) answers ``452`` and is a warning, so it is
  in ``dionaea-errors.log``
* A ``PORT`` to an address other than that of the client is answered ``500 Illegal PORT
  command.``, the session goes on
* A ``PORT`` whose connect fails and a ``PASV`` whose listen fails answer ``425`` and leave no
  data connection behind; a file or folder of ``RETR`` / ``LIST`` that can not be opened
  answers ``550``, a ``RETR`` whose read fails ``451``
* The url of an upload encodes a path segment of only dots (``%2E``); this holds for FTP
  as for SMB

**python/smb**

* SMB1 uploads (``NT_CREATE_ANDX``, ``OPEN_ANDX``, ``WRITE``, ``WRITE_ANDX``, ``CLOSE``) are
  captured with the url ``smb://<client>/<share>/<file name>`` (the share of the TID of
  the request; without a known TID ``smb://<client>/<file name>``), offsets and sizes are bound by
  ``max_upload_size`` (default 32 MiB), at most 32 open files per connection (from
  vertebarbe/dionaea)
* SMB1 replies carry the UID of the session from ``SESSION_SETUP_ANDX``, the TID of a new
  tree from ``TREE_CONNECT_ANDX`` and otherwise the TID and the UID of the request, as a
  Windows server does. The trees (with their share) and sessions are kept per connection, up to
  32 and 16; the ids of a request are not checked.
* ``TREE_CONNECT_ANDX`` follows the shares of the persona (``smb.yaml``): a share that is
  not configured gets ``STATUS_BAD_NETWORK_NAME`` (it was accepted, whatever its name), an
  administrative share (``ADMIN$``, ``C$``) ``STATUS_ACCESS_DENIED`` for an anonymous or guest
  session, and the reply has
  the ``Service`` / ``NativeFileSystem`` of the type of the share (``A:`` / ``NTFS``, ``IPC``,
  ``LPT1:``; it was the share name without ``$``, e.g. ``C``), Unicode and word-aligned when
  the client uses Unicode. A ``TREE_CONNECT_ANDX`` chained behind a ``SESSION_SETUP_ANDX``
  is answered in the chain (it was dropped while the request was dissected).
* A tree keeps at most 256 characters of its share (the name of the client, of any length
  for one that ends in ``share``); the url of an upload takes 255 of them, as before
* Fix the data length of ``WRITE_ANDX`` of large writes (from vertebarbe/dionaea)
* Files that are mostly holes (more than 1 MiB larger than the data written) are not recorded
* Fix the file name of offers (was ``b'\\name\x00'``), pipes of services are no files
* Log the commands of a client (``dionaea.modules.python.smb.command``, from vertebarbe/dionaea)
* Every request that arrives in one read is processed (the ``*_SECONDARY`` packets of MS17-010
  come in bursts; the bytes behind the first message were taken as its data or left until more
  data arrived)
* Track the order of ``SMB_COM_TRANSACTION``, ``_TRANSACTION2`` and ``_NT_TRANSACT`` and their
  ``*_SECONDARY`` requests (from DinoTools/dionaea ``eternalblue``): a continuation after a
  transaction of any kind is accepted without an answer, also behind other commands, in any
  order and with any totals or displacements (nothing is buffered); without a transaction
  before it ``STATUS_INVALID_PARAMETER`` is the answer, with the command of the request.
  ``SMB_COM_TRANSACTION_SECONDARY`` and ``_NT_TRANSACT_SECONDARY`` are no unknown commands any
  more, ``SMB_COM_TRANSACTION2_SECONDARY`` is read by its counts and no longer raises on a
  short request

**python/http**

* Multipart uploads: a boundary is a delimiter only as a whole line (``--boundary``
  followed by a line break, ``--`` or the end), so ``--boundaryX`` inside a file does not
  split it; bodies with bare LF line breaks are read (the line break of the first
  delimiter counts); the files of nested ``multipart/mixed`` parts are stored, up to
  three levels deep, with the field name of the part that holds them. The limits stay:
  ``get_max_num_fields`` counts the parts of all levels before they are parsed, the
  request is bound by ``max_request_size`` (32 MiB in T-Pot), linear time; the content
  of a file is stored as sent.
* The request of a multipart body ends at its closing delimiter line (CRLF or LF) or at
  its Content-Length, whichever comes first; a quoted boundary (``boundary="..."``) is
  found. A bare-LF body and a closing delimiter without a line break complete the request,
  ``--boundary--`` inside a line of a file does not end it.
* The temporary file of a POST body (in ``download.dir/.incoming``) is closed and removed
  when the body is parsed, when the request is over ``max_request_size`` (413; nothing
  more of it is read) and when the client leaves before the body is complete.

**python/emu_scripts**

* The URL of common script stagers is found: PowerShell ``Net.WebClient``
  ``DownloadString`` / ``DownloadFile`` / ``DownloadData`` (also inside ``IEX`` /
  ``Invoke-Expression``), ``Invoke-WebRequest`` / ``iwr``, ``Invoke-RestMethod`` / ``irm``,
  ``Start-BitsTransfer -Source``; VBScript ``.Open "GET", url`` of ``MSXML2.XMLHTTP``,
  ``Microsoft.XMLHTTP``, ``MSXML2.ServerXMLHTTP`` and ``WinHttp.WinHttpRequest``. Case,
  whitespace, ``'...'`` / ``"..."``, a simple concatenation of literals (``+``, ``&``)
  and a variable assigned a literal are understood; nothing of the script is run.
  Stagers and assignments in comments (PowerShell ``#`` and ``<# ... #>``, VBScript ``'``
  and ``Rem``) are skipped; the comments are found in one pass with the string literals
  (up to 16,384 of them, the rest of a file counts as code).
* The patterns run in linear time (1 MiB of large input per pattern in under 100 ms);
  at most 256 calls per pattern and 64 URLs per file. A
  variable is looked up by bisection in the assignments (one pass, at most 4,096),
  each literal read once, so a file costs linear time (30 MiB in about 0.6 s).
* The URLs go the way of every offer, so the download handlers still check their
  destination.
* The first letter of a cmdlet belongs to it: ``swr``, ``srm`` or ``itart-BitsTransfer``
  are no stagers.

**python/log_json**

New keys, existing keys and their types are unchanged:

* ``downloads``: list of ``path``, ``url``, ``md5`` and ``sha256`` of every file that was
  downloaded for or uploaded by the client (from vertebarbe/dionaea)
* ``smb.commands``: list of ``command``, the name of every SMB command of the client
* ``smb.domain``, ``workstation``, ``dialect``, ``ntlm_version``: login metadata;
  the same metadata uses the existing credential list fields

**python/store**

* ``dionaea.download.complete.hash`` and ``.unique`` / ``.again`` carry ``sha256hash``; the
  file is still named by its md5 (vertebarbe/dionaea names it by the sha256)

0.11.0 - (2020-11-30)
---------------------

**python**

* Add function calls to enable Python thread handling
* Add GIL handling and only ensure the lock if dionaea runs Python code
* Add Timer class and use Python threading

**python/pyev**

* Remove all source files and build steps from the source tree
  * pyev seems to be abandoned, no official repo
  * Use new Timer class

0.10.0 - (2020-11-16)
---------------------

**ci**

* Add mypy check

**dionaea**

* Add support for certificate chain files
* Add documentation for touched code

**doc**

* Update install instructions

**python**

* Drop Support for Python < 3.6

**python/http**

* Fix flake8 errors
* Fix issue with default Content-Type (Fixes #252)
* Add support to detect Content-Type by filename
* Add documentation to config
* Add new function to split path and query string (Refs #203)
* Add warnings if Jinja is not available
* Fix issues with template rendering
* Add connection context to template context
* Add improvements to POST request handling
* Add function to add GET vars to template context
* Add example how to use HTML forms in templates

**python/printer**

* Add initial release of the new printer service (Thanks Michael Neu)
* Add tests for printer service (Thanks Michael Neu)

**python/smb**

* Add config value to specify port

0.9.2 - (2020-10-25)
--------------------

**docker**

* Build and push docker images

0.9.1 - (2020-10-15)
--------------------

**ci**

* Add pre-commit config and fix code
* Add flake8 checks
* Add GitHub workflow to scan for vulnerabilities using CodeQL

**dev**

* Remove vagrant config

**dionaea**

* Add licensing information
* Add SPDX header to all files

**doc**

* Add info about first time setup

0.9.0 - (2020-09-18)
--------------------

**ci**

* Replace Jenkins with Drone CI

**development**

* Add docker compose to setup development environment

**dionaea**

* Improve names of bistrem files (Thanks Aws0mus)
* Fix reconnects with IP only
* Fix dropping privileges (Thanks Michal Ambroz)
* Fix bug to detect if linux/sockios.h is installed

**python**

* Add class to report more information about connection issues
* Fix support Cython < 0.21
* Add additional information if parsing a YAML file fails
* Change YAML load to safe load
* Replace deprecated API calls with new ones

**python/hpfeeds**

* Fix to show error message instead of id
* Add option to set reconnect timeout
* Change error handling to send authentication before sending messages (Thanks John Carr)

**python/mssql**

* Replace warn() with warning()

**python/mysql**

* Improve detection (Thanks Yorick Koster)

**python/s3**

* Add new ihandler to upload files to S3 storage (Thanks gento)

**python/virustotal**

* Add support for custom comments (Thanks Matteo Cantoni)


0.8.0 - (2018-06-15)
--------------------

**doc**

* Add migration instructions
* Fix warnings

**build**

* Replace autotools with cmake
* Remove autotools files
* Add git information to version string on development builds

**dionaea**

* Add option to enable/disable IPv4 mapped IPv6 addresses


0.7.0 - (2018-05-01)
--------------------

**build**

* Add initial cmake support

**ci**

* Add Debian 9

**dionaea**

* Fix build error with OpenSSL 1.1.0
* Improve OpenSSL 1.1.0 support
* Cleanup connection code
* Enable bistream for SSL/TLS connections (Thanks Aws0mus)
* Fixing chroot bugs (Thanks Michal Ambroz)

**doc**

* Add additional information
* Doxygen config file for dionaea c core
* Ubuntu 16.04 install instructions

**package**

* Remove old and deprecated debian package config

**python**

* Fix typo in config key
* Fix hardcoded python path
* Fix compilation on CentOS7 (Thanks Michal Ambroz)

**python/http**

* Initial support to handle SOAP requests

**python/log_incident**

* Improve hash generator
* Fix bug if parent is unknown
* Remove IDs from list if processed

**python/mongo**

* Initial support to simulate a MongoDB server

**python/pyev**

* Update from 0.8 to 0.9 to support Python >= 3.6

**python/smb**

* Add support for WannaCry and SambaCry (Big thanks to gento)
* Add additional config options to change identity

**python/util**

* Find Download commands for Linux shell

0.6.0 - (2016-11-14)
--------------------

**dionaea**

* Fix build for musl lib

**doc**

* Fix install instructions
* Extend README.md

**python/blackhole**

* New service/Initial version

**python/emu_scripts**

* New handler to analyse downloaded scripts
* Detect VBScript and PowerShell
* Limit number of subdownloads

**python/http**

* Clean up
* Use state vars instead of strings
* Add template support
  * Jinja 2 template engine
  * nginx template

**python/mysql**

* Dump files from SELECT queries
* Extract URLs from functions
* Variable handler
* Support for selecting variables

**python/p0f**

* Fix decode error

**python/pptp**

* Fix error if config is empty


0.5.1 - 2016-09-05
------------------

**dionaea**

* Don't report 'connection.free' incident to early
  to prevent segmentation faults

0.5.0 - 2016-08-06
------------------

**dionaea**

* Handle byte objects in incidents
* Bump required Python version from 3.2 to 3.4

**python/http**

* Detect Shellshock attacks

**python/log_incident**

* Initial support to export raw incident information

**python/log_sqlite**

* Log credentials from the ftp service

**python/memcache**

* Initial support for the memcached protocol

**python/pptp**

* Clean up
* Handle CallClearRequests packets
* Values for hostname, vendor name and firmware revision are now customizable

**python/util**

* New function to detect shellshock attacks and report detected URLs


0.4.2 - 2016-07-02
------------------

**doc**

* Add information about log levels for developers

**python/***

* Replace all critical log messages with error messages
* Catch exceptions in handle_io_in() and handle_io_out() to improve stability
* Catch exceptions in incident handlers

**python/sip**

* Fix error while reading config values

**python/upnp**

* Fix errors in log messages

**more**

* Add templates to create issues and merge requests on github


0.4.1 - 2016-06-14
------------------

**core**

* Initialize stdout logger earlier
* Log error,critical and warning by default

**python/***

* In glib2 critical is a critical warning
* Add support for exceptions
* Check file path and show warnings

**python/log_json**

* Add support for flat object lists to work with ELK stack

0.4.0 - 2016-05-31
------------------

**core**

* Replace lcfg with Key-value file parser from glib

**ci**

* Add build tests for Ubuntu 14.04, Ubuntu 16.04 and Debian 8

**doc**

* Add initial documentation for missing modules
* Update documentation to reflact config changes
* Add processor documentation

**python/***

* Replace lcfg with yaml configs
* Remove deprecated incident handlers (logxmpp, mwserv, SurfIDS)
* Rename incident handlers from logsql to log_sqlite
* Rename incident handlers from uniqdownload to submit_http_post

**python/mysql**

* Enable processor pipeline

0.3.0 - 2016-03-30
------------------

**core**

* Code clean up (Thanks to Katarina)
* Vagrant based dev environment
* Customize ssl/tls parameters for autogenerated certificates

**doc**

* Initial version of sphinx based documentation

**python/ftp**

* Support to customize response messages
* Small fixes

**python/hpfeeds**

* Initial ihandler support (Thanks to rep)

**python/http**

* Customize HTTP response headers
* Return HTTP/1.1 instead of HTTP/1.0

**python/log_json**

* Initial ihandler support

**python/mqtt**

* Initial protocol support (Thanks to gento)

**python/pptp**

* Initial protocol support (Thanks to gento)

**python/upnp**

* Initial protocol support (Thanks to gento)

0.2.1 - 2014-07-16
------------------

**core**

* Support for cython and cython3
* Fixes to build with glib 2.40
* Remove build warnings
* Support libnl >= 3.2.21

**python/http**

* Fix unlink() calls

**python/virustotal**

* virustotal API v2.0

0.2.0 - 2013-11-02
------------------

Last commit by original authors.

0.1.0
-----

* Initial release.

.. _`master`: https://github.com/DinoTools/dionaea
