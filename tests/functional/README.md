<!--
SPDX-FileCopyrightText: none
SPDX-License-Identifier: CC0-1.0
-->

# Functional tests

dionaea runs in a container with the T-Pot configuration (`config/`, all
services) on its own Docker network. pytest runs in a client container
(`client/Dockerfile`: python:3.14-slim, pytest, impacket, PyMySQL, pyftpdlib, paho-mqtt, nmap) on
the same network. The host needs only Docker. The client image is pinned: the base image by its
digest, nmap from snapshot.debian.org with its version, the Python packages from
`client/requirements.txt` with their hashes (`client/lock.sh` makes it from `client/requirements.in`,
with the files on PyPI before a fixed date; `unit/test_client_image.py` checks it).

    tests/functional/run.sh                  # build ./Dockerfile, run all tests
    tests/functional/run.sh -k banner -x     # arguments go to pytest
    DIONAEA_RUN_ARGS="--ulimit nofile=128" tests/functional/run.sh   # + accept() at EMFILE
    DIONAEA_TTY=1 tests/functional/run.sh                            # + stdin on a terminal
    DIONAEA_TTY=1 DIONAEA_TTY_CLOSE=eof tests/functional/run.sh      # the same, closed by ^D
    DIONAEA_IMAGE=ghcr.io/telekom-security/dionaea:24.04.1 tests/functional/run.sh -k "log_format"

The 24.04.1 image (0.11.x) fails the tests of what was fixed since: it never
answers an HTTP request (`detect_shellshock` gets bytes), its TFTP service and
FTP data connections end in `LoaderError`, the MySQL service fails on every query,
and so on. It passes `-k log_format` (the fixture is made from it), so that run
checks the harness.

## What run.sh does

1. Builds the image from `./Dockerfile`, or uses `DIONAEA_IMAGE` and builds nothing.
2. Builds the client image.
3. Makes a temporary folder with `etc/` (copy of `config/`), `var-dionaea/`
   (`/opt/dionaea/var/dionaea`: `binaries/`, `bistreams/`, `roots/`, ...) and
   `var-log/` (`/opt/dionaea/var/log`: `dionaea.json`, `dionaea.sqlite`).
4. Starts dionaea as in T-Pot: uid/gid 2000, `--read-only` with a tmpfs on `/tmp`
   (`uid=2000,gid=2000,size=16m`: the files of the emulation, `tempdownload_new()`), the
   three folders mounted and `roots/{ftp,tftp,www,upnp}` of `var-dionaea` mounted again
   read-only. It checks that `/tmp` is a tmpfs uid 2000 can write.
5. Runs pytest in the client; `var-dionaea` and `var-log` are mounted read-only
   there (`DIONAEA_DATA_DIR`, `DIONAEA_LOG_DIR`), the container name is
   `DIONAEA_HOST`.
6. Runs the executable `host-checks/*.sh` scripts in the order of their names
   with `DIONAEA_CONTAINER`, `DIONAEA_NETWORK`, `DIONAEA_CLIENT_IMAGE`,
   `DIONAEA_TESTS_DIR` and `DIONAEA_TMP_ROOT` in the environment, for checks the
   client cannot do, e.g. the CPU use of the process in the dionaea container
   (see *Host checks*).
7. Stops dionaea with SIGINT (as T-Pot does, the log files are buffered and
   written then) and checks `dionaea.log` and `dionaea-errors.log`: "Starting
   services" has to be there, `Traceback`, `LoaderError`, `Error loading module`
   and `Unable to start service` must not. Lines the host checks expect
   (`hc_expect_log`, in `out/expect-log`) have to be there as well. The exit
   status (255 after SIGINT, also in 24.04.1) is not checked.
8. Removes containers, network and temporary folder (on every exit, also ^C).
   On a failure the last lines of the container log, `dionaea.log` and
   `dionaea-errors.log` are printed.

## Environment

| Variable | Meaning |
| --- | --- |
| `DIONAEA_IMAGE` | test this image, do not build |
| `DIONAEA_RUN_ARGS` | more arguments for `docker run` of dionaea, e.g. `--ulimit nofile=128`: only `--ulimit nofile=N` and `-v FILE:TARGET:ro` into the modules or the configuration of dionaea (`tests/load/runargs.py`, needs `python3` on the host), anything else is exit 2 |
| `DIONAEA_TTY=1` | start dionaea with `-t -i`; `host-checks/20-tty-stdin.sh` then runs |
| `DIONAEA_TTY_CLOSE` | how that check closes stdin: `hangup` (default) or `eof` (^D) |
| `DIONAEA_FD_TEST_PORTS` | ports of `host-checks/10-fd-limit.sh` (default `445,443`) |
| `HC_CPU_LIMIT` | CPU limit of the host checks in percent of one core (default 20) |
| `DIONAEA_START_TIMEOUT` | seconds to wait for FTP (default 60) |
| `KEEP_ARTIFACTS=1` | keep the temporary folder (config, data, logs, `out/dionaea.container.log`) |

## Writing tests

`conftest.py` has the fixtures `dionaea_host`, `dionaea_ip`, `data_dir`,
`log_dir`, `json_log`, `sqlite_db`, `binaries_dir`, `wait_for_event(predicate,
timeout)` (first `dionaea.json` entry that matches), `query_db(sql,
params)` (read-only query on `dionaea.sqlite`) and `wait_for_rows(sql, params,
count, timeout)` (the query again until it has rows: log_sqlite commits once a
second, dionaea.json has an event at once). A session fixture waits once
until port 21 answers. Plain functions are in `helpers.py`.

The T-Pot configuration in `config/` is a copy of `tpotce/docker/dionaea/dist/etc`
and has to follow it. One difference: `dionaea.cfg` writes `dionaea.log` (info and
above) so the startup can be checked.

## Tests

- `test_smb_auth.py`: SMB1/SMB2 authentication and metadata, malformed frames,
  and 1001 SMB1 logins on one connection. JSON retains the first 1000 logins,
  SQLite retains all 1001, and the connection continues to answer.
- `unit/test_unreadable_messages.py`: a message of a client that SMB, epmapper, MQTT or MSSQL
  can not read is info when the parser raised (its traceback at debug), a warning with the
  traceback for any other exception.
- `unit/test_logtext.py` (`LogSummary`) and the unit tests of the services and handlers (SMB, FTP,
  TFTP, MQTT, the printer and spoolss, the uploads, the store, emu_scripts, SIP, hpfeeds, log_sqlite):
  a line that every connection can write (a limit, a lost capture, a failure of the system) is info,
  one warning a minute sums them up with their number and the last one.
- `unit/test_log_json_credentials.py`: credential limits for SMB, FTP, MySQL
  and MSSQL, both JSON output forms, and independent connection records.
- `test_errors_log_live.py`: `dionaea-errors.log` (`warning,error,critical`) is written per line: the
  summary warning of the SMB1 writes beyond `max_upload_size` (the uploads are dropped, the line of
  each is info) is in it within 1 s while dionaea runs, and the drops after it in the same minute
  are in the summary when that minute ends. An SMB1 message shorter than its header and a POST
  with more parts than `max_num_fields` are info, no line of it. After the stop, `run.sh` allows
  no critical line in it (other than `OWN_CRITICAL`), prints the warnings left, per message
  (`tools/count_warnings.sh`), and fails when a message is there too often: a message that every
  connection can write is one summary a minute (`src/log_summary.c`, `LogSummary` of
  `modules/python/dionaea/logtext.py`), counted by its text before the number, which may be there
  once per started minute of the run and once more; any other message five times.
- `test_smoke.py`: service ports, FTP login in `dionaea.json`, HTTP upload. The
  multipart tests (`test_http_multipart_*`: a file part is stored, a part with a
  Content-Transfer-Encoding is stored as sent, a line that starts with the boundary inside the
  data keeps the sample whole, a bare-LF body and the files of a nested multipart/mixed part
  are stored, a part whose headers can not be read is left out and the other files of the
  POST are stored without a warning, 900,000 empty parts, bare-LF or nested, are refused fast, a request over 32 MiB
  gets 413 and leaves no sample and no temporary file, nor does a client that leaves in the
  middle of its body) need an HTTP service
  that answers; `-k "not multipart"` leaves them all out (not only the upload test), e.g.
  for an image whose HTTP service never answers, as 24.04.1.
- `test_emu.py`: a Windows shellcode (call/pop GetPC, loop, `WinExec`) sent to
  port 445 and 135 is found by the emu module (bundled libemu), emulated, and
  its API call lands in the `emu_profiles` table of `dionaea.sqlite` (and as
  `profiledump` in `dionaea.log`). A sample without GetPC is not profiled.
- `test_mqtt.py`: an MQTT 5 client (paho-mqtt) connects, subscribes with QoS 1 (granted 1)
  and publishes with QoS 1; the CONNACK and SUBACK of protocol level 5 carry their property
  length, the subscription and the publication are in `dionaea.sqlite`. An MQTT 3.1.1 client
  subscribes to three filters (granted 0, 1, 2) and once more.
- `test_mongo.py`: the MongoDB service: isMaster as OP_QUERY on `admin.$cmd` (an OP_REPLY
  with one document, `ismaster` true, `responseTo` the request id), isMaster and buildInfo
  as OP_COMMAND, several messages in one read, the connection in `dionaea.json`; a header
  whose `messageLength` is below its own 16 bytes or above 64 KiB, and a query whose
  document is no BSON, end the connection (info) and the service goes on.
- `test_tftp.py`: TFTP read request for a file in `roots/tftp` (DATA), for a
  missing file and for a path outside the root (ERROR). run.sh puts the file there. The
  DATA comes from the port of the session, its connection is in `dionaea.json` (`dst_port`)
  and in the `connections` table (`local_port`) with port 69.
- `test_ftp.py`: data connections in active (`PORT` + `LIST`) and passive mode
  (`LIST`, `RETR`, `STOR` one after the other), transfer commands without a data
  connection (425), malformed commands (`PORT x`, `USER` without argument: 501, the
  session stays), a `PORT` to another address than the client's (a bounce scan: 500,
  the session stays, the command is logged), a `PORT` to a port the client does not listen on
  (425, and `RETR` / `LIST` afterwards get 425 too: no stale data connection), and that
  dionaea still answers a few seconds later.
- `test_emu_scripts.py`: the chain shellcode (`cmd.exe /c tftp -i <client> GET
  <script>`) -> TFTP download of a PowerShell / VBScript from the client container
  -> emu_scripts finds the URL in the file -> HTTP download of the payload from the
  client container (`servers.py`) -> row in `offers` / `downloads` and the file in
  `binaries/<md5>`. The same with an `ftp://` URL in the script against an
  anonymous pyftpdlib server in the client container (dionaea's FTP client).
- `test_shellshock.py`: a download command in a Shellshock header is followed.
- `test_mysql.py`: PyMySQL against the MySQL service (SET, `select database()`,
  `show databases|tables|variables`, `select @@var`, hex `into dumpfile`, `xpdl3`
  URL download).
- `test_smb_ids.py`: SMB1 replies carry the UID of the session (from `SESSION_SETUP_ANDX`),
  the TID of a new tree (`TREE_CONNECT_ANDX`) and otherwise the TID / UID of the request,
  as a Windows server; the share of the tree is in the url of an
  upload (`smb://<client>/<share>/<name>`, 255 characters of a longer share; a tree keeps 256). The shares of the persona: `Service` /
  `NativeFileSystem` per share type (OEM and Unicode, plain and extended reply), an unknown
  share gets `STATUS_BAD_NETWORK_NAME`, `C$` / `ADMIN$` `STATUS_ACCESS_DENIED` for an anonymous
  or guest session (impacket), a `TREE_CONNECT_ANDX` chained behind a plain `SESSION_SETUP_ANDX`
  is answered in the chain and an upload on its tree has the share in its url (raw packets).
- `test_upload.py`: uploads are captured like downloads: FTP `STOR` (passive,
  active, odd names, twice, an empty file, a client that leaves at once) and SMB1
  writes (impacket, dialect NT LM 0.12, plain session setup because dionaea's
  NTLM challenge has no target info) end as `binaries/<md5>`, a row in `downloads`
  (url `ftp://<client>/<name>` / `smb://<client>/<share>/<name>`, connection `ftpd` / `smbd`)
  and `downloads` / `smb.commands` in `dionaea.json`. The size is bound
  (`max_upload_size`, 32 MiB): an FTP upload of more than that gets 552, SMB writes
  at huge offsets or beyond the limit fail and the file is dropped, 32 open files per
  connection, a service pipe (`\srvsvc`) is no file, a file of holes is dropped,
  padded WRITE_ANDX (DataOffset past the parameters) keeps every byte, SMB_COM_WRITE
  offsets are little endian, FTP temp files are removed when a second STOR / RETR /
  LIST follows or the control connection is gone.
- `test_smb_pipeline.py`: requests that arrive in one read are all processed (a burst of
  echo requests, a request split in two segments, the start of one more message behind).
- `test_smb_trans.py`: TRANSACTION, TRANSACTION2 and NT_TRANSACT with their `*_SECONDARY`
  requests built byte by byte (`smb1_raw.py`, replies are read up to an SMB_COM_ECHO behind
  them): every pair of kinds, backwards displacements, an echo in between and thousands of
  secondaries get no answer and no error; a secondary without a transaction gets
  `STATUS_INVALID_PARAMETER` (command, TID, PID, UID and MID of the request), also one for one in a burst;
  declared totals and displacements at their maximum and lying word / byte counts are
  harmless; the state is per connection. nmap's `smb-vuln-ms17-010` and
  `smb-double-pulsar-backdoor` still report VULNERABLE (as on the 24.04.1 image).
- `test_ftp_readonly_root.py`: run.sh mounts `roots/{ftp,tftp,www,upnp}` read-only as T-Pot does
  (and checks it); `MKD` and `RMD` (also `RMD /`) get 550 instead of an OSError (Traceback, no reply,
  dropped connection), the session goes on, the commands are still logged; DELE, RNFR / RNTO, STOU,
  APPE and SITE are not implemented (502) and change nothing.
- `test_store_mode.py`: a stored sample (`binaries/<md5>`) is read-only and not
  executable, mode 0440: FTP `STOR`, HTTP POST, and the two download paths (script over
  TFTP, payload over HTTP by the curl module); no file in `binaries/` has an execute bit.
- `test_store_mode.py` also checks that the streams in `bistreams/` have no execute bit.
- `test_store_cap_instance.py`: the size cap `max_size` of the store handler, against a
  second dionaea that `host-checks/40-store-cap.sh` starts (not collected by the main
  run, `DIONAEA_CAP_INSTANCE=1`): with 1 MiB, a sample that fits is stored, one that would
  exceed the cap is not (no file, no temp file), its md5 is in `downloads` and in
  `dionaea.json`, a stored sample uploaded again is recorded, a small one still fits,
  dionaea keeps answering; a PCL print job on port 9100 (the printer service runs in that
  instance only) is stored by the store (0440, no `print-*` file) and refused over the cap.
- `test_bistream_cap_instance.py`: the limits of the streamdumper, against a second
  dionaea that `host-checks/42-bistream-cap.sh` starts (not collected by the main run):
  a burst of 200 HTTP connections (32 threads) against `config.max_files=40` leaves 40
  dumps, every connection is answered; `bistreams/` emptied from outside is noticed by
  the next count (at most 60 s later); 400 connections against `config.max_size=0.25`
  stay within 0.25 MiB, open dumps included (a dump whose answer does not fit stops
  before it), and every dump parses (`ast.literal_eval`); one FTP connection that sends
  about 1.5 times `config.max_size` is answered to its `QUIT`, its dump stops at the
  limit as a valid dump, and a new connection gets no dump and is answered.
- `test_log_format.py`: the reference session (`logformat.py`: FTP, MySQL, MSSQL,
  SMB, MQTT, epmap and HTTP connections) against `fixtures/log_0.11.1.json`: every
  event type, key and value type of `dionaea.json`, the timestamp format and every
  column of `dionaea.sqlite` that the 0.11.1 image has must be there; new keys,
  tables and columns are fine.
- `test_mirror.py`: a client with a private address connects to the mirror
  service (port 42) while listening on port 42 itself; dionaea must neither
  connect back nor send data back.
- `unit/`: pure Python tests without a container (`python3 -m pytest
  tests/functional/unit` with pytest installed; run.sh runs them in the client
  container with the sources mounted, `DIONAEA_PY_SRC`):
  - `test_connection_init.py` reads the sources with `ast` and fails when the
    `__init__` of a `connection` subclass (also derived over other classes) has an
    argument without a default; `connection.__init__` raises `LoaderError` for
    that, and the classes are created at run time (TFTP request, FTP data
    connection, SIP call, ...).
  - `test_emu_scripts_handler.py`, `test_util.py`: URL extraction on bytes; one script line per
    stager pattern of PowerShell and VBScript (a cmdlet with the first letter of another, as
    `swr`, is none), and 1 MiB of large input per pattern in under 100 ms (linear
    time).
  - `test_smb_uid.py`: the UIDs of new sessions (`new_uid` of `smb.py`, taken with `ast`):
    steps of 0x0800, every value from 0x0800 to 0xfffe once per round, never 0 or 0xffff; a
    tree (`new_tree`) keeps at most 256 characters of its share, 32 trees per connection;
    `smb_message` is None again once `handle_smb1_message` handled a message (also when it
    raised).
  - `test_http_multipart.py`: the multipart parser on raw bytes: delimiters only as whole
    lines, CRLF and bare-LF bodies, nested multipart/mixed parts up to three levels, the
    field limit over all levels, a body read in the time of its own length; a part whose
    headers the email package can not read is left out with one info line (also in a nested
    part), a Content-Type of the request whose parameters it can not read gives no files and
    one info line.
  - `test_http_post_framing.py`: `http.py` with stand-ins of the core: a multipart body ends
    at its closing delimiter line (CRLF or LF, in any read sizes) or at the Content-Length,
    a quoted boundary is found, `--boundary--` inside a line of a file does not end it.
    The temporary file of a body is removed when it is parsed, refused (413) or left by the
    client.
  - `test_mysql_logging.py`: `mysql.py` with stand-ins of the core: a configured database whose
    sqlite file can not be opened is one warning, a database name of the client that is not
    configured none; a statement sqlite refuses (or no UTF-8) is info, any other exception of a
    statement a warning with its traceback.
  - `test_ftp_session.py`: `ftp.py` with stand-ins of the connections: a command is logged
    at debug only (no warning per command, no PASS value above debug), its incident is
    unchanged; a bounce `PORT` gets 500 and the session goes on, a `PORT` of an IPv4-mapped
    client connects; a file of a `RETR` that can not be read on closes the data connection
    with 451, a `RETR` of a file that can not be opened or a `LIST` of a folder that can not be
    read on an established data connection get 550; an upload error and an error callback of a data connection whose control
    connection is gone (`ReferenceError`) raise nothing; the safety net of `processcmd`
    answers an `OSError` of the sockets (`EMFILE`, `ENFILE`, `EADDRINUSE`, `ENOBUFS`) with
    425 and logs its traceback, one of the filesystem with 550, a full disk (`ENOSPC`,
    `EDQUOT`) with 452 and a warning; a `PASV` whose socket can not be made gets one 425 and
    the next `PASV` works.
  - `test_mqtt_framing.py`: `mqtt.py` frames the packets by their fixed header: a packet
    in pieces, several in one read, the first byte of the next packet in the read
    before, packet types without a parser, a malformed or too large remaining length; a
    packet over 64 KiB is logged with its size, type, source and topic (PUBLISH, SUBSCRIBE;
    escaped, never the payload) before the connection is closed; the topic filter and
    the packet identifier of a SUBSCRIBE of MQTT 5 (behind its properties, the level comes
    from the CONNECT) and of a SUBSCRIBE over 127 bytes; topic, message and acknowledged packet
    identifier of a PUBLISH (MQTT 3.1.1 and 5, QoS 0/1/2, 5 bytes, over 127 bytes, over 16 KiB,
    RETAIN / DUP); the CONNACK and SUBACK of MQTT 5 with their property length, the SUBACK
    (3.1.1 and 5) with one return code per topic filter (0x80 for malformed options) and a
    remaining length that counts them.
  - `test_logsql_commits.py`: `logsql.py` puts the rows of a second in one transaction: the
    incidents mark it, a timer of the loop (`dionaea.core.timer`) commits it every second and
    on stop; a failed commit (a reader held its lock) is tried again; an existing database is
    taken over; the journal mode is unchanged.
  - `test_ihandlers_flush.py`: `ihandlers.py` `flush()` (dionaea calls it when its event
    loop ended, before the wait for the threadpool) calls `flush()` of every handler that
    has one, an error of one does not keep the others from it; a handler whose `start()`
    raises is logged and removed from `g_handlers`, the others start.
  - `test_download_clients.py`: the TFTP and FTP download clients (`tftp.py`, `ftp_download.py`)
    with stand-ins of the core: a target the download target filter refused (`ECONFILTERED`) is
    `download_refused()` with its url, any other end before the file is complete (no connection,
    an ERROR or a packet the server does not send, no answer, no data connection, a server that
    closes early) `download_failed()` with the url and a reason, once per download.
  - `test_mirror_policy.py`: `mirror_policy.py` (no `dionaea.core`): public
    IPv4 / IPv6 (also `::ffff:a.b.c.d`) are mirrored; loopback, link-local,
    RFC 1918, ULA, mapped private, multicast, unspecified, own addresses and the
    default gateway (`/proc/net/route`, `ipv6_route`, cached) are refused; one
    mirror per source at a time.
  - `test_mirror_peer.py`: `mirror.py`: the connect-back mirrors both ways once it is
    established; a client that closes before it is established gets no `AttributeError`,
    the connect-back is closed and its place given back once.
  - `test_store.py`: `store.py`: the mode of a stored sample (0440, also from an executable
    temp file, also copied from another filesystem), `max_size` (parsing, the total of the
    folder counted once per file, below one byte is one byte, running total and refresh, a refused sample: only `.hash`,
    one warning, a known sample is `.again`; a refused sample counts the folder again when its mtime changed, at
    most every 10 minutes; a gone folder is logged once).
  - `test_printer_pcl.py`: `printer.py`: a PCL job is a temporary file (0600, bound in size) that is
    reported as `dionaea.download.complete` when the connection ends, not a file the service names.
  - `test_upload_module.py`: `upload.py`: the size bound (offsets, 32 / 64 bit),
    discarded and empty files, the url of an upload (percent encoding, IPv6,
    control characters, length).
  - `test_smb_write_fields.py`: where the data of WRITE_ANDX starts (padding, WordCount
    12 and 14, writes of 64 KiB and more, lengths from the client) and the offset of
    SMB_COM_WRITE, on the packet classes of `smb/include/smbfields.py`.
  - `test_smb_trans_fields.py`: the `*_SECONDARY` requests are read by their word and byte
    counts, whatever the counts say, up to 255 words, and WordCount 9 without a byte count
    (`SMB_COM_TRANSACTION2_SECONDARY` used to raise).
  - `test_mongo_messages.py`: `mongo.py` with stand-ins of the core and of bson: a message the
    parser or BSON can not read closes the connection with one info line, an error of a handler
    of the service is not taken for one and goes on to the binding.
  - `test_logformat_compare.py`: the comparison of the log formats finds missing
    and retyped keys, other timestamp formats and changed columns.
  - `test_client_image.py`: `client/Dockerfile` is pinned (base image digest, Debian
    snapshot and package versions, pip `--require-hashes` from the requirements files).
  - `test_harness_scripts.py`: the shell scripts of the harness: an array that can be empty
    is expanded for bash before 4.4, `hc_main_pid` fails with a message without a dionaea
    process, `hc_count_warnings` takes its label as an argument.

The log fixture is recorded once with the image of the release before:

    tests/functional/tools/record_fixture.sh [image] [name]   # default: ghcr.io/telekom-security/dionaea:24.04.1, log_0.11.1.json

It starts the image like run.sh does, runs the reference session
(`DIONAEA_RECORD_FIXTURE=<name>`, run.sh mounts `fixtures/` writable) and writes
the shapes into `fixtures/<name>`. The image id is in the file. The T-Pot
24.04.1 image answers none of the HTTP requests (`detect_shellshock`), the session
only needs the connection of that service. The session has to stay the same when
the fixture is recorded again.

## Host checks

`host-checks/lib.sh` has the helpers (CPU of the dionaea processes from
`/proc/<pid>/stat` through `docker exec`; root with `--privileged` where
dionaea's file capabilities close `/proc/<pid>/fd` and its limits).

- `10-fd-limit.sh` runs only when the fd limit of dionaea is 256 or less
  (`DIONAEA_RUN_ARGS="--ulimit nofile=128"`). dionaea closes accepted
  connections whose fd is above 70 % of the limit it read at the start, so idle
  connections alone never reach the limit. The check therefore lowers the soft
  limit of the running process to the fds in use plus 8 (`prlimit`), so that
  `accept()` fails with EMFILE, and runs `scenarios/idle_connections.py` in a
  client container: 200 idle connections each to 445 (tcp) and 443 (tls).
  While they are held, dionaea must stay below the CPU limit; after they are
  closed, a new connection to 21 has to get the 220 banner within 30 s. Then
  the limit is set back. The check fails if the lowered limit is above the
  70 % guard (EMFILE could not happen), and after the stop `dionaea-errors.log`
  must have `accept() failed on ...:<port> (Too many open files)` for each port.
- `15-tftp-no-socket.sh` always: a TFTP session whose socket cannot be made gives its
  place back. The check lowers the soft fd limit of the running process below the fds
  it has open (`prlimit`, at most 16), sends 8 read requests from one client container
  (one source address), restores the limit, and the same client must get DATA. The core
  frees the handler without a disconnect after `socket()` failed, so its error callback
  gives the place back and the request goes no further. No Traceback in the container
  log meanwhile; after the stop
  `dionaea-errors.log` must have the EMFILE line of `socket()`.
- `16-ftp-pasv-no-socket.sh` always: a PASV whose socket can not be made. A client logs in on
  port 21, the check lowers the soft fd limit of the running process below the fds it has open
  (`prlimit`, as 15), the client sends PASV, the limit is restored and it sends PASV and PWD.
  The first PASV must get exactly one reply, 425, and no 227; the second a 227 with a port, PWD
  a 257; no Traceback in the container log. For TCP the core makes the socket in `listen()`, not
  in `bind()`.
- `20-tty-stdin.sh` runs only with `DIONAEA_TTY=1`. It types a Python line on
  dionaea's terminal (TIOCSTI) and waits for its result in the container log,
  then closes stdin by a hangup of the terminal (TIOCVHANGUP) or by ^D, and
  checks that dionaea still runs and stays below the CPU limit.
- `30-mirror-loop.sh` always: a client container (private address) listens on
  port 42 and holds connections to dionaea's port 42. dionaea must have no
  connection with the remote port 42 (`/proc/net/tcp` and `tcp6` in the
  container, the image has no `ss`), the client must see no connect-back and no
  data, and the CPU stays below the limit.
- `32-mirror-public.sh` always: the mirror for a client with a public address, which the
  other mirror checks can not reach. A second dionaea and a client on a network of their own
  with a public subnet (`HC_PUBLIC_SUBNET`, default `11.77.0.0/24`, `--internal`: nothing
  leaves the host): `scenarios/mirror_public_client.py` sees dionaea connect back to its
  port 42 and pass the data both ways, no second mirror for a second connection of the same
  source, and a mirror again once the first ended; the log of the second dionaea has no
  Traceback.
- `35-early-close.sh` always: `scenarios/early_close.py` in a client container, with
  dionaea at 0.3 CPU meanwhile (`docker update`, as on a loaded sensor; the limit is
  lifted again): 8 clients send HTTPS (and HTTP) requests and leave after the first
  record without a TLS shutdown, a quarter of them with a reset, and MQTT packets come
  across two reads (PUBLISH and the first byte of the DISCONNECT, then the second byte).
  The container log must get no Traceback, and dionaea must still answer HTTPS in full
  and an MQTT CONNECT.
- `48-errors-log.sh` always: a second dionaea gets `scenarios/routine_requests.py` (an FTP
  session with `LIST` / `RETR` without a data connection and a bounce `PORT`, a client that
  resets after its request, TFTP read requests for a missing
  file, a path outside the root, mode netascii and a whole file, a MySQL login with a refused
  statement, an SMB message over the limit, SMB1 transactions, a partial DCERPC bind, port
  scans that reset) and is stopped. Its `dionaea-errors.log` (warning and error, the only log
  of T-Pot) must have no line of these requests of every day (the FTP commands, the database
  of each MySQL login, `getpeername` / accept of a reset scan, the read on the socket of a
  TFTP session that closed itself, ...); the ones that moved to info are still in `dionaea.log`, and the `recv failed`
  of a client that resets after its request is there at info with the port that client
  printed (the line names the connection; a port scan that resets makes the same text from
  other ports).
- `49-shutdown-dumps.sh` always: a second dionaea (the streamdumper limits of T-Pot) gets FTP,
  HTTP and SMB connections that stay open (half a command, half a request) and is stopped
  while a client container holds them. Every file of `bistreams/` must parse with
  `ast.literal_eval`, the dumps of the open FTP connections among them (they ended without
  `')]`: dionaea never frees the connections that are open at its end).
- `90-cpu-idle.sh` always: dionaea below the CPU limit over 10 s after all tests.
- `40-store-cap.sh` always: starts a second dionaea (same image, `ihandlers/store.yaml`
  with `max_size: 1`) on the network, runs `test_store_cap_instance.py` against it and,
  after stopping it (the logs are written then), expects the `Not storing <md5>` warning
  of `dionaea.log` for every sample the tests had refused, once per md5.
- `42-bistream-cap.sh` always: starts a second dionaea three times (`config.max_files=40`,
  then `config.max_size=0.25` twice, for the burst and for the long connection, in
  `[processor.streamdumper]`), runs `test_bistream_cap_instance.py` against it and, after
  stopping it, expects the exit of a stop (0 or 255, no crash or kill), the line of the
  limit and at most one `Not dumping the streams of` and one `Stopped dumping the streams
  of` warning per minute in `dionaea.log`, without data of the connections. It takes
  about 80 s (the count of the folder every 60 s).
- `43-limits-env.sh` always: the limits from the environment. Starts a second dionaea
  four times: with `DIONAEA_STREAMDUMPER_MAX_SIZE=2048`,
  `DIONAEA_STREAMDUMPER_MAX_FILES=40` and `DIONAEA_STORE_MAX_SIZE=1` and no limits in
  the config; with `DIONAEA_STREAMDUMPER_MAX_SIZE=1` over `config.max_size=2048` (the
  size burst of `test_bistream_cap_instance.py` stays within 1 MiB); with `config.max_files=40` and `max_size: 1` in the config and the three
  variables set to values that are refused; and with that config and no variable. Else
  each time the burst of `test_bistream_cap_instance.py` (40 files) and
  `test_store_cap_instance.py` (1 MiB) run against it; after stopping it `dionaea.log`
  must have the three lines at the start (`streamdumper: max_size <N> MiB (from
  <SOURCE>)`, `streamdumper: max_files <N> (from <SOURCE>)`, `store: max_size <N> MiB
  (from <SOURCE>)`) with the value and source of that run, once each, and one
  `Ignoring DIONAEA_...` warning per refused variable (none otherwise).
- `45-binding.sh` always: the binding in a running dionaea. A second dionaea imports
  `probes/binding_probe.py`: `dionaea.core.timer` (one-shot and repeating timers, one
  without a reference, two that stop themselves inside their callback, one stopped
  before it fires, one whose first two calls raise), then 200 reads of `incident.con`
  (a new connection wrapper each, as the log handlers read it). `binding-probe.json`
  must have every timer called as often as it should be, the two exceptions logged,
  and the reads with at most 20 objects in reference cycles; the container log has the
  two Tracebacks of the probe and no other, and dionaea still answers on port 21.
- `50-stop-at-start.sh` always: a second dionaea gets the stop signal of the image (SIGINT,
  what `docker stop` sends), and another one SIGTERM (to PID 1, from a process in its
  container), as soon as the first of its ports answers. Each has to end within 30 s with
  exit code 0, and `dionaea.log` has the `sigint_cb` / `sigterm_cb` line and `stop
  dionaea.log` (dionaea handles the signals before its services listen and the python
  module keeps the handler of SIGINT; PID 1 ignores a signal without handler).
- `51-download-log.sh` always: the log lines of downloads that do not complete. A second
  dionaea, whose download policy allows the network of the test, gets
  `scenarios/download_offers.py`: for 65 s four MySQL `xpdl3` offers a second, HTTP and FTP
  from 127.0.0.1 (refused by the filter) and from a closed port of the client container
  (allowed, they fail), and three TFTP downloads from 127.0.0.1 in shellcode. A minute later it
  is stopped. Its `dionaea-errors.log` must have no line of a refused target or of a single
  failure, two or three `downloads: <N> failed in the last minute, the last: <url> (<reason>)`
  warnings at least 59 s apart whose N add up to the failed offers; `dionaea.log` has one
  `download target refused by the filter: <url>` or `download failed: <url> (<reason>)` info
  line per offer. It takes about 2.5 minutes.
- `52-unknown-transport.sh` always: a second dionaea whose blackhole service has port 4434 of
  the transport `tcp` and then port 4433 of the transport `dtls` (the core has tcp, udp and
  tls). The service does not start: 4434 accepts no connection on any address of the container
  (IPv4, and IPv6 when the container has it), `dionaea-errors.log` has one warning `Unable to
  start service blackhole: unknown transport 'dtls', the core has tcp, udp and tls` and no
  Traceback, and port 21 answers.
- `47-shutdown-flush.sh` always: a second dionaea gets 40 FTP connections (each up to its
  banner, so its row of `connections` is written but not yet committed) and is stopped
  right after the last one. All of them have to be in `dionaea.sqlite`, and `dionaea.log`
  has `flush dionaea.ihandlers` (module api `flush`, after the event loop, before the
  wait for the threadpool) before `stop dionaea.ihandlers`.

## Download destination policy

Production downloads accept public IP destinations only. The policy checks
resolved addresses immediately before FTP, TFTP or HTTP sockets are opened;
HTTP redirects are checked too, and downloads ignore environment proxies.
Loopback, link-local, local addresses and bridge gateways remain blocked even
with an explicit allowlist. Isolated lab CIDRs can be configured through
`download_policy.yaml` (`allowed_networks`). The harness enables only its
disposable Docker network for its private download servers. A refused target is
an info line, a failed download an info line and at most one warning a minute
(`doc/source/ihandler/download_policy.rst`, `host-checks/51-download-log.sh`).
