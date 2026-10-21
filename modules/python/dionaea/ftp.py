# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2001-2007 Twisted Matrix Laboratories
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
# SPDX-FileCopyrightText: 2009-2011 Markus Koetter
# SPDX-FileCopyrightText: 2015-2016 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later AND MIT
#
# Copyright (c) 2001-2009
#
# Allen Short
# Andrew Bennetts
# Apple Computer, Inc.
# Benjamin Bruheim
# Bob Ippolito
# Canonical Limited
# Christopher Armstrong
# David Reid
# Donovan Preston
# Eric Mangold
# Itamar Shtull-Trauring
# James Knight
# Jason A. Mobarak
# Jean-Paul Calderone
# Jonathan Lange
# Jonathan D. Simms
# Juergen Hermann
# Kevin Turner
# Mary Gardiner
# Matthew Lefkowitz
# Massachusetts Institute of Technology
# Moshe Zadka
# Paul Swartz
# Pavel Pergamenshchik
# Ralph Meijer
# Sean Riley
# Software Freedom Conservancy
# Travis B. Hartwell
# Thomas Herve
# Eyal Lotem
# Antoine Pitrou
# Andy Gayton
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

# ftp server
from dionaea import ServiceLoader
from dionaea.core import connection, ihandler, g_dionaea, incident
from dionaea.exception import ServiceConfigError
from dionaea.logtext import LogSummary, log_text
import errno
import inspect
import logging
import os
from os import stat
from stat import *
import time

from dionaea.upload import (
    DEFAULT_MAX_UPLOAD_SIZE,
    UploadError,
    UploadFile,
    UploadTooLarge,
    parse_max_upload_size,
    upload_url,
)

logger = logging.getLogger('ftp')

# one warning a minute for what fails in the sessions of all clients; the line of each is info
# (logtext.LogSummary)
STORAGE = LogSummary(logger, "FTP commands failed for lack of storage", "command(s)")
NO_SOCKET = LogSummary(logger, "FTP data connections failed for lack of sockets", "command(s)")
NO_FILE = LogSummary(logger, "uploads not stored, no file could be made", "upload(s)")
DROPPED = LogSummary(logger, "uploads dropped", "upload(s)")
logger.setLevel(logging.DEBUG)

#
# Parts of the following definitions are taken from twisted
# MIT licensed code, gpl compatible
# Copyright (c) 2001-2007 Twisted Matrix Laboratories.

RESPONSE = {
    # -- 100's --
    "data_cnx_already_open_start_xfr":    "125 Data connection already open, starting transfer",
    "file_status_ok_open_data_cnx":       "150 File status okay; about to open data connection.",

    # -- 200's --
    "cmd_ok":                             "200 Command OK",
    "type_set_ok":                        "200 Type set to {mode}.",
    "entering_port_mode":                 '200 PORT OK',
    "sys_status_or_help_reply":           '211 System status reply',
    "dir_status":                         '212 %s',
    "file_status":                        '213 {value}',
    #"help_msg":                           '214 help: %s',
    "name_sys_type":                      '215 UNIX Type: L8',
    "welcome_msg":                        "220 Welcome to the ftp service",
    "svc_ready_for_new_user":             '220 Service ready',
    "goodbye_msg":                        '221 Goodbye.',
    "data_cnx_open_no_xfr_in_progress":   '225 data connection open, no transfer in progress',
    "closing_data_cnx":                   '226 Abort successful',
    "txfr_complete_ok":                   '226 Transfer Complete.',
    "entering_pasv_mode":                 '227 Entering Passive Mode ({host}).',
    # where is epsv defined in the rfc's?
    #"entering_epsv_mode":                 '229 Entering Extended Passive Mode (|||%s|).',
    "usr_logged_in_proceed":              '230 User logged in, proceed',
    "guest_logged_in_proceed":            '230 Anonymous login ok, access restrictions apply.',
    #i.e. CWD completed ok
    "req_file_actn_completed_ok":         '250 Requested File Action Completed OK',
    "pwd_reply":                          "257 \"{cwd}\"",

    # -- 300's --
    "usr_name_ok_need_pass":              '331 Password required for {username}.',
    "guest_name_ok_need_email":           '331 Guest login ok, type your email address as password.',

    "req_file_actn_pending_further_info": '350 Requested file action pending further information.',

    # -- 400's --
    "cant_open_data_cnx":                 "425 Can't open data connection.",
    "cnx_closed_txfr_aborted":            '426 Transfer aborted.  Data connection closed.',
    "local_error":                        '451 Requested action aborted. Local error in processing.',
    "insufficient_storage":               '452 Requested action not taken. Insufficient storage space in system.',

    # -- 500's --
    "syntax_error_pass_requires_arg":     "500 Syntax error: PASS requires an argument",
    "syntax_error_user_requires_arg":     "500 Syntax error: USER requires an argument",
    "syntax_err_in_args":                 '501 syntax error in argument(s) {command}.',
    "illegal_port_cmd":                   "500 Illegal PORT command.",
    "cmd_not_implmntd":                   "502 Command '{command}' not implemented",
    "bad_cmd_seq_pass_after_user":        "503 Incorrect sequence of commands: PASS required after USER",
    "cmd_not_implmntd_for_param":         "504 Not implemented for parameter '{param}'.",
    "not_logged_in":                      '530 Please login with USER and PASS.',
    "auth_failure":                       '530 Sorry, Authentication failed.',
    "file_not_found":                     '550 {filename}: No such file or directory.',
    "permission_denied":                  '550 {path}: Permission denied.',
    "exceeded_storage_allocation":        '552 Exceeded storage allocation (file too large).',
}


# errors of the sockets of PASV / PORT (no fds, no ports, no buffers), not of the filesystem:
# the safety net of processcmd answers them with 425 instead of 550
SOCKET_ERRNOS = frozenset((
    errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM, errno.EADDRINUSE, errno.EADDRNOTAVAIL,
))


# a full disk (or quota): 452, not 425 (STOR) or 550 (the safety net)
STORAGE_ERRNOS = frozenset((errno.ENOSPC, errno.EDQUOT))


class FTPService(ServiceLoader):
    name = "ftp"

    @classmethod
    def start(cls, addr,  iface=None, config=None):
        if config is None:
            config = {}

        daemon = FTPd()
        try:
            daemon.apply_config(config)
        except ServiceConfigError as e:
            logger.error(e.msg, *e.args)
            return
        daemon.bind(addr, 21, iface=iface)
        daemon.listen()
        return daemon


class FTPd(connection):
    UNAUTH, INAUTH, AUTHED, RENAMING = range(4)

    protocol_name = "ftpd"
    shared_config_values = (
        "basedir",
        "max_upload_size",
        "response_msgs"
    )

    def __init__(self, proto='tcp'):
        connection.__init__(self, proto)
        logger.debug("ftp test")
        self.state = self.UNAUTH
        self.user = 'bar'
        self.cwd = '/'
        self.basedir = None
        self.dtp = None
        self.dtf = None
        self.limits = {}  # { '_out' : 8192 }
        self.max_upload_size = DEFAULT_MAX_UPLOAD_SIZE
        # Copy default response messages
        self.response_msgs = dict(RESPONSE.items())

    def apply_config(self, config):
        self.basedir = config.get("root")
        if self.basedir is None:
            raise ServiceConfigError("basedir not defined")
        if not os.path.isdir(self.basedir):
            raise ServiceConfigError("The basedir '%s' is not a directory", self.basedir)
        if not os.access(self.basedir, os.R_OK):
            raise ServiceConfigError("Unable to read files in the '%s' directory", self.basedir)

        self.max_upload_size = parse_max_upload_size(config.get("max_upload_size"))

        self.response_msgs.update(config.get("response_messages", {}))

    def chroot(self, p):
        self.basedir = p

    def sendline(self, data):
        self.send(data + '\r\n')

    def reply(self, name, **kwargs):
        msg = self.response_msgs.get(name, "")
        self.sendline(msg.format(**kwargs))

    def handle_origin(self, parent):
        logger.debug("setting basedir to %s" % parent.basedir)
        self.basedir = parent.basedir
        self.max_upload_size = parent.max_upload_size

    def handle_established(self):
        self.processors()
        self.reply("welcome_msg")

    def handle_io_in(self, data):
        # try:
        #     data = data.decode()
        # except UnicodeDecodeError:
        #     logger.warning("error decoding")
        #     logger.debug("io_in" + data)

        logger.debug(data)
        lastsep = data.rfind(b"\n")
        if lastsep == -1:
            logger.debug("data without linebreak")
            return 0

        lastsep += 1  # add last \n
        logger.debug("input size %i, can do %i", len(data), lastsep)
        data = data[:lastsep]
        lines = data.splitlines(0)
        for line in lines:
            logger.debug("processing line '%s'" % line)
            if len(line) == 0:
                continue
            space = line.find(b' ')
            if space != -1:
                cmd = line[:space]
                args = (line[space + 1:],)
            else:
                cmd = line
                args = ()
            self.processcmd(cmd, args)
        return lastsep

    def _call(self, cmd, method, args):
        """Call the handler of a command, answer 501 if the arguments do not fit it."""
        try:
            inspect.signature(method).bind(*args)
        except TypeError:
            self.reply("syntax_err_in_args", command=cmd.decode(errors="replace"))
            return None
        return method(*args)

    def processcmd(self, cmd, args):
        logger.debug("cmd '%s'" % cmd)
        l = [i.decode(errors="replace") for i in args]

        i = incident("dionaea.modules.python.ftp.command")
        i.con = self
        i.command = cmd
        i.arguments = l
        i.report()

        cmd = cmd.upper()
        if self.state == self.UNAUTH:
            if cmd != b'USER':
                self.reply("not_logged_in")
                return
            self._call(cmd, self.ftp_USER, l)
        elif self.state == self.INAUTH:
            if cmd != b'PASS':
                self.reply("bad_cmd_seq_pass_after_user")
                return
            self._call(cmd, self.ftp_PASS, l)
        else:
            method = getattr(self, "ftp_" + cmd.decode(errors="replace"), None)
            if method is not None:
                try:
                    msg = self._call(cmd, method, l)
                except OSError as e:
                    if e.errno in STORAGE_ERRNOS:
                        # a full disk or quota: in dionaea-errors.log through the summary
                        text = "%s %s failed: %s" % (log_text(cmd), log_text(" ".join(str(a) for a in l)),
                                                     log_text(e))
                        logger.info("%s", text)
                        STORAGE.add(text)
                        self.reply("insufficient_storage")
                        return
                    if e.errno in SOCKET_ERRNOS:
                        # no socket for the data connection (EMFILE, ENFILE, ENOBUFS in the bind of PASV,
                        # ...): the resources of the system, of every session: info, one warning a minute
                        text = "%s failed: %s (%s)" % (log_text(cmd), log_text(e), self.remote.host)
                        logger.info("%s", text)
                        NO_SOCKET.add(text)
                        self.reply("cant_open_data_cnx")
                        return
                    # e.g. a root that is read-only (T-Pot mounts it :ro): answer, do not drop the session
                    logger.info("%s %s failed: %s", cmd.decode(errors="replace"), l, e)
                    self.reply("permission_denied", path=l[0] if l else "")
                    return
                if isinstance(msg, str):
                    self.error("Returning messages is deprecated please report so we can fix it")
                    self.sendline(msg)
            else:
                self.reply("cmd_not_implmntd", command=cmd.decode(errors="replace"))

    def ftp_USER(self, username):
        if not username:
            self.reply("syntax_error_user_requires_arg")
            return

        self.state = self.INAUTH
        self.user = username
        if username == "anonymous":
            self.reply("guest_name_ok_need_email")
            return
        else:
            self.reply("usr_name_ok_need_pass", username=username)
            return

    def ftp_PASS(self, password):
        if not password:
            self.reply("syntax_error_pass_requires_arg")
            return

        i = incident("dionaea.modules.python.ftp.login")
        i.con = self
        i.username = self.user
        i.password = password
        i.report()

        self.state = self.AUTHED
        if self.user == "anonymous":
            self.reply("guest_logged_in_proceed")
        else:
            self.reply("usr_logged_in_proceed")

    def ftp_FEAT(self):
        self.send('211-Features:\r\n' +
                  ' PASV\r\n' +
                  ' PORT\r\n' +
                  '211 End\r\n')
        return None

    def ftp_PORT(self, address):
        if self.dtf:
            self.dtf.close()
            self.dtf = None
        if self.dtp:
            self.dtp.close()
            self.dtp = None
        try:
            addr = list(map(int, address.split(',')))
            if len(addr) != 6 or any(not 0 <= n <= 255 for n in addr):
                raise ValueError("PORT needs h1,h2,h3,h4,p1,p2")
        except ValueError:
            self.reply("syntax_err_in_args", command="PORT")
            return None
        ip = '%d.%d.%d.%d' % tuple(addr[:4])
        port = addr[4] << 8 | addr[5]
        logger.debug("PORT cmd for port %i" % port)
        # a dual-stack socket sees an IPv4 client as ::ffff:a.b.c.d
        if self.remote.host != ip and self.remote.host != "::ffff:" + ip:
            # the client chooses it (and a client over IPv6 always hits it): info, not a warning
            logger.info("Potential FTP Bounce Scan detected")
            # a server answers it (the client would wait), the session goes on
            self.reply("illegal_port_cmd")
            return None
        dtp = FTPDataConnect(ip, port, self)
        # an error inside connect (no socket) has answered 425, the core frees it
        if not dtp.error_replied:
            self.dtp = dtp
        return None

    def ftp_PASV(self):
        if self.dtf:
            self.dtf.close()
            self.dtf = None
        if self.dtp:
            self.dtp.close()
            self.dtp = None
        dtf = FTPDataListen(host=self.local.host, port=0, ctrl=self)
        if not dtf.bound:
            # no socket (socket() failed: the core called handle_error, which answered 425, and
            # frees the connection) or bind / listen failed without an error callback
            if not dtf.error_replied:
                self.reply("cant_open_data_cnx")
                try:
                    dtf.close()
                except ReferenceError:
                    pass
            return
        self.dtf = dtf
        host = self.dtf.local.host
        port = self.dtf.local.port
        self.reply("entering_pasv_mode", host=encodeHostPort(host, port))

    def ftp_QUIT(self):
        self.reply("goodbye_msg")
        self.close()

    def real_path(self, p=None):
        if p:
            name = os.path.join(self.cwd, p)
        else:
            name = self.cwd

        if len(name) >= 1 and name[0] == '/':
            name = name[1:]
        name = os.path.join(self.basedir, name)
        name = os.path.normpath(name)
        return name

    def ftp_RETR(self, p):
        if not p:
            self.reply("syntax_err_in_args", command="RETR")
            return

        name = self.real_path(p)
        if not name.startswith(self.basedir):
            self.reply("permission_denied", path=p)
            return

        if os.path.exists(name) and os.path.isfile(name):
            if self.dtp:
                if self.dtp.status == 'established':
                    self.reply("file_status_ok_open_data_cnx")
                    self.dtp.send_file(name)
                else:
                    logger.info(
                        "dtp state %s %s:%i <-> %s:%i!",
                        self.dtp.status,
                        self.dtp.remote.host,
                        self.dtp.remote.port,
                        self.dtp.local.host,
                        self.dtp.local.port
                    )
            else:
                logger.info(
                    "no dtp on %s:%i <-> %s:%i!",
                    self.remote.host,
                    self.remote.port,
                    self.local.host,
                    self.local.port
                )
                self.reply("cant_open_data_cnx")
        else:
            self.reply("file_not_found", filename=p)

    def ftp_STOR(self, p):
        if not p:
            self.reply("syntax_err_in_args", command="STOR")
            return

        file = self.real_path(p)
        if os.path.exists(file):
            self.reply("permission_denied", path=p)
            return

        if not file.startswith(self.basedir):
            self.reply("permission_denied", path=p)
            return

        if self.dtp:
            if self.dtp.status == 'established':
                self.reply("file_status_ok_open_data_cnx")
                # The data is kept as a download, not in the root of the service; the name the
                # client used goes into the url of the upload.
                self.dtp.recv_file(p, self.max_upload_size)
            else:
                logger.info(
                    "dtp state %s %s:%i <-> %s:%i!",
                    self.dtp.status,
                    self.dtp.remote.host,
                    self.dtp.remote.port,
                    self.dtp.local.host,
                    self.dtp.local.port
                )
        else:
            logger.info(
                "no dtp on %s:%i <-> %s:%i!",
                self.remote.host,
                self.remote.port,
                self.local.host,
                self.local.port
            )
            self.reply("cant_open_data_cnx")

    def ftp_TYPE(self, t):
        if t == 'I':
            self.reply("type_set_ok", mode="I")
            return
        else:
            self.reply("cmd_not_implmntd_for_param", param=t)
            return

    def ftp_LIST(self, p=None):
        name = self.real_path(p)

        if not name.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        if os.path.exists(name):
            if self.dtp:
                if self.dtp.status == 'established':
                    self.reply("file_status_ok_open_data_cnx")
                    self.dtp.send_list(name, len(name)+1)
                else:
                    logger.info(
                        "dtp state %s %s:%i <-> %s:%i!",
                        self.dtp.status,
                        self.dtp.remote.host,
                        self.dtp.remote.port,
                        self.dtp.local.host,
                        self.dtp.local.port
                    )
            else:
                logger.info(
                    "no dtp on %s:%i <-> %s:%i!",
                    self.remote.host,
                    self.remote.port,
                    self.local.host,
                    self.local.port
                )
                self.reply("cant_open_data_cnx")
        else:
            self.reply("permission_denied", path=p)

    def ftp_PWD(self):
        self.reply("pwd_reply", cwd=self.cwd)

    def ftp_CWD(self, p):
        cwd = self.real_path(p)

        if not cwd.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        self.cwd = cwd[len(self.basedir):]
        if self.cwd == "":
            self.cwd = "/"

        if os.path.exists(cwd) and os.path.isdir(cwd):
            self.reply("req_file_actn_completed_ok")
            return

        self.reply("permission_denied", path=p)

    def ftp_PBSZ(self, arg):
        self.reply("cmd_ok")

    def ftp_SYST(self):
        self.reply("name_sys_type")

    def ftp_SIZE(self, p):
        if not p:
            self.reply("file_not_found", filename=p)
            return

        file = self.real_path(p)

        if not file.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        if os.path.exists(file) and os.path.isfile(file):
            self.reply("file_status", value=str(stat(file).st_size))
            return

        self.reply("file_not_found", filename=p)

    def ftp_MDTM(self, p):
        if not p:
            self.reply("file_not_found", filename=p)
            return

        file = self.real_path(p)
        if not file.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        if os.path.exists(file) and os.path.isfile(file):
            self.reply(
                "file_status",
                value=time.strftime('%Y%m%d%H%M%S', time.gmtime(stat(file).st_mtime))
            )
            return

        self.reply("file_not_found", filename=p)

    def ftp_RMD(self, p):
        if not p:
            self.reply("file_not_found", filename=p)
            return

        dir = self.real_path(p)
        if not dir.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        if os.path.exists(dir) and os.path.isdir(dir):
            try:
                os.rmdir(dir)
            except OSError as e:
                logger.info("RMD %s failed: %s", p, e)
                self.reply("permission_denied", path=p)
                return
            self.reply("req_file_actn_completed_ok")
            return

        self.reply("file_not_found", filename=p)

    def ftp_MKD(self, p):
        if not p:
            self.reply("file_not_found", filename=p)
            return

        dir = self.real_path(p)
        if not dir.startswith(self.basedir):
            self.reply("file_not_found", filename=p)
            return

        if os.path.isdir(dir):
            self.reply("permission_denied", path=p)
            return

        try:
            os.mkdir(dir)
        except OSError as e:
            logger.info("MKD %s failed: %s", p, e)
            self.reply("permission_denied", path=p)
            return
        self.reply("req_file_actn_completed_ok")

    def handle_error(self, err):
        pass

    def handle_disconnect(self):
        if self.dtf:
            self.dtf.close()
            self.dtf = None
        if self.dtp:
            self.dtp.close()
            self.dtp = None
        return 0


def encodeHostPort(host, port):
    numbers = host.split('.') + [str(port >> 8), str(port % 256)]
    return ','.join(numbers)


class FTPDataCon(connection):
    def __init__(self, ctrl=None):
        connection.__init__(self, 'tcp')
        self.ctrl = ctrl
        self.mode = None
        self.file = None
        self.upload = None
        self.upload_name = ""
        # handle_error answered the control connection (425)
        self.error_replied = False

    def handle_error(self, err):
        self.error_replied = True

        def failed(ctrl):
            # the core frees this connection: the session must not use it any more
            if ctrl.dtp is self:
                ctrl.dtp = None
            if ctrl.dtf is self:
                ctrl.dtf = None
            ctrl.reply("cant_open_data_cnx")
        self._ctrl_call(failed)

    def send_list(self, p, rm):
        def ls(f, r):
            logger.debug("stat %s" % f)
            name = f[r:]
            s=stat(f)
            size = s.st_size
            directory = S_ISDIR(s.st_mode)
            permissions = S_IMODE(s[ST_MODE])
            hardlinks = s.st_nlink
            modified = s.st_mtime
            owner = s.st_uid
            group = s.st_gid

            def formatMode(mode):
                return ''.join([mode & (256 >> n) and 'rwx'[n % 3] or '-' for n in range(9)])

            def formatDate(mtime):
                now = time.gmtime()
                info = {
                    'month': mtime.tm_mon,
                    'day': mtime.tm_mday,
                    'year': mtime.tm_year,
                    'hour': mtime.tm_hour,
                    'minute': mtime.tm_min
                }
                if now.tm_year != mtime.tm_year:
                    return '%(month)s %(day)02d %(year)5d' % info
                else:
                    return '%(month)s %(day)02d %(hour)02d:%(minute)02d' % info

            format = (
                '%(directory)s%(permissions)s%(hardlinks)4d '
                '%(owner)-9s %(group)-9s %(size)15d %(date)12s '
                '%(name)s'
            )
            return format % {
                'directory': directory and 'd' or '-',
                'permissions': formatMode(permissions),
                'hardlinks': hardlinks,
                'owner': owner,
                'group': group,
                'size': size,
                'date': formatDate(time.gmtime(modified)),
                'name': name
            }

        self._drop_upload()
        self.mode = 'list'
        try:
            if os.path.isdir(p):
                self.data = [ls(os.path.join(p,f), rm) for f in os.listdir(p)]
            elif os.path.isfile(p):
                self.data = [ls(p)]
        except OSError as e:
            self._transfer_failed("LIST", p, e)
            return

        logger.debug("p %s len %i" % (p, len(self.data)) )
        if len(self.data) > 0:
            self.off = 0
            self.off = self.off + 1
            self.send(self.data[self.off-1] + '\r\n')
        else:
            self.close()
            self._ctrl_call(self._transfer_done)

    def recv_file(self, name, max_size=DEFAULT_MAX_UPLOAD_SIZE):
        """
        Take the data of the connection as an upload.

        :param name: File name as the client sent it, goes into the url of the upload
        :param max_size: Maximum size of the file, a larger upload is dropped
        """
        logger.debug("upload %s", name)
        # a second STOR on this connection: what the first one got is not kept
        self._drop_upload()
        self.upload_name = name
        try:
            self.upload = UploadFile("ftp-", max_size=max_size)
        except OSError as e:
            logger.info("unable to create a file for the upload: %s (%s)", log_text(e), self.remote.host)
            NO_FILE.add("%s (%s)" % (log_text(e), self.remote.host))
            self.mode = None
            answer = "insufficient_storage" if e.errno in STORAGE_ERRNOS else "cant_open_data_cnx"
            self._ctrl_call(lambda ctrl: ctrl.reply(answer))
            self.close()
            return
        self.mode = 'recv_file'

    def send_file(self, p):
        self._drop_upload()
        self.mode = "file"
        try:
            self.file = open(p, "rb")
        except OSError as e:
            self._transfer_failed("RETR", p, e)
            return
        self.handle_io_out()

    def _transfer_failed(self, command, path, error):
        """The file or folder of a transfer can not be read: 550 on the control connection, close the data connection."""
        logger.info("%s %s failed: %s", command, path, error)
        self.mode = None
        self.data = []
        self.close()

        def answer(ctrl):
            ctrl.dtp = None
            base = ctrl.basedir
            shown = path[len(base):] if path.startswith(base) else path
            ctrl.reply("permission_denied", path=shown or "/")
        self._ctrl_call(answer)

    def _read_failed(self, error):
        """The file of a RETR can not be read on: close the data connection, 451 on the control connection."""
        logger.info("RETR read failed: %s", error)
        self.mode = None
        fileobj, self.file = self.file, None
        if fileobj is not None:
            try:
                fileobj.close()
            except OSError:
                pass
        self.close()

        def answer(ctrl):
            ctrl.dtp = None
            ctrl.reply("local_error")
        self._ctrl_call(answer)

    @staticmethod
    def _transfer_done(ctrl):
        ctrl.dtp = None
        ctrl.reply("txfr_complete_ok")

    def handle_io_in(self, data):
        if self.mode == "recv_file":
            try:
                self.upload.write(data)
            except UploadError as e:
                # too large or not writable: drop the upload and the connection
                logger.info("upload dropped: %s (%s)", log_text(e), self.remote.host)
                DROPPED.add("%s (%s)" % (log_text(e), self.remote.host))
                self.upload.discard()
                self.upload = None
                self.mode = None
                if isinstance(e, UploadTooLarge):
                    answer = "exceeded_storage_allocation"
                elif e.errno in STORAGE_ERRNOS:
                    answer = "insufficient_storage"
                else:
                    answer = "cant_open_data_cnx"

                def drop(ctrl):
                    ctrl.dtp = None
                    ctrl.reply(answer)
                # the control connection can be gone already
                self._ctrl_call(drop)
                self.close()
        # data that is no upload (after a dropped one, until the close; on the connection of a
        # LIST or RETR) is read and left
        return len(data)

    def handle_io_out(self):
        logger.debug("io_out")
        if self.mode == 'list':
            if self.off < len(self.data):
                self.off = self.off + 1
                self.send(self.data[self.off - 1] + '\r\n')
            else:
                self.close()
                self._ctrl_call(self._transfer_done)

        elif self.mode == "file":
            try:
                w = self.file.read(1024)
            except OSError as e:
                # e.g. EIO: no Traceback in the event loop, the client gets an answer
                self._read_failed(e)
                return
            self.send(w)
            if len(w) < 1024 and self.mode is not None:
                self.mode = None
                self.close()
                self.file.close()
                self._ctrl_call(self._transfer_done)

    def _drop_upload(self):
        """Remove the file of an upload that is not finished (a new command came, the connection is gone)."""
        upload, self.upload = self.upload, None
        if upload is not None:
            upload.discard()

    def handle_disconnect(self):
        upload, self.upload = self.upload, None
        try:
            if self.mode == 'recv_file' and upload:
                # the client closed the data connection: the upload is complete
                self.mode = None
                con, host = self._upload_target()
                upload.complete(con, upload_url("ftp", host, self.upload_name))
                upload = None
                self._ctrl_call(lambda ctrl: ctrl.reply("txfr_complete_ok"))
        except Exception:
            logger.exception("unable to record an upload")
        finally:
            # whatever happened (other mode, no control connection, an error): no file is left behind
            if upload is not None:
                upload.discard()
        if self.mode == 'file' and self.file:
            self.file.close()

        def forget(ctrl):
            if ctrl.dtf:
                ctrl.dtf = None
            if ctrl.dtp:
                ctrl.dtp = None
        self._ctrl_call(forget)
        return 0

    def _ctrl_call(self, func):
        """Call func(control connection) if there is one; the control connection can be freed already."""
        if not self.ctrl:
            return
        try:
            func(self.ctrl)
        except ReferenceError:
            logger.debug("control connection is gone")

    def _upload_target(self):
        """Connection an upload is logged for (the control connection: login, commands; else this one) and the address of the client."""
        try:
            ctrl = self.ctrl
            if ctrl:
                return ctrl, ctrl.remote.host
        except ReferenceError:
            pass
        return self, self.remote.host

    def handle_origin(self, parent):
        pass
        # if parent.limits._out:
        #     self._out.limit = parent.limits._out


class FTPDataConnect(FTPDataCon):
    protocol_name = "ftpdataconnect"

    def __init__(self, host=None, port=None, ctrl=None):
        FTPDataCon.__init__(self, ctrl)
        self.connect(host, port)

    def handle_established(self):
        logger.debug("DATA connection established")
        self._ctrl_call(lambda ctrl: ctrl.reply("entering_port_mode"))


class FTPDataListen(FTPDataCon):
    protocol_name = "ftpdatalisten"

    def __init__(self, host=None, port=None, ctrl=None):
        FTPDataCon.__init__(self, ctrl)
        # False: no listening socket. For TCP bind only takes the address, listen makes the socket:
        # when socket() fails (EMFILE, ...) the core calls handle_error and frees the connection,
        # when listen() fails the socket is closed without an error callback
        self.bound = False
        if host is not None:
            self.bound = bool(self.bind(host, port)) and bool(self.listen(1))
            if not self.bound:
                return
            if ctrl.limits:
                self._out.throttle = ctrl.limits['_out']

    def handle_established(self):
        logger.debug("DATA connection established")

    def handle_origin(self, parent):
        FTPDataCon.handle_origin(self, parent)
        logger.debug("Meeting parent")
        self.ctrl = parent.ctrl
        self.ctrl.dtp = self
        self.ctrl.dtf = None
        parent.ctrl = None
        parent.close()
