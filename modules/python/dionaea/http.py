# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter & Mark Schloesser
# SPDX-FileCopyrightText: 2016-2020 PhiBo (DinoTools)
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import ServiceLoader
from dionaea.core import connection, g_dionaea, incident
from dionaea.upload import incoming_file
from dionaea.util import detect_shellshock
from dionaea.exception import ServiceConfigError
from dionaea.logtext import log_text
from collections import OrderedDict
import logging
import os
import sys
import io
import email.message
import email.parser
import email.policy
import html
import mimetypes
import urllib.parse
import re
from datetime import datetime
from typing import Optional

try:
    import jinja2
    import jinja2.exceptions
except ImportError:
    jinja2 = None

logger = logging.getLogger('http')
logger.setLevel(logging.DEBUG)

STATE_HEADER, STATE_SENDFILE, STATE_POST, STATE_PUT = range(0, 4)
# the request was refused (413): what the client still sends is dropped (handle_io_in
# takes it all, see _check_max_request_size_reached)
STATE_DISCARD = 4


# multipart parts inside a part (multipart/mixed: several files of one field, RFC 2388,
# RFC 7578 4.3) are followed this deep below the body, deeper ones are ignored
MULTIPART_MAX_DEPTH = 3
# transport padding (spaces, tabs) after a boundary
MULTIPART_MAX_PADDING = 1024


def _multipart_chain(first, rest):
    yield first
    yield from rest


def _multipart_delimiters(body: bytes, start: int, end: int, boundary: bytes, budget):
    """
    The delimiter lines of body[start:end], up to the closing one, and the line break.

    A delimiter is ``--boundary`` as a whole line: at the start of the body or
    after a line break, followed by ``--`` (the closing delimiter), padding and a
    line break or the end. The line break is that of the first delimiter, CRLF
    (as RFC 2046 says) or a bare LF; the other kind inside the data is data. The
    work is bound by budget before a part is parsed.

    :param budget: [parts left] of all levels, None for no limit
    :return: (list of match objects, line break)
    """
    name = re.escape(boundary)
    padding = rb"[ \t]{0,%d}" % MULTIPART_MAX_PADDING
    line = re.compile(rb"--" + name + rb"(?:--)?" + padding + rb"(\r?\n|$)")
    m = line.match(body, start, end)
    if m is None:
        m = re.compile(rb"\n" + line.pattern).search(body, start, end)
    eol = b"\n" if m is not None and m.group(1) == b"\n" else b"\r\n"

    tail = rb"(?:(?P<closing>--)" + padding + rb"(?:" + re.escape(eol) + rb"|$)|" + padding + rb"(?:" \
        + re.escape(eol) + rb"|$))"
    opening = re.compile(rb"--" + name + tail)
    delimiter = re.compile(re.escape(eol) + rb"--" + name + tail)
    first_marker = opening.match(body, start, end)
    if first_marker is None:
        found = delimiter.finditer(body, start, end)
    else:
        found = _multipart_chain(first_marker, delimiter.finditer(body, first_marker.end(), end))
    markers = []
    for marker in found:
        markers.append(marker)
        if marker.group("closing"):
            break
        if budget is not None:
            budget[0] -= 1
            if budget[0] < 0:
                raise ValueError("Max number of fields exceeded")
    return markers, eol


def _multipart_files(body: bytes, start: int, end: int, boundary: str, budget, depth: int, field=None):
    """The files of the multipart body body[start:end], see iter_uploaded_files."""
    markers, eol = _multipart_delimiters(body, start, end, boundary.encode("utf-8", "replace"), budget)
    parser = email.parser.BytesParser(policy=email.policy.HTTP)
    separator = eol + eol
    for index, marker in enumerate(markers):
        if marker.group("closing"):
            break
        part_start = marker.end()
        part_end = markers[index + 1].start() if index + 1 < len(markers) else end
        if body.startswith(eol, part_start, part_end):
            # no headers
            continue
        pos = body.find(separator, part_start, part_end)
        if pos < 0:
            continue
        part_headers = parser.parsebytes(body[part_start:pos + len(eol)], headersonly=True)
        content_start = pos + len(separator)
        if index == len(markers) - 1 and body.endswith(eol, content_start, part_end):
            # no closing boundary (the HTTP service cuts it off): the line
            # break in front of it is not part of the content
            part_end -= len(eol)
        name = field
        if name is None:
            name = part_headers.get_param("name", header="content-disposition")
        filename = part_headers.get_filename()
        if filename is None:
            inner = part_headers.get_boundary() if part_headers.get_content_maintype() == "multipart" else None
            if inner and depth < MULTIPART_MAX_DEPTH:
                yield from _multipart_files(body, content_start, part_end, inner, budget, depth + 1, name)
            continue
        yield name, filename, body[content_start:part_end]


def iter_uploaded_files(fp, content_type: str, max_num_fields: Optional[int] = None):
    """
    Get the uploaded files of a multipart/form-data request body.

    The cgi module was removed in Python 3.13. The body is split at complete
    boundary lines (CRLF or bare LF); the work is bound by max_num_fields before
    any part is parsed (the parser of the email package parses the whole body at
    once and is slow on bodies with many tiny parts). The content of a part is
    returned as it was sent, a Content-Transfer-Encoding is not decoded (as with
    cgi). Parts that are not files are ignored; the files of nested multipart
    parts (multipart/mixed) are returned with the field name of the part that
    holds them, up to MULTIPART_MAX_DEPTH levels deep. Nothing is copied but the
    content of the files.

    :param fp: File object with the request body
    :param content_type: Value of the Content-Type header of the request
    :param max_num_fields: Raise a ValueError if the body has more parts, those of
        nested parts included
    :return: Generator of tuples (field name, file name, content as bytes)
    """
    if not content_type.lower().startswith("multipart/"):
        return

    header = email.message.Message()
    header["Content-Type"] = content_type
    boundary = header.get_boundary()
    if not boundary:
        return

    body = fp.read()
    budget = None if max_num_fields is None else [max_num_fields]
    yield from _multipart_files(body, 0, len(body), boundary, budget, 0)


class DionaeaHTTPError(Exception):
    def __init__(self, code: int):
        super().__init__(code)
        self.code = code


class FileListItem(object):
    def __init__(self, path, name):
        self.path = path
        self.name = name
        self._size = None
        self._stat = None
        self._file_type = None

    @property
    def fullname(self):
        return os.path.join(self.path, self.name)

    @property
    def is_dir(self):
        return os.path.isdir(self.fullname)

    @property
    def mtime(self):
        return datetime.fromtimestamp(self.stat.st_mtime)

    @property
    def is_link(self):
        return os.path.islink(self.fullname)

    @property
    def size(self):
        return self.stat.st_size

    @property
    def stat(self):
        if self._stat is None:
            self._stat = os.stat(self.fullname)
        return self._stat


class HTTPService(ServiceLoader):
    name = "http"

    @classmethod
    def start(cls, addr, iface=None, config=None):
        if config is None:
            config = {}

        root_path = config.get("root")
        if not root_path:
            logger.warning("Root path not set skipping service")

        daemons = []

        for port in config.get("ports", []):
            daemon = httpd(proto="tcp")
            try:
                daemon.apply_config(config)
            except ServiceConfigError as e:
                logger.error(e.msg, *e.args)
                continue
            daemon.bind(addr, port, iface=iface)
            daemon.listen()
            daemons.append(daemon)

        for port in config.get("ssl_ports", []):
            daemon = httpd(proto="tls")
            try:
                daemon.apply_config(config)
            except ServiceConfigError as e:
                logger.error(e.msg, *e.args)
                continue
            daemon.bind(addr, port, iface=iface)
            daemon.listen()
            daemons.append(daemon)

        return daemons


class httpreq:
    def __init__(self, header: bytes, connection):
        hlines = header.split(b'\n')
        req = hlines[0]
        reqparts = req.split(b" ")
        self.type = reqparts[0]
        path_parsed = urllib.parse.urlsplit(reqparts[1].decode('utf-8'))
        self.path = urllib.parse.unquote_plus(path_parsed.path)
        self.fields = {}
        try:
            if sys.version_info[1] >= 8:
                self.fields = urllib.parse.parse_qs(
                    path_parsed.query,
                    max_num_fields=connection.get_max_num_fields
                )
            else:
                logger.warning("max_num_fields is only supported with Python >= 3.8")
                self.fields = urllib.parse.parse_qs(path_parsed.query)
        except Exception:
            logger.warning("Unable to parse query string", exc_info=True)

        logger.debug("Extracted path %s", self.path)
        logger.debug("Found %d url value(s)", len(self.fields))

        self.version = reqparts[2]
        r = self.version.find(b"\r")
        if r:
            self.version = self.version[:r]
        self.headers = {}
        for header_line in hlines[1:]:
            if header_line[len(header_line)-1] == 13:  # \r
                header_line = header_line[:len(header_line)-1]
            header_name, _, header_value = header_line.partition(b":")
            if header_value is None:
                logger.warning("Header without value '%s'", log_text(header_name))
                continue
            self.headers[header_name.lower()] = header_value.strip()

    def log_req(self):
        logger.debug(
            self.type + b" " + self.path.encode('utf-8') + b" " + self.version)
        for i in self.headers:
            logger.debug(i + b":" + self.headers[i])


class Headers(object):
    def __init__(self, headers, global_headers=None, filename_pattern=None, methods=None, status_codes=None):
        if global_headers is not None:
            headers = global_headers + headers

        self.headers = OrderedDict(headers)
        logger.debug("Headers: %r", self.headers)

        self.methods = None
        if methods:
            self.methods = methods[:]

        self.filename_pattern = None
        if filename_pattern:
            self.filename_pattern = re.compile(filename_pattern)

        self.status_codes = None
        if status_codes:
            self.status_codes = status_codes[:]

    def match(self, code, method=None, filename=None):
        if self.methods:
            if not method or method not in self.methods:
                return False

        if self.filename_pattern:
            if not filename or not self.filename_pattern.match(filename):
                return False

        if self.status_codes:
            if not code or code not in self.status_codes:
                return False

        return True

    def prepare(self, values):
        for n, v in self.headers.items():
            try:
                yield (n, v.format(**values))
            except KeyError:
                logger.warning("Key error in header: %s: %s" % (n, v), exc_info=True)

    def send(self, connection, values):
        for header in self.prepare(values):
            connection.send_header(header[0], header[1])


class httpd(connection):
    shared_config_values = [
        "default_headers",
        "default_content_type",
        "detect_content_type",
        "download_dir",
        "download_suffix",
        "file_template",
        "get_max_num_fields",
        "global_template",
        "headers",
        "root",
        "rwchunksize",
        "root",
        "soap_enabled",
        "template_autoindex",
        "template_enabled",
        "template_error_pages",
        "template_file_extension",
        "template_values"
    ]

    def __init__(self, proto="tcp"):
        logger.debug("http test")
        connection.__init__(self, proto)
        self.state = STATE_HEADER
        self.header: Optional[httpreq] = None
        self.rwchunksize = 64*1024
        self._out.speed.limit = 16*1024
        self.env = None
        self.boundary = None
        self.boundary_start = None
        self.boundary_end = None
        self.fp_tmp = None
        self.cur_length = 0
        self.content_length: Optional[int] = None
        self.content_type: Optional[str] = None

        self.headers = []
        self.max_request_size = 32768 * 1024
        self.download_dir = None
        self.download_suffix = ".tmp"
        self._default_headers = [
            ("Content-Type", "{content_type}"),
            ("Content-Length", "{content_length}"),
            ("Connection", "{connection}")
        ]
        self.default_content_type = "text/html; charset=utf-8"
        self.default_headers = Headers(self._default_headers)
        self.detect_content_type = True
        self.get_max_num_fields = 100
        self.root = None
        self.global_template = None
        self.file_template = None
        self.soap_enabled = False
        self.template_autoindex = None
        self.template_enabled = False
        self.template_error_pages = None
        self.template_file_extension = ".j2"
        self.template_values = {}

        # Use own class so we can add additional files later
        self._mimetypes = mimetypes.MimeTypes()

    @property
    def request_fields(self):
        if self.header:
            return self.header.fields
        return None

    def _apply_template_config(self, config):
        """
        Load template config and if required load the template engine and the environment

        :param dict config: Template config
        :return: True = Success | False = Failure
        """
        self.template_enabled = config.get("enabled")
        if not self.template_enabled:
            return True

        if jinja2 is None:
            logger.warning("Templates enabled but jinja2 module not found")
            return False

        tpl_path = config.get("path")
        if tpl_path is None:
            logger.warning("Template path not set")
            return False
        if not os.path.isdir(tpl_path):
            logger.warning("Configured template path '%s' is not a directory", tpl_path)
            return False

        self.global_template = jinja2.Environment(
            loader=jinja2.FileSystemLoader(tpl_path)
        )
        self.file_template = jinja2.Environment(
            loader=jinja2.FileSystemLoader(self.root)
        )
        tpl_cfg = config.get("templates")
        if not tpl_cfg:
            tpl_cfg = {}
        self.template_autoindex = tpl_cfg.get("autoindex")
        self.template_error_pages = tpl_cfg.get("error_pages")
        self.template_file_extension = config.get("file_extension")
        if not self.template_file_extension:
            logger.info("File extension not configured using .j2")
            self.template_file_extension = ".j2"
        self.template_values = config.get("values")
        if not self.template_values:
            self.template_values = {}
        return True

    def _discard_post(self):
        """Close and remove the temporary file of a request body (taken, refused or left by the client)."""
        if self.fp_tmp is None:
            return
        name = self.fp_tmp.name
        try:
            self.fp_tmp.close()
        except OSError:
            pass
        self.fp_tmp = None
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass

    def _check_max_request_size_reached(self) -> bool:
        if self.cur_length > self.max_request_size:
            # nothing of the request is stored, nothing more of it is read: handle_io_in has
            # no branch for STATE_DISCARD, it ends in its last "return len(data)", so all
            # the client still sends is taken from the buffer and dropped
            self._discard_post()
            self.state = STATE_DISCARD
            # Close connection if request is to large.
            # RFC2616: "The server MAY close the connection to prevent the client from continuing the request."
            # http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html#sec10.4.14
            x = self.send_error(413)
            if x:
                self.copyfile(x)
            return True
        return False

    def _get_headers(self, code=None, filename=None, method=None):
        for header in self.headers:
            if header.match(code=code, filename=filename, method=method):
                return header
        return self.default_headers

    def _render_file_template(self, filename):
        if not self.template_enabled:
            return None

        if self.file_template is None:
            logger.error("Need to render file template, but template engine not loaded.")
            raise DionaeaHTTPError(code=500)

        logger.debug("%s %s", filename, self.root)

        filename = filename[len(os.path.abspath(self.root)):] + self.template_file_extension
        filename = filename.lstrip("/")
        try:
            template = self.file_template.get_template(filename)
        except jinja2.exceptions.TemplateNotFound:
            logger.debug("Template file '%s' not found", filename)
            return None

        return template.render(
            connection=self,
            values=self.template_values
        )

    def _render_global_autoindex(self, files):
        if not self.template_enabled:
            return None
        if self.global_template is None:
            logger.warning("Template Engine for global templates not found.")
            return None
        if self.template_autoindex is None:
            logger.warning("Template for auto index not set")
            return None

        try:
            template = self.global_template.get_template(self.template_autoindex.get("filename"))
        except jinja2.exceptions.TemplateNotFound:
            logger.warning("Template file not found. See stacktrace for additional information", exc_info=True)
            return None

        return template.render(
            connection=self,
            files=files,
            values=self.template_values
        )

    def _render_global_error_page(self, code: int, message: str):
        if not self.template_enabled:
            return None

        if self.global_template is None:
            logger.warning("Template Engine for global templates not found.")
            return None
        if self.template_error_pages is None:
            logger.warning("List with error pages not set.")
            return None

        for tpl in self.template_error_pages:
            tpl_codes = tpl.get("codes")
            if tpl_codes and code not in tpl_codes:
                continue
            tpl_filename = tpl.get("filename")
            if not tpl_filename:
                logger.warning("Template filename not set")
                continue

            template = None
            try:
                template = self.global_template.get_template(
                    tpl_filename.format(code=code)
                )
            except jinja2.exceptions.TemplateNotFound:
                pass

            if template:
                return template.render(
                    code=code,
                    message=message,
                    values=self.template_values
                )

        return None

    def apply_config(self, config):
        dionaea_config = g_dionaea.config().get("dionaea")
        self.download_dir = dionaea_config.get("download.dir")
        self.download_suffix = dionaea_config.get("download.suffix", ".tmp")
        self.default_content_type = config.get(
            "default_content_type",
            self.default_content_type
        )
        self.detect_content_type = config.get(
            "detect_content_type",
            self.detect_content_type
        )
        self.get_max_num_fields = config.get(
            "get_max_num_fields",
            self.get_max_num_fields
        )

        default_headers = config.get("default_headers", self._default_headers)
        global_headers = config.get('global_headers', [])

        self.default_headers = Headers(default_headers, global_headers=global_headers)

        headers = config.get('headers', [])
        for header in headers:
            self.headers.append(
                Headers(
                    header.get("headers", []),
                    global_headers=global_headers,
                    filename_pattern=header.get("filename_pattern"),
                    status_codes=header.get("status_codes")
                )
            )

        self.headers.append(
            Headers(
                [
                    ("Location", "{location}"),
                    ("Connection", "{connection}")
                ],
                global_headers=global_headers,
                status_codes=[301, 302]
            )
        )

        self.headers.append(
            Headers(
                [
                    ("Allow", "{allow}"),
                    ("Connection", "{connection}")
                ],
                global_headers=global_headers,
                methods=["options"]
            )
        )

        conf_max_request_size = config.get("max_request_size")
        if conf_max_request_size is not None:
            try:
                self.max_request_size = int(conf_max_request_size) * 1024
            except ValueError:
                logger.warning("Error while converting 'max_request_size' to an integer value. Using default value.")

        self.soap_enabled = True if config.get("soap_enabled") else False

        self.root = config.get("root")
        if self.root is None:
            logger.warning("Root directory not configured")
        else:
            if not os.path.isdir(self.root):
                logger.warning("Root path '%s' is not a directory", self.root)
            elif not os.access(self.root, os.R_OK):
                logger.warning("Unable to read content of root directory '%s'", self.root)

        template_config = config.get("template")
        if template_config is None:
            template_config = {}
        self._apply_template_config(template_config)

    def handle_origin(self, parent):
        pass

    def handle_established(self):
        self.timeouts.idle = 10
        self.processors()

    def chroot(self, path):
        self.root = path

    def handle_io_in(self, data):
        if self.state == STATE_HEADER:
            # End Of Head
            end_of_head = data.find(b'\r\n\r\n')
            # Start Of Content
            start_of_content = end_of_head + 4

            if end_of_head == -1:
                end_of_head = data.find(b'\n\n')
                start_of_content = end_of_head + 2
            if end_of_head == -1:
                return 0

            header = data[0:end_of_head]
            data = data[start_of_content:]
            self.header = httpreq(header, self)
            self.header.log_req()
            for _n, v in self.header.headers.items():
                detect_shellshock(self, v)

            if self.header.type == b'GET':
                self.handle_GET()
                return len(data)

            elif self.header.type == b'HEAD':
                self.handle_HEAD()
                return len(data)

            elif self.header.type == b'POST':
                if b'content-type' not in self.header.headers and b'content-type' not in self.header.headers:
                    self.handle_POST()
                    return len(data)

                if self.soap_enabled and b"soapaction" in self.header.headers:
                    return self.handle_POST_SOAP(data)

                try:
                    self.content_length = int(self.header.headers[b'content-length'].decode("utf-8"))
                    self.content_type = self.header.headers[b'content-type'].decode("utf-8")
                except Exception:
                    # ignore decode() errors
                    logger.warning("Ignoring decode errors", exc_info=True)
                    self.handle_POST()
                    return len(data)

                self.state = STATE_POST

                if self.content_type.lower().startswith("multipart/form-data"):
                    # the boundary as the parser reads it (quoted or not, other parameters behind it).
                    # More on boundaries see: https://www.rfc-editor.org/rfc/rfc2046#section-5.1.1
                    header = email.message.Message()
                    header["Content-Type"] = self.content_type
                    boundary = header.get_boundary()
                    if boundary:
                        self.boundary = b"--" + boundary.encode("utf-8", "replace") + b"--"
                        name = re.escape(self.boundary)
                        self.boundary_end = re.compile(rb"\n" + name + rb"\r?\n")
                        self.boundary_start = re.compile(name + rb"\r?\n")

                # dump post content to file
                self.fp_tmp = incoming_file("http-", suffix=self.download_suffix, download_dir=self.download_dir)

                self.cur_length = start_of_content

                if self.boundary:
                    return start_of_content + self._post_multipart(data)

                if len(data) < self.content_length:
                    return start_of_content
                self.fp_tmp.write(data[:self.content_length])

                self.handle_POST()
                return start_of_content + self.content_length

            elif self.header.type == b'OPTIONS':
                self.handle_OPTIONS()
                return len(data)

            # ToDo
            # elif self.header.type == b'PUT':
            #     self.handle_PUT()

            # method not found
            self.handle_unknown()
            return len(data)

        elif self.state == STATE_POST:
            data_length = len(data)
            if self.boundary:
                return self._post_multipart(data)

            self.cur_length += data_length
            if self._check_max_request_size_reached():
                return data_length
            if self.fp_tmp.tell() + data_length > self.content_length:
                logger.warning("More data send as specified in the Content-Length header")
                self.fp_tmp.write(data[:self.content_length - self.fp_tmp.tell()])
                self.handle_POST()
                return data_length

            self.fp_tmp.write(data)
            if self.fp_tmp.tell() == self.content_length:
                self.handle_POST()
            return data_length

        elif self.state == STATE_PUT:
            logger.debug("putting to me")
        elif self.state == STATE_SENDFILE:
            logger.debug("sending file")
            return 0

        return len(data)

    def _post_multipart(self, data):
        """
        Write the data of a multipart body into the temporary file, up to its end.

        The body ends after its closing delimiter, a line of its own
        (``--boundary--``, CRLF or a bare LF), or at the Content-Length, whichever
        comes first. What could be the start of the closing delimiter stays in the
        buffer until more data comes.

        :return: Number of bytes of data used
        """
        written = self.fp_tmp.tell()
        end = None
        m = self.boundary_start.match(data) if written == 0 else None
        if m is None:
            m = self.boundary_end.search(data)
        if m is not None:
            end = m.end()
        if self.content_length and self.content_length > 0 and written + (len(data) if end is None else end) \
                >= self.content_length:
            end = self.content_length - written
        if end is None:
            # \n--boundary--\r\n can start in the last bytes
            take = max(0, len(data) - len(self.boundary) - 3)
        else:
            take = end
        self.cur_length += take
        if self._check_max_request_size_reached():
            return len(data)
        self.fp_tmp.write(data[:take])
        if end is not None:
            self.handle_POST()
        return take

    def handle_GET(self):
        """Handle the GET method. Send the header and the file."""
        x = self.send_head()
        if x:
            self.copyfile(x)

    def handle_HEAD(self):
        """Handle the HEAD method. Send only the header but not the file."""
        x = self.send_head()
        if x:
            x.close()
            self.close()

    def handle_OPTIONS(self):
        """
        Handle the OPTIONS method. Returns the HTTP methods that the server supports.
        """
        self.send_response(200)
        headers = self._get_headers(code=200, method="options")
        headers.send(
            self,
            {
                "allow": "OPTIONS, GET, HEAD, POST",
                "connection": "close",
                "content_length": 0
            }
        )
        self.end_headers()
        self.close()

    def handle_POST(self):
        """
        Handle the POST method. Send the head and the file. But ignore the POST params.
        Use the bistreams for a better analysis.
        """
        if self.fp_tmp is not None:
            self.fp_tmp.seek(0)
            try:
                uploads = list(iter_uploaded_files(
                    self.fp_tmp,
                    self.content_type,
                    max_num_fields=self.get_max_num_fields
                ))
            except ValueError as e:
                logger.warning("Ignoring the POST data: %s", log_text(e))
                uploads = []
            except Exception:
                logger.warning("Unable to parse the POST data", exc_info=True)
                uploads = []

            for _field_name, _filename, data in uploads:
                # don't handle empty files
                if len(data) == 0:
                    continue

                fp_tmp = incoming_file("http-", suffix=self.download_suffix, download_dir=self.download_dir)
                fp_tmp.write(data)

                icd = incident("dionaea.download.complete")
                icd.path = fp_tmp.name
                icd.con = self
                # We need the url for logging
                icd.url = ""
                fp_tmp.close()
                icd.report()
                os.unlink(fp_tmp.name)

            self._discard_post()

        x = self.send_head()
        if x:
            self.copyfile(x)

    def handle_POST_SOAP(self, data):
        soap_action = self.header.headers[b'soapaction']
        content_length = int(self.header.headers[b'content-length'].decode("ascii"))
        if len(data) < content_length:
            return 0

        if soap_action == b"urn:dslforum-org:service:Time:1#SetNTPServers":
            regex = re.compile(rb"<(?P<tag_name>NewNTPServer\d)[^>]*>(?P<data>.*?)</(?P=tag_name)\s*>")
            for d in regex.finditer(data[:content_length], re.I):
                from .util import find_shell_download
                find_shell_download(self, d.group("data"))

        # ToDo: response
        self.close()
        return content_length

    def handle_PUT(self):
        pass

    def handle_unknown(self):
        x = self.send_error(501)
        if x:
            self.copyfile(x)

    def copyfile(self, f):
        self.file = f
        self.state = STATE_SENDFILE
        self.handle_io_out()

    def send_head(self):
        rpath = os.path.normpath(self.header.path)
        fpath = os.path.join(self.root, rpath[1:])
        apath = os.path.abspath(fpath)
        aroot = os.path.abspath(self.root)
        logger.debug(
            "root %s aroot %s rpath %s fpath %s apath %s" % (
                self.root,
                aroot,
                rpath,
                fpath,
                apath
            )
        )

        if not apath.startswith(aroot):
            return self.send_error(404, "File not found")

        if os.path.isdir(apath):
            if self.header.path.endswith('/'):
                testpath = os.path.join(apath, "index.html")
                if os.path.isfile(testpath) or os.path.isfile(testpath + self.template_file_extension):
                    apath = testpath
            else:
                self.send_response(301)
                headers = self._get_headers(code=301)
                headers.send(
                    self,
                    {
                        "connection": "close",
                        "location": self.header.path + "/"
                    }
                )
                self.end_headers()
                self.close()
                return None

        if os.path.isdir(apath):
            return self.list_directory(apath)

        elif os.path.isfile(apath) or os.path.isfile(apath + self.template_file_extension):
            if apath.endswith(self.template_file_extension):
                # Don't return raw template files
                return self.send_error(404)

            try:
                content = self._render_file_template(apath)
            except DionaeaHTTPError as e:
                return self.send_error(code=e.code)

            if isinstance(content, str):
                content = content.encode("utf-8")

            if content:
                f = io.BytesIO()
                f.write(content)
                f.seek(0)
                content_length = len(content)
            else:
                f = io.open(apath, "rb")
                content_length = os.stat(apath).st_size

            content_type = self.default_content_type
            if self.detect_content_type:
                # Try to detect Content-Type of a file
                detected_mimetype = self._mimetypes.guess_type(apath)
                logger.debug("Detected mimetype %s", detected_mimetype)
                if detected_mimetype[0]:
                    content_type = detected_mimetype[0]

            self.send_response(200)
            headers = self._get_headers(code=200, filename=apath)
            headers.send(
                self,
                {
                    "connection": "close",
                    "content_length": content_length,
                    "content_type": content_type
                }
            )
            self.end_headers()
            return f

        return self.send_error(404)

    def handle_io_out(self):
        logger.debug("handle_io_out")
        if self.state == STATE_SENDFILE:
            w = self.file.read(self.rwchunksize)
            if len(w) > 0:
                self.send(w)
            # send call call handle_io_out
            # to avoid double close warning we check state
            if len(w) < self.rwchunksize and self.state is not None:
                self.state = None
                self.close()
                self.file.close()

    def list_directory(self, path):
        """Helper to produce a directory listing (absent index.html).

        Return value is either a file object, or None (indicating an
        error).  In either case, the headers are sent, making the
        interface the same as for send_head().

        """
        try:
            filenames = os.listdir(path)
        except os.error:
            self.send_error(404, "No permission to list directory")
            return None

        files = []
        for name in filenames:
            if name.endswith(self.template_file_extension):
                # ToDo: add templates to the file list
                # How to calculate the size of the template file
                continue
            files.append(
                FileListItem(
                    path=path,
                    name=name
                )
            )

        content = self._render_global_autoindex(files=files)
        enc = "utf-8"
        if content is None:
            files.sort(key=lambda a: a.name.lower())
            r = []
            displaypath = html.escape(self.header.path)
            r.append('<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">')
            r.append("<html>\n<title>Directory listing for %s</title>\n" % displaypath)
            r.append("<body>\n<h2>Directory listing for %s</h2>\n" % displaypath)
            r.append("<hr>\n<ul>\n")
            r.append('<li><a href="../">../</a>\n')

            for file in files:
                displayname = linkname = file.name
                # Append / for directories or @ for symbolic links
                if file.is_dir:
                    displayname = file.name + "/"
                    linkname = file.name + "/"
                if file.is_link:
                    displayname = file.name + "@"
                    # Note: a link to a directory displays with @ and links with /
                r.append(
                    '<li><a href="%s">%s</a>\n' % (
                        urllib.parse.quote(linkname),
                        html.escape(displayname)
                    )
                )

            r.append("</ul>\n<hr>\n</body>\n</html>\n")
            enc = sys.getfilesystemencoding()
            content = "".join(r).encode(enc)

        if isinstance(content, str):
            content = content.encode("utf-8")

        self.send_response(200)
        headers = self._get_headers(code=200)
        headers.send(
            self,
            {
                "connection": "close",
                "content_length": len(content),
                "content_type": "text/html; charset=%s" % enc
            }
        )
        self.end_headers()
        f = io.BytesIO()
        f.write(content)
        f.seek(0)
        return f

    def send_response(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        self.send("%s %d %s\r\n" % ("HTTP/1.1", code, message))

    def send_error(self, code, message=None):
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        enc = sys.getfilesystemencoding()

        content = self._render_global_error_page(
            code=code,
            message=message
        )

        if content is None:
            r = []
            r.append('<?xml version="1.0" encoding="%s"?>\n' % (enc))
            r.append('<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"\n')
            r.append('         "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">\n')
            r.append('<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">\n')
            r.append(' <head>\n')
            r.append('  <title>%d - %s</title>\n' % (code, message))
            r.append(' </head>\n')
            r.append(' <body>\n')
            r.append('  <h1>%d - %s</h1>\n' % (code, message))
            r.append(' </body>\n')
            r.append('</html>\n')
            content = ''.join(r)

        if isinstance(content, str):
            content = content.encode(enc)

        self.send_response(code, message)

        headers = self._get_headers(code=code)
        headers.send(
            self,
            {
                "connection": "close",
                "content_length": len(content),
                "content_type": "text/html; charset=%s" % enc
            }
        )
        self.end_headers()

        f = io.BytesIO()
        f.write(content)
        f.seek(0)
        return f

    def send_header(self, key, value):
        self.send("%s: %s\r\n" % (key, value))

    def end_headers(self):
        self.send("\r\n")

    def handle_disconnect(self):
        # the body of a request that never got complete
        self._discard_post()
        return False

    def handle_timeout_idle(self):
        return False

    responses = {
        100: ('Continue', 'Request received, please continue'),
        101: ('Switching Protocols',
              'Switching to new protocol; obey Upgrade header'),

        200: ('OK', 'Request fulfilled, document follows'),
        201: ('Created', 'Document created, URL follows'),
        202: ('Accepted',
              'Request accepted, processing continues off-line'),
        203: ('Non-Authoritative Information', 'Request fulfilled from cache'),
        204: ('No Content', 'Request fulfilled, nothing follows'),
        205: ('Reset Content', 'Clear input form for further input.'),
        206: ('Partial Content', 'Partial content follows.'),

        300: ('Multiple Choices',
              'Object has several resources -- see URI list'),
        301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
        302: ('Found', 'Object moved temporarily -- see URI list'),
        303: ('See Other', 'Object moved -- see Method and URL list'),
        304: ('Not Modified',
              'Document has not changed since given time'),
        305: ('Use Proxy',
              ('You must use proxy specified in Location to access this '
               'resource.')),
        307: ('Temporary Redirect',
              'Object moved temporarily -- see URI list'),

        400: ('Bad Request',
              'Bad request syntax or unsupported method'),
        401: ('Unauthorized',
              'No permission -- see authorization schemes'),
        402: ('Payment Required',
              'No payment -- see charging schemes'),
        403: ('Forbidden',
              'Request forbidden -- authorization will not help'),
        404: ('Not Found', 'Nothing matches the given URI'),
        405: ('Method Not Allowed',
              'Specified method is invalid for this server.'),
        406: ('Not Acceptable', 'URI not available in preferred format.'),
        407: ('Proxy Authentication Required',
              ('You must authenticate with '
               'this proxy before proceeding.')),
        408: ('Request Timeout', 'Request timed out; try again later.'),
        409: ('Conflict', 'Request conflict.'),
        410: ('Gone',
              'URI no longer exists and has been permanently removed.'),
        411: ('Length Required', 'Client must specify Content-Length.'),
        412: ('Precondition Failed', 'Precondition in headers is false.'),
        413: ('Request Entity Too Large', 'Entity is too large.'),
        414: ('Request-URI Too Long', 'URI is too long.'),
        415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
        416: ('Requested Range Not Satisfiable',
              'Cannot satisfy request range.'),
        417: ('Expectation Failed',
              'Expect condition could not be satisfied.'),

        500: ('Internal Server Error', 'Server got itself in trouble'),
        501: ('Not Implemented',
              'Server does not support this operation'),
        502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
        503: ('Service Unavailable',
              'The server cannot process the request due to a high load'),
        504: ('Gateway Timeout',
              'The gateway server did not receive a timely response'),
        505: ('HTTP Version Not Supported', 'Cannot fulfill request.'),
    }
