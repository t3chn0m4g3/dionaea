# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2026 T-Pot contributors
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Files that a client uploads (FTP STOR, SMB write).

An upload goes the same way as a download: the service collects the data in a
temporary file in ``<download.dir>/.incoming`` (:func:`incoming_file`) and reports
``dionaea.download.complete``, ``store`` makes ``dionaea.download.complete.hash``
and the file ``<download.dir>/<md5>`` of it, the sqlite and JSON logs take the rest.

What a client sends is not trusted: the size of a file is bound by
``max_upload_size`` (the highest offset that is written counts, so a small
write at a huge offset does not make a huge sparse file).
"""

import logging
import os
import tempfile
from typing import Optional
from urllib.parse import quote

from dionaea.logtext import LogSummary, log_text

logger = logging.getLogger("upload")

#: The warnings of the uploads that are dropped or whose file stays (one a minute, the line of each is info)
HOLES = LogSummary(logger, "uploads dropped for their holes", "upload(s)")
NOT_CLOSED = LogSummary(logger, "upload files not closed", "file(s)")
NOT_REMOVED = LogSummary(logger, "upload files not removed", "file(s)")

#: Default of the service option ``max_upload_size`` (bytes), the same as the largest HTTP request
DEFAULT_MAX_UPLOAD_SIZE = 32 * 1024 * 1024

#: Bytes a file may be larger than the data that was written into it (holes of a client that writes out of order)
MAX_SPARSE_GAP = 1024 * 1024

#: Longest file name in the url of an upload (characters before the percent encoding)
MAX_URL_NAME_LENGTH = 255


#: Folder of the temporary files of samples, in download.dir (the same filesystem: store.py links a sample from
#: there as ``<download.dir>/<md5>``). A file made and removed there does not change download.dir itself: the size
#: cap of the store reads download.dir again only when its mtime changed, and counts only its own files.
INCOMING_DIR = ".incoming"


def _client(con) -> str:
    """The address of the client of con, "-" without one."""
    remote = getattr(con, "remote", None)
    host = getattr(remote, "host", None) if remote is not None else None
    return host if host else "-"


def incoming_dir(download_dir: str) -> str:
    """The folder of the temporary files of samples in ``download_dir``."""
    return os.path.join(download_dir, INCOMING_DIR)


def incoming_file(prefix: str, suffix: Optional[str] = None, download_dir: Optional[str] = None):
    """
    A temporary file for a sample: ``NamedTemporaryFile(delete=False)`` (mode 0600) in ``<download_dir>/.incoming``.

    dionaea makes the folder (0700) and removes what an earlier run left in it at the start (src/util.c,
    ``incoming_prepare``); if it is gone meanwhile it is made again here.

    :param prefix: Prefix of the name (ftp-, http-, ...)
    :param suffix: Suffix of the name
    :param download_dir: download.dir (None: the folder of the system for temporary files, store.py copies the
        sample then)
    :return: The open file, its name is ``.name``
    """
    if download_dir is None:
        return tempfile.NamedTemporaryFile(delete=False, prefix=prefix, suffix=suffix)
    folder = incoming_dir(download_dir)
    try:
        return tempfile.NamedTemporaryFile(delete=False, prefix=prefix, suffix=suffix, dir=folder)
    except FileNotFoundError:
        if not os.path.isdir(download_dir):
            raise
    try:
        os.mkdir(folder, 0o700)
    except FileExistsError:
        pass
    return tempfile.NamedTemporaryFile(delete=False, prefix=prefix, suffix=suffix, dir=folder)


class UploadError(Exception):
    """The data of an upload can not be taken.

    :param errno: errno of the OSError behind it (ENOSPC, EDQUOT: the disk is full), None if there is none
    """

    # errno is a keyword argument of the callers; the exception is never pickled or copied
    def __init__(self, *args, errno: Optional[int] = None):  # noqa: B042
        super().__init__(*args)
        self.errno = errno


class UploadTooLarge(UploadError):
    """The upload would be larger than max_upload_size."""


def parse_max_upload_size(value, default=DEFAULT_MAX_UPLOAD_SIZE) -> int:
    """
    Read the service option ``max_upload_size``.

    :param value: Value of the option (bytes) or None
    :param default: Value to use if the option is not set or not valid
    :return: Maximum size of one uploaded file in bytes
    """
    if value is None:
        return default
    try:
        size = int(value)
    except (TypeError, ValueError):
        logger.warning("max_upload_size '%s' is not a number, using %d", value, default)
        return default
    if size <= 0:
        logger.warning("max_upload_size '%s' is not positive, using %d", value, default)
        return default
    return size


def _url_segment(segment: str, safe: str) -> str:
    """One segment of the path of an url, percent encoded; one of only dots ("." or "..") is percent encoded too."""
    if segment and segment.strip(".") == "":
        return "%2E" * len(segment)
    return quote(segment, safe=safe)


def upload_url(scheme: str, host: str, filename, share=None) -> str:
    """
    Url of an uploaded file: ``<scheme>://<address of the client>/<file name>``, with a
    share ``<scheme>://<address of the client>/<share>/<file name>``.

    The url is made of what the client sent: the names are shortened and
    percent encoded, so a log line and a url hold them as plain text.

    :param scheme: ftp or smb
    :param host: Address of the client
    :param filename: File name or path as the client sent it, str or bytes
    :param share: Name of the share (SMB) the file is in, str or bytes; None or empty for none
    """
    if isinstance(filename, bytes):
        filename = filename.decode("utf-8", errors="replace")
    filename = filename.replace("\\", "/").replace("\x00", "").lstrip("/")
    filename = filename[:MAX_URL_NAME_LENGTH]
    path = "/".join(_url_segment(part, "") for part in filename.split("/"))
    if isinstance(share, bytes):
        share = share.decode("utf-8", errors="replace")
    if share:
        share = share.replace("\x00", "").replace("\\", "/").strip("/").rsplit("/", 1)[-1]
    if share:
        # a share name has no "/"; "$" (C$, IPC$) is a character a path may have as it is
        path = _url_segment(share[:MAX_URL_NAME_LENGTH], "$") + "/" + path
    host = host or ""
    if host.startswith("::ffff:") and host.count(":") == 3 and "." in host:
        # IPv4 address of a client that came in on an IPv6 socket
        host = host[len("::ffff:"):]
    if ":" in host:
        host = "[%s]" % host
    return "%s://%s/%s" % (scheme, host, path)


class UploadFile(object):
    """
    A temporary file for the data of one upload, bound in size.

    :param prefix: Prefix of the name of the temporary file (ftp-, smb-)
    :param max_size: Maximum size of the file in bytes
    :param download_dir: download.dir, default is ``download.dir`` of the dionaea config; the temporary file is in
        its folder ``.incoming`` (:func:`incoming_file`)
    :param suffix: Suffix of the temporary file, default is ``download.suffix`` of the dionaea config
    """

    def __init__(self, prefix: str, max_size: int = DEFAULT_MAX_UPLOAD_SIZE,
                 download_dir: Optional[str] = None, suffix: Optional[str] = None):
        if download_dir is None or suffix is None:
            from dionaea.core import g_dionaea
            dionaea_config = g_dionaea.config().get("dionaea")
            if download_dir is None:
                download_dir = dionaea_config.get("download.dir")
            if suffix is None:
                suffix = dionaea_config.get("download.suffix", ".tmp")
        self.max_size = max_size
        self.size = 0
        #: Bytes written, with overlaps counted twice; size - received is the length of the holes
        self.received = 0
        self._too_large = False
        #: Name the client gave the file, for the url (set by the service)
        self.client_name = ""
        #: Share of an SMB upload, for the url (set by the service)
        self.share = None
        self._dropped = False
        self._fp = incoming_file(prefix, suffix=suffix, download_dir=download_dir)
        self.name = self._fp.name

    def write(self, data: bytes, offset: Optional[int] = None) -> int:
        """
        Write data at offset (default: after the data written so far).

        :return: Number of bytes written
        :raises UploadTooLarge: if the data would end beyond max_size, nothing is written then
        :raises UploadError: if the file is closed or can not be written
        """
        if self._fp is None:
            if self._too_large:
                raise UploadTooLarge("file was dropped, it was too large")
            raise UploadError("file is closed or dropped")
        if offset is None:
            offset = self.size
        if offset < 0 or offset + len(data) > self.max_size:
            self._too_large = True
            raise UploadTooLarge("write of %d bytes at offset %d, limit is %d" % (len(data), offset, self.max_size))
        try:
            self._fp.seek(offset)
            self._fp.write(data)
        except OSError as e:
            raise UploadError("unable to write to %s: %s" % (self.name, e), errno=e.errno) from e
        self.size = max(self.size, offset + len(data))
        self.received += len(data)
        return len(data)

    def discard(self) -> None:
        """Close and remove the file, it is not reported then."""
        self._dropped = True
        self._close()
        self._unlink()

    def complete(self, con, url: str) -> bool:
        """
        Close the file and report it as ``dionaea.download.complete``, then remove it.

        An empty file, a file that was discarded and a file that is mostly holes
        (more than MAX_SPARSE_GAP larger than the data written; store.py would read all of it
        for a few bytes of the client) are not reported.

        :param con: Connection of the client
        :param url: Url of the upload, see :func:`upload_url`
        :return: True if the file was reported
        """
        from dionaea.core import incident
        self._close()
        reported = False
        try:
            if self.size - self.received > MAX_SPARSE_GAP:
                client = _client(con)
                logger.info("dropping %s: %d bytes written, size is %d (%s)", self.name, self.received, self.size,
                            client)
                HOLES.add("%d bytes written, size is %d (%s)" % (self.received, self.size, client))
            elif self.size > 0 and not self._dropped:
                icd = incident("dionaea.download.complete")
                icd.url = url
                icd.con = con
                icd.path = self.name
                icd.report()
                reported = True
        finally:
            self._unlink()
        return reported

    def _close(self):
        if self._fp is not None:
            try:
                self._fp.close()
            except OSError as e:
                logger.info("unable to close %s: %s", self.name, e)
                NOT_CLOSED.add(log_text(e))
            self._fp = None

    def _unlink(self):
        try:
            os.unlink(self.name)
        except FileNotFoundError:
            pass
        except OSError as e:
            logger.info("unable to remove %s: %s", self.name, e)
            NOT_REMOVED.add(log_text(e))
