# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2009  Paul Baecher & Markus Koetter
#
# SPDX-License-Identifier: GPL-2.0-or-later

from dionaea import IHandlerLoader
from dionaea.core import ihandler, incident, g_dionaea
from dionaea.exception import LoaderError
from dionaea.logtext import LogSummary, log_text
from dionaea.upload import incoming_dir
from dionaea.util import md5file, sha256file

import collections
import errno
import logging
import math
import os
import re
import shutil
import stat
import tempfile
import threading
import time
logger = logging.getLogger('store')
logger.setLevel(logging.DEBUG)

# one warning a minute for the samples of all clients that are not stored or whose mode stays; the
# line of each is info (logtext.LogSummary)
NOT_STORED = LogSummary(logger, "samples not stored at max_size", "sample(s)")
NOT_PROTECTED = LogSummary(logger, "samples whose mode could not be set", "sample(s)")


#: Mode of a stored sample: read-only, never executable (the folder is on the host of the operator)
SAMPLE_MODE = 0o440
#: Seconds between two looks at download.dir (it is counted again only when it was replaced)
USAGE_REFRESH = 60.0
#: Seconds between two counts of download.dir at a refused sample (only when the folder changed since the last count)
RECOUNT_INTERVAL = 600.0
MIB = 1024 * 1024
#: The largest ``max_size`` in MiB, 2^40 as ``config.max_size`` of the streamdumper (the bytes fit into 64 bits)
MAX_MIB = 2 ** 40
#: The environment variable that replaces the option ``max_size`` (MiB, decimal digits)
MAX_SIZE_ENV = "DIONAEA_STORE_MAX_SIZE"
#: The source of ``max_size`` when it is not the variable, in the line at the start
CONFIG_SOURCE = "store.yaml"
#: A rejected value of the environment in a warning: at most this many characters
ENV_SHOWN_MAX = 64
#: Refused samples that are remembered, so a client that uploads one again and again is warned about once
REFUSED_MEMORY = 1024


def parse_max_size(value):
    """
    Convert the option ``max_size`` (MiB) to bytes.

    :param value: Value of the option, ``None``, ``""`` and ``0`` mean unlimited
    :return: Size in bytes, 0 for unlimited (a value above 0 is at least 1 byte)
    :raises ValueError: if the value is not a number from 0 to 2^40 (MAX_MIB)
    """
    if value is None or value == "":
        return 0
    if isinstance(value, bool):
        raise ValueError("max_size is no number: %r" % (value,))
    try:
        mib = float(value)
    except (TypeError, ValueError, OverflowError):
        # OverflowError: an int beyond the range of a float
        raise ValueError("max_size is no number: %.64r" % (value,))
    if math.isnan(mib) or math.isinf(mib) or mib < 0 or mib > MAX_MIB:
        raise ValueError("max_size must be a number of MiB from 0 to 2^40: %.64r" % (value,))
    size = int(mib * MIB)
    if mib > 0 and size == 0:
        # below one byte is one byte: 0 would be no limit
        return 1
    return size


def parse_env_max_size(value):
    """
    Convert the value of ``DIONAEA_STORE_MAX_SIZE`` (MiB) to bytes.

    :param value: decimal digits only (no sign, space, fraction or suffix), in the range of
        the option ``max_size``; ``0`` means unlimited
    :return: Size in bytes, 0 for unlimited
    :raises ValueError: for anything else, also ``""``
    """
    expected = "a whole number of MiB >= 0 (decimal digits) is expected"
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]+", value):
        raise ValueError(expected)
    # the range of the option (a number that is no float is refused there as well); the
    # message of the option would carry the whole value
    try:
        parse_max_size(value)
    except ValueError:
        raise ValueError(expected) from None
    return int(value) * MIB


def env_shown(value):
    """A rejected value for a warning: its first 64 characters, each one that is no printable ASCII as ``?``."""
    return "".join(c if " " <= c <= "~" else "?" for c in value[:ENV_SHOWN_MAX])


def mib_text(size):
    """``max_size`` in MiB for the line at the start: a whole number as it is, else 6 digits."""
    if size % MIB == 0:
        return "%d" % (size // MIB)
    return "%.6g" % (size / MIB)


def max_size_setting(config_value, environ=None):
    """
    The size limit in effect and its source.

    ``DIONAEA_STORE_MAX_SIZE`` replaces the option when it is set and valid (an empty one
    is unset), then the option is not read. An invalid variable is a warning and the option
    holds; an invalid option is a warning and no limit.

    :return: (bytes, source), source ``DIONAEA_STORE_MAX_SIZE`` or ``store.yaml``
    """
    if environ is None:
        environ = os.environ
    variable = environ.get(MAX_SIZE_ENV, "")
    if variable != "":
        try:
            return parse_env_max_size(variable), MAX_SIZE_ENV
        except ValueError as e:
            logger.warning("Ignoring %s='%s': %s, the value of %s holds",
                           MAX_SIZE_ENV, env_shown(variable), e, CONFIG_SOURCE)
    try:
        max_bytes = parse_max_size(config_value)
    except ValueError as e:
        logger.warning("Ignoring the option max_size of the store handler, the folder has no limit: %s", e)
        max_bytes = 0
    return max_bytes, CONFIG_SOURCE


#: _folder before the first count: no folder is known yet (None: the folder is gone)
_UNCOUNTED = object()


class DirQuota:
    """
    Total size of the files in a folder, against a limit.

    The folder is counted once (``os.scandir``, a file with several names counts
    once), in a thread of its own: dionaea loads the handlers before it listens
    and does not wait for it. Until that count ended the total is what was stored
    since the start (for that time the samples of an earlier run are not in it,
    more than ``max_bytes`` can be stored). After that it is a
    running total of what is added. Only the regular files of the folder itself
    count, not what is in its subfolders (the temporary files of the samples are
    in ``.incoming``, see upload.py).

    Every ``refresh`` seconds a thread looks at the folder itself (one stat), not
    at the samples in it: the folder is counted again only when it was replaced or
    is gone (another st_dev or st_ino; T-Pot's clean.sh does rm -rf and mkdir).
    A count of all samples every minute read 35,000 files on a Docker Desktop bind
    mount, and every file request of the event loop waited behind it.

    A sample removed from outside (ewsposter's ``del_malware_after_send``) is not
    seen by the running total. So a sample that does not fit starts a count of the
    folder in that thread, when the folder changed since the last count (its
    ``st_mtime_ns``: every create, rename and unlink of an entry of the folder
    changes it) and the last such count is ``recount_interval`` seconds ago
    (600 s). The sample itself is refused, the next one is taken from the new
    total. What dionaea does itself is no such change: the temporary file of a
    sample is made and removed in ``.incoming`` (that changes the mtime of
    ``.incoming``, not of the folder), and when the store adds a sample to a
    folder that did not change since the last count (``look()`` before, then
    ``add()``), the mtime after it is taken as the counted one. So a folder that
    is really full is not read again while samples come; at most one stat per
    refused sample. Between two such counts the total can count samples that are
    gone (fewer samples are stored, never more than ``max_bytes``), never less than
    the folder holds (a
    removal in the same tick of the filesystem clock as the count, or between the
    look and the add of a sample, is not seen until the next change). A file
    stored while a count runs can be counted twice (the count may see it as
    well), and what is added during a count is counted on top of its result.
    ``stop()`` ends a count after the entry it reads.
    """

    def __init__(self, path, max_bytes, refresh=USAGE_REFRESH, clock=time.monotonic,
                 recount_interval=RECOUNT_INTERVAL):
        self.path = path
        self.max_bytes = max_bytes
        self.refresh = refresh
        self.recount_interval = recount_interval
        self._clock = clock
        self.used = 0
        self.counts = 0             # counts of the folder that were taken (tests)
        self._checked_at = None
        self._folder = _UNCOUNTED   # (st_dev, st_ino) of the folder the last count read, None: gone
        self._mtime = None          # its st_mtime_ns, taken before that count read it
        self._recounted_at = None   # the start of the last count at a refused sample
        self._scan = None           # the thread of a check
        self._scan_result = None    # (total, folder, mtime) of a count, set by that thread
        self._scan_recounts = False  # the check runs for a refused sample and counted (set by that thread)
        self._added_since_scan = 0
        self._problem = None        # what was logged about the folder last (gone, unreadable), once per change
        self._stop = threading.Event()
        if self.max_bytes:
            self._start()

    def _problem_once(self, problem, msg, *args):
        """Log a problem with the folder when it is another one than the last (a gone folder every minute is noise)."""
        if problem != self._problem:
            self._problem = problem
            logger.warning(msg, *args)

    def _total(self):
        """
        The size of the regular files of the folder (the file that is being stored is in ``.incoming``, not counted).

        None if the folder could not be read in full, or at the stop.
        """
        seen = set()
        total = 0
        try:
            with os.scandir(self.path) as entries:
                for entry in entries:
                    if self._stop.is_set():
                        return None
                    try:
                        st = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    file_id = (st.st_dev, st.st_ino)
                    # only a file with more names can come again: the set stays small however many samples there are
                    if st.st_nlink > 1:
                        if file_id in seen:
                            continue
                        seen.add(file_id)
                    total += st.st_size
        except FileNotFoundError:
            # no folder: nothing in it (it is counted again once it is there)
            self._problem_once("gone", "Unable to read the size of %s: it is gone", self.path)
            return 0
        except OSError as e:
            self._problem_once(("unreadable", e.errno), "Unable to read the size of %s, the total stays: %s",
                               self.path, e)
            return None
        self._problem = None
        return total

    def _check(self, known, known_mtime, recount):
        """
        The thread: count the folder if it is another one than the last count read (or gone), or, for a refused
        sample (``recount``), if it changed since that count.
        """
        try:
            st = os.stat(self.path)
            folder, mtime = (st.st_dev, st.st_ino), st.st_mtime_ns
        except OSError:
            folder, mtime = None, None
        if folder is None and known is None:
            # still gone: nothing to count, logged once already
            return
        if folder == known and not (recount and mtime != known_mtime):
            return
        if folder == known:
            self._scan_recounts = True
        total = self._total() if folder is not None else self._gone()
        if total is not None:
            self._scan_result = (total, folder, mtime)

    def _gone(self):
        self._problem_once("gone", "Unable to read the size of %s: it is gone", self.path)
        return 0

    def _start(self, recount=False):
        self._checked_at = self._clock()
        self._added_since_scan = 0
        self._scan_result = None
        self._scan_recounts = False
        self._scan = threading.Thread(target=self._check, args=(self._folder, self._mtime, recount),
                                      name="store-count", daemon=True)
        self._scan.start()

    def _take_rescan(self):
        """A count that has ended becomes the total (plus what was added while it ran)."""
        if self._scan is None or self._scan.is_alive():
            return
        self._scan = None
        if self._scan_recounts:
            self._recounted_at = self._checked_at
        if self._scan_result is not None:
            total, self._folder, self._mtime = self._scan_result
            self.used = total + self._added_since_scan
            self.counts += 1
        self._scan_result = None

    def wait(self, timeout=None):
        """Wait for a running check and take its result (tests)."""
        if self._scan is not None:
            self._scan.join(timeout)
        self._take_rescan()

    def stop(self, timeout=5.0):
        """End a running count after the entry it reads (the stop of dionaea)."""
        self._stop.set()
        if self._scan is not None:
            self._scan.join(timeout)
            if not self._scan.is_alive():
                self._scan = None
                self._scan_result = None

    def allows(self, size):
        """True if a new file of ``size`` bytes fits under the limit."""
        if not self.max_bytes:
            return True
        self._take_rescan()
        fits = self.used + size <= self.max_bytes
        if self._scan is None and not self._stop.is_set():
            now = self._clock()
            if not fits and (self._recounted_at is None or now - self._recounted_at >= self.recount_interval):
                # removed samples (ewsposter) are not in the running total: count again if the folder changed
                self._start(recount=True)
            elif now - self._checked_at >= self.refresh:
                self._start()
        return fits

    def look(self):
        """
        The folder before a sample is added to it: its id and mtime (one stat), None without a limit, while a
        check runs, or if it can not be read. Give it to ``add()``.
        """
        if not self.max_bytes or self._scan is not None or self._folder in (_UNCOUNTED, None):
            return None
        try:
            st = os.stat(self.path)
        except OSError:
            return None
        return (st.st_dev, st.st_ino), st.st_mtime_ns

    def add(self, size, before=None):
        """
        Count a file that was stored.

        :param before: ``look()`` before the file was put into the folder: if the folder had not changed since the
            last count, the file is the only change, and the mtime after it is taken as the counted one (a refusal
            does not read the folder for a sample of the store itself)
        """
        self.used += size
        if self._scan is not None:
            self._added_since_scan += size
            return
        if before is None or before != (self._folder, self._mtime):
            return
        try:
            st = os.stat(self.path)
        except OSError:
            return
        if (st.st_dev, st.st_ino) == self._folder:
            self._mtime = st.st_mtime_ns


class StoreHandlerLoader(IHandlerLoader):
    name = "store"

    @classmethod
    def start(cls, config=None):
        try:
            return storehandler("dionaea.download.complete", config=config)
        except LoaderError as e:
            logger.error(e.msg, *e.args)
            return None


class storehandler(ihandler):
    """
    Move the files of ``dionaea.download.complete`` to ``<download.dir>/<md5>``.

    Incidents: ``.hash`` for every file (md5 and sha256), then ``.unique`` for a
    new file or ``.again`` for a known one. A new file that would take the
    total size of ``download.dir`` over the option ``max_size`` (MiB, 0 or
    absent: no limit) is not stored: only ``.hash`` is reported, so the md5 is
    in the logs (sqlite, json), but nothing is offered for a file that is not
    there (``.unique`` feeds the submission handlers, which read the file).
    The services remove their temporary files themselves after the incident.
    """

    def __init__(self, path, config=None):
        logger.debug("%s ready!" % (self.__class__.__name__))
        ihandler.__init__(self, path)
        if config is None:
            config = {}

        dionaea_config = g_dionaea.config().get("dionaea")
        self.download_dir = dionaea_config.get("download.dir")
        if self.download_dir is None:
            raise LoaderError("Setting download.dir not configured")
        else:
            if not os.path.isdir(self.download_dir):
                raise LoaderError("'%s' is not a directory", self.download_dir)
            if not os.access(self.download_dir, os.W_OK):
                raise LoaderError("Not allowed to create files in the '%s' directory", self.download_dir)

        max_bytes, source = max_size_setting(config.get("max_size"))
        # one line in a fixed format (doc/source/ihandler/store.rst)
        logger.info("store: max_size %s MiB (from %s)", mib_text(max_bytes), source)
        self.max_size = max_bytes
        self.quota = DirQuota(self.download_dir, max_bytes)
        self._refused = collections.OrderedDict()
        if max_bytes:
            logger.info("Stored samples are limited to %d MiB in %s", max_bytes // MIB, self.download_dir)

    def stop(self):
        """dionaea stops: a count of download.dir ends after the entry it reads."""
        self.quota.stop()

    def handle_incident(self, icd):
        logger.debug("storing file")
        p = icd.path
        md5 = md5file(p)
        sha256 = sha256file(p)

        # ToDo: use sys.path.join()
        # The file is named by its md5, as before: ewsposter and the T-Pot tools read
        # binaries/<md5>. The sha256 is reported with the incidents only.
        n = os.path.join(self.download_dir, md5)
        i = incident("dionaea.download.complete.hash")
        i.file = n
        i.url = icd.url
        if hasattr(icd, 'con'):
            i.con = icd.con
        i.md5hash = md5
        i.sha256hash = sha256
        i.report()

        try:
            os.stat(n)
            i = incident("dionaea.download.complete.again")
            logger.debug("file %s already existed" % md5)
            self._protect(n)
        except OSError:
            size = os.stat(p).st_size
            if not self.quota.allows(size):
                self._warn_refused(md5, size, icd.url)
                return
            logger.debug("saving new file %s to %s" % (md5, n))
            before = self.quota.look()
            self._place(p, n)
            self.quota.add(size, before)
            i = incident("dionaea.download.complete.unique")
        i.file = n
        if hasattr(icd, 'con'):
            i.con = icd.con
        i.url = icd.url
        i.md5hash = md5
        i.sha256hash = sha256
        i.report()

    def _warn_refused(self, md5, size, url):
        """One info line per refused sample (the last REFUSED_MEMORY of them are remembered) and the
        summary warning of all of them."""
        if md5 in self._refused:
            self._refused.move_to_end(md5)
            logger.debug("still not storing %s (%d bytes, %s)", md5, size, log_text(url))
            return
        self._refused[md5] = True
        while len(self._refused) > REFUSED_MEMORY:
            self._refused.popitem(last=False)
        logger.info(
            "Not storing %s (%d bytes, %s): %d of %d bytes of %s are used (max_size %d MiB)",
            md5, size, log_text(url), self.quota.used, self.max_size, self.download_dir, self.max_size // MIB
        )
        NOT_STORED.add("%s (%d bytes): %d of %d bytes of %s are used (max_size %d MiB)" % (
            md5, size, self.quota.used, self.max_size, self.download_dir, self.max_size // MIB))

    def _protect(self, path):
        """A sample that was stored by an earlier version may have another mode: make it 0440."""
        try:
            if stat.S_IMODE(os.stat(path).st_mode) != SAMPLE_MODE:
                os.chmod(path, SAMPLE_MODE)
        except OSError as e:
            logger.info("Unable to set the mode of %s to %o: %s", path, SAMPLE_MODE, e)
            NOT_PROTECTED.add("%s: %s" % (os.path.basename(path), log_text(e)))

    def _place(self, src, dst):
        """
        Make ``dst`` a read-only, not executable copy of ``src``.

        The mode is set on ``src`` first and ``dst`` is a hard link to it, so
        the name of the sample never exists with another mode. Where a link is
        not possible (another filesystem, e.g. the files of the emulation in /tmp),
        the data is copied to a temporary file in ``.incoming`` of the folder and
        renamed.
        """
        os.chmod(src, SAMPLE_MODE)
        try:
            os.link(src, dst)
            return
        except OSError as e:
            if e.errno != errno.EXDEV:
                raise
        folder = incoming_dir(self.download_dir)
        try:
            fd, tmp = tempfile.mkstemp(dir=folder, prefix=".store-")
        except FileNotFoundError:
            # made at the start of dionaea, gone meanwhile
            try:
                os.mkdir(folder, 0o700)
            except FileExistsError:
                pass
            fd, tmp = tempfile.mkstemp(dir=folder, prefix=".store-")
        try:
            with os.fdopen(fd, "wb") as out, open(src, "rb") as fp:
                shutil.copyfileobj(fp, out)
                os.fchmod(out.fileno(), SAMPLE_MODE)
            os.rename(tmp, dst)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
