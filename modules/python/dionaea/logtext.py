# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2026 T-Pot contributors
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Text of a client for a log line, as src/log_text.c makes it for the core.

Every byte outside 0x20..0x7e is a '?' (a str counts by its UTF-8 bytes), and the text is cut
at LIMIT characters with "..." behind, so a url, a file name or a header of a client stays on
its line and in its size. A traceback keeps its lines: each one is such a text, and at most
TRACEBACK_LINES of them stay (LogTextFormatter, the formatter of the log handler of dionaea, log.py).
LogSummary is the summary of src/log_summary.c for the python modules: at most one warning a
minute for a message that can come once per connection, request or session.
This module imports nothing of dionaea at its import (tests/functional/unit).
"""

import logging
import struct
import threading
import time
import traceback

LIMIT = 256
TRACEBACK_LINES = 40


def log_text(value, limit=LIMIT, none="None"):
    """value (bytes, str or any object) as printable ASCII of at most limit characters (and "...")."""
    if value is None:
        return none
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
    else:
        raw = str(value).encode("utf-8", "backslashreplace")
    cut = len(raw) > limit
    text = "".join(chr(b) if 0x20 <= b <= 0x7e else "?" for b in raw[:limit])
    return text + "..." if cut else text


def log_traceback(text, lines=TRACEBACK_LINES, limit=LIMIT):
    """A traceback (or any text of several lines) with every line as log_text and at most lines lines.

    A longer one keeps its first and its last lines (the outer calls, the inner calls and the
    exception) and one line in between that says how many were left out.
    """
    rows = str(text).split("\n")
    if len(rows) > lines:
        head = (lines - 1) // 2
        tail = lines - 1 - head
        rows = rows[:head] + ["... %d lines left out" % (len(rows) - head - tail)] + rows[len(rows) - tail:]
    return "\n".join(log_text(row, limit) for row in rows)


PARSE_ERRORS = (ValueError, IndexError, struct.error, UnicodeError, EOFError)


def log_unreadable(logger, message, exc, parse_errors=PARSE_ERRORS):
    """exc came up while dionaea read a message of a client: message and the text of exc.

    A parse error of the client's bytes (an instance of parse_errors) is info, with its
    traceback at debug; True is returned. Any other exception (AttributeError, TypeError,
    NameError, KeyError, ...) is an error of dionaea: a warning with its traceback, False.
    """
    if isinstance(exc, parse_errors):
        logger.info("%s: %s", message, log_text(exc))
        logger.debug("%s", message, exc_info=exc)
        return True
    logger.warning("%s, an error of dionaea: %s", message, log_text(exc), exc_info=exc)
    return False


class LogTextFormatter(logging.Formatter):
    """The exception and the stack of a record (exc_info, stack_info) as log_traceback.

    The message is the text of the record as before: the services pass a text of a client
    through log_text themselves. The record keeps its exc_text for other handlers.
    """

    def formatException(self, ei):
        return log_traceback(super().formatException(ei))

    def formatStack(self, stack_info):
        return log_traceback(super().formatStack(stack_info))

    def format(self, record):
        exc_text = record.exc_text
        if record.exc_info:
            record.exc_text = self.formatException(record.exc_info)
        elif exc_text:
            record.exc_text = log_traceback(exc_text)
        try:
            return super().format(record)
        finally:
            record.exc_text = exc_text


def log_exception(exc, name="python", message="There was an error in the Python code"):
    """An exception the C code of the python module has (traceback() of module.c).

    With a handler for the logger name (the log handler of dionaea, log.py) it is logged at
    warning with its traceback and None is returned. Without one (before log.py new(), after
    its stop()) logging would write it to stderr as it is (logging.lastResort): the message
    and log_traceback of the traceback are returned instead, which the C code writes with
    g_warning.
    """
    logger = logging.getLogger(name)
    if logger.hasHandlers():
        logger.warning(message, exc_info=exc)
        return None
    text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)).rstrip("\n")
    return message + "\n" + log_traceback(text)


#: Seconds between two warnings of a LogSummary (LOG_SUMMARY_PERIOD of src/log_summary.c)
SUMMARY_PERIOD = 60.0


class LogSummary(object):
    """At most one warning a period for a message that can come once per connection, request or session.

    The caller logs its line of every event at info, with all its detail, and hands the summary a
    short text of the event (a text of a client through log_text first): add(). The summary writes
    "<what>: <N> <unit> in the last minute, the last: <text of the last event>" at warning with its
    logger, as src/log_summary.c does for the core: the first event after a quiet period at once,
    the ones after it when the period of that warning ends.

    The services and handlers of dionaea run in the thread of the event loop, so is add(): the
    timer at the end of a period is a dionaea.core.timer, made in that thread. Without the binding
    (tests) there is no timer and the next event after the period writes the warning. clock and
    schedule(summary, after) -> bool are for tests.
    """

    def __init__(self, logger, what, unit, period=SUMMARY_PERIOD, clock=time.monotonic, schedule=None):
        self.logger = logger if isinstance(logger, logging.Logger) else logging.getLogger(logger)
        self.what = what
        self.unit = unit
        self.period = period
        self.clock = clock
        self.schedule = schedule if schedule is not None else LogSummary._timer_schedule
        self._lock = threading.Lock()
        self._timer = None
        self.reset()

    def reset(self):
        """Forget the events and the last warning (tests)."""
        with self._lock:
            self.pending = 0
            self.last = None
            self.warned_at = None
            self.scheduled = False

    def add(self, text):
        """One event; text is the text of it in the warning (None: "-")."""
        with self._lock:
            self.pending += 1
            self.last = "-" if text is None else str(text)
            due = self._due_locked()
        self._finish(due)

    def due(self):
        """The timer of the summary fired."""
        with self._lock:
            self.scheduled = False
            due = self._due_locked() if self.pending > 0 else None
        self._finish(due)

    def _due_locked(self):
        # (count, last) when the warning is due now, else the seconds to schedule (or None)
        now = self.clock()
        if self.warned_at is None or now - self.warned_at >= self.period:
            due = (self.pending, self.last)
            self.pending = 0
            self.last = None
            self.warned_at = now
            return due
        if self.scheduled:
            return None
        self.scheduled = True
        return self.warned_at + self.period - now

    def _finish(self, due):
        if due is None:
            return
        if isinstance(due, tuple):
            self.logger.warning("%s: %d %s in the last minute, the last: %s", self.what, due[0], self.unit, due[1])
            return
        if not self.schedule(self, due):
            with self._lock:
                self.scheduled = False

    @staticmethod
    def _timer_schedule(summary, after):
        try:
            from dionaea.core import timer
        except ImportError:
            return False
        summary._timer = timer(summary.due, after)
        return True
