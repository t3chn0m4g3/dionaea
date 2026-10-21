# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""logtext.py: the text of a client for a warning, as download_log.c makes it.

Every byte outside 0x20..0x7e is a '?' (a str counts by its UTF-8 bytes), and the text is
cut at 256 characters with "..." behind; None is the text given for it.
"""

import importlib.util
import os
from pathlib import Path

ROOT = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
    Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
spec = importlib.util.spec_from_file_location("logtext_under_test", ROOT / "logtext.py")
logtext = importlib.util.module_from_spec(spec)
spec.loader.exec_module(logtext)


def test_a_line_break_and_escapes_are_question_marks():
    text = logtext.log_text("a\nb \x1b[31mred\x1b[0m\r\x7f")
    assert text == "a?b ?[31mred?[0m??"


def test_bytes_are_cleaned_by_byte_and_utf8_counts_by_byte():
    assert logtext.log_text(b"GET /\x00\xff x") == "GET /?? x"
    assert logtext.log_text("ä") == "??"


def test_a_long_text_is_cut_at_256_with_dots():
    assert logtext.log_text("a" * 256) == "a" * 256
    assert logtext.log_text("a" * 257) == "a" * 256 + "..."
    assert logtext.log_text(b"b" * 5000) == "b" * 256 + "..."


def test_none_and_other_objects():
    assert logtext.log_text(None) == "None"
    assert logtext.log_text(None, none="(no url)") == "(no url)"
    assert logtext.log_text(OSError(28, "No space\nleft")) == "[Errno 28] No space?left"


# ---- tracebacks: every line as above, at most 40 lines ----

def test_a_traceback_keeps_its_lines_and_each_is_cleaned():
    text = 'Traceback (most recent call last):\n  File "x.py", line 1, in f\nValueError: a\x1b[31m' + "b" * 300
    lines = logtext.log_traceback(text).split("\n")
    assert lines[:2] == ['Traceback (most recent call last):', '  File "x.py", line 1, in f']
    want = "ValueError: a?[31m" + "b" * 300
    assert lines[2] == want[:256] + "..."
    assert len(lines) == 3


def test_a_long_traceback_keeps_its_first_and_last_lines():
    lines = logtext.log_traceback("\n".join("line %d" % i for i in range(1000))).split("\n")
    assert len(lines) == logtext.TRACEBACK_LINES == 40
    assert lines[:19] == ["line %d" % i for i in range(19)]
    assert lines[19] == "... 961 lines left out"
    assert lines[20:] == ["line %d" % i for i in range(980, 1000)]


def test_a_traceback_of_40_lines_stays_whole():
    text = "\n".join("line %d" % i for i in range(40))
    assert logtext.log_traceback(text) == text


def _record(exc_info=None, stack_info=None):
    import logging
    return logging.LogRecord("t", logging.ERROR, __file__, 1, "There was an error", None, exc_info,
                             sinfo=stack_info)


def _raised(message):
    import sys
    try:
        raise ValueError(message)
    except ValueError:
        return sys.exc_info()


def _printable(lines):
    return all(0x20 <= ord(c) <= 0x7e for line in lines for c in line)


def test_the_formatter_cleans_the_exception_of_a_record():
    record = _record(_raised("text of a client\n\x1b[2J" + "x" * 1000 + "\n" * 100 + "end"))
    lines = logtext.LogTextFormatter().format(record).split("\n")
    assert lines[0] == "There was an error"
    assert lines[1] == "Traceback (most recent call last):"
    assert "ValueError: text of a client" in lines
    assert "?[2J" + "x" * 252 + "..." in lines
    assert lines[-1] == "end"
    assert len(lines) == 1 + logtext.TRACEBACK_LINES
    assert _printable(lines)
    assert max(len(line) for line in lines) <= logtext.LIMIT + 3
    # the record keeps what it had, for other handlers
    assert record.exc_text is None


def test_the_formatter_cleans_a_stack_and_a_text_of_an_exception():
    record = _record(stack_info="Stack (most recent call last):\n  \x00" + "s" * 400)
    lines = logtext.LogTextFormatter().format(record).split("\n")
    assert lines == ["There was an error", "Stack (most recent call last):", "  ?" + "s" * 253 + "..."]
    record = _record()
    record.exc_text = "Traceback\n\x07bell"
    assert logtext.LogTextFormatter().format(record).split("\n") == ["There was an error", "Traceback", "?bell"]
    assert record.exc_text == "Traceback\n\x07bell"


def test_the_log_handler_of_dionaea_formats_with_it():
    """log.py: what goes to the log of the core (dlhfn) has the exception cleaned."""
    import importlib.util as util
    import logging
    import sys
    import types

    names = [name for name in sys.modules if name == "dionaea" or name.startswith("dionaea.")]
    saved = {name: sys.modules.pop(name) for name in names}
    calls = []
    package = types.ModuleType("dionaea")
    package.__path__ = [str(ROOT)]
    core = types.ModuleType("dionaea.core")
    core.dlhfn = lambda *args: calls.append(args)
    sys.modules.update({"dionaea": package, "dionaea.core": core})
    try:
        log_spec = util.spec_from_file_location("dionaea.log", ROOT / "log.py")
        log = util.module_from_spec(log_spec)
        log_spec.loader.exec_module(log)
        log.new()
        try:
            logging.getLogger("unit").error("There was an error", exc_info=_raised("\x1b]0;title\x07" + "y" * 600))
        finally:
            log.stop()
    finally:
        for name in [n for n in sys.modules if n == "dionaea" or n.startswith("dionaea.")]:
            sys.modules.pop(name, None)
        sys.modules.update(saved)
    name, level, _path, _line, msg = calls[-1]
    assert (name, level) == ("unit", logging.ERROR)
    lines = msg.split("\n")
    assert lines[0] == "There was an error"
    assert lines[-1] == ("ValueError: ?]0;title?" + "y" * 600)[:256] + "..."
    assert _printable(lines)


def test_no_service_logs_a_traceback_as_its_message():
    """A traceback goes to the log as the exception of a record (exc_info), which the formatter
    cleans, never as the text of a message (traceback.format_exc() / print_exc()). logtext.py is
    the formatter: it formats a traceback itself for log_exception."""
    import ast

    found = []
    for path in sorted(ROOT.rglob("*.py")):
        if path == ROOT / "logtext.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == "traceback"
                    and node.func.attr in ("format_exc", "print_exc", "format_exception", "print_exception")):
                found.append("%s:%d" % (path.relative_to(ROOT), node.lineno))
    assert found == []


def test_no_summary_names_its_logger_again():
    """The line of a summary has the name of its logger already ("log_sqlite ... <what>: N <unit>
    ..."): its what is no name of its logger or module and has no "<name>: " of its own."""
    import ast

    found = []
    for path in sorted(ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        loggers = {}
        for node in ast.walk(tree):
            if (isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                    and isinstance(node.value, ast.Call) and getattr(node.value.func, "attr", None) == "getLogger"
                    and node.value.args and isinstance(node.value.args[0], ast.Constant)):
                loggers[node.targets[0].id] = node.value.args[0].value
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "LogSummary"):
                continue
            what = node.args[1].value
            names = {path.stem, path.parent.name}
            if isinstance(node.args[0], ast.Name) and node.args[0].id in loggers:
                names.add(loggers[node.args[0].id])
            if what in names or ": " in what:
                found.append("%s:%d %r" % (path.relative_to(ROOT), node.lineno, what))
    assert found == []


# ---- an exception of the C code of the python module (module.c traceback()) ----

def test_an_exception_goes_to_the_logger_when_it_has_a_handler(caplog):
    import logging
    exc = _raised("handled \x1b[1m")[1]
    with caplog.at_level(logging.DEBUG, logger="python"):
        assert logtext.log_exception(exc) is None
    (record,) = [r for r in caplog.records if r.name == "python"]
    assert record.levelno == logging.WARNING
    assert record.getMessage() == "There was an error in the Python code"
    assert record.exc_info[1] is exc


def test_without_a_handler_the_text_is_returned_cleaned(monkeypatch, capsys):
    # before log.new() and after log.stop() no handler takes the record: logging would write it
    # raw to stderr (lastResort); the text comes back for g_warning of the core instead
    import logging
    root = logging.getLogger()
    monkeypatch.setattr(root, "handlers", [])
    monkeypatch.setattr(logging.getLogger("python"), "handlers", [])
    exc = _raised("at stop\x1b[2J" + "s" * 900 + "\n" * 80 + "last line")[1]
    text = logtext.log_exception(exc)
    lines = text.split("\n")
    assert lines[0] == "There was an error in the Python code"
    assert lines[1] == "Traceback (most recent call last):"
    assert lines[-1] == "last line"
    assert len(lines) == 1 + logtext.TRACEBACK_LINES
    assert _printable(lines)
    assert max(len(line) for line in lines) <= logtext.LIMIT + 3
    assert capsys.readouterr().err == ""


# ---- LogSummary: at most one warning a minute for a message of every connection ----
# (as src/log_summary.c: the first event after a quiet minute at once, the others when that
# minute ends, with their number and the text of the last one)

class SummaryClock:
    """The clock and the timer of a LogSummary in a test."""

    def __init__(self):
        self.now = 1000.0
        self.fires_at = None
        self.schedules = 0
        self.refuse = False

    def __call__(self):
        return self.now

    def schedule(self, summary, after):
        if self.refuse:
            self.refuse = False
            return False
        assert 0 < after <= logtext.SUMMARY_PERIOD
        self.fires_at = self.now + after
        self.schedules += 1
        return True

    def advance(self, summary, to):
        while self.fires_at is not None and self.fires_at <= to:
            self.now, self.fires_at = self.fires_at, None
            summary.due()
        self.now = to


def _summary(caplog, name="unit.summary"):
    import logging
    clock = SummaryClock()
    summary = logtext.LogSummary(logging.getLogger(name), "upload dropped", "upload(s)",
                                 clock=clock, schedule=clock.schedule)
    caplog.set_level(logging.DEBUG, logger=name)
    return summary, clock


def _warnings(caplog, name="unit.summary"):
    import logging
    return [r.getMessage() for r in caplog.records if r.name == name and r.levelno == logging.WARNING]


def test_a_single_event_is_a_warning_at_once(caplog):
    summary, clock = _summary(caplog)
    summary.add("write of 100 bytes at offset 5, limit is 4")
    assert _warnings(caplog) == [
        "upload dropped: 1 upload(s) in the last minute, the last: write of 100 bytes at offset 5, limit is 4"]
    assert clock.schedules == 0
    clock.advance(summary, clock.now + 600)
    assert len(_warnings(caplog)) == 1


def test_the_events_of_a_minute_are_one_more_warning_when_it_ends(caplog):
    summary, clock = _summary(caplog)
    summary.add("one")
    clock.advance(summary, clock.now + 1)
    summary.add("two")
    clock.advance(summary, clock.now + 20)
    summary.add("three")
    assert len(_warnings(caplog)) == 1
    assert clock.schedules == 1 and clock.fires_at == 1060.0
    clock.advance(summary, 1059.0)
    assert len(_warnings(caplog)) == 1
    clock.advance(summary, 1060.0)
    assert _warnings(caplog)[1] == "upload dropped: 2 upload(s) in the last minute, the last: three"
    clock.advance(summary, clock.now + 600)
    assert len(_warnings(caplog)) == 2


def test_after_a_quiet_minute_an_event_warns_at_once(caplog):
    summary, clock = _summary(caplog)
    summary.add("one")
    clock.advance(summary, clock.now + 61)
    summary.add("two")
    assert _warnings(caplog)[1] == "upload dropped: 1 upload(s) in the last minute, the last: two"
    assert clock.schedules == 0


def test_many_events_give_one_warning_a_minute(caplog):
    import re
    summary, clock = _summary(caplog)
    start = clock.now
    events = 0
    t = start
    while t < start + 600:
        clock.advance(summary, t)
        summary.add("again")
        events += 1
        t += 0.03
    clock.advance(summary, clock.now + 61)
    warnings = _warnings(caplog)
    assert len(warnings) == 11
    counts = [int(re.match(r"upload dropped: (\d+) upload\(s\) in the last minute", w).group(1)) for w in warnings]
    assert sum(counts) == events


def test_a_timer_that_fires_early_waits_for_the_minute(caplog):
    summary, clock = _summary(caplog)
    summary.add("one")
    clock.advance(summary, clock.now + 30)
    summary.add("two")
    clock.now = clock.fires_at - 10
    clock.fires_at = None
    summary.due()
    assert len(_warnings(caplog)) == 1
    assert clock.fires_at == clock.now + 10
    clock.advance(summary, clock.fires_at)
    assert len(_warnings(caplog)) == 2


def test_an_unarmed_timer_is_armed_by_the_next_event(caplog):
    summary, clock = _summary(caplog)
    summary.add("one")
    clock.advance(summary, clock.now + 1)
    clock.refuse = True
    summary.add("two")
    assert clock.fires_at is None
    summary.add("three")
    assert clock.fires_at is not None
    clock.advance(summary, clock.fires_at)
    assert _warnings(caplog)[1] == "upload dropped: 2 upload(s) in the last minute, the last: three"


def test_the_default_timer_is_one_of_the_event_loop(monkeypatch, caplog):
    """Without a schedule the summary makes a dionaea.core.timer; without the binding the
    next event after the minute warns."""
    import logging
    import sys
    import types

    made = []

    class FakeTimer:
        def __init__(self, callback, after, repeat=0.0):
            made.append((callback, after, repeat))

    core = types.ModuleType("dionaea.core")
    core.timer = FakeTimer
    monkeypatch.setitem(sys.modules, "dionaea.core", core)
    clock = SummaryClock()
    summary = logtext.LogSummary(logging.getLogger("unit.summary"), "upload dropped", "upload(s)", clock=clock)
    caplog.set_level(logging.DEBUG, logger="unit.summary")
    summary.add("one")
    clock.now += 15
    summary.add("two")
    assert len(made) == 1
    callback, after, repeat = made[0]
    assert (after, repeat) == (45.0, 0.0)
    clock.now += 45
    callback()
    assert _warnings(caplog)[1] == "upload dropped: 1 upload(s) in the last minute, the last: two"

    monkeypatch.setitem(sys.modules, "dionaea.core", None)
    clock.now += 1
    summary.add("three")
    assert len(made) == 1
    clock.now += 60
    summary.add("four")
    assert _warnings(caplog)[2] == "upload dropped: 2 upload(s) in the last minute, the last: four"


def test_a_summary_without_a_text_names_none(caplog):
    summary, clock = _summary(caplog)
    summary.add(None)
    assert _warnings(caplog) == ["upload dropped: 1 upload(s) in the last minute, the last: -"]
