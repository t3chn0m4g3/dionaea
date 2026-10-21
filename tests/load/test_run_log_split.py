#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""run.py: the lines of the load in dionaea.log end at the mark of the probe, not at a time.

dionaea.log has the time in seconds. The lines of the load were those before the time of
the container taken at the start of the functional tests, so a line of the load in that
second went to the functional tests. Now the probe (probe.py, loaded into dionaea) logs a
mark when run.py asks for it, and the lines before the mark are those of the load.

    python3 tests/load/test_run_log_split.py      (standard library only, no docker)
"""

import json
import logging
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import probe  # noqa: E402
import run  # noqa: E402

SECOND = "[17102026 12:00:00]"


class SplitTest(unittest.TestCase):
    def log(self, mark):
        return "\n".join([
            SECOND + " processor processor.c:10-info: emu scan stopped (scan limit), "
            "connection 0x1 smbd 10.0.0.2:4001 goes on",
            SECOND + " load-probe probe.py:1-info: " + run.LOAD_MARK % mark,
            # the functional tests, in the same second
            SECOND + " processor processor.c:10-info: emu scan stopped (scan limit), "
            "connection 0x2 smbd 10.0.0.3:5001 goes on",
        ]) + "\n"

    def test_the_lines_before_the_mark_are_the_load(self):
        lines = run.load_lines(self.log("abc"), "abc")
        self.assertEqual(len(lines), 1)
        self.assertIn(":4001 goes on", lines[0])

    def test_without_the_mark_there_is_no_split(self):
        self.assertIsNone(run.load_lines(self.log("abc"), "other"))
        self.assertIsNone(run.load_lines(self.log("abc"), None))


class GiveUpTest(unittest.TestCase):
    """The lines of the emu scans that stop are info since 0.12.3 (a warning before at a limit): the
    reason tells a stop at a limit from the scan limit; the summary warning names only reason and address."""

    LOG = "\n".join([
        SECOND + " processor processor.c:10-info: emu scan stopped (job queue full), "
        "connection 0x1 smbd 10.0.0.2:4001 goes on",
        SECOND + " processor processor.c:10-warning: emu scan stopped (stream data limit), "
        "connection 0x2 smbd 10.0.0.2:4002 goes on",
        SECOND + " processor processor.c:10-info: emu scan stopped (scan limit), "
        "connection 0x3 smbd 10.0.0.2:4003 goes on",
    ])

    def test_the_reason_tells_a_limit_from_the_scan_limit(self):
        gave_up, scan_limit = run.give_ups(self.LOG)
        self.assertEqual(gave_up, [("job queue full", 4001), ("stream data limit", 4002)])
        self.assertEqual(scan_limit, [4003])

    def test_the_summary_line_has_reason_and_address_only(self):
        line = (SECOND + " processor processor.c:20-warning: scans stopped at a limit: "
                "704 connection(s) in the last minute, the last: emu scan, job queue full (smbd 10.0.0.2:4001)")
        self.assertIsNotNone(run.SUMMARY_LINE.match(line))
        self.assertIsNone(run.SUMMARY_LINE.match(line + " AAAA"))
        overload = (SECOND + " processor processor.c:20-warning: connections closed at a limit: "
                    "3 connection(s) in the last minute, the last: stream data limit (smbd 10.0.0.2:4001)")
        self.assertIsNotNone(run.SUMMARY_LINE.match(overload))
        info = (SECOND + " processor processor.c:30-info: Stream processing limit reached (job queue full), "
                "closing connection 0xabc smbd 10.0.0.2:4001")
        self.assertEqual(run.OVERLOAD_LINE.findall(info), [("job queue full", "4001")])

    def test_a_limit_line_with_more_than_reason_and_address_is_found(self):
        summary = (SECOND + " processor processor.c:20-warning: scans stopped at a limit: "
                   "704 connection(s) in the last minute, the last: emu scan, job queue full (smbd 10.0.0.2:4001)")
        give_up = self.LOG.splitlines()[0]
        self.assertEqual(run.odd_limit_lines("\n".join([summary, give_up])), [])
        self.assertEqual(run.odd_limit_lines("\n".join([summary + " AAAA", give_up + " AAAA"])),
                         [summary + " AAAA", give_up + " AAAA"])


class MarkTest(unittest.TestCase):
    def test_without_the_file_of_the_probe_there_is_no_mark(self):
        # the probe never wrote probe.jsonl (or it is gone): the mark is missing, a failed check, no traceback
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "log").mkdir()
            load = run.Run("overload", "img", Path(folder))
            with unittest.mock.patch.object(run, "MARK_TIMEOUT", 1.0):
                self.assertIsNone(load.mark_load_end())

    def test_the_mark_the_probe_confirmed(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "log").mkdir()
            load = run.Run("overload", "img", Path(folder))
            mark = "%d-overload" % os.getpid()
            (Path(folder) / "log/probe.jsonl").write_text('{"timestamp": 1}\nnot json\n{"mark": "%s"}\n' % mark)
            self.assertEqual(load.mark_load_end(), mark)


class ProbeMarkTest(unittest.TestCase):
    def test_the_mark_is_logged_once_and_reported(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "probe-mark"
            with self.assertLogs("load-probe", logging.INFO) as logs:
                self.assertIsNone(probe.take_mark(path))
                path.write_text("abc\n")
                self.assertEqual(probe.take_mark(path), "abc")
                # once: the file is gone
                self.assertIsNone(probe.take_mark(path))
                logging.getLogger("load-probe").info("end")
            self.assertEqual([r.getMessage() for r in logs.records], [run.LOAD_MARK % "abc", "end"])
            self.assertFalse(path.exists())

    def test_a_snapshot_line_carries_the_mark(self):
        line = json.loads(probe.line({"timestamp": 1.0}, "abc"))
        self.assertEqual(line["mark"], "abc")
        self.assertNotIn("mark", json.loads(probe.line({"timestamp": 1.0}, None)))


if __name__ == "__main__":
    unittest.main()
