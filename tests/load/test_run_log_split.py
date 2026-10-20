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
