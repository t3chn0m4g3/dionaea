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
