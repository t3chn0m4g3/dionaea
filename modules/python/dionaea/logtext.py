# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2026 T-Pot contributors
#
# SPDX-License-Identifier: GPL-2.0-or-later

"""Text of a client for a log line, as src/log_text.c makes it for the core.

Every byte outside 0x20..0x7e is a '?' (a str counts by its UTF-8 bytes), and the text is cut
at LIMIT characters with "..." behind, so a url, a file name or a header of a client stays on
its line and in its size. This module imports nothing of dionaea (tests/functional/unit).
"""

LIMIT = 256


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
