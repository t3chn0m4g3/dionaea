# This file is part of the dionaea honeypot
# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: CC0-1.0

"""Check raw multipart bytes without loading the native connection binding."""

import ast
import email.message
import email.parser
import email.policy
import io
import os
from pathlib import Path
import re
from typing import Optional

import pytest


def load_parser():
    root = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
    source = root / "http.py"
    tree = ast.parse(source.read_text(), filename=str(source))

    def wanted(node):
        # the parser and its helpers / bounds (_multipart_*, MULTIPART_*)
        if isinstance(node, ast.FunctionDef):
            return node.name == "iter_uploaded_files" or node.name.startswith("_multipart")
        if isinstance(node, ast.Assign):
            return all(isinstance(t, ast.Name) and t.id.startswith("MULTIPART_") for t in node.targets)
        return False

    nodes = [node for node in tree.body if wanted(node)]
    namespace = dict(email=email, re=re, Optional=Optional)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    return namespace["iter_uploaded_files"]


parse = load_parser()
BOUNDARY = b"capture-boundary"


def part(payload, padding=b""):
    return (b"--" + BOUNDARY + padding + b'\r\nContent-Disposition: form-data; name="file"; '
            b'filename="sample.bin"\r\n\r\n' + payload + b"\r\n")


def uploaded(body, limit=1):
    return list(parse(io.BytesIO(body), "multipart/form-data; boundary=capture-boundary", limit))


@pytest.mark.parametrize("suffix", [b"-NOT-A-DELIMITER", b"--NOT-A-DELIMITER", b"X", b" \tX"])
def test_boundary_prefix_in_payload_is_preserved(suffix):
    payload = b"before\r\n--" + BOUNDARY + suffix + b"\r\nafter\0\xff"
    body = part(payload) + b"--" + BOUNDARY + b"--\r\n"
    assert uploaded(body) == [("file", "sample.bin", payload)]


def test_payload_prefixes_do_not_consume_field_limit():
    payload = (b"\r\n--" + BOUNDARY + b"X\r\n") * 1000
    assert uploaded(part(payload) + b"--" + BOUNDARY + b"--\r\n")[0][2] == payload


@pytest.mark.parametrize("padding", [b"", b" ", b"\t", b" \t"])
def test_transport_padding_and_terminal_crlf_are_preserved(padding):
    payload = b"first\r\nlast\r\n"
    body = part(payload, padding) + b"--" + BOUNDARY + b"--" + padding + b"\r\n"
    assert uploaded(body) == [("file", "sample.bin", payload)]


def test_actual_parts_still_obey_field_limit():
    body = part(b"first") + part(b"second") + b"--" + BOUNDARY + b"--\r\n"
    with pytest.raises(ValueError, match="Max number of fields"):
        uploaded(body)
    assert [entry[2] for entry in uploaded(body, 2)] == [b"first", b"second"]


# --- bare LF line breaks ------------------------------------------------------------


def lf_part(payload, name=b"sample.bin"):
    return (b"--" + BOUNDARY + b'\nContent-Disposition: form-data; name="file"; filename="' + name
            + b'"\n\n' + payload + b"\n")


def test_a_bare_lf_body_gives_its_files():
    payload = b"MZ\x90\x00 first line\nsecond\r\nthird"
    body = lf_part(payload) + lf_part(b"other", b"b.bin") + b"--" + BOUNDARY + b"--\n"
    assert uploaded(body, 2) == [("file", "sample.bin", payload), ("file", "b.bin", b"other")]


@pytest.mark.parametrize("suffix", [b"X", b"-NOT-A-DELIMITER", b"--NOT-A-DELIMITER", b" \tX"])
def test_a_boundary_prefix_in_a_bare_lf_payload_is_preserved(suffix):
    payload = b"before\n--" + BOUNDARY + suffix + b"\nafter\0\xff"
    body = lf_part(payload) + b"--" + BOUNDARY + b"--\n"
    assert uploaded(body) == [("file", "sample.bin", payload)]


def test_a_crlf_body_keeps_bare_lf_delimiters_inside_a_payload():
    # the line breaks of the delimiters of a body are those of its first one
    payload = b"a\n--" + BOUNDARY + b"\nb"
    body = part(payload) + b"--" + BOUNDARY + b"--\r\n"
    assert uploaded(body) == [("file", "sample.bin", payload)]


def test_a_closing_delimiter_at_the_end_without_line_break():
    body = lf_part(b"data") + b"--" + BOUNDARY + b"--"
    assert uploaded(body) == [("file", "sample.bin", b"data")]


def test_a_bare_lf_body_without_closing_delimiter():
    # the HTTP service cut the closing delimiter off: the line break in front of it goes too
    assert uploaded(lf_part(b"data")) == [("file", "sample.bin", b"data")]


def test_bare_lf_parts_obey_the_field_limit():
    body = lf_part(b"first") + lf_part(b"second") + b"--" + BOUNDARY + b"--\n"
    with pytest.raises(ValueError, match="Max number of fields"):
        uploaded(body)


# --- nested multipart/mixed ---------------------------------------------------------


def mixed(boundary, parts):
    """A multipart/mixed body of (file name, content) parts, CRLF."""
    body = b""
    for name, content in parts:
        body += (b"--" + boundary + b'\r\nContent-Disposition: file; filename="' + name
                 + b'"\r\nContent-Type: application/octet-stream\r\n\r\n' + content + b"\r\n")
    return body + b"--" + boundary + b"--"


def mixed_part(boundary, inner, name=b"files"):
    """A form-data part that holds a multipart/mixed body."""
    return (b"--" + BOUNDARY + b'\r\nContent-Disposition: form-data; name="' + name + b'"\r\n'
            b"Content-Type: multipart/mixed; boundary=" + boundary + b"\r\n\r\n" + inner + b"\r\n")


def test_the_files_of_a_nested_multipart_mixed_part_are_found():
    first, second = b"MZ first\r\n--inner-bX\r\n", b"second\x00\xff"
    body = (part(b"top") + mixed_part(b"inner-b", mixed(b"inner-b", [(b"one.exe", first), (b"two.exe", second)]))
            + b"--" + BOUNDARY + b"--\r\n")
    assert uploaded(body, 10) == [("file", "sample.bin", b"top"), ("files", "one.exe", first),
                                  ("files", "two.exe", second)]


def test_a_nested_bare_lf_part():
    inner = (b'--in\nContent-Disposition: file; filename="lf.bin"\n\nlf data\n--in--\n')
    body = (b"--" + BOUNDARY + b'\nContent-Disposition: form-data; name="files"\n'
            b'Content-Type: multipart/mixed; boundary="in"\n\n' + inner + b"\n--" + BOUNDARY + b"--\n")
    assert uploaded(body, 10) == [("files", "lf.bin", b"lf data")]


def nest(levels, content=b"deep"):
    """content as a file part levels multipart/mixed parts deep below the form-data body."""
    body = b'--b0\r\nContent-Disposition: file; filename="deep.bin"\r\n\r\n' + content + b"\r\n--b0--"
    for level in range(1, levels):
        body = (b"--b%d\r\nContent-Type: multipart/mixed; boundary=b%d\r\n\r\n" % (level, level - 1)
                + body + b"\r\n--b%d--" % level)
    return mixed_part(b"b%d" % (levels - 1), body) + b"--" + BOUNDARY + b"--\r\n"


@pytest.mark.parametrize("levels", [1, 2, 3])
def test_nested_parts_are_followed_three_levels_deep(levels):
    assert uploaded(nest(levels), 10) == [("files", "deep.bin", b"deep")]


def test_a_fourth_level_of_nesting_is_not_followed():
    assert uploaded(nest(4), 10) == []


def test_nested_parts_count_against_the_field_limit():
    body = mixed_part(b"in", mixed(b"in", [(b"%d.bin" % i, b"x") for i in range(3)])) + b"--" + BOUNDARY + b"--\r\n"
    assert len(uploaded(body, 4)) == 3
    with pytest.raises(ValueError, match="Max number of fields"):
        uploaded(body, 3)


# --- bounds -------------------------------------------------------------------------


def _timed(body, limit):
    import time
    start = time.perf_counter()
    try:
        result = uploaded(body, limit)
    except ValueError:
        result = None
    return result, time.perf_counter() - start


@pytest.mark.parametrize("line_break", [b"\r\n", b"\n"], ids=["crlf", "lf"])
def test_many_empty_parts_fail_fast(line_break):
    body = (b"--" + BOUNDARY + line_break * 2) * 900000 + b"--" + BOUNDARY + b"--" + line_break
    result, seconds = _timed(body, 100)
    assert result is None
    assert seconds < 1, seconds


def test_many_empty_nested_parts_fail_fast():
    inner = b"--in\r\n\r\n" * 900000 + b"--in--"
    result, seconds = _timed(mixed_part(b"in", inner) + b"--" + BOUNDARY + b"--\r\n", 100)
    assert result is None
    assert seconds < 1, seconds


def test_many_nested_parts_each_with_many_empty_parts_fail_fast():
    # the limit is for all levels together, not per part
    body = b"".join(mixed_part(b"in", b"--in\r\n\r\n" * 90 + b"--in--") for _ in range(90))
    result, seconds = _timed(body + b"--" + BOUNDARY + b"--\r\n", 100)
    assert result is None
    assert seconds < 1, seconds


def test_32_mib_three_levels_deep_is_linear():
    content = (b"MZ" + bytes(range(256)) * 4096) * 32  # 32 MiB
    result, seconds = _timed(nest(3, content), 10)
    assert result == [("files", "deep.bin", content)]
    assert seconds < 2, seconds
