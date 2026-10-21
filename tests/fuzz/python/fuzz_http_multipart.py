#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""atheris target of the multipart parser of the HTTP service (http.py, iter_uploaded_files).

The parser raises a ValueError above max_num_fields on purpose (handle_POST
ignores the POST data then) and leaves out a part whose headers the email
package can not read (one info line); any other error is a failing input. A body
is read in the time of its own length, and nothing is copied but the files. The parser and its helpers are taken from
http.py with ast, as tests/functional/unit/test_http_multipart.py does (http.py
needs the binding). Every body is parsed as
it is and repeated up to 256 KiB (a POST body may have 32 MiB), with the
max_num_fields of the service (100); -timeout reports a body that takes longer.
The files it returns are slices of the body: together never more than the body.
"""

import ast
import email
import logging
import email.message
import email.parser
import email.policy
import io
import re
import sys
from typing import Optional

import atheris

import standins

REPEATED_SIZE = 256 * 1024
MAX_NUM_FIELDS = 100


def load_parser():
    source = standins.SRC / "http.py"
    tree = ast.parse(source.read_text(), filename=str(source))

    def wanted(node):
        if isinstance(node, ast.FunctionDef):
            return node.name == "iter_uploaded_files" or node.name.startswith("_multipart")
        if isinstance(node, ast.Assign):
            return all(isinstance(t, ast.Name) and t.id.startswith("MULTIPART_") for t in node.targets)
        return False

    nodes = [node for node in tree.body if wanted(node)]
    logtext = standins.load("dionaea.logtext", "logtext.py")
    namespace = dict(email=email, re=re, Optional=Optional, logger=logging.getLogger("http"),
                     log_text=logtext.log_text)
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
    return namespace["iter_uploaded_files"]


iter_uploaded_files = load_parser()
atheris.instrument_all()


def parse(body, content_type):
    try:
        files = list(iter_uploaded_files(io.BytesIO(body), content_type, MAX_NUM_FIELDS))
    except ValueError:
        # handle_POST: "Ignoring the POST data" (more parts than max_num_fields)
        return
    total = 0
    for _name, _filename, content in files:
        assert isinstance(content, bytes)
        total += len(content)
    assert total <= len(body), (total, len(body))


def target(data):
    # a byte n, the boundary of n bytes (at most 72), a byte m, m more bytes of the header (at most 32), the body
    n = min(data[0], 72) if data else 0
    boundary = data[1:1 + n]
    m = min(data[1 + n], 32) if len(data) > 1 + n else 0
    params = data[2 + n:2 + n + m]
    body = data[2 + n + m:]
    content_type = "multipart/form-data; boundary=" + (boundary + params).decode("latin-1")
    parse(body, content_type)
    if body:
        parse(body * max(1, min(4096, REPEATED_SIZE // len(body))), content_type)


def TestOneInput(data):
    standins.run(target, data)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
