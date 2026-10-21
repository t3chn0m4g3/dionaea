# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Every handle_io_in of the services ends in a return (or a raise) on every path.

The binding takes the int handle_io_in returns (binding.pyx handle_io_in_cb); a method that
falls off its end returns None, the binding raises TypeError then and the core logs it with
its traceback. The check reads the sources with ast: the last statement of the method, of both
branches of an if, of a with, of a try and its handlers.
"""

import ast
import os
from pathlib import Path

ROOT = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
    Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


def _ends(body):
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    if isinstance(last, ast.If):
        return _ends(last.body) and _ends(last.orelse)
    if isinstance(last, ast.With):
        return _ends(last.body)
    if isinstance(last, ast.Try):
        if last.finalbody and _ends(last.finalbody):
            return True
        body_ends = _ends(last.orelse) if last.orelse else _ends(last.body)
        return body_ends and all(_ends(handler.body) for handler in last.handlers)
    if isinstance(last, ast.While):
        return isinstance(last.test, ast.Constant) and last.test.value is True and not any(
            isinstance(node, ast.Break) for node in ast.walk(last))
    return False


def test_every_handle_io_in_returns():
    falls_off = []
    for path in sorted(ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "handle_io_in" and not _ends(node.body):
                falls_off.append("%s:%d" % (path.relative_to(ROOT), node.lineno))
    assert falls_off == []
