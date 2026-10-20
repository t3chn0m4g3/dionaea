#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The TLS clients of the tests ask for TLS 1.2 at least.

Every function of tests/functional and tests/load that makes an ssl context sets
its minimum_version to TLSv1_2 (or TLSv1_3) and never lower. tls_context() of
scenarios/early_close.py is also run.

    python3 tests/load/test_tls_minimum.py      (standard library only, no docker)
"""

import ast
import importlib.util
import ssl
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TESTS = HERE.parent
ALLOWED = {"TLSv1_2", "TLSv1_3"}
MAKERS = {"create_default_context", "SSLContext"}


def sources():
    for path in sorted(TESTS.rglob("*.py")):
        if "__pycache__" not in path.parts:
            yield path


def makes_context(node):
    return isinstance(node, ast.Call) and (
        (isinstance(node.func, ast.Attribute) and node.func.attr in MAKERS)
        or (isinstance(node.func, ast.Name) and node.func.id in MAKERS))


def minimum_versions(node):
    """The TLSVersion names assigned to <x>.minimum_version in node."""
    for child in ast.walk(node):
        if not isinstance(child, ast.Assign):
            continue
        for target in child.targets:
            if isinstance(target, ast.Attribute) and target.attr == "minimum_version":
                value = child.value
                yield value.attr if isinstance(value, ast.Attribute) else ast.dump(value)


class TlsMinimumTest(unittest.TestCase):
    def test_every_context_of_the_tests_asks_for_tls_1_2_at_least(self):
        found = []
        for path in sources():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for function in ast.walk(tree):
                if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                if not any(makes_context(node) for node in ast.walk(function)):
                    continue
                name = "%s:%s" % (path.relative_to(TESTS), function.name)
                found.append(name)
                versions = list(minimum_versions(function))
                self.assertTrue(versions, "%s sets no minimum_version" % name)
                for version in versions:
                    self.assertIn(version, ALLOWED, "%s sets minimum_version %s" % (name, version))
        # the two clients of today: the early close scenario and the HTTPS request of the replay
        self.assertIn("functional/scenarios/early_close.py:tls_context", found)
        self.assertIn("load/replay_client.py:https_get", found)

    def test_the_context_of_early_close(self):
        path = TESTS / "functional" / "scenarios" / "early_close.py"
        spec = importlib.util.spec_from_file_location("early_close", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        context = module.tls_context()
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_2)
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)


if __name__ == "__main__":
    unittest.main()
