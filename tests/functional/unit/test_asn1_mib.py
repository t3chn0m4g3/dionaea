# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""smb/include/asn1/mib.py: the pattern of an OBJECT declaration of a MIB file finds nested braces.

mib.py needs scapy and is not imported by dionaea; the pattern is taken from it with ast.
"""

import ast
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
    Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")
MIB = ROOT / "smb" / "include" / "asn1" / "mib.py"


def _pattern():
    """(text, flags) of re.compile(text, re.M) of _mib_re_oiddecl"""
    tree = ast.parse(MIB.read_text(), filename=str(MIB))
    for node in tree.body:
        if isinstance(node, ast.Assign) and [t.id for t in node.targets if isinstance(t, ast.Name)] == [
                "_mib_re_oiddecl"]:
            call = node.value
            flags = 0
            for arg in call.args[1:]:
                assert isinstance(arg, ast.Attribute) and arg.attr in ("M", "MULTILINE"), ast.dump(arg)
                flags |= re.M
            return ast.literal_eval(call.args[0]), flags
    raise AssertionError("no _mib_re_oiddecl in mib.py")


TEXT, FLAGS = _pattern()
PATTERN = re.compile(TEXT, FLAGS)


def _declarations(text):
    # what mib.py takes of a match: the first and the last group
    return [(m.groups()[0], m.groups()[-1]) for m in PATTERN.finditer(text)]


def test_declarations_are_found():
    text = ("\nifIndex OBJECT-TYPE SYNTAX INTEGER { up(1), down(2) } ACCESS read-only ::= { ifEntry 1 }"
            "\nsysDescr OBJECT-TYPE SYNTAX DisplayString ::= { system 1 }"
            "\nentry OBJECT-TYPE SYNTAX SEQUENCE { a INTEGER { b(1) } } ::= { table 2 }"
            "\ninternet OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 }")
    assert _declarations(text) == [("ifIndex", " ifEntry 1 "), ("sysDescr", " system 1 "),
                                   ("entry", " table 2 "), ("internet", " iso org(3) dod(6) 1 ")]


def test_long_texts_with_nested_braces_are_searched():
    code = ("import re\npattern = re.compile(%r, %d)\n" % (TEXT, FLAGS)
            + "for n in (40, 4000):\n    pattern.search('\\nx OBJECT{' + '9}}{{' * n)\n"
            + "    pattern.search('\\nx OBJECT{9' + '}{9' * n)\n")
    result = subprocess.run([sys.executable, "-c", code], timeout=10, capture_output=True)
    assert result.returncode == 0, result.stderr
