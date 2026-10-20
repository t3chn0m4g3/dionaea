# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Every subclass of ``connection`` needs defaults for all arguments of __init__.

connection.__init__ (modules/python/binding.pyx) checks the signature of the
__init__ of the class it is called for and raises LoaderError for an argument
without a default value. The classes are created at run time (a TFTP request,
an FTP data connection, a SIP call, ...), so the error shows up only then.

The check here reads the source with ``ast`` and needs neither the binding nor
a container. It finds the classes that derive from ``connection``, directly or
over other classes of the package. Run it with the checkout:

    python3 -m pytest tests/functional/unit
"""

import ast
import os
from pathlib import Path


def python_source_dir():
    """DIONAEA_PY_SRC (run.sh mounts the checkout's package there), else the checkout of this file."""
    if os.environ.get("DIONAEA_PY_SRC"):
        return Path(os.environ["DIONAEA_PY_SRC"])
    return Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea"


def parse_classes(root):
    """{class name: [(file, ClassDef, [base names])]} of all modules below root."""
    classes = {}
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            bases = []
            for base in node.bases:
                if isinstance(base, ast.Name):
                    bases.append(base.id)
                elif isinstance(base, ast.Attribute):
                    bases.append(base.attr)
            classes.setdefault(node.name, []).append((path, node, bases))
    return classes


def connection_classes(classes):
    """Names of connection and of all classes derived from it."""
    found = {"connection"}
    changed = True
    while changed:
        changed = False
        for name, definitions in classes.items():
            if name in found:
                continue
            if any(base in found for _, _, bases in definitions for base in bases):
                found.add(name)
                changed = True
    return found


def init_arguments_without_default(node):
    """Names of the arguments of the __init__ of a class without a default (self excluded)."""
    missing = []
    for item in node.body:
        if not (isinstance(item, ast.FunctionDef) and item.name == "__init__"):
            continue
        args = item.args
        positional = args.posonlyargs + args.args
        without_default = positional[:len(positional) - len(args.defaults)]
        missing += [a.arg for a in without_default if a.arg != "self"]
        missing += [a.arg for a, d in zip(args.kwonlyargs, args.kw_defaults) if d is None]
    return missing


def test_source_dir_is_there():
    assert (python_source_dir() / "ftp.py").is_file(), (
        "dionaea python sources not found in %s (DIONAEA_PY_SRC)" % python_source_dir()
    )


def test_known_connection_classes_are_found():
    # guards the walker itself: it must see these, directly and transitively derived
    found = connection_classes(parse_classes(python_source_dir()))
    assert {"FTPd", "FTPDataConnect", "TftpServerHandler", "SipCall", "p0fconnection", "hpclient"} <= found


def test_init_arguments_have_defaults():
    classes = parse_classes(python_source_dir())
    offenders = []
    for name in sorted(connection_classes(classes)):
        for path, node, _ in classes.get(name, []):
            missing = init_arguments_without_default(node)
            if missing:
                offenders.append("%s:%d %s.__init__ needs defaults for %s" % (
                    path.relative_to(python_source_dir()), node.lineno, name, ", ".join(missing)))
    assert not offenders, "connection.__init__ raises LoaderError for these:\n" + "\n".join(offenders)


def test_walker_flags_an_argument_without_default():
    tree = ast.parse("class A(connection):\n def __init__(self, a, b=1, *, c): pass\n")
    assert init_arguments_without_default(tree.body[0]) == ["a", "c"]
