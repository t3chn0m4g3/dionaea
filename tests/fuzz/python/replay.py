#!/usr/bin/env python3
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Run inputs through a Python fuzz target without atheris (any Python, e.g. the 3.14 of the image):

    python3 replay.py TARGET FILE_OR_FOLDER...

Every input runs once through TestOneInput of fuzz_TARGET.py, uninstrumented; an
error is raised as without FUZZ_FAILURES. With coverage.py
(python3 -m coverage run replay.py ...) it gives the line coverage of a corpus.
"""

import importlib.util
import os
import sys
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent


def main():
    target, paths = sys.argv[1], sys.argv[2:]
    if "atheris" not in sys.modules:
        try:
            import atheris
        except ImportError:
            atheris = types.ModuleType("atheris")
            sys.modules["atheris"] = atheris
        atheris.instrument_all = lambda: None
    sys.path.insert(0, str(HERE))
    spec = importlib.util.spec_from_file_location("fuzz_" + target, HERE / ("fuzz_%s.py" % target))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    files = []
    for path in paths:
        if os.path.isdir(path):
            files += sorted(os.path.join(path, name) for name in os.listdir(path))
        else:
            files.append(path)
    for name in files:
        with open(name, "rb") as f:
            module.TestOneInput(f.read())
    print("%d inputs of %s" % (len(files), target))


if __name__ == "__main__":
    main()
