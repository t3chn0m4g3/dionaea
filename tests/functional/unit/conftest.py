# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

import pytest


@pytest.fixture(scope="session", autouse=True)
def dionaea_ready():
    """The unit tests need no dionaea container (overrides the fixture of ../conftest.py)."""
