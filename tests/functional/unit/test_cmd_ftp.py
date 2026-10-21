# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""cmd.py: the FTP script of the emulated shell (ftp -s:file) and its log line.

The download offer of the script keeps its url with the user and the password, as the
honeypot records it (offers, dionaea.json). The info line of the script names neither the
password nor any byte outside 0x20..0x7e of the texts of the client. A lone "open" takes the
host and the port from the next line; a port that is no number of 1 to 65535 gives no offer
and an info line.
"""

import contextlib
import importlib.util
import logging
import os
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
    Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


class FakeIncident:
    reported = []

    def __init__(self, name):
        self.name = name

    def report(self):
        FakeIncident.reported.append((self.name, dict(vars(self))))


class FakeConnection:
    pass


class FakeIHandler:
    def __init__(self, *args, **kwargs):
        pass


@contextlib.contextmanager
def _stand_ins():
    names = [name for name in sys.modules if name == "dionaea" or name.startswith("dionaea.")]
    saved = {name: sys.modules.pop(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(ROOT)]
    package.IHandlerLoader = object
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    core.incident = FakeIncident
    core.ihandler = FakeIHandler
    sys.modules.update({"dionaea": package, "dionaea.core": core})
    try:
        yield
    finally:
        for name in [n for n in sys.modules if n == "dionaea" or n.startswith("dionaea.")]:
            sys.modules.pop(name, None)
        sys.modules.update(saved)


with _stand_ins():
    spec = importlib.util.spec_from_file_location("dionaea.cmd", ROOT / "cmd.py")
    cmd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cmd)


def _run_script(script, caplog):
    FakeIncident.reported.clear()
    shell = cmd.cmdexe(None)
    shell.files["s.txt"] = script
    with caplog.at_level(logging.DEBUG, logger="cmd"):
        shell.cmd_FTP(["-s:s.txt"])
    return [r for r in caplog.records if r.name == "cmd" and r.levelno >= logging.INFO]


def test_the_info_line_of_an_ftp_script_has_no_password(caplog):
    records = _run_script("open 192.0.2.10 2121\nbob\ns3cr3t-pass\nbinary\nget x.exe\nbye\n", caplog)
    assert [name for name, _ in FakeIncident.reported] == ["dionaea.download.offer"]
    # the offer keeps what the client sent
    assert FakeIncident.reported[0][1]["url"] == "ftp://bob:s3cr3t-pass@192.0.2.10:2121/x.exe"
    assert len(records) == 1
    message = records[0].getMessage()
    assert "s3cr3t-pass" not in message
    assert "bob" in message and "192.0.2.10" in message and "x.exe" in message


def test_the_info_line_of_an_ftp_script_is_printable_and_bounded(caplog):
    records = _run_script("open 192.0.2.10 21\nbob\npw\ncd \x1b[2J" + "d" * 600 + "\nget f\x07.exe\n", caplog)
    (record,) = records
    message = record.getMessage()
    assert all(0x20 <= ord(c) <= 0x7e for c in message), message
    assert len(message) < 400


def _offers():
    return [values["url"] for name, values in FakeIncident.reported if name == "dionaea.download.offer"]


def test_open_on_its_own_line_takes_host_and_port_of_the_next(caplog):
    # ftp asks "To" after a lone open: the next line is the host and maybe a port
    _run_script("open\n192.0.2.10 2121\nbob\npw\nget x.exe\n", caplog)
    assert _offers() == ["ftp://bob:pw@192.0.2.10:2121/x.exe"]
    _run_script("open\nto 192.0.2.11 2122\nbob\npw\nget y.exe\n", caplog)
    assert _offers() == ["ftp://bob:pw@192.0.2.11:2122/y.exe"]
    _run_script("open\n192.0.2.12\nbob\npw\nget z.exe\n", caplog)
    assert _offers() == ["ftp://bob:pw@192.0.2.12:21/z.exe"]


@pytest.mark.parametrize("script", [
    "open 192.0.2.10 99999\nbob\npw\nget x.exe\n",
    "open 192.0.2.10 0\nbob\npw\nget x.exe\n",
    "open 192.0.2.10 2l\nbob\npw\nget x.exe\n",
    "open\n192.0.2.10 \x1b[31mport\nbob\npw\nget x.exe\n",
    "open\n192.0.2.10 -21\nbob\npw\nget\nx.exe\n",
])
def test_a_port_that_is_none_gives_no_offer_and_an_info_line(script, caplog):
    records = _run_script(script, caplog)
    assert _offers() == []
    messages = [r.getMessage() for r in records]
    assert any("no port" in m for m in messages), messages
    assert all(all(0x20 <= ord(c) <= 0x7e for c in m) for m in messages)


@pytest.mark.parametrize("script", ["open\nto\nbob\npw\nget x.exe\n", "open\nTO\nbob\npw\nget\nx.exe\n"])
def test_a_lone_open_and_to_without_a_host_gives_no_offer_and_an_info_line(script, caplog):
    records = _run_script(script, caplog)
    assert _offers() == []
    messages = [r.getMessage() for r in records]
    assert sum("no host" in m for m in messages) == 1, messages
