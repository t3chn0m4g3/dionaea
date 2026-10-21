# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""A message of a client that can not be read, in SMB (smbd.handle_message, the header of
epmapper), MQTT (the type of a packet) and MSSQL (the header of a TDS packet).

A parse error of the client's bytes (ValueError, IndexError, struct.error, UnicodeError,
EOFError, for SMB also ASN1_Error) is info with the text of the exception, its traceback at
debug only. Any other exception (an AttributeError, TypeError, KeyError, NameError of the code)
is an error of dionaea: a warning with its traceback (logtext.log_unreadable).
"""

import contextlib
import importlib.util
import logging
import os
import sys
import types
from pathlib import Path

import pytest


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


class FakeConnection:
    def __init__(self, *args, **kwargs):
        pass


class FakeIncident:
    def __init__(self, origin=None):
        pass

    def report(self):
        pass


@contextlib.contextmanager
def _stand_ins():
    names = [name for name in sys.modules if name == "dionaea" or name.startswith("dionaea.")]
    saved = {name: sys.modules.pop(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(_src_root())]
    core = types.ModuleType("dionaea.core")
    core.connection = FakeConnection
    core.incident = FakeIncident
    core.g_dionaea = None
    core.__all__ = ["connection", "incident", "g_dionaea"]
    sys.modules.update({"dionaea": package, "dionaea.core": core})
    # the packages without their __init__ (they need dionaea itself)
    for sub in ("smb", "mqtt", "mssql"):
        module = types.ModuleType("dionaea." + sub)
        module.__path__ = [str(_src_root() / sub)]
        sys.modules["dionaea." + sub] = module
    try:
        yield
    finally:
        for name in [n for n in sys.modules if n == "dionaea" or n.startswith("dionaea.")]:
            sys.modules.pop(name, None)
        sys.modules.update(saved)


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, _src_root() / file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


with _stand_ins():
    smb = _load("dionaea.smb.smb", "smb/smb.py")
    mqtt = _load("dionaea.mqtt.mqtt", "mqtt/mqtt.py")
    mssql = _load("dionaea.mssql.mssql", "mssql/mssql.py")


def raising(exc):
    def parse(*args, **kwargs):
        raise exc
    return parse


class FakeSMB2:
    active = False

    def __init__(self, exc):
        self.process = raising(exc)


def smb_message(exc, monkeypatch):
    con = object.__new__(smb.smbd)
    con.smb2 = FakeSMB2(exc)
    monkeypatch.setattr(con, "close", lambda: None, raising=False)
    # an SMB2 message: handle_message gives it to smb2.process()
    con.handle_message(b"\x00\x00\x00\x40\xfeSMB" + b"\x00" * 60)


def epmapper_header(exc, monkeypatch):
    monkeypatch.setattr(smb, "DCERPC_Header", raising(exc))
    con = object.__new__(smb.epmapper)
    assert con.handle_io_in(b"\x05\x00\x0b\x03" + b"\x00" * 20) == 24


def mqtt_type(exc, monkeypatch):
    monkeypatch.setattr(mqtt, "MQTT_ControlMessage_Type", raising(exc))
    con = object.__new__(mqtt.mqttd)
    assert con.handle_packet(b"\x10\x02\x00\x00") == 0


def tds_header(exc, monkeypatch):
    monkeypatch.setattr(mssql, "TDS_Header", raising(exc))
    con = object.__new__(mssql.mssqld)
    con.buf = b""
    assert con.handle_io_in(b"\x12\x01\x00\x10\x00\x00\x00\x00" + b"\x00" * 8) == 0


SITES = {
    "smb message": (smb_message, "Invalid SMB request"),
    "epmapper header": (epmapper_header, "Unable to read the header of a DCERPC packet"),
    "mqtt type": (mqtt_type, "Unable to read the type of an MQTT packet"),
    "tds header": (tds_header, "Unable to read the header of a TDS packet"),
}


def records_of(caplog, text):
    return [r for r in caplog.records if r.getMessage().startswith(text)]


@pytest.mark.parametrize("site", sorted(SITES))
@pytest.mark.parametrize("exc", [ValueError("bytes \x1b[31m of a client"), IndexError("index out of range")],
                         ids=["ValueError", "IndexError"])
def test_a_parse_error_of_the_client_is_info_with_the_traceback_at_debug(site, exc, caplog, monkeypatch):
    call, text = SITES[site]
    caplog.set_level(logging.DEBUG)
    call(exc, monkeypatch)
    records = records_of(caplog, text)
    assert [r.levelno for r in records] == [logging.INFO, logging.DEBUG], records
    info, debug = records
    assert info.exc_info is None
    assert "\x1b" not in info.getMessage()   # the text of the exception through log_text
    assert debug.exc_info and debug.exc_info[1] is exc


@pytest.mark.parametrize("site", sorted(SITES))
def test_an_error_of_the_code_is_a_warning_with_its_traceback(site, caplog, monkeypatch):
    call, text = SITES[site]
    exc = AttributeError("'NoneType' object has no attribute 'Data'")
    caplog.set_level(logging.DEBUG)
    call(exc, monkeypatch)
    records = records_of(caplog, text)
    assert [r.levelno for r in records] == [logging.WARNING], records
    assert records[0].exc_info and records[0].exc_info[1] is exc
    assert "an error of dionaea" in records[0].getMessage()
