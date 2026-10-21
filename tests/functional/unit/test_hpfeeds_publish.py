# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""hpfeeds.py: a publication that fails (no broker, the own address not resolved yet) is an
info line for every incident; one warning a minute sums them up (LogSummary of logtext.py).

hpfeeds.py is loaded with stand-ins of dionaea and dionaea.core (it needs the binding)."""

import contextlib
import importlib.util
import logging
import os
import sys
import types
from pathlib import Path


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins():
    names = [name for name in sys.modules if name == "dionaea" or name.startswith("dionaea.")]
    saved = {name: sys.modules.pop(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(_src_root())]
    package.IHandlerLoader = type("IHandlerLoader", (), {})
    package.Timer = type("Timer", (), {})
    core = types.ModuleType("dionaea.core")
    core.ihandler = type("ihandler", (), {"__init__": lambda self, path: None})
    core.incident = type("incident", (), {})
    core.g_dionaea = None
    core.connection = type("connection", (), {})
    util = types.ModuleType("dionaea.util")
    util.sha512file = lambda path: "0" * 128
    sys.modules.update({"dionaea": package, "dionaea.core": core, "dionaea.util": util})
    try:
        spec = importlib.util.spec_from_file_location("hpfeeds_under_test", _src_root() / "hpfeeds.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        yield module
    finally:
        for name in [n for n in sys.modules if n == "dionaea" or n.startswith("dionaea.")]:
            sys.modules.pop(name, None)
        sys.modules.update(saved)


with _stand_ins() as loaded:
    hpfeeds = loaded


class Client:
    connected = True

    def publish(self, channel, **kwargs):
        raise OSError(32, "Broken pipe")


def handler():
    h = object.__new__(hpfeeds.hpfeedihandler)
    h.client = Client()
    h.dynip_resolve = ""
    h.ownip = None
    return h


def incident(port):
    node = types.SimpleNamespace(host="198.51.100.5", port=port, hostname="")
    local = types.SimpleNamespace(host="192.0.2.1", port=445, hostname="")
    con = types.SimpleNamespace(remote=node, local=local, transport="tcp", protocol="smbd")
    return types.SimpleNamespace(con=con, uuid="4b324fc8-1670-01d3-1278-5a47bf6ee188", opnum=31)


def test_failed_publications_are_info_and_one_warning_a_minute(caplog, summaries):
    clock = summaries(hpfeeds.PUBLISH_FAILED)
    h = handler()
    with caplog.at_level(logging.INFO, logger="hpfeeds"):
        for port in range(4):
            h.connection_publish(incident(40000 + port), "accept")
            h.handle_incident_dionaea_modules_python_smb_dcerpc_request(incident(41000 + port))
            clock.advance(1)
        infos = [r.getMessage() for r in caplog.records
                 if r.levelno == logging.INFO and r.getMessage().startswith("exception when publishing")]
        assert infos == ["exception when publishing: [Errno 32] Broken pipe"] * 8
        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert warnings == [("hpfeeds publications failed: 1 incident(s) in the last minute, "
                            "the last: [Errno 32] Broken pipe")]
        clock.advance(60)
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert warnings[1:] == [("hpfeeds publications failed: 7 incident(s) in the last minute, "
                            "the last: [Errno 32] Broken pipe")]
