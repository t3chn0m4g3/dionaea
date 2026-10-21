# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""smb/rpcservices.py SRVSVC NetrShareEnum (opnum 15): the information level of the request.

The service answers levels 0, 1 and 502 (SHARE_INFO_0/1/502_CONTAINER); a request for
any other level is refused as an invalid value (DCERPCValueError, processrequest
answers nothing), nothing escapes the handler. The loading of rpcservices.py is the
one of test_smb_spoolss.py.
"""

import contextlib
import importlib.util
import os
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest


class FakeIncident:
    reported = []

    def __init__(self, name):
        self.name = name

    def report(self):
        FakeIncident.reported.append(self.name)


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


@contextlib.contextmanager
def _stand_ins(download_dir):
    names = [name for name in sys.modules if name == "dionaea" or name.startswith("dionaea.")]
    saved = {name: sys.modules.pop(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(_src_root())]
    core = types.ModuleType("dionaea.core")
    core.incident = FakeIncident
    config = {"dionaea": {"download.dir": str(download_dir), "download.suffix": ".tmp"}}
    core.g_dionaea = SimpleNamespace(config=lambda: config)
    smb = types.ModuleType("dionaea.smb")
    smb.__path__ = [str(_src_root() / "smb")]
    sys.modules.update({"dionaea": package, "dionaea.core": core, "dionaea.smb": smb})
    try:
        spec = importlib.util.spec_from_file_location("dionaea.smb.rpcservices", _src_root() / "smb" / "rpcservices.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules["dionaea.smb.rpcservices"] = module
        spec.loader.exec_module(module)
        yield module
    finally:
        for name in [n for n in sys.modules if n == "dionaea" or n.startswith("dionaea.")]:
            sys.modules.pop(name, None)
        sys.modules.update(saved)


@pytest.fixture
def rpc(tmp_path):
    FakeIncident.reported.clear()
    with _stand_ins(tmp_path) as module:
        yield module


def connection():
    return SimpleNamespace(remote=SimpleNamespace(host="198.51.100.9"))


def share_enum(rpc, level):
    """the stub of a NetrShareEnum: server name, level, its container (empty), max length, no resume handle"""
    packer = rpc.ndrlib.Packer()
    packer.pack_pointer(0x20000)
    packer.pack_string("\\\\192.0.2.1\0".encode("utf-16-le"))
    packer.pack_long(level)
    packer.pack_long(level)
    packer.pack_pointer(0x20004)
    packer.pack_long(0)
    packer.pack_pointer(0)
    packer.pack_long(0xffffffff)
    packer.pack_pointer(0)
    # what the container of a level reads more (502), as zeros
    for _ in range(8):
        packer.pack_long(0)
    return SimpleNamespace(StubData=packer.get_buffer(), CallID=1)


@pytest.mark.parametrize("level", [0, 1, 502])
def test_the_levels_of_the_service_are_answered(rpc, level):
    reply = rpc.SRVSVC.processrequest(rpc.SRVSVC, connection(), 0x0f, share_enum(rpc, level))
    assert reply is not None


@pytest.mark.parametrize("level", [2, 501, 503, 0xffffffff])
def test_another_level_is_refused(rpc, level):
    assert rpc.SRVSVC.processrequest(rpc.SRVSVC, connection(), 0x0f, share_enum(rpc, level)) is None
    with pytest.raises(rpc.DCERPCValueError):
        rpc.SRVSVC.handle_NetShareEnum(connection(), share_enum(rpc, level))
