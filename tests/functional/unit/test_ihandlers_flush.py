# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""dionaea/ihandlers.py: start() of the handlers and flush() when dionaea's event loop ended.

start(): a handler whose loader or start() raises is logged at error and the others
still start (an exception of the store handler kept log_json and log_sqlite from it).

dionaea calls the flush() of the python imports (module api flush,
modules/python/module.c flushpy) after the event loop and before it waits for
its threadpool; a stop timeout (10 s in Docker) can kill it during that wait.
dionaea.ihandlers.flush() calls flush() of every handler that has one
(log_sqlite commits the rows of the last second), an error of one handler
does not keep the others from it.
"""

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
    names = ("dionaea", "dionaea.core")
    saved = {name: sys.modules.get(name) for name in names}
    package = types.ModuleType("dionaea")
    package.__path__ = [str(_src_root())]
    package.IHandlerLoader = []
    package.load_config_from_files = lambda patterns: []
    package.load_submodules = lambda base_pkg=None: None
    core = types.ModuleType("dionaea.core")
    core.g_dionaea = None
    sys.modules.update({"dionaea": package, "dionaea.core": core})
    try:
        yield
    finally:
        for name, module in saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


with _stand_ins():
    spec = importlib.util.spec_from_file_location("ihandlers_under_test", _src_root() / "ihandlers.py")
    ihandlers = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ihandlers)


class Buffered:
    def __init__(self):
        self.flushes = 0

    def flush(self):
        self.flushes += 1


class Plain:
    pass


class Broken:
    def flush(self):
        raise RuntimeError("disk gone")


def test_flush_calls_every_handler_that_has_one(monkeypatch, caplog):
    first, second = Buffered(), Buffered()
    monkeypatch.setattr(ihandlers, "g_handlers", {"a": [first, Plain()], "b": [Broken(), second]})
    with caplog.at_level(logging.ERROR, logger="ihandlers"):
        ihandlers.flush()
    assert first.flushes == 1
    assert second.flushes == 1
    assert "Unable to flush" in caplog.text


def test_flush_before_the_handlers_started(monkeypatch):
    monkeypatch.setattr(ihandlers, "g_handlers", None)
    ihandlers.flush()


class Started:
    def __init__(self, name, log):
        self.name = name
        self.log = log

    def start(self):
        self.log.append(self.name)


def loader(name, log, start_fails=False, handler_start_fails=False):
    class Loader:
        @classmethod
        def start(cls, config=None):
            if start_fails:
                raise OverflowError("the loader of %s" % name)
            handler = Started(name, log)
            if handler_start_fails:
                def start():
                    raise RuntimeError("the start of %s" % name)
                handler.start = start
            return handler
    Loader.name = name
    return Loader


def test_a_failing_handler_does_not_stop_the_others(monkeypatch, caplog):
    log = []
    loaders = [loader("store", log, start_fails=True), loader("broken", log, handler_start_fails=True),
               loader("log_json", log), loader("log_sqlite", log)]
    monkeypatch.setattr(ihandlers, "IHandlerLoader", loaders)
    monkeypatch.setattr(ihandlers, "g_handler_configs",
                        [{"name": "store", "config": {}}, {"name": "broken"}, {"name": "log_json"},
                         {"name": "log_sqlite"}])
    with caplog.at_level(logging.ERROR, logger="ihandlers"):
        ihandlers.start()
    assert log == ["log_json", "log_sqlite"]
    errors = [r for r in caplog.records if r.levelname == "ERROR"]
    assert len(errors) == 2
    assert "store" in errors[0].getMessage() and errors[0].exc_info is not None
    assert "broken" in errors[1].getMessage() and errors[1].exc_info is not None


def test_a_handler_whose_start_raises_is_deregistered(monkeypatch):
    # a handler that did not start is dropped from g_handlers: its reference goes
    # (__dealloc__ -> ihandler_free), so no incident reaches the half made handler
    log = []
    loaders = [loader("broken", log, handler_start_fails=True), loader("log_json", log)]
    monkeypatch.setattr(ihandlers, "IHandlerLoader", loaders)
    monkeypatch.setattr(ihandlers, "g_handler_configs", [{"name": "broken"}, {"name": "log_json"}])
    ihandlers.start()
    by_name = {h.name: handlers for h, handlers in ihandlers.g_handlers.items()}
    assert by_name["broken"] == []
    assert [h.name for h in by_name["log_json"]] == ["log_json"]
    assert log == ["log_json"]
