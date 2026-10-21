# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Probe of host-checks/45-binding.sh, loaded into dionaea (dionaea.cfg imports=...,binding_probe).

It drives dionaea.core.timer (a libev timer of the loop, modules/python/module.c
py_timer_*) and the connection wrappers of incidents through the binding and
writes what happened to /opt/dionaea/var/log/binding-probe.json two seconds
after the start:

    one_shot          a one-shot timer fires once
    unreferenced      a one-shot timer nobody keeps a reference to fires once
    self_stop_repeat  a repeating timer that stops itself in its 3rd call: 3 calls
    self_stop_once    a one-shot timer that stops itself in its call: 1 call
    raises            a repeating timer whose first 2 calls raise ValueError, stopped in
                      its 4th: 4 calls, the 2 errors logged with their Traceback
    stopped_early     a timer stopped before it fires: 0 calls
    errors            the records "There was an error in a timer callback" with the
                      exception of each
    wrapper_gets      incident.con read 200 times (a new connection wrapper each time, as
                      the log handlers read it, about 7 times per connection)
    wrapper_garbage   the objects in reference cycles those reads left (gc.collect()):
                      connection.__init__ checked its signature with inspect.signature
                      every time, which parsed the text signature of the Cython __init__
                      and left a class (RewriteSymbolics) in a cycle per read
    wrapper_us        microseconds per read
    raised            an ihandler whose handle_incident raises (with a text of 1000 characters,
                      an escape sequence and 60 line breaks in its message) got its incident: the
                      exception leaves the binding to the C code of the python module
                      (traceable_ihandler_cb, traceback()), which logs it

At the stop of dionaea the probe removes the handlers of logging (as the stop of dionaea.log
does) and its stop() raises: the C code of the python module (traceback()) writes that
exception itself, through the same rule, and logging writes nothing raw to stderr.

dionaea has to go on running afterwards (the host check looks).
"""

import json
import logging
from pathlib import Path

OUT = Path("/opt/dionaea/var/log/binding-probe.json")
calls = {name: 0 for name in ("one_shot", "unreferenced", "self_stop_repeat", "self_stop_once", "raises",
                              "stopped_early")}
errors = []
timers = {}


class _Errors(logging.Handler):
    def emit(self, record):
        if record.getMessage() == "There was an error in a timer callback":
            exc = record.exc_info[1] if record.exc_info else None
            errors.append({"exception": type(exc).__name__ if exc else None, "message": str(exc) if exc else None})


def _count(name):
    calls[name] += 1


def _self_stop_repeat():
    calls["self_stop_repeat"] += 1
    if calls["self_stop_repeat"] == 3:
        timers["self_stop_repeat"].stop()


def _self_stop_once():
    calls["self_stop_once"] += 1
    timers["self_stop_once"].stop()


def _raises():
    calls["raises"] += 1
    if calls["raises"] <= 2:
        raise ValueError("timer probe %d" % calls["raises"])
    if calls["raises"] == 4:
        timers["raises"].stop()


wrappers = {}
handlers = []
RAISE_ORIGIN = "dionaea.binding_probe.raise"
RAISE_MESSAGE = "binding probe\x1b[31m" + "z" * 1000 + "\n" * 60 + "end of the binding probe"
STOP_MESSAGE = "binding probe at stop\x1b[2J" + "s" * 1000 + "\n" * 60 + "end of the stop"


def _raising_handler():
    from dionaea.core import ihandler

    class RaisingHandler(ihandler):
        def handle_incident(self, i):
            wrappers["raised"] = wrappers.get("raised", 0) + 1
            raise ValueError(RAISE_MESSAGE) from None

    return RaisingHandler(RAISE_ORIGIN)


def _wrappers():
    import gc
    import time
    from dionaea.core import connection, incident
    con = connection("udp")
    i = incident("dionaea.binding_probe")
    i.con = con
    i.con   # the first read checks the class
    gc.collect()
    started = time.perf_counter()
    for _ in range(200):
        assert i.con == con
    wrappers["wrapper_us"] = round((time.perf_counter() - started) / 200 * 1e6, 1)
    wrappers["wrapper_gets"] = 200
    wrappers["wrapper_garbage"] = gc.collect()
    del i
    con.close()


def _report():
    try:
        _wrappers()
    except Exception as e:   # the probe must not stop dionaea
        wrappers["wrapper_error"] = repr(e)
    try:
        from dionaea.core import incident
        incident(RAISE_ORIGIN).report()
    except Exception as e:
        wrappers["raise_error"] = repr(e)
    OUT.write_text(json.dumps({"calls": calls, "errors": errors, **wrappers}) + "\n")


def new():
    pass


def start():
    from dionaea.core import timer
    logging.getLogger().addHandler(_Errors())
    timers["one_shot"] = timer(lambda: _count("one_shot"), 0.1)
    timer(lambda: _count("unreferenced"), 0.1)       # no reference kept: the loop holds it until it ran
    timers["self_stop_repeat"] = timer(_self_stop_repeat, 0.1, 0.1)
    timers["self_stop_once"] = timer(_self_stop_once, 0.1)
    timers["raises"] = timer(_raises, 0.1, 0.1)
    timers["stopped_early"] = timer(lambda: _count("stopped_early"), 0.5)
    timers["stopped_early"].stop()
    handlers.append(_raising_handler())
    timers["report"] = timer(_report, 2.0)


def stop():
    for t in timers.values():
        t.stop()
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    raise ValueError(STOP_MESSAGE)
