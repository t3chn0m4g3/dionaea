# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: 2010 Markus Koetter & Tan Kean Siong
# SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter & Mark Schloesser
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging

from dionaea import IHandlerLoader, load_config_from_files, load_submodules
from dionaea.core import g_dionaea

logger = logging.getLogger('ihandlers')
logger.setLevel(logging.DEBUG)

# global handler list
# keeps a ref on our handlers
# allows restarting
g_handlers = None
g_handler_configs = []


def new():
    global g_handler_configs
    logger.info("Load iHandlers")
    load_submodules()

    module_config = g_dionaea.config().get("module")
    filename_patterns = module_config.get("ihandler_configs", [])
    g_handler_configs = load_config_from_files(filename_patterns)


def start():
    global g_handlers
    g_handlers = {}
    logger.info("START THE IHANDLERS")

    for ihandler_config in g_handler_configs:
        for h in IHandlerLoader:
            if ihandler_config.get("name") != h.name:
                continue
            if h not in g_handlers:
                g_handlers[h] = []

            # one handler that can not start does not keep the others (log_json, log_sqlite) from it
            try:
                handlers = h.start(config=ihandler_config.get("config", {}))
            except Exception:
                logger.error("Unable to start the ihandler %s", h.name, exc_info=True)
                continue
            if isinstance(handlers, (list, tuple)):
                g_handlers[h] += handlers
            elif handlers is not None:
                g_handlers[h].append(handlers)

    for handler_loader, ihandlers in g_handlers.items():
        for i in list(ihandlers):
            logger.info("Starting %s", str(i))
            method = getattr(i, "start", None)
            if method is None:
                continue
            try:
                method()
            except Exception:
                logger.error("Unable to start %s of the ihandler %s", str(i), handler_loader.name, exc_info=True)
                # deregistered: the last reference goes (__dealloc__ -> ihandler_free), no incident
                # reaches a handler that did not start
                ihandlers.remove(i)


def flush():
    """dionaea's event loop ended: the handlers with a flush() write what they buffer
    (log_sqlite commits its rows), before dionaea waits for its threadpool."""
    if not g_handlers:
        return
    for handler_loader, ihandlers in g_handlers.items():
        for i in ihandlers:
            method = getattr(i, "flush", None)
            if method is None:
                continue
            try:
                method()
            except Exception:
                logger.exception("Unable to flush %s", str(i))


def stop():
    global g_handlers
    for handler_loader, ihandlers in g_handlers.items():
        for i in ihandlers:
            logger.debug("deleting %s" % str(i))
            handler_loader.stop(i)
            del i
    del g_handlers
