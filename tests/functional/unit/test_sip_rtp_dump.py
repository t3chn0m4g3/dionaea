# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""sip/extras.py PCAP.open(): an RTP dump whose file can not be made is an info line; one warning
a minute sums them up for all calls (LogSummary of logtext.py). The module needs only the
standard library and logtext."""

import importlib.util
import logging
import os
import sys
from pathlib import Path


def _src_root():
    return Path(os.environ["DIONAEA_PY_SRC"]) if os.environ.get("DIONAEA_PY_SRC") else (
        Path(__file__).resolve().parents[3] / "modules" / "python" / "dionaea")


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_extras():
    saved = sys.modules.get("dionaea.logtext")
    sys.modules["dionaea.logtext"] = _load("dionaea.logtext", _src_root() / "logtext.py")
    try:
        return _load("sip_extras_under_test", _src_root() / "sip" / "extras.py")
    finally:
        if saved is None:
            sys.modules.pop("dionaea.logtext", None)
        else:
            sys.modules["dionaea.logtext"] = saved


extras = _load_extras()


def test_rtp_dumps_without_a_file_are_info_and_one_warning_a_minute(tmp_path, caplog, summaries):
    clock = summaries(extras.RTP_NOT_DUMPED)
    # the folder of the dumps is a file: no dump can be made in it
    (tmp_path / "rtp").write_bytes(b"")
    with caplog.at_level(logging.INFO, logger="sip"):
        for port in range(5):
            pcap = extras.PCAP(str(tmp_path / "rtp"), "{remote_host}_{remote_port}_in.rtp")
            assert pcap.open(None, remote_host="198.51.100.3", remote_port=5000 + port) is False
            clock.advance(1)
        infos = [r.getMessage() for r in caplog.records
                 if r.levelno == logging.INFO and "RTP-Dump file" in r.getMessage()]
        assert len(infos) == 5
        warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
        assert len(warnings) == 1
        assert warnings[0].startswith("RTP dumps not made: 1 stream(s) in the last minute, the last: ")
        clock.advance(60)
    warnings = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert len(warnings) == 2 and warnings[1].startswith("RTP dumps not made: 4 stream(s) in the last minute")
