# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""The size cap of the store handler (``max_size``), against a second dionaea.

host-checks/40-store-cap.sh starts that dionaea with ``max_size: 1`` (MiB) in
ihandlers/store.yaml and runs this file against it (DIONAEA_CAP_INSTANCE=1,
DIONAEA_HOST, DIONAEA_DATA_DIR, DIONAEA_LOG_DIR of the second instance). The main run
of pytest does not collect it (conftest.py).

An upload that would take binaries/ over 1 MiB is not stored, its md5 is still in
``dionaea.sqlite`` (table ``downloads``) and ``dionaea.json``, no temporary file stays
behind and dionaea keeps answering. A sample that is stored already is recorded again,
a small one fits. The md5 of the samples that were refused go to ``$DIONAEA_CAP_OUT``
for the host check, which looks for the warning in ``dionaea.log`` after dionaea
was stopped (the log is written then).
"""

import hashlib
import os
import socket
import stat
import time
import uuid

import helpers
from test_ftp import _command, _login, _passive_data_socket, _read_reply
from test_smoke import _file_part, _post_multipart
from test_upload import _entries, _json_download, _unique

KIB = 1024


def _stor(host, content):
    with socket.create_connection((host, 21), timeout=10) as ctrl:
        _login(ctrl)
        with _passive_data_socket(ctrl, host) as data_sock:
            assert _command(ctrl, "STOR cap-%s.bin" % uuid.uuid4().hex[:8]).startswith("150")
            data_sock.sendall(content)
        assert _read_reply(ctrl).startswith("226")
        _command(ctrl, "QUIT")


def _rows(query_db, md5):
    deadline = time.monotonic() + 30
    while True:
        rows = query_db("SELECT download_md5_hash FROM downloads WHERE download_md5_hash = ?", (md5,))
        if rows or time.monotonic() >= deadline:
            return rows
        time.sleep(0.5)


def _refused(md5):
    out = os.environ.get("DIONAEA_CAP_OUT")
    if out:
        with open(os.path.join(out, "cap-refused"), "a") as fp:
            fp.write(md5 + "\n")


def _files(binaries_dir):
    return sorted(helpers.binaries_names(binaries_dir))


def test_the_sample_that_fits_is_stored(dionaea_host, binaries_dir, query_db):
    content = _unique("cap first", size=600 * KIB)
    md5 = hashlib.md5(content).hexdigest()
    _stor(dionaea_host, content)
    assert _rows(query_db, md5)
    assert (binaries_dir / md5).read_bytes() == content


def test_a_sample_over_the_cap_is_not_stored_but_logged(dionaea_host, binaries_dir, query_db, wait_for_event):
    content = _unique("cap second", size=600 * KIB)
    md5 = hashlib.md5(content).hexdigest()
    before = _files(binaries_dir)
    _stor(dionaea_host, content)
    assert _rows(query_db, md5), "the md5 of the refused sample is not in the downloads table"
    event = _json_download(wait_for_event, md5)
    download = [d for d in _entries(event["downloads"]) if d["md5"] == md5][0]
    assert download["sha256"] == hashlib.sha256(content).hexdigest()
    _refused(md5)
    assert not (binaries_dir / md5).exists()
    # no temporary file (.incoming/ftp-*.tmp) stays behind either
    time.sleep(1)
    assert _files(binaries_dir) == before


def test_a_refused_sample_is_refused_again_and_dionaea_answers(dionaea_host, binaries_dir, query_db):
    content = _unique("cap third", size=700 * KIB)
    md5 = hashlib.md5(content).hexdigest()
    for _ in range(2):
        _stor(dionaea_host, content)
    deadline = time.monotonic() + 30
    while len(query_db("SELECT 1 FROM downloads WHERE download_md5_hash = ?", (md5,))) < 2:
        assert time.monotonic() < deadline, "both uploads are in the downloads table"
        time.sleep(0.5)
    _refused(md5)
    assert not (binaries_dir / md5).exists()
    for port in (21, 81, 445):
        helpers.wait_for_port(dionaea_host, port, timeout=10)


def test_a_stored_sample_is_not_affected_by_the_cap(dionaea_host, binaries_dir, query_db):
    first = [p for p in binaries_dir.iterdir() if p.stat().st_size >= 600 * KIB]
    assert len(first) == 1
    content = first[0].read_bytes()
    md5 = hashlib.md5(content).hexdigest()
    assert first[0].name == md5
    _stor(dionaea_host, content)
    deadline = time.monotonic() + 30
    while len(query_db("SELECT 1 FROM downloads WHERE download_md5_hash = ?", (md5,))) < 2:
        assert time.monotonic() < deadline, "the second upload of a stored sample is not recorded"
        time.sleep(0.5)
    assert first[0].read_bytes() == content


def _print_job(host, content):
    with socket.create_connection((host, 9100), timeout=10) as sock:
        sock.sendall(b"\x1bE" + content)


def test_a_pcl_job_is_stored_by_the_store_and_read_only(dionaea_host, binaries_dir, query_db):
    content = b"\x1bE" + _unique("cap pcl", size=100 * KIB)
    md5 = hashlib.md5(content).hexdigest()
    _print_job(dionaea_host, content[2:])
    rows = _rows(query_db, md5)
    assert rows, "the print job is not in the downloads table"
    path = binaries_dir / md5
    deadline = time.monotonic() + 15
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert path.read_bytes() == content
    assert stat.S_IMODE(path.stat().st_mode) == 0o440
    # The downloads row is committed inside incident.report(), before
    # UploadFile.complete() returns and unlinks the temporary file.
    deadline = time.monotonic() + 15
    while helpers.temp_names(binaries_dir, ("print-",)):
        assert time.monotonic() < deadline, "the completed print job left a temporary file"
        time.sleep(0.1)


def test_a_pcl_job_over_the_cap_is_not_stored(dionaea_host, binaries_dir, query_db):
    content = b"\x1bE" + _unique("cap pcl big", size=700 * KIB)
    md5 = hashlib.md5(content).hexdigest()
    _print_job(dionaea_host, content[2:])
    assert _rows(query_db, md5), "the md5 of the refused print job is not in the downloads table"
    _refused(md5)
    time.sleep(1)
    assert not (binaries_dir / md5).exists()
    assert not helpers.temp_names(binaries_dir, ("print-",))


def test_a_small_sample_still_fits(dionaea_host, binaries_dir, query_db):
    payload = ("MZ cap http %s" % uuid.uuid4().hex).encode()
    md5 = hashlib.md5(payload).hexdigest()
    boundary = "cap" + uuid.uuid4().hex
    body = (_file_part(boundary, payload, "Content-Type: application/octet-stream\r\n")
            + ("--%s--\r\n" % boundary).encode())
    response, _ = _post_multipart(dionaea_host, body, boundary)
    assert response.startswith(b"HTTP/1."), response[:100]
    deadline = time.monotonic() + 15
    while not (binaries_dir / md5).exists() and time.monotonic() < deadline:
        time.sleep(0.5)
    assert (binaries_dir / md5).read_bytes() == payload
