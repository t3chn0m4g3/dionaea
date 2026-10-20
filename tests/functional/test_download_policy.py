# SPDX-FileCopyrightText: none
# SPDX-License-Identifier: CC0-1.0

"""Downloads must not reach local targets, directly or through redirects."""

import http.server
import socket
import threading
import time
import uuid

import pytest
import pymysql

from test_mysql import mysql as mysql_fixture

mysql = mysql_fixture


def offer(cursor, url):
    try:
        cursor.execute("select xpdl3('%s') into dumpfile 'x'" % url)
    except pymysql.err.MySQLError:
        pass


@pytest.mark.parametrize('target', ['127.0.0.1', '169.254.169.254'])
def test_internal_http_download_is_not_completed(target, mysql, query_db, wait_for_rows):
    url = 'http://%s:81/blocked-%s' % (target, uuid.uuid4().hex)
    offer(mysql, url)
    time.sleep(0.5)
    assert wait_for_rows('SELECT offer_url FROM offers WHERE offer_url = ?', (url,))
    assert not query_db('SELECT download_url FROM downloads WHERE download_url = ?', (url,))


@pytest.mark.parametrize('target', ['honeypot', 'localhost', '[::1]', '[::ffff:127.0.0.1]'])
def test_http_redirect_does_not_reach_honeypot(target, mysql, dionaea_ip, my_ip, query_db, wait_for_rows):
    destination = dionaea_ip if target == 'honeypot' else target

    class Redirect(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header('Location', 'http://%s:81/forbidden-redirect' % destination)
            self.send_header('Content-Length', '0')
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer((my_ip, 0), Redirect)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = 'http://%s:%d/redirect-%s' % (my_ip, server.server_port, uuid.uuid4().hex)
    try:
        offer(mysql, url)
        time.sleep(1)
        assert wait_for_rows('SELECT offer_url FROM offers WHERE offer_url = ?', (url,))
        assert not query_db('SELECT download_url FROM downloads WHERE download_url = ?', (url,))
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize('protocol, name', [('ftp', 'functional-list.txt'), ('tftp', 'functional-test.txt')])
def test_native_download_clients_reject_local_targets(protocol, name, dionaea_host, query_db):
    from test_emu import winexec_shellcode

    command = ('cmd.exe /c tftp -i 127.0.0.1 GET ' + name if protocol == 'tftp'
               else 'cmd.exe /c ftp -s:ftp.txt 127.0.0.1')
    # TFTP's command emulation offers a URL directly. FTP is exercised with a
    # one-line script URL found in the existing command emulator below.
    if protocol == 'ftp':
        command = ('cmd.exe /c echo open 127.0.0.1>ftp.txt&echo anonymous>>ftp.txt&'
                   'echo get %s>>ftp.txt&ftp -s:ftp.txt' % name)
    with socket.create_connection((dionaea_host, 445), timeout=5) as sock:
        sock.sendall(winexec_shellcode(command.encode()))
    deadline = time.monotonic() + 10
    rows = []
    while not rows and time.monotonic() < deadline:
        rows = query_db('SELECT offer_url FROM offers WHERE offer_url LIKE ?', (protocol + '://%127.0.0.1%/' + name,))
        time.sleep(0.1)
    assert rows
    time.sleep(0.5)
    for row in rows:
        assert not query_db('SELECT download_url FROM downloads WHERE download_url = ?', (row['offer_url'],))
