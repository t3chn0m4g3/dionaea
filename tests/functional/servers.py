# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

"""Servers of the client container that dionaea downloads from (TFTP, HTTP)."""

import http.server
import socket
import struct
import threading


class TftpServer(threading.Thread):
    """Minimal read-only TFTP server on port 69 (one DATA block, own socket per request)."""

    def __init__(self, files, address):
        super().__init__(daemon=True)
        self.files = files
        self.requests = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((address, 69))
        self.sock.settimeout(0.5)
        self._stopping = threading.Event()

    def run(self):
        while not self._stopping.is_set():
            try:
                packet, peer = self.sock.recvfrom(1024)
            except socket.timeout:
                continue
            if struct.unpack("!H", packet[:2])[0] != 1:
                continue
            name = packet[2:].split(b"\x00")[0].decode()
            self.requests.append(name)
            content = self.files.get(name)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reply:
                reply.settimeout(3)
                if content is None:
                    reply.sendto(struct.pack("!HH", 5, 1) + b"not found\x00", peer)
                    continue
                assert len(content) < 512
                reply.sendto(struct.pack("!HH", 3, 1) + content, peer)
                try:
                    reply.recvfrom(1024)  # ACK
                except socket.timeout:
                    pass

    def close(self):
        self._stopping.set()
        self.join(timeout=5)
        self.sock.close()


class HttpServer:
    def __init__(self, files, address):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(handler):
                content = files.get(handler.path)
                self.requests.append(handler.path)
                if content is None:
                    handler.send_error(404)
                    return
                handler.send_response(200)
                handler.send_header("Content-Length", str(len(content)))
                handler.end_headers()
                handler.wfile.write(content)

            def log_message(handler, *args):
                pass

        self.requests = []
        self.connections = []
        outer = self

        class Server(http.server.ThreadingHTTPServer):
            def get_request(server):
                request, client = super().get_request()
                outer.connections.append(client)
                return request, client

        self.server = Server((address, 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class FtpServer:
    """Anonymous, read-only FTP server (pyftpdlib) serving files, in threads."""

    def __init__(self, files, address, directory):
        from pyftpdlib.authorizers import DummyAuthorizer
        from pyftpdlib.handlers import FTPHandler
        from pyftpdlib.servers import ThreadedFTPServer

        for name, content in files.items():
            with open("%s/%s" % (directory, name), "wb") as fp:
                fp.write(content)
        authorizer = DummyAuthorizer()
        authorizer.add_anonymous(directory, perm="elr")

        class Handler(FTPHandler):
            def on_file_sent(handler, file):
                outer.sent.append(file)

            def ftp_PORT(handler, line):
                outer.port_commands.append(line)
                return super().ftp_PORT(line)

        outer = self
        self.sent = []
        self.port_commands = []
        Handler.authorizer = authorizer
        self.server = ThreadedFTPServer((address, 0), Handler)
        self.port = self.server.address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.close_all()
        self.thread.join(timeout=5)
