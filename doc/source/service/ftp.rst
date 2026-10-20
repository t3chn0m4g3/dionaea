..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

FTP
===

Dionaea provives a basic ftp server on port 21, it can create
directories and upload and download files. From my own experience there
are very little automated attacks on ftp services and I'm yet to see
something interesting happening on port 21.

Uploads
-------

A file that a client uploads (``STOR``) is not kept in the root of the
service. It is stored like a download: ``<download.dir>/<md5>`` and a row in
the table ``downloads`` of the sqlite log (``log_sqlite``), the hashes are in
the ``downloads`` key of the connection in ``log_json``.

The url of an upload is ``ftp://<address of the client>/<file name>``, the
name is what the client sent, percent encoded and cut to 255 characters. The
upload belongs to the control connection (login and commands of the client).

A file larger than ``max_upload_size`` (bytes, default 33554432 = 32 MiB) is
dropped, the client gets ``552`` and the data connection is closed. An empty
file is not recorded.

Example config
--------------

.. literalinclude:: ../../../conf/services/ftp.yaml.in
    :language: yaml
    :caption: services/ftp.yaml
