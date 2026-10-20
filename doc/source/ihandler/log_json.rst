..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

log_json
========

This ihandler can submit information about attacks/connections encoded as json.

.. warning:: This ihandler is in pre alpha state and it might be changed or removed in the near future.

Configure
---------


flat_data

    Set to true to flatten object lists.

handlers

    List of URLs to submit the information to.
    At the moment only file, http and https are supported.

Format
------

Format of the connection information:

.. code-block:: JavaScript

    {
        "connection": {
            "local": {
                "address": "<string:local ip address>",
                "port": <integer:local port>,
            },
            "protocol": "<string:service name e.g. httpd>",
            "remote": {
                "address": "<string:remote ip address>",
                "port": <integer:remote port>,
                "hostname": "<string:hostname of the remote host>"
            },
            "transport": "<string:transport protocol e.g. tcp or udp>",
            "type": "<string:connection type e.g. accepted, listen, ...>"
        }
    }


Further keys of the entry of a connection (added when something happens on it):

``credentials``, ``ftp.commands``
    Logins and the commands of an FTP client.

    The credentials list retains the first 1000 logins per connection, shared
    across SMB, FTP, MySQL and MSSQL. Further logins are omitted from JSON;
    protocol responses and SQLite login logging continue. SMB summary metadata
    still describes the latest login. This limit also applies with ``flat_data``.

``smb.commands``
    The commands of an SMB client, ``[{"command": "SMB_COM_NEGOTIATE"}, ...]``;
    the arguments are not logged. At most 1000 commands per connection.

``downloads``
    The files that were downloaded by dionaea on behalf of the client (offered
    by shellcode or a script) or uploaded by the client (FTP, SMB), at most 1000 per
    connection:
    ``[{"path": "<file in download.dir>", "url": "<url>", "md5": "<md5>", "sha256": "<sha256>"}, ...]``.
    The file is named by its md5.

With ``flat_data`` these lists become objects of lists (``{"md5": [...], "url": [...]}``), as
``credentials`` and ``ftp.commands`` do.

Example config
--------------

.. literalinclude:: ../../../conf/ihandlers/log_json.yaml.in
   :language: yaml
   :caption: ihandlers/log_json.yaml
