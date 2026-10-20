..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

HTTP
====

Dionaea supports http on port 80 as well as https, but there is no code making use of the data gathered on these ports.
For https, the self-signed ssl certificate is created at startup.

Configure
---------

Example configuration:

.. code-block:: yaml

    - name: http
      config:
        root = "var/dionaea/wwwroot"

default_headers

    Default header fields are send if none of the other header patterns match.

global_headers

    Global header fields are added to all response headers.

headers

    List of header fields to be used in the response header.
    Only applied if filename_pattern, status_code and methods match.
    The first match in the list is used.

get_max_num_fields

    Maximum number of fields of a query string, and of the parts of a multipart
    body (those of nested parts included). A body with more parts is not parsed,
    no file of it is stored. Default: 100

max_request_size

     Maximum size in kbytes of the request. 32768 = 32MB

     The files of a multipart/form-data POST are stored as samples (as they were
     sent, a Content-Transfer-Encoding is not decoded). Delimiters are found as
     whole lines, with CRLF or bare LF line breaks; the files of nested
     ``multipart/mixed`` parts are stored too, up to three levels deep. The body
     ends at its closing delimiter or at the Content-Length; a request larger
     than ``max_request_size`` is answered with 413 and nothing of it is stored.

root

    The root directory so serve files from.


Example config
--------------

.. literalinclude:: ../../../conf/services/http.yaml.in
    :language: yaml
    :caption: services/http.yaml

Additional examples
-------------------

Set the Server response field.

.. code-block:: yaml

    - name: http
      config:
        global_headers:
          - ["Server", "nginx"]

Define headers to use if the filename matches a pattern.

.. code-block:: yaml

    - name: http
      config:
        headers:
          - filename_pattern: ".*\\.php"
            headers:
              - ["Content-Type", "text/html; charset=utf-8"]
              - ["Content-Length", "{content_length}"]
              - ["Connection", "{connection}"]
              - ["X-Powered-By", "PHP/5.5.9-1ubuntu4.5"]

Templates
---------

It is possible to use Jinja_ templates to customise the content returned by dionaea.

Requirements:

- Jinja

Before any template is used the template processing has to be enabled in the config file.
Some global templates (e.g. for error pages) are specified in the config file.
To use the template function in a static file just place it under the content root directory and add the template file extension as specified with the ``file_extension``.

Example:

- you have a file called ``my-app.html``
- to enabled template processing rename the file to ``my-app.html.j2``
- now you can use template strings

Template values:

- ``connection`` is an instance of HTTP connection class
- ``values`` is a Dictionary of additional template values specified in the config

Demo:


Have a look at our demo template and play with it in your test lab before releasing it into the wild.

.. literalinclude:: ../../../share/python/http/template/example/form.html.j2
    :language: jinja
    :caption: http/root/form.html.j2

.. _Jinja: https://palletsprojects.com/p/jinja/
