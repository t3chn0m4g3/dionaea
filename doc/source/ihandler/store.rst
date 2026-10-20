..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

store
=====

Stores the files of ``dionaea.download.complete`` as ``download.dir/<md5>``.

The services collect a sample in a temporary file in ``download.dir/.incoming``
(mode ``0700``, made at the start of dionaea, which also removes the temporary files
an earlier run left there; made again if it is gone). It is on the same filesystem,
so a sample is linked from there; a sample of the emulation (in ``/tmp``) is copied
through it. The temporary files never change ``download.dir`` itself.

Incomplete and truncated samples
--------------------------------

A sample is the file as the service got it. Where the size of an upload is
bound, the services do one of two things:

* **Dropped** (no sample, the hash is not recorded): an FTP ``STOR`` over
  ``max_upload_size`` (32 MiB; answered ``552``), an SMB file with a write beyond
  ``max_upload_size`` (that write and all later ones fail with
  ``STATUS_DISK_FULL``), an SMB file that is mostly holes or never closed, an HTTP
  request over ``max_request_size`` (32 MiB in T-Pot; answered ``413``).
* **Cut** (a truncated sample): a print job (port 9100) larger than 32 MiB is
  stored with at most its first 32 MiB (the data before the read that would
  cross the limit); the rest is read from the socket and thrown away,
  and ``print job from <address> is cut`` is logged once. Its md5 is that of the
  truncated file, not of the job the client sent, so it will not match the hash
  of the original elsewhere.

A sample can also be incomplete because its transfer ended early: an FTP upload
whose data connection closes in the middle (the stream mode of FTP has no other
end of a file than the end of the connection), a print job of a client that
leaves, an SMB file the client closes before it wrote all of it, and the last
file of an HTTP multipart body that ends (at its Content-Length) without its
closing delimiter. They are stored as far as they came.

Mode
----

A stored sample is read-only and never executable (mode ``0440``). The mode is set
before the file gets its name.

Size limit
----------

``max_size`` is the limit of the total size of ``download.dir`` in MiB (``0`` or
absent: no limit): of the regular files in it, not of its subfolders (``.incoming``).
It is a number from ``0`` to ``1099511627776`` (2^40, as ``config.max_size`` of the
streamdumper); anything else is logged as a warning and means no limit.

Environment
~~~~~~~~~~~

The variable ``DIONAEA_STORE_MAX_SIZE`` of the environment of dionaea replaces
``max_size`` of ``store.yaml`` when it is set (an empty variable counts as unset), in
MiB. Its value is decimal digits only, no sign, space, fraction or suffix (``1024``,
not ``1024M`` or ``1024.0``); ``0`` is no limit, as in the config. The value of
``store.yaml`` is not read when the variable is valid. Any other value is logged as a
warning that names the variable and the value (at most 64 characters, others than
printable ASCII as ``?``), and the value of ``store.yaml`` holds:

.. code-block:: text

    Ignoring DIONAEA_STORE_MAX_SIZE='1024M': a whole number of MiB >= 0 (decimal digits) is expected, the value of store.yaml holds

The variable is read once, when the store handler starts.

At the start the store logs one line (level info, ``dionaea.log``) with the limit in
effect and where it came from, in this format:

.. code-block:: text

    store: max_size <N> MiB (from <SOURCE>)

``<SOURCE>`` is ``DIONAEA_STORE_MAX_SIZE`` or ``store.yaml``. ``<N>`` is a whole number,
``0`` for no limit; a fraction of MiB from ``store.yaml`` is written with up to six
significant digits (``0.25``). For example:

.. code-block:: text

    store: max_size 1024 MiB (from DIONAEA_STORE_MAX_SIZE)
    store: max_size 0 MiB (from store.yaml)

The format of this line stays as it is, tools may match it.

What is counted
~~~~~~~~~~~~~~~

* The samples the store adds are counted exactly: each one adds its size.
* Samples that something else removes (ewsposter's ``del_malware_after_send``, a
  cleanup job) are noticed later: when a sample is refused at the limit and the
  folder changed since the last count (at most once every 10 minutes), when the
  folder is replaced or removed (looked at every 60 seconds), or when dionaea
  restarts.
* Until then the total counts samples that are gone, so the store keeps fewer
  samples than it could, never more than ``max_size``. The disk stays protected.

The total can count less than the folder holds only until the first count at the
start has ended (it holds just the samples stored since the start), and for files
that something else puts into ``download.dir``: they are counted only at the next
count of the folder (when it was replaced, or at a refused sample once its mtime
changed, or at a restart). In T-Pot nothing but dionaea writes there.

Details
~~~~~~~

The size is counted once at the start, beside dionaea, and kept as a running total.
Every 60 seconds only the folder itself is looked at: it is counted again when it was
replaced (``rm -rf`` and ``mkdir``, as T-Pot's clean.sh does). A sample that does not
fit starts a count of the folder beside dionaea when the folder changed from outside since
the last count (its mtime; every create and unlink of a file in it changes it), at most
once every 10 minutes. That sample is refused, the next one is taken from the new total.
dionaea's own work is no such change: its temporary files are in ``.incoming``, and a
sample the store adds to an unchanged folder gives the folder the mtime that is taken as
counted. So a folder that is really full is not read again while samples come. While the
folder is gone, that is logged once. A new sample that would take the total over the limit
is not stored: one warning is logged, ``dionaea.download.complete.hash`` is reported (so the
md5 stays in ``dionaea.sqlite`` and ``dionaea.json``), ``dionaea.download.complete.unique``
is not (there is no file to submit). A sample that is stored already (``.again``) is not
affected.

Example config
--------------

.. literalinclude:: ../../../conf/ihandlers/store.yaml
   :language: yaml
   :caption: ihandlers/store.yaml
