..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2019 Michael Neu

    SPDX-License-Identifier: GPL-2.0-or-later

Printer
=======

Dionaea provides a basic PJL/PCL printer server on port 9100. It can
receive prints and `PRET <https://github.com/RUB-NDS/PRET/>`_ works
with it. Most messages can be overridden using the configuration file,
please refer to the ``pjl_default_responses`` `dictionary
<https://github.com/DinoTools/dionaea/blob/feature/printer/modules/python/dionaea/printer.py>`_
for all available messages.

Print jobs
----------

A PCL print job is stored as a sample (see :doc:`../ihandler/store`) when the
client disconnects. A job is bound to 32 MiB: from the read that would cross it on,
the data is read and thrown away, what came before (at most 32 MiB) is stored as a truncated sample (its md5 is not
that of the whole job) and ``print job from <address> is cut`` is logged once.

Example config
--------------

.. code-block:: yaml

    - name: printer
      config:
        root: "var/lib/printer/root"
        pjl_msgs:
            info_id: "HP LASERJET 5ML"

Volumes
-------

When connecting to a printer using PRET, one may inspect the filesystem.
By creating folders in the configured printer root (``var/lib/printer/root``
above), they'll be usable from the PRET shell.

PRET by default checks the ``info_filesys`` command, which needs to be
adjusted to match your setup. The default configuration assumes there's a
volume called ``0``.
