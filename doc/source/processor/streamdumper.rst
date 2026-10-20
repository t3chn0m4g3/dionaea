..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

Streamdumper
============

This processor can dump a connection as bi-directional stream.
The dump can be used to replay an attack on ip-level without messing with pcap and tcpreplay.

Configuration
-------------

**path**

    Dumps will be created in this directory.
    It needs a strftime field (``%Y-%m-%d``), the folder before the first field is
    the base folder of the limits.

**max_size**

    Limit of the total size of the dumps below the base folder in MiB, all date
    folders included (``config.max_size``, ``0`` or absent: no limit).

**max_files**

    Limit of the number of dumps below the base folder (``config.max_files``, ``0``
    or absent: no limit).

Environment
-----------

Two variables of the environment of dionaea replace the limits of the config when
they are set (an empty variable counts as unset):

``DIONAEA_STREAMDUMPER_MAX_SIZE``
    replaces ``config.max_size``, in MiB.

``DIONAEA_STREAMDUMPER_MAX_FILES``
    replaces ``config.max_files``.

A value is decimal digits only, no sign, space, fraction or suffix (``2048``, not
``2048M`` or ``2048.0``), in the range of the config option; ``0`` is no limit, as in
the config. The value of the config is not read when its variable is valid. Any other
value is logged as a warning that names the variable and the value (at most 64
characters, others than printable ASCII as ``?``), and the value of the config holds:

.. code-block:: text

    Ignoring DIONAEA_STREAMDUMPER_MAX_SIZE='2048M': a whole number of MiB >= 0 (decimal digits) is expected, the value of dionaea.cfg holds

The variables are read once, at the start of dionaea. They apply to every
reference of the streamdumper in the processor tree.

At the start dionaea logs one line per limit (level info, ``dionaea.log``) with the
limit in effect and where it came from, in this format:

.. code-block:: text

    streamdumper: max_size <N> MiB (from <SOURCE>)
    streamdumper: max_files <N> (from <SOURCE>)

``<SOURCE>`` is the name of the variable (``DIONAEA_STREAMDUMPER_MAX_SIZE``,
``DIONAEA_STREAMDUMPER_MAX_FILES``) or ``dionaea.cfg``. ``<N>`` is a whole number, ``0``
for no limit; a fraction of MiB from the config is written with up to six significant
digits (``0.25``). For example:

.. code-block:: text

    streamdumper: max_size 2048 MiB (from DIONAEA_STREAMDUMPER_MAX_SIZE)
    streamdumper: max_files 200000 (from dionaea.cfg)

The format of these lines stays as it is, tools may match them.

Limits
------

What is counted
~~~~~~~~~~~~~~~

The limits count the dumps below the base folder: their number and their size.

* dionaea's own dumps are counted exactly. A dump counts from its first write,
  with the size it will have once it is closed, and every later chunk is counted
  before it is written.
* Dumps that something else removes (a cleanup job, ``find -mtime +7 -delete``)
  are noticed later:

  * a whole date folder (or the base folder) that is removed: at the next check,
    at most 60 seconds later;
  * single dumps removed from an older date folder (not today's, and not one this
    run of dionaea made): when a connection is refused at a limit, at most once
    every 10 minutes (only the folders whose mtime changed are counted again);
  * single dumps removed from a date folder that dionaea writes to (today's
    folder, and every folder this run made): when that folder is removed as a
    whole, or when dionaea restarts. When the date rolls over dionaea writes into
    the new day's folder, the old one stays counted as it was until it goes.

* Until then the total counts dumps that are gone, so dionaea writes fewer dumps
  than it could, never more than the limits. The disk stays protected.

The total can count fewer dumps than the folder holds (and more than the limits
can be written) only in these cases: until the first count at the start has
ended (it holds just the dumps of this run), for a date folder whose first count
failed (until a count of it succeeds), with more than one reference of the
streamdumper (see below), and for files that something else puts into the
bistreams: they are counted only at the next count of their folder. In T-Pot
nothing but dionaea writes there.

Details
~~~~~~~

An invalid value of ``config.max_size`` or ``config.max_files`` is logged as a
warning and means no limit. The total is counted once at the start, by a thread
of its own (dionaea listens at once), and kept as a running total of what is
written. Every 60 seconds the thread reads only the base folder, not the dumps:
a date folder that is removed takes its dumps out of the total, a date folder
that is new or was replaced is counted, and a replaced or removed base folder
(``rm -rf`` and ``mkdir``, as T-Pot's clean.sh does) is counted again in full.
(A count of the whole folder every minute took minutes on a Docker Desktop bind
mount with 188,000 dumps, and dionaea's file requests waited behind it.) At a
connection refused at a limit the thread compares the mtime of every date folder
with the one before its count and counts only the folders that changed; a later
connection is dumped again once there is room. A folder that is really full does
not change and is not read again. A date folder that dionaea made itself is never
read again, not at a refused connection either: on a Docker Desktop bind mount it
can hold 200,000 dumps just when the limit is reached, and reading it held up
every file request of dionaea. The same holds for today's folder (the one
``config.path`` names now) after a restart of dionaea alone (autoheal or the
restart policy, without T-Pot's clean.sh): only dionaea writes into the
bistreams, so the dumps of the run before are counted once by the first count,
and the folder is not read again at a refused connection. A folder that is
removed and made again by dionaea's dumps while a check reads the base stays
dionaea's. A date folder that can not be read keeps what was known of it, the
other folders are counted, and only that folder is tried again, less and less
often (after 1, 2, 4, ... 64 minutes) with a warning each time. A count stops
after the entry it reads when dionaea stops.

The totals are kept per entry of the base folder. With nested date folders
(``%Y/%m/%d``) that is the first level (the year): a year folder is counted,
compared and taken out as a whole. A month removed from it changes its mtime
and is noticed at a refused connection; a day removed from a month, or dumps
from a day, do not change the mtime of the year and are counted until the year
folder goes or dionaea restarts. T-Pot's ``%Y-%m-%d`` has one level: a removed
day is noticed at the next check, dumps removed from a day at a refused
connection (not from a day that dionaea made). A connection whose
first dump write would not fit (the number of files reached, or the bytes of its
first data over ``max_size``) gets no dump at all, also when room is made later;
the connection itself goes on. An open dump counts with what it will hold once
closed, and every later chunk of it must fit below ``max_size`` as well: a chunk
that does not fit stops the dump, which is closed as at the end of its
connection (a valid dump, ending in ``')]``) and gets nothing more, while the
connection goes on. So the total, open dumps included, stays at or below
``max_size``. One warning per minute and kind (refused, stopped) names the
totals and the limits, never the data. When dionaea stops, the dumps of the
connections that are still open are closed the same way, so every dump is a
Python literal (``stream = [...]``).

Reference the streamdumper once in the processor tree (``processors`` and
``next`` of dionaea.cfg): every reference gets its own configuration, so each
would count the folder and apply the limits on its own. After the first count
each one sees only the dumps of its own reference, so every total misses the
dumps of the others and together they can write more than the limits; dionaea
logs a warning when two references have the same base folder.

Example config
--------------

.. code-block:: ini

    [processor.streamdumper]
    name=streamdumper
    config.path=/opt/dionaea/var/dionaea/bistreams/%Y-%m-%d/
    config.max_size=2048
    config.max_files=200000
