..
    This file is part of the dionaea honeypot

    SPDX-FileCopyrightText: 2011-2012 Markus Koetter
    SPDX-FileCopyrightText: 2015-2017 PhiBo (DinoTools)

    SPDX-License-Identifier: GPL-2.0-or-later

curl
====

The curl module is used to transfer files from and to servers, it is
used to download files via http as well as submitting files to 3rd parties.

Every address of a download, also of a redirect, is checked by the
:doc:`download_policy <../ihandler/download_policy>` ihandler before curl
connects to it. A download that does not complete is logged as described there:
an info line for a target the filter refused, an info line for a failure and at
most one warning a minute that sums the failures up.
