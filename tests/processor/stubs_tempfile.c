/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * The temp files of src/util.c for the tests that link processor.c without
 * util.c: the streamdumper is linked with it there, never used.
 */
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <glib.h>

#include "util.h"

struct tempfile *tempfile_new(char *path, char *prefix)
{
	(void)path;
	(void)prefix;
	g_assert_not_reached();
}

void tempfile_close(struct tempfile *tf)
{
	(void)tf;
	g_assert_not_reached();
}

void tempfile_free(struct tempfile *tf)
{
	(void)tf;
	g_assert_not_reached();
}
