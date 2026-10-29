/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DIONAEA_EMU_HOOKS_H
#define DIONAEA_EMU_HOOKS_H

struct connection;

struct async_connect_helper
{
	struct connection *parent;
	struct connection *con;
	char *hostname;
	int port;
};

void async_connection_connect(void *data);

#endif
