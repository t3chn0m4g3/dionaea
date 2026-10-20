/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2026 T-Pot contributors
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Texts of a client for a log line, see include/log_text.h.
 */

#include <glib.h>
#include <stdbool.h>
#include <string.h>

#include "log_text.h"

char *log_text_new(const char *s, const char *none)
{
	if( s == NULL )
		return g_strdup(none);
	size_t len = strlen(s);
	bool cut = len > LOG_TEXT_MAX;
	if( cut )
		len = LOG_TEXT_MAX;
	char *out = g_malloc(len + (cut ? 3 : 0) + 1);
	for( size_t i = 0; i < len; i++ )
	{
		unsigned char c = (unsigned char)s[i];
		out[i] = c >= 0x20 && c <= 0x7e ? (char)c : '?';
	}
	if( cut )
		memcpy(out + len, "...", 3);
	out[len + (cut ? 3 : 0)] = '\0';
	return out;
}
