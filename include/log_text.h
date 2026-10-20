/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2026 T-Pot contributors
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_LOG_TEXT_H
#define HAVE_LOG_TEXT_H

/* characters of a text of a client (a url, a reason, a name) in a log line */
#define LOG_TEXT_MAX 256

/*
 * A text of a client for a log line, to g_free: every byte outside 0x20..0x7e is a
 * '?', at most LOG_TEXT_MAX characters and "..." behind a longer one; a copy of none
 * for NULL. The text stays on its line and in its size (modules/python/dionaea/logtext.py
 * is the same for the python modules).
 */
char *log_text_new(const char *s, const char *none);

#endif
