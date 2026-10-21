/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2026 T-Pot contributors
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_LOG_SUMMARY_H
#define HAVE_LOG_SUMMARY_H

#include <glib.h>
#include <ev.h>
#include <stdbool.h>

/*
 * At most one warning a period for a message that can come once per connection, request
 * or session (modules/python/dionaea/logtext.py LogSummary is the same for the python
 * modules). The caller writes its line of every event at info, with all its detail, and
 * hands the summary a short text of the event: log_summary_add(). The summary writes
 *
 *   "<what>: <N> <unit> in the last minute, the last: <text of the last event>"
 *
 * at warning in the log domain of the file that made it (LOG_SUMMARY_INIT): the first
 * event after a quiet period at once, the ones after it when the period of that warning
 * ends. A single event is in the log of warnings within the period, many give one line
 * per period; the events of the last period before dionaea stops are only in the info
 * lines.
 *
 * Threads: log_summary_add() can be called from any thread (the processor jobs of the
 * threadpool); its count, its last text and its times are under the lock of the summary.
 * The warning of an event that comes after a quiet period is written by the thread of
 * that event, after the lock is given back. The warning at the end of a period is
 * written by the event loop: the default schedule hands the event loop an async command
 * (g_dionaea->threads->cmds and its trigger) that arms an ev_timer of the summary, so
 * the timer is only ever touched by the thread of the event loop.
 *
 * The text of an event is the caller's: a text of a client goes through log_text_new()
 * (log_text.h) first.
 */

/* seconds between two warnings of a summary */
#define LOG_SUMMARY_PERIOD 60

struct log_summary;

/* tests: the clock (microseconds, default g_get_monotonic_time) and the timer of the
 * summary (log_summary_due() after that many seconds, default an ev_timer of the event
 * loop armed through its async commands; false: no timer, the next event tries again).
 * A NULL member is the default. */
struct log_summary_hooks
{
	gint64 (*clock)(void);
	bool (*schedule)(struct log_summary *s, double after);
};

struct log_summary
{
	const char *domain;
	const char *what;
	const char *unit;
	const struct log_summary_hooks *hooks;
	GMutex lock;
	/* events since the last warning, and the text of the last of them */
	guint64 pending;
	char *last;
	/* the last warning */
	bool warned;
	gint64 warned_at;
	/* a timer of the next warning is armed (or asked for) */
	bool scheduled;
	/* the timer, of the event loop's thread only */
	struct ev_timer timer;
	double timer_after;
};

/* a summary of the messages of this file (G_LOG_DOMAIN of the file, log.h) */
#define LOG_SUMMARY_INIT(what_, unit_) { .domain = G_LOG_DOMAIN, .what = (what_), .unit = (unit_) }

/* one event, text is copied (NULL: "-") */
void log_summary_add(struct log_summary *s, const char *text);
void log_summary_addf(struct log_summary *s, const char *format, ...) G_GNUC_PRINTF(2, 3);

/* the timer of the summary fired */
void log_summary_due(struct log_summary *s);

/* tests: the hooks (NULL: the defaults), and forget the events and the last warning */
void log_summary_set_hooks(struct log_summary *s, const struct log_summary_hooks *hooks);
void log_summary_reset(struct log_summary *s);

#endif
