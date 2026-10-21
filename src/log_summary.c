/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2026 T-Pot contributors
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * At most one warning a period for a message of every connection, see include/log_summary.h.
 */

#include <glib.h>
#include <ev.h>
#include <stdarg.h>
#include <stdbool.h>

#include "dionaea.h"
#include "threads.h"
#include "log_summary.h"

#define PERIOD_US ((gint64)LOG_SUMMARY_PERIOD * G_USEC_PER_SEC)

static gint64 clock_now(struct log_summary *s)
{
	if( s->hooks != NULL && s->hooks->clock != NULL )
		return s->hooks->clock();
	return g_get_monotonic_time();
}

static void timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	(void)loop;
	(void)revents;
	log_summary_due(w->data);
}

/* the event loop: arm the timer for the end of the period of the last warning */
static void arm_cb(void *data)
{
	struct log_summary *s = data;
	if( g_dionaea == NULL || g_dionaea->loop == NULL )
		return;
	g_mutex_lock(&s->lock);
	double after = (double)(s->warned_at + PERIOD_US - clock_now(s)) / G_USEC_PER_SEC;
	g_mutex_unlock(&s->lock);
	if( after < 0. )
		after = 0.;
	ev_timer_stop(g_dionaea->loop, &s->timer);
	ev_timer_init(&s->timer, timer_cb, after, 0.);
	s->timer.data = s;
	s->timer_after = after;
	ev_timer_start(g_dionaea->loop, &s->timer);
}

/* any thread: the event loop arms the timer (libev is not for other threads) */
static bool default_schedule(struct log_summary *s, double after)
{
	(void)after;
	if( g_dionaea == NULL || g_dionaea->loop == NULL || g_dionaea->threads == NULL ||
		g_dionaea->threads->cmds == NULL )
		return false;
	g_async_queue_push(g_dionaea->threads->cmds, async_cmd_new(arm_cb, s));
	ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);
	return true;
}

static bool schedule(struct log_summary *s, double after)
{
	if( s->hooks != NULL && s->hooks->schedule != NULL )
		return s->hooks->schedule(s, after);
	return default_schedule(s, after);
}

/*
 * lock held, events are pending: true when the warning is due now (*count and *last are
 * taken for it, to write after the lock); else *after is the seconds until the period
 * ends when the caller has to schedule the timer, -1 when one is scheduled already
 */
static bool due_locked(struct log_summary *s, gint64 now, guint64 *count, char **last, double *after)
{
	if( !s->warned || now - s->warned_at >= PERIOD_US )
	{
		*count = s->pending;
		*last = s->last;
		s->pending = 0;
		s->last = NULL;
		s->warned = true;
		s->warned_at = now;
		return true;
	}
	*after = -1.;
	if( !s->scheduled )
	{
		s->scheduled = true;
		*after = (double)(s->warned_at + PERIOD_US - now) / G_USEC_PER_SEC;
	}
	return false;
}

/* after the lock: the warning, or the timer */
static void finish(struct log_summary *s, bool now_due, guint64 count, char *last, double after)
{
	if( now_due )
	{
		g_log(s->domain, G_LOG_LEVEL_WARNING, "%s: %" G_GUINT64_FORMAT " %s in the last minute, the last: %s",
			  s->what, count, s->unit, last);
		g_free(last);
		return;
	}
	if( after < 0. )
		return;
	if( !schedule(s, after) )
	{
		/* no timer: the next event tries again */
		g_mutex_lock(&s->lock);
		s->scheduled = false;
		g_mutex_unlock(&s->lock);
	}
}

void log_summary_add(struct log_summary *s, const char *text)
{
	char *copy = g_strdup(text != NULL ? text : "-");
	guint64 count = 0;
	char *last = NULL;
	double after = -1.;

	g_mutex_lock(&s->lock);
	s->pending++;
	g_free(s->last);
	s->last = copy;
	bool now_due = due_locked(s, clock_now(s), &count, &last, &after);
	g_mutex_unlock(&s->lock);

	finish(s, now_due, count, last, after);
}

void log_summary_addf(struct log_summary *s, const char *format, ...)
{
	va_list ap;
	va_start(ap, format);
	char *text = g_strdup_vprintf(format, ap);
	va_end(ap);
	log_summary_add(s, text);
	g_free(text);
}

void log_summary_due(struct log_summary *s)
{
	guint64 count = 0;
	char *last = NULL;
	double after = -1.;
	bool now_due = false;

	g_mutex_lock(&s->lock);
	s->scheduled = false;
	if( s->pending > 0 )
		now_due = due_locked(s, clock_now(s), &count, &last, &after);
	g_mutex_unlock(&s->lock);

	finish(s, now_due, count, last, after);
}

void log_summary_set_hooks(struct log_summary *s, const struct log_summary_hooks *hooks)
{
	g_mutex_lock(&s->lock);
	s->hooks = hooks;
	g_mutex_unlock(&s->lock);
}

void log_summary_reset(struct log_summary *s)
{
	g_mutex_lock(&s->lock);
	s->pending = 0;
	g_free(s->last);
	s->last = NULL;
	s->warned = false;
	s->warned_at = 0;
	s->scheduled = false;
	g_mutex_unlock(&s->lock);
}
