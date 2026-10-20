/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2026 T-Pot contributors
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The log lines of downloads that do not complete, see include/download_log.h.
 */

#include <glib.h>
#include <ev.h>
#include <stdbool.h>
#include <string.h>

#include "dionaea.h"
#include "download_log.h"
#include "log_text.h"
#include "log.h"

#define D_LOG_DOMAIN "download"

#define PERIOD_US ((gint64)DOWNLOAD_FAILURES_PERIOD * G_USEC_PER_SEC)

static gint64 default_clock(void);
static bool default_schedule(double after);

static const struct download_failures_hooks default_hooks = { default_clock, default_schedule };

static struct
{
	const struct download_failures_hooks *hooks;
	/* failures since the last summary, and the last of them */
	guint64 pending;
	char *last_url;
	char *last_reason;
	/* the last summary */
	bool warned;
	gint64 warned_at;
	/* the timer of the next summary is armed */
	bool scheduled;
	struct ev_timer timer;
} failures = { .hooks = &default_hooks };

static gint64 default_clock(void)
{
	return g_get_monotonic_time();
}

static void timer_cb(struct ev_loop *loop, struct ev_timer *w, int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
	download_failures_due();
}

static bool default_schedule(double after)
{
	if( g_dionaea == NULL || g_dionaea->loop == NULL )
		return false;
	ev_timer_stop(g_dionaea->loop, &failures.timer);
	ev_timer_init(&failures.timer, timer_cb, after, 0.);
	ev_timer_start(g_dionaea->loop, &failures.timer);
	return true;
}

static void summary(gint64 now)
{
	g_warning("downloads: %" G_GUINT64_FORMAT " failed in the last minute, the last: %s (%s)",
			  failures.pending, failures.last_url, failures.last_reason);
	failures.pending = 0;
	failures.warned = true;
	failures.warned_at = now;
}

/* the next summary comes when the period of the last one ends */
static void schedule(gint64 now)
{
	if( failures.scheduled )
		return;
	/* armed, or the next failure tries again */
	failures.scheduled = failures.hooks->schedule((double)(failures.warned_at + PERIOD_US - now) / G_USEC_PER_SEC);
}

void download_refused(const char *url)
{
	char *u = log_text_new(url, "(no url)");
	g_info("download target refused by the filter: %s", u);
	g_free(u);
}

void download_failed(const char *url, const char *reason)
{
	char *u = log_text_new(url, "(no url)");
	char *r = log_text_new(reason, "no reason");
	g_info("download failed: %s (%s)", u, r);
	failures.pending++;
	g_free(failures.last_url);
	g_free(failures.last_reason);
	failures.last_url = u;
	failures.last_reason = r;

	gint64 now = failures.hooks->clock();
	if( !failures.warned || now - failures.warned_at >= PERIOD_US )
		summary(now);
	else
		schedule(now);
}

void download_failures_due(void)
{
	failures.scheduled = false;
	if( failures.pending == 0 )
		return;
	gint64 now = failures.hooks->clock();
	if( now - failures.warned_at >= PERIOD_US )
		summary(now);
	else
		schedule(now);
}

void download_failures_set_hooks(const struct download_failures_hooks *hooks)
{
	failures.hooks = hooks != NULL ? hooks : &default_hooks;
}

void download_failures_reset(void)
{
	failures.pending = 0;
	g_free(failures.last_url);
	g_free(failures.last_reason);
	failures.last_url = NULL;
	failures.last_reason = NULL;
	failures.warned = false;
	failures.warned_at = 0;
	failures.scheduled = false;
}
