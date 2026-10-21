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
#include "log_summary.h"
#include "log_text.h"

#define D_LOG_DOMAIN "download"
#include "log.h"

/* the warnings of the failures: at most one a minute (log_summary.h) */
static struct log_summary failures = LOG_SUMMARY_INIT("downloads", "failed");

/* the hooks of a test, through those of the summary */
static const struct download_failures_hooks *test_hooks;

static gint64 test_clock(void)
{
	return test_hooks->clock();
}

static bool test_schedule(struct log_summary *s, double after)
{
	(void)s;
	return test_hooks->schedule(after);
}

static const struct log_summary_hooks summary_hooks = { test_clock, test_schedule };

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
	log_summary_addf(&failures, "%s (%s)", u, r);
	g_free(u);
	g_free(r);
}

void download_failures_due(void)
{
	log_summary_due(&failures);
}

void download_failures_set_hooks(const struct download_failures_hooks *hooks)
{
	test_hooks = hooks;
	log_summary_set_hooks(&failures, hooks != NULL ? &summary_hooks : NULL);
}

void download_failures_reset(void)
{
	log_summary_reset(&failures);
}
