/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2026 T-Pot contributors
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_DOWNLOAD_LOG_H
#define HAVE_DOWNLOAD_LOG_H

#include <glib.h>
#include <stdbool.h>

#include "log_summary.h"
#include "log_text.h"

/*
 * The log lines of downloads that do not complete, for every download client (curl,
 * the FTP and TFTP clients of the python module). The summary of the failures is a
 * log_summary (log_summary.h).
 *
 * The url and the reason come from the client: in every line (and in the summary) a
 * byte outside 0x20..0x7e is a '?', and each is cut at DOWNLOAD_LOG_TEXT_MAX
 * characters with "..." behind.
 *
 * download_refused(): the download target filter refused the target of url (a local,
 * loopback or link-local address, or one outside allowed_networks): one info line,
 * "download target refused by the filter: <url>".
 *
 * download_failed(): the download of url failed for reason: one info line,
 * "download failed: <url> (<reason>)". At most one warning per period sums the
 * failures up, "downloads: <N> failed in the last minute, the last: <url> (<reason>)":
 * the first failure after a quiet period at once, the ones after it when the period of
 * that warning ends (a timer of the event loop). A single failure is in the log of
 * warnings within the period, many give one line per period; the failures of the
 * last period before dionaea stops are only in the info lines.
 */

/* seconds between two summaries of the failed downloads */
#define DOWNLOAD_FAILURES_PERIOD LOG_SUMMARY_PERIOD

/* characters of a url or a reason in a log line (log_text.h) */
#define DOWNLOAD_LOG_TEXT_MAX LOG_TEXT_MAX

void download_refused(const char *url);
void download_failed(const char *url, const char *reason);

/* the timer of the summary fired */
void download_failures_due(void);

/* tests: the clock (microseconds, default g_get_monotonic_time) and the timer of the
 * summary (call download_failures_due() after that many seconds, default a timer of
 * the event loop; false: no timer was armed); NULL: the defaults.
 * download_failures_reset() forgets the failures. */
struct download_failures_hooks
{
	gint64 (*clock)(void);
	bool (*schedule)(double after);
};
void download_failures_set_hooks(const struct download_failures_hooks *hooks);
void download_failures_reset(void);

#endif
