/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * The log lines of downloads that do not complete (src/download_log.c). A target
 * the download target filter refused is one info line and nothing else. A failed
 * download is one info line with its reason; at most one warning a minute sums the
 * failures up (their count, the last url and its reason), so a single failure is in
 * dionaea-errors.log within a minute and many give one line a minute. The url and
 * the reason come from the client: in every line a byte outside 0x20..0x7e is a
 * '?', and each is cut at 256 characters with "..." behind. The clock and
 * the timer of the summary are the hooks of the test.
 */
#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "dionaea.h"
#include "download_log.h"

struct dionaea *g_dionaea = NULL;

#define SECOND G_USEC_PER_SEC

static gint64 now;
static GPtrArray *infos;
static GPtrArray *warnings;
/* the clock time of every warning */
static GArray *warning_times;
/* the timer of the summary: armed, and when it fires (clock time) */
static gboolean armed;
static gint64 fires_at;
static guint scheduled;

static gint64 test_clock(void)
{
	return now;
}

/* the next schedule arms no timer (no event loop) */
static gboolean refuse_arm;

static bool test_schedule(double after)
{
	if( refuse_arm )
	{
		refuse_arm = FALSE;
		return false;
	}
	g_assert_cmpfloat(after, >, 0.);
	g_assert_cmpfloat(after, <=, (double)DOWNLOAD_FAILURES_PERIOD);
	armed = TRUE;
	fires_at = now + (gint64)(after * SECOND);
	scheduled++;
	return true;
}

static const struct download_failures_hooks hooks = { test_clock, test_schedule };

static void log_handler(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data)
{
	(void)domain;
	(void)data;
	if( level & G_LOG_LEVEL_INFO )
		g_ptr_array_add(infos, g_strdup(message));
	else if( level & G_LOG_LEVEL_WARNING )
	{
		g_ptr_array_add(warnings, g_strdup(message));
		g_array_append_val(warning_times, now);
	}
	else if( level & (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL) )
		g_assert_not_reached();
}

static void setup(void)
{
	now = 1000 * SECOND;
	armed = FALSE;
	scheduled = 0;
	infos = g_ptr_array_new_with_free_func(g_free);
	warnings = g_ptr_array_new_with_free_func(g_free);
	warning_times = g_array_new(FALSE, FALSE, sizeof(gint64));
	download_failures_set_hooks(&hooks);
	download_failures_reset();
}

static void teardown(void)
{
	download_failures_reset();
	download_failures_set_hooks(NULL);
	g_ptr_array_free(infos, TRUE);
	g_ptr_array_free(warnings, TRUE);
	g_array_free(warning_times, TRUE);
}

/* the clock goes on to t; the timer fires on the way when it is due */
static void advance(gint64 t)
{
	while( armed && fires_at <= t )
	{
		now = fires_at;
		armed = FALSE;
		download_failures_due();
	}
	now = t;
}

static guint64 summary_count(const char *warning)
{
	guint64 n = 0;
	g_assert_true(g_str_has_prefix(warning, "downloads: "));
	g_assert_cmpint(sscanf(warning, "downloads: %" G_GUINT64_FORMAT " failed in the last minute, the last: ", &n), ==, 1);
	return n;
}

static void a_refused_target_is_one_info_line(void)
{
	setup();
	download_refused("http://127.0.0.1:81/x");
	g_assert_cmpuint(infos->len, ==, 1);
	g_assert_cmpstr(g_ptr_array_index(infos, 0), ==, "download target refused by the filter: http://127.0.0.1:81/x");
	g_assert_cmpuint(warnings->len, ==, 0);
	g_assert_cmpuint(scheduled, ==, 0);
	advance(now + 10 * 60 * SECOND);
	g_assert_cmpuint(warnings->len, ==, 0);
	teardown();
}

static void a_single_failure_is_a_warning_at_once(void)
{
	setup();
	download_failed("http://198.51.100.7/a.exe", "Connection refused");
	g_assert_cmpuint(infos->len, ==, 1);
	g_assert_cmpstr(g_ptr_array_index(infos, 0), ==, "download failed: http://198.51.100.7/a.exe (Connection refused)");
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_cmpstr(g_ptr_array_index(warnings, 0), ==,
					"downloads: 1 failed in the last minute, the last: http://198.51.100.7/a.exe (Connection refused)");
	g_assert_false(armed);
	teardown();
}

static void the_failures_of_a_minute_are_one_summary(void)
{
	setup();
	download_failed("http://198.51.100.7/1", "one");
	g_assert_cmpuint(warnings->len, ==, 1);
	advance(now + 1 * SECOND);
	download_failed("http://198.51.100.7/2", "two");
	advance(now + 20 * SECOND);
	download_failed("http://198.51.100.7/3", "three");
	download_refused("http://10.0.0.1/r");
	advance(now + 20 * SECOND);
	download_failed("http://198.51.100.7/4", "four");
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_cmpuint(infos->len, ==, 5);
	/* armed once, for the end of the minute of the first warning */
	g_assert_cmpuint(scheduled, ==, 1);
	g_assert_cmpint(fires_at, ==, 1060 * SECOND);
	advance(1059 * SECOND);
	g_assert_cmpuint(warnings->len, ==, 1);
	advance(1060 * SECOND);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpstr(g_ptr_array_index(warnings, 1), ==,
					"downloads: 3 failed in the last minute, the last: http://198.51.100.7/4 (four)");
	/* nothing more: the timer stays off */
	g_assert_false(armed);
	advance(now + 10 * 60 * SECOND);
	g_assert_cmpuint(warnings->len, ==, 2);
	teardown();
}

static void after_a_quiet_minute_a_failure_warns_at_once(void)
{
	setup();
	download_failed("http://198.51.100.7/1", "one");
	advance(now + 61 * SECOND);
	download_failed("http://198.51.100.7/2", "two");
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpuint(summary_count(g_ptr_array_index(warnings, 1)), ==, 1);
	teardown();
}

static void many_failures_give_one_warning_a_minute(void)
{
	setup();
	gint64 start = now;
	guint64 failures = 0;
	/* 20,000 failures over 10 minutes, one every 30 ms */
	for( gint64 t = start; t < start + 600 * SECOND; t += 30000 )
	{
		advance(t);
		download_failed("http://198.51.100.7/x", "Connection refused");
		failures++;
	}
	/* the minute after the last failure: the timer sums up the rest */
	advance(now + 61 * SECOND);
	g_assert_cmpuint(failures, ==, 20000);
	/* the first at once, then one at the end of every minute */
	g_assert_cmpuint(warnings->len, ==, 11);
	guint64 sum = 0;
	for( guint i = 0; i < warnings->len; i++ )
	{
		sum += summary_count(g_ptr_array_index(warnings, i));
		/* a minute between two warnings */
		if( i > 0 )
			g_assert_cmpint(g_array_index(warning_times, gint64, i) - g_array_index(warning_times, gint64, i - 1),
							>=, DOWNLOAD_FAILURES_PERIOD * SECOND);
	}
	g_assert_cmpuint(sum, ==, failures);
	g_assert_cmpuint(infos->len, ==, failures);
	teardown();
}

static void a_timer_that_fires_early_waits_for_the_minute(void)
{
	setup();
	download_failed("http://198.51.100.7/1", "one");
	advance(now + 30 * SECOND);
	download_failed("http://198.51.100.7/2", "two");
	g_assert_true(armed);
	/* the timer fires 10 s early (the loop's clock): no warning, armed again for the rest */
	now = fires_at - 10 * SECOND;
	armed = FALSE;
	download_failures_due();
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_true(armed);
	g_assert_cmpint(fires_at, ==, now + 10 * SECOND);
	advance(fires_at);
	g_assert_cmpuint(warnings->len, ==, 2);
	teardown();
}

static void no_url_and_no_reason_are_named_so(void)
{
	setup();
	download_failed(NULL, NULL);
	download_refused(NULL);
	g_assert_cmpstr(g_ptr_array_index(infos, 0), ==, "download failed: (no url) (no reason)");
	g_assert_cmpstr(g_ptr_array_index(infos, 1), ==, "download target refused by the filter: (no url)");
	g_assert_cmpstr(g_ptr_array_index(warnings, 0), ==,
					"downloads: 1 failed in the last minute, the last: (no url) (no reason)");
	teardown();
}

/* a timer that could not be armed is armed by the next failure */
static void an_unarmed_timer_is_armed_by_the_next_failure(void)
{
	setup();
	download_failed("http://198.51.100.7/1", "one");
	advance(now + 1 * SECOND);
	refuse_arm = TRUE;
	download_failed("http://198.51.100.7/2", "two");
	g_assert_false(armed);
	download_failed("http://198.51.100.7/3", "three");
	g_assert_true(armed);
	advance(fires_at);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpstr(g_ptr_array_index(warnings, 1), ==,
					"downloads: 2 failed in the last minute, the last: http://198.51.100.7/3 (three)");
	teardown();
}

/* a url with a line break and the escape sequences of a terminal */
static void the_text_of_the_client_stays_on_its_line(void)
{
	setup();
	download_failed("http://198.51.100.7/a\nb \x1b[31mred\x1b[0m", "no\r\nreply\x7f");
	download_refused("http://127.0.0.1/\nb \x1b]0;title\x07");
	g_assert_cmpstr(g_ptr_array_index(infos, 0), ==,
					"download failed: http://198.51.100.7/a?b ?[31mred?[0m (no??reply?)");
	g_assert_cmpstr(g_ptr_array_index(infos, 1), ==,
					"download target refused by the filter: http://127.0.0.1/?b ?]0;title?");
	g_assert_cmpstr(g_ptr_array_index(warnings, 0), ==,
					"downloads: 1 failed in the last minute, the last: "
					"http://198.51.100.7/a?b ?[31mred?[0m (no??reply?)");
	/* the summary later on keeps the cleaned text of the last failure */
	advance(now + 1 * SECOND);
	download_failed("http://198.51.100.7/\xc3\xa4\x01", "\xff");
	advance(now + 60 * SECOND);
	g_assert_cmpstr(g_ptr_array_index(warnings, 1), ==,
					"downloads: 1 failed in the last minute, the last: http://198.51.100.7/??? (?)");
	for( guint i = 0; i < infos->len; i++ )
		for( const char *c = g_ptr_array_index(infos, i); *c != '\0'; c++ )
			g_assert_true(*c >= 0x20 && *c <= 0x7e);
	teardown();
}

/* a url and a reason of any length: 256 characters and "..." */
static void a_long_text_is_cut(void)
{
	setup();
	GString *url = g_string_new("http://198.51.100.7/");
	while( url->len < 5000 )
		g_string_append_c(url, 'a');
	char *reason = g_strnfill(300, 'r');
	download_failed(url->str, reason);
	char *cut_url = g_strdup_printf("%.256s...", url->str);
	char *cut_reason = g_strdup_printf("%.256s...", reason);
	char *info = g_strdup_printf("download failed: %s (%s)", cut_url, cut_reason);
	char *warning = g_strdup_printf("downloads: 1 failed in the last minute, the last: %s (%s)", cut_url, cut_reason);
	g_assert_cmpstr(g_ptr_array_index(infos, 0), ==, info);
	g_assert_cmpstr(g_ptr_array_index(warnings, 0), ==, warning);
	/* exactly 256 characters stay as they are */
	char *exact = g_strnfill(256, 'b');
	download_refused(exact);
	char *refused = g_strdup_printf("download target refused by the filter: %s", exact);
	g_assert_cmpstr(g_ptr_array_index(infos, 1), ==, refused);
	g_free(refused);
	g_free(exact);
	g_free(warning);
	g_free(info);
	g_free(cut_reason);
	g_free(cut_url);
	g_free(reason);
	g_string_free(url, TRUE);
	teardown();
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	/* the warnings are what the test looks at, not fatal */
	g_log_set_always_fatal(G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
	g_log_set_default_handler(log_handler, NULL);
	g_test_add_func("/download_log/refused-is-info", a_refused_target_is_one_info_line);
	g_test_add_func("/download_log/single-failure-warns", a_single_failure_is_a_warning_at_once);
	g_test_add_func("/download_log/one-summary-a-minute", the_failures_of_a_minute_are_one_summary);
	g_test_add_func("/download_log/quiet-minute", after_a_quiet_minute_a_failure_warns_at_once);
	g_test_add_func("/download_log/many-failures", many_failures_give_one_warning_a_minute);
	g_test_add_func("/download_log/early-timer", a_timer_that_fires_early_waits_for_the_minute);
	g_test_add_func("/download_log/no-url", no_url_and_no_reason_are_named_so);
	g_test_add_func("/download_log/unarmed-timer", an_unarmed_timer_is_armed_by_the_next_failure);
	g_test_add_func("/download_log/client-text-on-its-line", the_text_of_the_client_stays_on_its_line);
	g_test_add_func("/download_log/long-text-is-cut", a_long_text_is_cut);
	return g_test_run();
}
