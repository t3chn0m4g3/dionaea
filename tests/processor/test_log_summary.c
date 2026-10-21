/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * At most one warning a minute for a message that can come once per connection
 * (src/log_summary.c). The first event after a quiet minute is a warning at once,
 * the events after it are one warning when the minute of that warning ends; the
 * warning names how many events there were and the text of the last one, in the log
 * domain of the file of the summary. Events from several threads are all counted.
 * The clock and the timer of the summary are the hooks of the test; the default
 * timer is armed by an async command of the event loop (async_cmd_new() of the
 * real src/threads.c; the stubs below are what it needs of the rest of dionaea).
 */
#include <glib.h>
#include <stdio.h>
#include <string.h>

#include "dionaea.h"
#include "threads.h"
#include "bistream.h"
#include "incident.h"
#include "connection.h"
#include "log_summary.h"

#define D_LOG_DOMAIN "summarytest"
#include "log.h"

struct dionaea *g_dionaea = NULL;

/* src/threads.c needs these of the rest of dionaea; the test uses none of them */
#define NOT_REACHED(ret, name, ...) ret name(__VA_ARGS__) { g_assert_not_reached(); }
NOT_REACHED(void, bistream_stats_get, struct bistream_stats *stats)
NOT_REACHED(void, incident_report, struct incident *i)
NOT_REACHED(bool, incident_value_con_get, struct incident *e, const char *name, struct connection **con)
NOT_REACHED(int, connection_unref, struct connection *con)
NOT_REACHED(void, incident_free, struct incident *e)

#define SECOND G_USEC_PER_SEC

static gint64 now;
static GMutex logged_lock;
static GPtrArray *warnings;
static GPtrArray *domains;
static GArray *warning_times;
static gboolean armed;
static gint64 fires_at;
static guint scheduled;
static gboolean refuse_arm;

static gint64 test_clock(void)
{
	return now;
}

static bool test_schedule(struct log_summary *s, double after)
{
	(void)s;
	if( refuse_arm )
	{
		refuse_arm = FALSE;
		return false;
	}
	g_assert_cmpfloat(after, >, 0.);
	g_assert_cmpfloat(after, <=, (double)LOG_SUMMARY_PERIOD);
	armed = TRUE;
	fires_at = now + (gint64)(after * SECOND);
	scheduled++;
	return true;
}

static const struct log_summary_hooks hooks = { test_clock, test_schedule };

static struct log_summary summary = LOG_SUMMARY_INIT("test: things went wrong", "thing(s)");

static void log_handler(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data)
{
	(void)data;
	if( level & G_LOG_LEVEL_WARNING )
	{
		g_mutex_lock(&logged_lock);
		g_ptr_array_add(warnings, g_strdup(message));
		g_ptr_array_add(domains, g_strdup(domain));
		g_array_append_val(warning_times, now);
		g_mutex_unlock(&logged_lock);
	}
	else if( level & (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL) )
		g_assert_not_reached();
}

static void setup(void)
{
	now = 1000 * SECOND;
	armed = FALSE;
	refuse_arm = FALSE;
	scheduled = 0;
	warnings = g_ptr_array_new_with_free_func(g_free);
	domains = g_ptr_array_new_with_free_func(g_free);
	warning_times = g_array_new(FALSE, FALSE, sizeof(gint64));
	log_summary_set_hooks(&summary, &hooks);
	log_summary_reset(&summary);
}

static void teardown(void)
{
	log_summary_reset(&summary);
	log_summary_set_hooks(&summary, NULL);
	g_ptr_array_free(warnings, TRUE);
	g_ptr_array_free(domains, TRUE);
	g_array_free(warning_times, TRUE);
}

static void advance(gint64 t)
{
	while( armed && fires_at <= t )
	{
		now = fires_at;
		armed = FALSE;
		log_summary_due(&summary);
	}
	now = t;
}

static guint64 count_of(const char *warning)
{
	guint64 n = 0;
	g_assert_true(g_str_has_prefix(warning, "test: things went wrong: "));
	g_assert_cmpint(sscanf(warning, "test: things went wrong: %" G_GUINT64_FORMAT " thing(s) in the last minute, the last: ", &n), ==, 1);
	return n;
}

static void a_single_event_warns_at_once(void)
{
	setup();
	log_summary_add(&summary, "the first (smbd 192.0.2.1:445)");
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_cmpstr(g_ptr_array_index(warnings, 0), ==,
					"test: things went wrong: 1 thing(s) in the last minute, the last: the first (smbd 192.0.2.1:445)");
	/* in the domain of the file that made the summary (with DEBUG its file and line behind) */
	g_assert_true(g_str_has_prefix(g_ptr_array_index(domains, 0), "summarytest"));
	g_assert_false(armed);
	g_assert_cmpuint(scheduled, ==, 0);
	advance(now + 10 * 60 * SECOND);
	g_assert_cmpuint(warnings->len, ==, 1);
	teardown();
}

static void the_events_of_a_minute_are_one_warning(void)
{
	setup();
	log_summary_add(&summary, "one");
	advance(now + 1 * SECOND);
	log_summary_add(&summary, "two");
	advance(now + 20 * SECOND);
	log_summary_addf(&summary, "%s %d", "three", 3);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_cmpuint(scheduled, ==, 1);
	g_assert_cmpint(fires_at, ==, 1060 * SECOND);
	advance(1059 * SECOND);
	g_assert_cmpuint(warnings->len, ==, 1);
	advance(1060 * SECOND);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpstr(g_ptr_array_index(warnings, 1), ==,
					"test: things went wrong: 2 thing(s) in the last minute, the last: three 3");
	g_assert_false(armed);
	advance(now + 10 * 60 * SECOND);
	g_assert_cmpuint(warnings->len, ==, 2);
	teardown();
}

static void after_a_quiet_minute_an_event_warns_at_once(void)
{
	setup();
	log_summary_add(&summary, "one");
	advance(now + 61 * SECOND);
	log_summary_add(&summary, "two");
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpuint(count_of(g_ptr_array_index(warnings, 1)), ==, 1);
	g_assert_cmpuint(scheduled, ==, 0);
	teardown();
}

static void many_events_give_one_warning_a_minute(void)
{
	setup();
	gint64 start = now;
	guint64 events = 0;
	for( gint64 t = start; t < start + 600 * SECOND; t += 30000 )
	{
		advance(t);
		log_summary_add(&summary, "again");
		events++;
	}
	advance(now + 61 * SECOND);
	g_assert_cmpuint(warnings->len, ==, 11);
	guint64 sum = 0;
	for( guint i = 0; i < warnings->len; i++ )
	{
		sum += count_of(g_ptr_array_index(warnings, i));
		if( i > 0 )
			g_assert_cmpint(g_array_index(warning_times, gint64, i) - g_array_index(warning_times, gint64, i - 1),
							>=, LOG_SUMMARY_PERIOD * SECOND);
	}
	g_assert_cmpuint(sum, ==, events);
	teardown();
}

static void a_timer_that_fires_early_waits_for_the_minute(void)
{
	setup();
	log_summary_add(&summary, "one");
	advance(now + 30 * SECOND);
	log_summary_add(&summary, "two");
	g_assert_true(armed);
	now = fires_at - 10 * SECOND;
	armed = FALSE;
	log_summary_due(&summary);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_true(armed);
	g_assert_cmpint(fires_at, ==, now + 10 * SECOND);
	advance(fires_at);
	g_assert_cmpuint(warnings->len, ==, 2);
	teardown();
}

static void an_unarmed_timer_is_armed_by_the_next_event(void)
{
	setup();
	log_summary_add(&summary, "one");
	advance(now + 1 * SECOND);
	refuse_arm = TRUE;
	log_summary_add(&summary, "two");
	g_assert_false(armed);
	log_summary_add(&summary, "three");
	g_assert_true(armed);
	advance(fires_at);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpstr(g_ptr_array_index(warnings, 1), ==,
					"test: things went wrong: 2 thing(s) in the last minute, the last: three");
	teardown();
}

static void no_text_is_a_dash(void)
{
	setup();
	log_summary_add(&summary, NULL);
	g_assert_cmpstr(g_ptr_array_index(warnings, 0), ==,
					"test: things went wrong: 1 thing(s) in the last minute, the last: -");
	teardown();
}

/* events of several threads at once: every one counted, one warning at once */
#define THREADS 8
#define EVENTS_PER_THREAD 2000

static gpointer add_events(gpointer data)
{
	(void)data;
	for( int i = 0; i < EVENTS_PER_THREAD; i++ )
		log_summary_addf(&summary, "event %d", i);
	return NULL;
}

static void the_events_of_threads_are_all_counted(void)
{
	setup();
	GThread *threads[THREADS];
	for( int i = 0; i < THREADS; i++ )
		threads[i] = g_thread_new("summary", add_events, NULL);
	for( int i = 0; i < THREADS; i++ )
		g_thread_join(threads[i]);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_cmpuint(scheduled, ==, 1);
	advance(fires_at);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpuint(count_of(g_ptr_array_index(warnings, 0)) + count_of(g_ptr_array_index(warnings, 1)), ==,
					 THREADS * EVENTS_PER_THREAD);
	teardown();
}

/* the default timer: an async command of the event loop arms an ev_timer for the end of the minute */
static void trigger(struct ev_loop *loop, struct ev_async *w, int revents)
{
	(void)loop;
	(void)w;
	(void)revents;
}

static void the_default_timer_is_armed_by_the_event_loop(void)
{
	static const struct log_summary_hooks clock_only = { test_clock, NULL };
	setup();
	struct dionaea d = { 0 };
	struct threads t = { 0 };
	d.threads = &t;
	d.loop = ev_loop_new(0);
	t.cmds = g_async_queue_new();
	ev_async_init(&t.trigger, trigger);
	ev_async_start(d.loop, &t.trigger);
	g_dionaea = &d;
	log_summary_set_hooks(&summary, &clock_only);

	log_summary_add(&summary, "one");
	advance(now + 20 * SECOND);
	log_summary_add(&summary, "two");
	log_summary_add(&summary, "three");
	/* one command for the event loop, the timer is not touched before it runs */
	g_assert_cmpint(g_async_queue_length(t.cmds), ==, 1);
	g_assert_false(ev_is_active(&summary.timer));
	struct async_cmd *cmd = g_async_queue_try_pop(t.cmds);
	cmd->function(cmd->data);
	g_free(cmd);
	g_assert_true(ev_is_active(&summary.timer));
	/* due 40 s later: the end of the minute of the first warning */
	g_assert_cmpfloat(summary.timer_after, ==, 40.);
	/* the timer fires: the warning of the other two */
	now += 40 * SECOND;
	ev_invoke(d.loop, &summary.timer, EV_TIMER);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpstr(g_ptr_array_index(warnings, 1), ==,
					"test: things went wrong: 2 thing(s) in the last minute, the last: three");

	/* without an event loop there is no timer: the next event after the minute warns */
	g_dionaea = NULL;
	advance(now + 1 * SECOND);
	log_summary_add(&summary, "four");
	g_assert_cmpint(g_async_queue_length(t.cmds), ==, 0);
	advance(now + 60 * SECOND);
	log_summary_add(&summary, "five");
	g_assert_cmpuint(warnings->len, ==, 3);
	g_assert_cmpstr(g_ptr_array_index(warnings, 2), ==,
					"test: things went wrong: 2 thing(s) in the last minute, the last: five");

	ev_timer_stop(d.loop, &summary.timer);
	ev_async_stop(d.loop, &t.trigger);
	ev_loop_destroy(d.loop);
	g_async_queue_unref(t.cmds);
	teardown();
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_log_set_always_fatal(G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
	g_log_set_default_handler(log_handler, NULL);
	g_test_add_func("/log_summary/single-event-warns", a_single_event_warns_at_once);
	g_test_add_func("/log_summary/one-warning-a-minute", the_events_of_a_minute_are_one_warning);
	g_test_add_func("/log_summary/quiet-minute", after_a_quiet_minute_an_event_warns_at_once);
	g_test_add_func("/log_summary/many-events", many_events_give_one_warning_a_minute);
	g_test_add_func("/log_summary/early-timer", a_timer_that_fires_early_waits_for_the_minute);
	g_test_add_func("/log_summary/unarmed-timer", an_unarmed_timer_is_armed_by_the_next_event);
	g_test_add_func("/log_summary/no-text", no_text_is_a_dash);
	g_test_add_func("/log_summary/threads", the_events_of_threads_are_all_counted);
	g_test_add_func("/log_summary/default-timer", the_default_timer_is_armed_by_the_event_loop);
	return g_test_run();
}
