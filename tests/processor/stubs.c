/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 */
#include <string.h>

#include "stubs.h"
#include "incident.h"
#include "util.h"

struct dionaea *g_dionaea;
gint stub_refs, stub_closes, stub_incidents, stub_overload_logs, stub_scan_stopped_logs, stub_connection_warnings,
	stub_give_up_summaries, stub_overload_summaries, stub_trim_thread_logs;
static GMutex summary_lock;
static char *last_summary;

static struct dionaea stub_d;
static struct threads stub_t;

int connection_ref(struct connection *con)
{
	(void)con;
	return g_atomic_int_add(&stub_refs, 1) + 1;
}

int connection_unref(struct connection *con)
{
	(void)con;
	int refs = g_atomic_int_add(&stub_refs, -1) - 1;
	g_assert_cmpint(refs, >=, 0);
	return refs;
}

void connection_close(struct connection *con)
{
	(void)con;
	g_atomic_int_inc(&stub_closes);
}

const char *connection_type_to_string(enum connection_type type)
{
	(void)type;
	return "accept";
}

struct incident *incident_new(const char *origin)
{
	return (struct incident *)g_strdup(origin);
}

void incident_free(struct incident *e)
{
	g_free(e);
}

void incident_report(struct incident *i)
{
	(void)i;
	g_atomic_int_inc(&stub_incidents);
}

bool incident_value_con_get(struct incident *e, const char *name, struct connection **con)
{
	(void)e;
	(void)name;
	(void)con;
	return false;
}

static void trigger(struct ev_loop *loop, struct ev_async *watcher, int events)
{
	(void)loop;
	(void)watcher;
	(void)events;
}

static void summary_seen(gint *counter, const gchar *message)
{
	g_mutex_lock(&summary_lock);
	g_free(last_summary);
	last_summary = g_strdup(message);
	g_mutex_unlock(&summary_lock);
	g_atomic_int_inc(counter);
}

char *stub_last_summary(void)
{
	g_mutex_lock(&summary_lock);
	char *text = g_strdup(last_summary);
	g_mutex_unlock(&summary_lock);
	return text;
}

static void log_handler(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data)
{
	if( (level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_INFO)) && strstr(message, " scan stopped (") != NULL )
	{
		/* the line names the connection, never its data */
		g_assert_null(strstr(message, "AAAA"));
		g_assert_nonnull(strstr(message, "goes on"));
		g_atomic_int_inc((level & G_LOG_LEVEL_WARNING) ? &stub_connection_warnings : &stub_scan_stopped_logs);
		return;
	}
	if( (level & (G_LOG_LEVEL_WARNING | G_LOG_LEVEL_INFO)) && strstr(message, "Stream processing limit reached") != NULL )
	{
		/* the line names the connection, never its data */
		g_assert_null(strstr(message, "AAAA"));
		g_atomic_int_inc((level & G_LOG_LEVEL_WARNING) ? &stub_connection_warnings : &stub_overload_logs);
		return;
	}
	if( (level & G_LOG_LEVEL_WARNING) && g_str_has_prefix(message, "processor: scans stopped at a limit: ") )
	{
		g_assert_null(strstr(message, "AAAA"));
		summary_seen(&stub_give_up_summaries, message);
		return;
	}
	if( (level & G_LOG_LEVEL_WARNING) && g_str_has_prefix(message, "processor: connections closed at a limit: ") )
	{
		g_assert_null(strstr(message, "AAAA"));
		summary_seen(&stub_overload_summaries, message);
		return;
	}
	if( level & (G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO) )
		return;
	if( (level & G_LOG_LEVEL_WARNING) && strstr(message, "no thread for the trailing trim") != NULL )
	{
		g_atomic_int_inc(&stub_trim_thread_logs);
		return;
	}
	g_log_default_handler(domain, level, message, data);
}

/* the clock of the summaries stands still, their timer is never due */
static gint64 stub_clock(void)
{
	return 1000 * G_USEC_PER_SEC;
}

static bool stub_schedule(struct log_summary *s, double after)
{
	(void)s;
	(void)after;
	return true;
}

static const struct log_summary_hooks stub_summary_hooks = { stub_clock, stub_schedule };

void stub_summaries_reset(void)
{
	struct log_summary *summaries[] = { processor_give_up_summary(), processors_overload_summary() };
	for( size_t i = 0; i < G_N_ELEMENTS(summaries); i++ )
	{
		log_summary_set_hooks(summaries[i], &stub_summary_hooks);
		log_summary_reset(summaries[i]);
	}
	g_atomic_int_set(&stub_give_up_summaries, 0);
	g_atomic_int_set(&stub_overload_summaries, 0);
	g_atomic_int_set(&stub_connection_warnings, 0);
}

void stub_quiet_logs(void)
{
	/* an expected overload is a warning, not a failure of the test */
	g_log_set_always_fatal(G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
	g_log_set_default_handler(log_handler, NULL);
}

void stub_dionaea_init(void)
{
	g_dionaea = &stub_d;
	stub_d.threads = &stub_t;
	stub_d.loop = ev_loop_new(0);
	stub_t.cmds = g_async_queue_new();
	ev_async_init(&stub_t.trigger, trigger);
	ev_async_start(stub_d.loop, &stub_t.trigger);
	stub_summaries_reset();
}

void stub_dionaea_exit(void)
{
	ev_async_stop(stub_d.loop, &stub_t.trigger);
	ev_loop_destroy(stub_d.loop);
	g_async_queue_unref(stub_t.cmds);
}

void stub_pool_new(int workers)
{
	g_dionaea->threads->pool = g_thread_pool_new(threadpool_wrapper, NULL, workers, TRUE, NULL);
}

void stub_run_async(void)
{
	struct async_cmd *cmd;
	while( (cmd = g_async_queue_try_pop(g_dionaea->threads->cmds)) != NULL )
	{
		cmd->function(cmd->data);
		g_free(cmd);
	}
}

void stub_drain(void)
{
	g_thread_pool_free(g_dionaea->threads->pool, FALSE, TRUE);
	g_dionaea->threads->pool = NULL;
	stub_run_async();
	g_assert_cmpint(g_atomic_int_get(&stub_refs), ==, 0);
	struct thread_stats jobs;
	thread_stats_get(&jobs);
	g_assert_cmpuint(jobs.waiting, ==, 0);
}

void stub_instance(struct connection *con, struct processor_data **pd, struct processor *p)
{
	memset(con, 0, sizeof(*con));
	con->state = connection_state_established;
	con->processor_data = processor_data_new();
	*pd = processor_data_new();
	(*pd)->processor = p;
	con->processor_data->filters = g_list_append(NULL, *pd);
}

void stub_assert_budget_empty(void)
{
	struct bistream_stats stats;
	bistream_stats_get(&stats);
	g_assert_cmpuint(stats.bytes, ==, 0);
	g_assert_cmpuint(stats.chunks, ==, 0);
}

void stub_dispose(struct connection *con, struct processor_data *pd)
{
	g_list_free(con->processor_data->filters);
	processor_data_free(pd);
	processor_data_free(con->processor_data);
	con->processor_data = NULL;
	stub_assert_budget_empty();
}

void stub_gate_reset(struct stub_gate *gate)
{
	g_mutex_lock(&gate->mutex);
	gate->entered = 0;
	gate->released = false;
	g_mutex_unlock(&gate->mutex);
}

void stub_gate_wait(struct stub_gate *gate)
{
	g_mutex_lock(&gate->mutex);
	gate->entered++;
	g_cond_broadcast(&gate->cond);
	while( !gate->released )
		g_cond_wait(&gate->cond, &gate->mutex);
	g_mutex_unlock(&gate->mutex);
}

void stub_gate_await(struct stub_gate *gate, int entered)
{
	gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	g_mutex_lock(&gate->mutex);
	while( gate->entered < entered )
		g_assert_true(g_cond_wait_until(&gate->cond, &gate->mutex, deadline));
	g_mutex_unlock(&gate->mutex);
}

void stub_gate_release(struct stub_gate *gate)
{
	g_mutex_lock(&gate->mutex);
	gate->released = true;
	g_cond_broadcast(&gate->cond);
	g_mutex_unlock(&gate->mutex);
}
