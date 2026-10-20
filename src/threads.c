/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <glib.h>
#include <ev.h>
#include <unistd.h>


#include "dionaea.h"
#include "threads.h"
#include "bistream.h"
#include "log.h"
#include "incident.h"
#include "connection.h"

#define D_LOG_DOMAIN "thread"


/*
 * Admission to the threadpool, shared by the processor jobs and the
 * continuations of the emulation. A job counts as waiting from its submission
 * until a worker starts it. admission_mutex is a leaf lock apart from the
 * pool's own queue lock, taken inside it by g_thread_pool_push().
 */
static GMutex admission_mutex;
static struct thread_stats admission;

bool thread_submit(struct thread *t)
{
	GError *error = NULL;
	bool accepted = false;

	g_mutex_lock(&admission_mutex);
	if( admission.waiting < THREADS_MAX_WAITING )
	{
		admission.waiting++;
		accepted = g_thread_pool_push(g_dionaea->threads->pool, t, &error);
		if( accepted )
			admission.peak_waiting = MAX(admission.peak_waiting, admission.waiting);
		else
			admission.waiting--;
	}
	if( !accepted )
		admission.refused++;
	g_mutex_unlock(&admission_mutex);

	if( error != NULL )
	{
		g_debug("threadpool refused a job: %s", error->message);
		g_clear_error(&error);
	}
	return accepted;
}

void thread_stats_get(struct thread_stats *stats)
{
	g_mutex_lock(&admission_mutex);
	*stats = admission;
	g_mutex_unlock(&admission_mutex);
}

int threads_pool_size(long cpus)
{
	return (int)CLAMP(cpus, 2, THREADS_MAX_WORKERS);
}

void threadpool_wrapper(gpointer data, gpointer user_data)
{
	struct thread *t = data;

	g_mutex_lock(&admission_mutex);
	g_assert(admission.waiting > 0);
	admission.waiting--;
	g_mutex_unlock(&admission_mutex);

#ifdef DEBUG
	GTimer *timer = g_timer_new();
#endif
	t->function(t->con, t->data);
#ifdef DEBUG
	g_timer_stop(timer);
	g_debug("Thread fn %p con %p data %p took %f ms", t->function, t->con, t->data, g_timer_elapsed(timer, NULL));
	g_timer_destroy(timer);
#endif
	g_free(data);
}

void trigger_cb(struct ev_loop *loop, struct ev_async *w, int revents)
{
	GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
	struct async_cmd *cmd;
	while( (cmd = g_async_queue_try_pop(aq)) != NULL )
	{
		cmd->function(cmd->data);
		g_free(cmd);
	}
	g_async_queue_unref(aq);
}

/*
 * Periodic report of a busy threadpool. It only reports, it never waits:
 * the admission limit refuses jobs instead of suspending the eventloop.
 */
void surveillance_cb(struct ev_loop *loop, struct ev_periodic *w, int revents)
{
	struct thread_stats jobs;
	struct bistream_stats streams;
	thread_stats_get(&jobs);
	bistream_stats_get(&streams);

	if( jobs.waiting > (unsigned)g_thread_pool_get_max_threads(g_dionaea->threads->pool) )
	{
		g_info("Threadpool is busy: %u jobs waiting (limit %u), %zu bytes of stream data in %zu chunks",
			   jobs.waiting, THREADS_MAX_WAITING, streams.bytes, streams.chunks);
	}
}


struct thread *thread_new(struct connection *con, void *data, GFunc function)
{
	struct thread *t = g_malloc0(sizeof(struct thread));
	t->con = con;
	t->data = data;
	t->function = function;
	return t;
}


struct async_cmd *async_cmd_new(async_cmd_cb function, void *data)
{
	struct async_cmd *cmd = g_malloc0(sizeof(struct async_cmd));
	cmd->data = data;
	cmd->function = function;
	return cmd;
}

void async_incident_report(void *data)
{
	struct incident *i = data;
	incident_report(i);
	struct connection *con;
	if( incident_value_con_get(i, "con", &con ) )
		connection_unref(con);
	incident_free(i);
}
