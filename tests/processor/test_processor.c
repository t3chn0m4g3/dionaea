/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * Jobs of the threaded processors and the threadpool admission
 * (src/processor.c, src/threads.c): one job per instance, the queue limit,
 * enqueue failures, overload closes, processor_done and teardown.
 */
#include <arpa/inet.h>
#include <string.h>

#include "stubs.h"

#define PROCESSOR_TEST_PENDING_IN (1U << bistream_in)

static gint push_failures;      /* > 0: g_thread_pool_push refuses that many jobs */
static gint calls;
static struct stub_gate gate;

static gboolean refuse_push(GError **error)
{
	if( g_atomic_int_get(&push_failures) <= 0 )
		return FALSE;
	g_atomic_int_add(&push_failures, -1);
	g_set_error_literal(error, G_THREAD_ERROR, G_THREAD_ERROR_AGAIN, "injected refusal");
	return TRUE;
}

gboolean __real_g_thread_pool_push(GThreadPool *pool, gpointer data, GError **error);
gboolean __wrap_g_thread_pool_push(GThreadPool *pool, gpointer data, GError **error)
{
	if( refuse_push(error) )
		return FALSE;
	return __real_g_thread_pool_push(pool, data, error);
}

static void block_job(gpointer con, gpointer data)
{
	(void)con;
	(void)data;
	stub_gate_wait(&gate);
}

static void noop_job(gpointer con, gpointer data)
{
	(void)con;
	(void)data;
}

/* a consumer that waits at the gate in its first call, then reads and drops everything */
static void consume(struct connection *con, struct processor_data *pd)
{
	(void)con;
	if( g_atomic_int_add(&calls, 1) == 0 )
		stub_gate_wait(&gate);
	bistream_discard_before(pd->bistream, bistream_in, UINT64_MAX);
	bistream_discard_before(pd->bistream, bistream_out, UINT64_MAX);
}

/* a consumer that keeps everything (as one that needs the whole history) */
static void keep(struct connection *con, struct processor_data *pd)
{
	(void)con;
	(void)pd;
	g_atomic_int_inc(&calls);
}

static void finish(struct connection *con, struct processor_data *pd)
{
	(void)con;
	g_atomic_int_inc(&calls);
	stub_gate_wait(&gate);
	g_atomic_int_set(&pd->state, processor_done);
}

/* a consumer that waits at the gate in its first call, then reads its whole stream */
static gint read_size;
static void read_all(struct connection *con, struct processor_data *pd)
{
	(void)con;
	if( g_atomic_int_add(&calls, 1) == 0 )
		stub_gate_wait(&gate);
	void *data = NULL;
	g_atomic_int_set(&read_size, bistream_get_stream(pd->bistream, bistream_in, 0, -1, &data));
	g_free(data);
}

static struct processor in_only = { .name = "in", .thread_io_in = consume };
static struct processor both = { .name = "both", .thread_io_in = consume, .thread_io_out = consume };
static struct processor keeper = { .name = "keeper", .thread_io_in = keep };
static struct processor finisher = { .name = "finisher", .thread_io_in = finish };
/* processors that give up at a limit (as the emu) */
static struct processor giver = { .name = "giver", .thread_io_in = consume, .give_up_on_limit = true };
static struct processor hoarder = { .name = "hoarder", .thread_io_in = keep, .give_up_on_limit = true };
static struct processor reader = { .name = "reader", .thread_io_in = read_all };

static void reset(void)
{
	stub_gate_reset(&gate);
	g_atomic_int_set(&calls, 0);
	g_atomic_int_set(&stub_closes, 0);
	g_atomic_int_set(&stub_overload_logs, 0);
	g_atomic_int_set(&stub_scan_stopped_logs, 0);
	stub_summaries_reset();
	g_atomic_int_set(&read_size, 0);
}

static unsigned gave_up_count(void)
{
	struct processor_stats stats;
	processor_stats_get(&stats);
	return stats.gave_up;
}

/*
 * pd gave up: done, nothing kept, the connection open; one info line, and the summary
 * warning of the give-ups (the first one since reset())
 */
static void assert_gave_up(struct connection *con, struct processor_data *pd)
{
	g_assert_cmpint(g_atomic_int_get(&pd->state), ==, processor_done);
	g_assert_cmpint(g_atomic_int_get(&pd->gave_up), ==, 1);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpuint(pd->pending, ==, 0);
	g_assert_cmpint(g_atomic_int_get(&con->processor_data->closing), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_scan_stopped_logs), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_connection_warnings), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_give_up_summaries), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_logs), ==, 0);
}

static struct thread_stats jobs(void)
{
	struct thread_stats stats;
	thread_stats_get(&stats);
	return stats;
}

static void await_idle(struct processor_data *pd)
{
	for( int i = 0; i < 10000; i++ )
	{
		g_mutex_lock(&pd->queued.mutex);
		bool idle = pd->queued.refs == 0;
		g_mutex_unlock(&pd->queued.mutex);
		if( idle )
			return;
		g_usleep(1000);
	}
	g_assert_not_reached();
}

static void fill_queue(unsigned count)
{
	for( unsigned i = 0; i < count; i++ )
		g_assert_true(thread_submit(thread_new(NULL, NULL, noop_job)));
}

static void pool_size(void)
{
	g_assert_cmpint(threads_pool_size(-1), ==, 2);
	g_assert_cmpint(threads_pool_size(1), ==, 2);
	g_assert_cmpint(threads_pool_size(3), ==, 3);
	g_assert_cmpint(threads_pool_size(4), ==, THREADS_MAX_WORKERS);
	g_assert_cmpint(threads_pool_size(64), ==, THREADS_MAX_WORKERS);
}

/* at most THREADS_MAX_WAITING jobs wait, a refused job is given back */
static void admission(void)
{
	reset();
	stub_pool_new(1);
	struct thread_stats before = jobs();
	g_assert_true(thread_submit(thread_new(NULL, NULL, block_job)));
	stub_gate_await(&gate, 1);

	g_atomic_int_set(&push_failures, 1);
	struct thread *job = thread_new(NULL, NULL, noop_job);
	g_assert_false(thread_submit(job));
	g_free(job);
	g_assert_cmpuint(jobs().waiting, ==, 0);

	fill_queue(THREADS_MAX_WAITING - 1);
	g_assert_true(thread_submit(thread_new(NULL, NULL, noop_job)));    /* at */
	job = thread_new(NULL, NULL, noop_job);
	g_assert_false(thread_submit(job));                                 /* over */
	g_free(job);
	struct thread_stats now = jobs();
	g_assert_cmpuint(now.waiting, ==, THREADS_MAX_WAITING);
	g_assert_cmpuint(now.peak_waiting, ==, THREADS_MAX_WAITING);
	g_assert_cmpuint(now.refused, ==, before.refused + 2);

	stub_gate_release(&gate);
	stub_drain();
	stub_pool_new(1);
	g_assert_true(thread_submit(thread_new(NULL, NULL, noop_job)));
	stub_drain();
}

/* the surveillance only reports a crowded pool, it does not wait for it */
static void surveillance(void)
{
	reset();
	stub_pool_new(1);
	g_assert_true(thread_submit(thread_new(NULL, NULL, block_job)));
	stub_gate_await(&gate, 1);
	fill_queue(THREADS_MAX_WAITING);
	gint64 start = g_get_monotonic_time();
	surveillance_cb(g_dionaea->loop, NULL, 0);
	g_assert_cmpint(g_get_monotonic_time() - start, <, G_TIME_SPAN_SECOND / 2);
	stub_gate_release(&gate);
	stub_drain();
}

/* one job per instance: new data while it runs only sets pending flags */
static void one_job(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &both);
	reset();
	stub_pool_new(2);
	char byte = 'A';
	processor_io_single(&con, pd, &byte, 1, bistream_in);
	stub_gate_await(&gate, 1);
	/* the eventloop goes on while the job runs and holds pd->mutex */
	for( int i = 0; i < 500; i++ )
		processor_io_single(&con, pd, &byte, 1, i % 2);
	g_mutex_lock(&pd->queued.mutex);
	g_assert_cmpint(pd->queued.refs, ==, 1);
	g_assert_cmpuint(pd->pending, ==, 3);
	g_mutex_unlock(&pd->queued.mutex);
	g_assert_cmpuint(jobs().waiting, ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_refs), ==, 1);
	stub_gate_release(&gate);
	await_idle(pd);
	stub_drain();
	/* both directions in one more job */
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 3);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpint(g_atomic_int_get(&con.processor_data->closing), ==, 0);
	stub_dispose(&con, pd);

	/* an instance with a waiting job does not queue a second one */
	stub_instance(&con, &pd, &in_only);
	reset();
	g_atomic_int_set(&calls, 1);
	stub_pool_new(1);
	g_assert_true(thread_submit(thread_new(NULL, NULL, block_job)));
	stub_gate_await(&gate, 1);
	for( int i = 0; i < 100; i++ )
		processor_io_single(&con, pd, &byte, 1, bistream_in);
	g_assert_cmpuint(jobs().waiting, ==, 1);
	stub_gate_release(&gate);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 2);
	stub_dispose(&con, pd);
}

/* a direction without a consumer is not kept */
static void no_consumer(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &in_only);
	reset();
	stub_pool_new(1);
	char data[100] = { 0 };
	processor_io_single(&con, pd, data, sizeof(data), bistream_out);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpint(pd->queued.refs, ==, 0);
	g_assert_cmpuint(jobs().waiting, ==, 0);
	stub_drain();
	stub_dispose(&con, pd);
}

/* processor_done: nothing new is kept, the data goes once the job ends */
static void done(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &finisher);
	reset();
	stub_pool_new(1);
	char byte = 'A';
	processor_io_single(&con, pd, &byte, 1, bistream_in);
	stub_gate_await(&gate, 1);
	for( int i = 0; i < 100; i++ )
		processor_io_single(&con, pd, &byte, 1, bistream_in);
	g_assert_cmpuint(bistream_end(pd->bistream, bistream_in), ==, 101);
	g_assert_cmpuint(pd->bistream->bytes, >=, 101);
	stub_gate_release(&gate);
	await_idle(pd);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&pd->state), ==, processor_done);
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 1);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_pool_new(1);
	processor_io_single(&con, pd, &byte, 1, bistream_in);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpint(pd->queued.refs, ==, 0);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	stub_dispose(&con, pd);
}

/* the stream limit closes the connection once, from the eventloop */
static void stream_limit(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &in_only);
	reset();
	stub_pool_new(1);
	char *large = g_malloc(BISTREAM_MAX_BYTES);
	memset(large, 'A', BISTREAM_MAX_BYTES);
	processor_io_single(&con, pd, large, 1, bistream_in);
	stub_gate_await(&gate, 1);
	processor_io_single(&con, pd, large, BISTREAM_MAX_BYTES - 1, bistream_in);  /* at */
	g_assert_cmpint(g_atomic_int_get(&con.processor_data->closing), ==, 0);
	processor_io_single(&con, pd, large, 1, bistream_in);                       /* over */
	g_assert_cmpint(g_atomic_int_get(&con.processor_data->closing), ==, 1);
	/* given back at once, while the job still runs; nothing more is kept */
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_assert_budget_empty();
	processor_io_single(&con, pd, large, 1, bistream_in);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	for( int i = 0; i < 10; i++ )
		processors_overload(&con, "test");
	g_assert_cmpint(g_async_queue_length(g_dionaea->threads->cmds), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_logs), ==, 1);
	/* an info line of the connection, the summary warning of the overloads */
	g_assert_cmpint(g_atomic_int_get(&stub_connection_warnings), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_summaries), ==, 1);
	/* nothing is closed by the worker */
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	stub_gate_release(&gate);
	await_idle(pd);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 1);
	g_free(large);
	stub_dispose(&con, pd);
}

/* a refused job: the reservation, the job and the reference are given back */
static void enqueue_failure(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &in_only);
	reset();
	stub_pool_new(1);
	char data[64];
	memset(data, 'A', sizeof(data));
	g_atomic_int_set(&push_failures, 1);
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	g_assert_cmpint(pd->queued.refs, ==, 0);
	g_assert_cmpuint(pd->pending, ==, 0);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_assert_budget_empty();
	g_assert_cmpint(g_atomic_int_get(&con.processor_data->closing), ==, 1);
	/* only the reference of the close command is left */
	g_assert_cmpint(g_atomic_int_get(&stub_refs), ==, 1);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 0);
	stub_dispose(&con, pd);
}

/* a full queue closes the connection that wanted a job */
static void queue_full(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &in_only);
	reset();
	stub_pool_new(1);
	g_assert_true(thread_submit(thread_new(NULL, NULL, block_job)));
	stub_gate_await(&gate, 1);
	fill_queue(THREADS_MAX_WAITING);
	char data[64];
	memset(data, 'A', sizeof(data));
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	g_assert_cmpint(g_atomic_int_get(&con.processor_data->closing), ==, 1);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpint(pd->queued.refs, ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_logs), ==, 1);
	/* an info line of the connection, the summary warning of the overloads */
	g_assert_cmpint(g_atomic_int_get(&stub_connection_warnings), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_summaries), ==, 1);
	stub_gate_release(&gate);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 1);
	stub_dispose(&con, pd);
}

/*
 * the job of an instance can not queue its next run (queue full, or the pool
 * refuses it): it goes on in the same worker, the connection stays open
 */
static void resubmit_failure(void)
{
	for( int refused = 0; refused < 2; refused++ )
	{
		struct connection con;
		struct processor_data *pd;
		stub_instance(&con, &pd, &in_only);
		reset();
		stub_pool_new(1);
		char data[64];
		memset(data, 'A', sizeof(data));
		processor_io_single(&con, pd, data, sizeof(data), bistream_in);
		stub_gate_await(&gate, 1);
		if( refused )
			g_atomic_int_set(&push_failures, 1);
		else
			fill_queue(THREADS_MAX_WAITING);
		processor_io_single(&con, pd, data, sizeof(data), bistream_in);
		g_assert_cmpuint(pd->pending, ==, PROCESSOR_TEST_PENDING_IN);
		stub_gate_release(&gate);
		await_idle(pd);
		/* run twice in one job: the data of both calls is read */
		g_assert_cmpint(g_atomic_int_get(&calls), ==, 2);
		g_assert_cmpuint(pd->bistream->bytes, ==, 0);
		g_assert_cmpint(g_atomic_int_get(&con.processor_data->closing), ==, 0);
		stub_drain();
		g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
		g_assert_cmpint(g_atomic_int_get(&stub_overload_logs), ==, 0);
		g_atomic_int_set(&push_failures, 0);
		stub_dispose(&con, pd);
	}
}

/* the eventloop does not close a connection that is closed already */
static void close_guard(void)
{
	static const enum connection_state closed[] = { connection_state_close, connection_state_shutdown };
	for( unsigned i = 0; i < G_N_ELEMENTS(closed); i++ )
	{
		struct connection con;
		struct processor_data *pd;
		stub_instance(&con, &pd, &in_only);
		reset();
		stub_pool_new(1);
		con.state = closed[i];
		processors_overload(&con, "test");
		stub_drain();
		g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
		stub_dispose(&con, pd);
	}
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &in_only);
	reset();
	stub_pool_new(1);
	connection_flag_set(&con, connection_busy_close);
	processors_overload(&con, "test");
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	stub_dispose(&con, pd);
}

/* the connection goes away while its job runs */
static void teardown(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &in_only);
	reset();
	stub_pool_new(1);
	char data[64];
	memset(data, 'A', sizeof(data));
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	stub_gate_await(&gate, 1);
	/* the job holds a reference: connection_free_cb would wait for it */
	g_assert_cmpint(g_atomic_int_get(&stub_refs), ==, 1);
	processors_overload(&con, "test");
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_gate_release(&gate);
	await_idle(pd);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 1);
	/* processors_clear() of connection_free_cb: nothing reserved is left */
	stub_dispose(&con, pd);
}

/* an instance with data and a job that waits behind a busy worker */
static void waiting_job(struct connection *con, struct processor_data **pd, char *data, size_t size)
{
	stub_instance(con, pd, &in_only);
	reset();
	g_atomic_int_set(&calls, 1);    /* consume() does not wait at the gate */
	stub_pool_new(1);
	g_assert_true(thread_submit(thread_new(NULL, NULL, block_job)));
	stub_gate_await(&gate, 1);
	memset(data, 'A', size);
	processor_io_single(con, *pd, data, (int)size, bistream_in);
	g_assert_cmpuint(jobs().waiting, ==, 1);
	g_assert_cmpuint((*pd)->bistream->bytes, ==, size);
}

/* an overload gives the stream data back at once, not when the waiting job runs */
static void overload_releases(void)
{
	struct connection con;
	struct processor_data *pd;
	char data[4096];
	waiting_job(&con, &pd, data, sizeof(data));
	processors_overload(&con, "test");
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpuint(pd->pending, ==, 0);
	stub_assert_budget_empty();
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_gate_release(&gate);
	stub_drain();
	/* the job ended without work */
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_logs), ==, 1);
	/* an info line of the connection, the summary warning of the overloads */
	g_assert_cmpint(g_atomic_int_get(&stub_connection_warnings), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_summaries), ==, 1);
	stub_dispose(&con, pd);
}

/*
 * the connection ends (connection_free) while its job waits: the job still
 * reads what arrived before the end, then the data is given back; without a
 * job it is given back at once
 */
static void stop_releases(void)
{
	struct connection con;
	struct processor_data *pd;
	char data[4096];
	memset(data, 'A', sizeof(data));
	stub_instance(&con, &pd, &keeper);
	reset();
	stub_pool_new(1);
	g_assert_true(thread_submit(thread_new(NULL, NULL, block_job)));
	stub_gate_await(&gate, 1);
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	g_assert_cmpuint(jobs().waiting, ==, 1);
	processors_stop(&con);
	g_assert_cmpuint(pd->bistream->bytes, ==, sizeof(data));
	g_assert_cmpint(g_atomic_int_get(&con.processor_data->closing), ==, 0);
	/* nothing arrives after the end */
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	g_assert_cmpuint(pd->bistream->bytes, ==, sizeof(data));
	stub_gate_release(&gate);
	await_idle(pd);
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 1);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_assert_budget_empty();
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_logs), ==, 0);
	stub_dispose(&con, pd);

	stub_instance(&con, &pd, &keeper);
	reset();
	stub_pool_new(1);
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	await_idle(pd);
	g_assert_cmpuint(pd->bistream->bytes, ==, sizeof(data));
	processors_stop(&con);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_assert_budget_empty();
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	stub_dispose(&con, pd);
}

/*
 * dionaea stops (processors_jobs_drop): a job that waits for a worker runs
 * none of its processors and gives its data back; the wait for the pool is
 * only for what runs
 */
static void drop_waiting_job(void)
{
	struct connection con;
	struct processor_data *pd;
	char data[4096];
	memset(data, 'A', sizeof(data));
	stub_instance(&con, &pd, &keeper);
	reset();
	stub_pool_new(1);
	g_assert_true(thread_submit(thread_new(NULL, NULL, block_job)));
	stub_gate_await(&gate, 1);
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	g_assert_cmpuint(jobs().waiting, ==, 1);
	processors_jobs_drop(true);
	stub_gate_release(&gate);
	await_idle(pd);
	/* keep() never ran, its data is back */
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 0);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpuint(pd->pending, ==, 0);
	stub_assert_budget_empty();
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	processors_jobs_drop(false);
	stub_dispose(&con, pd);
}

/* a running job finishes its step, the data that arrived meanwhile is not run again */
static void drop_running_job(void)
{
	struct connection con;
	struct processor_data *pd;
	char data[4096];
	memset(data, 'A', sizeof(data));
	stub_instance(&con, &pd, &reader);
	reset();
	stub_pool_new(1);
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	/* read_all() waits at the gate in its first call */
	stub_gate_await(&gate, 1);
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	g_assert_cmpuint(pd->pending, ==, PROCESSOR_TEST_PENDING_IN);
	processors_jobs_drop(true);
	stub_gate_release(&gate);
	await_idle(pd);
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 1);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpuint(pd->pending, ==, 0);
	g_assert_cmpuint(jobs().waiting, ==, 0);
	stub_assert_budget_empty();
	stub_drain();
	processors_jobs_drop(false);
	stub_dispose(&con, pd);
}

/* unicode keeps no outgoing data and hands the incoming data on */
extern struct processor proc_unicode;

static void unicode(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &proc_unicode);
	pd->ctx = proc_unicode.new(NULL);
	struct processor_data *child = processor_data_new();
	child->processor = &keeper;
	pd->filters = g_list_append(NULL, child);
	reset();
	stub_pool_new(1);

	char data[4096];
	memset(data, 'A', sizeof(data));
	processor_io_single(&con, pd, data, sizeof(data), bistream_out);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpint(pd->queued.refs, ==, 0);

	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	await_idle(pd);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpuint(child->bistream->bytes, ==, sizeof(data));
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 1);

	/* the processor behind keeps everything: its limit closes the connection */
	for( unsigned i = 0; i < BISTREAM_MAX_BYTES / sizeof(data) + 1; i++ )
	{
		processor_io_single(&con, pd, data, sizeof(data), bistream_in);
		await_idle(pd);
	}
	g_assert_cmpint(g_atomic_int_get(&con.processor_data->closing), ==, 1);
	g_assert_cmpuint(child->bistream->bytes, ==, 0);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 1);

	processor_data_free(child);
	g_list_free(pd->filters);
	proc_unicode.free(pd->ctx);
	stub_dispose(&con, pd);
}

/*
 * a processor that gives up at a limit: the instance limit stops it, not the
 * connection; its data is given back at once, also while its job runs
 */
static void give_up_stream_limit(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &giver);
	reset();
	unsigned before = gave_up_count();
	stub_pool_new(1);
	char *large = g_malloc(BISTREAM_MAX_BYTES);
	memset(large, 'A', BISTREAM_MAX_BYTES);
	processor_io_single(&con, pd, large, 1, bistream_in);
	stub_gate_await(&gate, 1);
	processor_io_single(&con, pd, large, BISTREAM_MAX_BYTES - 1, bistream_in);  /* at */
	g_assert_cmpint(g_atomic_int_get(&pd->gave_up), ==, 0);
	processor_io_single(&con, pd, large, 1, bistream_in);                       /* over */
	assert_gave_up(&con, pd);
	stub_assert_budget_empty();
	/* nothing more is kept, a second limit or call does not log again */
	processor_io_single(&con, pd, large, BISTREAM_MAX_BYTES, bistream_in);
	for( int i = 0; i < 10; i++ )
		processor_give_up(&con, pd, "test", true);
	assert_gave_up(&con, pd);
	g_assert_cmpuint(gave_up_count(), ==, before + 1);
	stub_gate_release(&gate);
	await_idle(pd);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	g_free(large);
	stub_dispose(&con, pd);
}

/* the limit of the process: the instance that can not store gives up */
static void give_up_global_limit(void)
{
	enum { N = BISTREAM_GLOBAL_BYTES / BISTREAM_MAX_BYTES };
	struct connection con[N + 1];
	struct processor_data *pd[N + 1];
	char *large = g_malloc(BISTREAM_MAX_BYTES);
	memset(large, 'A', BISTREAM_MAX_BYTES);
	reset();
	stub_pool_new(1);
	g_assert_true(thread_submit(thread_new(NULL, NULL, block_job)));
	stub_gate_await(&gate, 1);
	for( unsigned i = 0; i <= N; i++ )
	{
		stub_instance(&con[i], &pd[i], &hoarder);
		processor_io_single(&con[i], pd[i], large, BISTREAM_MAX_BYTES, bistream_in);
	}
	/* the first N fit, the last one gives up; all stay open */
	for( unsigned i = 0; i < N; i++ )
	{
		g_assert_cmpint(g_atomic_int_get(&pd[i]->gave_up), ==, 0);
		g_assert_cmpuint(pd[i]->bistream->bytes, ==, BISTREAM_MAX_BYTES);
	}
	assert_gave_up(&con[N], pd[N]);
	stub_gate_release(&gate);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	for( unsigned i = 0; i < N; i++ )
		processors_stop(&con[i]);
	for( unsigned i = 0; i <= N; i++ )
		stub_dispose(&con[i], pd[i]);
	g_free(large);
}

/* a full queue or a refused job: the instance gives up, the connection stays open */
static void give_up_queue(void)
{
	for( int refused = 0; refused < 2; refused++ )
	{
		struct connection con;
		struct processor_data *pd;
		stub_instance(&con, &pd, &giver);
		reset();
		stub_pool_new(1);
		g_assert_true(thread_submit(thread_new(NULL, NULL, block_job)));
		stub_gate_await(&gate, 1);
		if( refused )
			g_atomic_int_set(&push_failures, 1);
		else
			fill_queue(THREADS_MAX_WAITING);
		char data[64];
		memset(data, 'A', sizeof(data));
		processor_io_single(&con, pd, data, sizeof(data), bistream_in);
		assert_gave_up(&con, pd);
		g_assert_cmpint(pd->queued.refs, ==, 0);
		stub_assert_budget_empty();
		processor_io_single(&con, pd, data, sizeof(data), bistream_in);
		g_assert_cmpuint(pd->bistream->bytes, ==, 0);
		g_assert_cmpint(g_atomic_int_get(&stub_refs), ==, 0);
		stub_gate_release(&gate);
		stub_drain();
		g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
		g_assert_cmpint(g_atomic_int_get(&calls), ==, 0);
		g_atomic_int_set(&push_failures, 0);
		stub_dispose(&con, pd);
	}
}

/* a job that still waits when its instance gives up runs without work */
static void give_up_waiting_job(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &giver);
	reset();
	g_atomic_int_set(&calls, 1);    /* consume() does not wait at the gate */
	stub_pool_new(1);
	g_assert_true(thread_submit(thread_new(NULL, NULL, block_job)));
	stub_gate_await(&gate, 1);
	char data[4096];
	memset(data, 'A', sizeof(data));
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	g_assert_cmpuint(jobs().waiting, ==, 1);
	processor_give_up(&con, pd, "test", true);
	assert_gave_up(&con, pd);
	stub_assert_budget_empty();
	stub_gate_release(&gate);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&calls), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	stub_dispose(&con, pd);
}

/* done with what it reads (limit false): an info, not counted as a limit */
static void give_up_done(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &hoarder);
	reset();
	unsigned before = gave_up_count();
	stub_pool_new(1);
	char data[64];
	memset(data, 'A', sizeof(data));
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	await_idle(pd);
	processor_give_up(&con, pd, "scan limit", false);
	processor_give_up(&con, pd, "scan limit", false);
	g_assert_cmpint(g_atomic_int_get(&pd->state), ==, processor_done);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_scan_stopped_logs), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_give_up_summaries), ==, 0);
	g_assert_cmpuint(gave_up_count(), ==, before);
	/* an instance done on its own (a shellcode found) does not log a stop */
	stub_drain();
	stub_dispose(&con, pd);
	stub_instance(&con, &pd, &hoarder);
	reset();
	g_atomic_int_set(&pd->state, processor_done);
	processor_give_up(&con, pd, "test", true);
	g_assert_cmpint(g_atomic_int_get(&pd->gave_up), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_scan_stopped_logs), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_give_up_summaries), ==, 0);
	stub_dispose(&con, pd);
}

/* unicode feeds one processor that gives up and one that goes on */
static void unicode_give_up(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &proc_unicode);
	pd->ctx = proc_unicode.new(NULL);
	struct processor_data *hoard = processor_data_new();
	hoard->processor = &hoarder;
	struct processor_data *other = processor_data_new();
	other->processor = &in_only;
	pd->filters = g_list_append(g_list_append(NULL, hoard), other);
	reset();
	g_atomic_int_set(&calls, 1);    /* consume() does not wait at the gate */
	stub_pool_new(1);
	char data[4096];
	memset(data, 'A', sizeof(data));
	for( unsigned i = 0; i < BISTREAM_MAX_BYTES / sizeof(data) + 1; i++ )
	{
		processor_io_single(&con, pd, data, sizeof(data), bistream_in);
		await_idle(pd);
	}
	assert_gave_up(&con, hoard);
	/* the other one still gets the data */
	unsigned calls_before = (unsigned)g_atomic_int_get(&calls);
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	await_idle(pd);
	g_assert_cmpuint((unsigned)g_atomic_int_get(&calls), >, calls_before);
	g_assert_cmpint(g_atomic_int_get(&other->state), ==, processor_continue);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	processor_data_free(hoard);
	processor_data_free(other);
	g_list_free(pd->filters);
	proc_unicode.free(pd->ctx);
	stub_dispose(&con, pd);
}

/*
 * the connection ends while the job of unicode feeds the processor behind it:
 * that processor still reads what it was given (its data is not taken from
 * under the job), then everything is given back
 */
static void stop_keeps_fed_instances(void)
{
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &proc_unicode);
	pd->ctx = proc_unicode.new(NULL);
	struct processor_data *child = processor_data_new();
	child->processor = &reader;
	pd->filters = g_list_append(NULL, child);
	reset();
	stub_pool_new(1);
	char data[4096];
	memset(data, 'A', sizeof(data));
	processor_io_single(&con, pd, data, sizeof(data), bistream_in);
	stub_gate_await(&gate, 1);
	processors_stop(&con);
	g_assert_cmpuint(child->bistream->bytes, ==, sizeof(data));
	stub_gate_release(&gate);
	await_idle(pd);
	g_assert_cmpint(g_atomic_int_get(&read_size), ==, sizeof(data));
	g_assert_cmpuint(child->bistream->bytes, ==, 0);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_assert_budget_empty();
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	processor_data_free(child);
	g_list_free(pd->filters);
	proc_unicode.free(pd->ctx);
	stub_dispose(&con, pd);
}

/* the clock and the timer of the summaries of the next two tests */
static gint64 summary_now;
static gboolean summary_armed;
static gint64 summary_fires_at;
static guint summary_schedules;

static gint64 summary_clock(void)
{
	return summary_now;
}

static bool summary_schedule(struct log_summary *s, double after)
{
	(void)s;
	summary_armed = TRUE;
	summary_fires_at = summary_now + (gint64)(after * G_USEC_PER_SEC);
	summary_schedules++;
	return true;
}

static const struct log_summary_hooks summary_hooks = { summary_clock, summary_schedule };

static void summary_start(struct log_summary *s)
{
	reset();
	log_summary_set_hooks(s, &summary_hooks);
	log_summary_reset(s);
	summary_now = (gint64)5000 * G_USEC_PER_SEC;
	summary_armed = FALSE;
	summary_schedules = 0;
}

static void assert_last_summary(const char *expected)
{
	char *last = stub_last_summary();
	g_assert_cmpstr(last, ==, expected);
	g_free(last);
}

/* an instance of a connection from 192.0.2.7:port of the protocol smbd */
static void summary_instance(struct connection *con, struct processor_data **pd, struct processor *p, int port)
{
	stub_instance(con, pd, p);
	con->protocol.name = "smbd";
	g_strlcpy(con->remote.ip_string, "192.0.2.7", sizeof(con->remote.ip_string));
	con->remote.port = htons(port);
}

/*
 * the give-ups of many connections at a limit (many clients at once): an info line each,
 * one warning at once and one when its minute ends; after a quiet minute a give-up warns
 * at once; the scan that is done reading is no give-up at a limit
 */
static void give_up_summary(void)
{
	struct log_summary *s = processor_give_up_summary();
	summary_start(s);
	unsigned before = gave_up_count();
	struct connection con;
	struct processor_data *pd;
	for( int i = 0; i < 100; i++ )
	{
		summary_instance(&con, &pd, &giver, 1000 + i);
		processor_give_up(&con, pd, "job queue full", true);
		stub_dispose(&con, pd);
		summary_now += G_USEC_PER_SEC / 10;
	}
	g_assert_cmpuint(gave_up_count(), ==, before + 100);
	g_assert_cmpint(g_atomic_int_get(&stub_scan_stopped_logs), ==, 100);
	g_assert_cmpint(g_atomic_int_get(&stub_connection_warnings), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_give_up_summaries), ==, 1);
	assert_last_summary("scans stopped at a limit: 1 connection(s) in the last minute, "
						"the last: giver scan, job queue full (smbd 192.0.2.7:1000)");
	/* the rest when the minute of the first warning ends */
	g_assert_true(summary_armed);
	g_assert_cmpuint(summary_schedules, ==, 1);
	g_assert_cmpint(summary_fires_at, ==, (gint64)5060 * G_USEC_PER_SEC);
	summary_now = summary_fires_at;
	summary_armed = FALSE;
	log_summary_due(s);
	g_assert_cmpint(g_atomic_int_get(&stub_give_up_summaries), ==, 2);
	assert_last_summary("scans stopped at a limit: 99 connection(s) in the last minute, "
						"the last: giver scan, job queue full (smbd 192.0.2.7:1099)");
	g_assert_false(summary_armed);

	/* a quiet minute, then one give-up: at once */
	summary_now += 61 * G_USEC_PER_SEC;
	summary_instance(&con, &pd, &giver, 2000);
	processor_give_up(&con, pd, "stream data limit", true);
	stub_dispose(&con, pd);
	g_assert_cmpint(g_atomic_int_get(&stub_give_up_summaries), ==, 3);
	assert_last_summary("scans stopped at a limit: 1 connection(s) in the last minute, "
						"the last: giver scan, stream data limit (smbd 192.0.2.7:2000)");

	/* done reading (limit false): its info line, no event of the summary */
	summary_now += 1 * G_USEC_PER_SEC;
	summary_instance(&con, &pd, &giver, 2001);
	processor_give_up(&con, pd, "scan limit", false);
	stub_dispose(&con, pd);
	g_assert_cmpint(g_atomic_int_get(&stub_scan_stopped_logs), ==, 102);
	g_assert_false(summary_armed);
	g_assert_cmpuint(gave_up_count(), ==, before + 101);
	stub_summaries_reset();
}

/* the overloads of many connections: an info line each, one warning a minute */
static void overload_summary(void)
{
	struct log_summary *s = processors_overload_summary();
	summary_start(s);
	struct processor_stats before, after;
	processor_stats_get(&before);
	struct connection con;
	struct processor_data *pd;
	for( int i = 0; i < 50; i++ )
	{
		summary_instance(&con, &pd, &in_only, 3000 + i);
		processors_overload(&con, "stream data limit");
		/* the close of the event loop */
		stub_run_async();
		stub_dispose(&con, pd);
		summary_now += G_USEC_PER_SEC / 10;
	}
	processor_stats_get(&after);
	g_assert_cmpuint(after.overloads, ==, before.overloads + 50);
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 50);
	g_assert_cmpint(g_atomic_int_get(&stub_refs), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_logs), ==, 50);
	g_assert_cmpint(g_atomic_int_get(&stub_connection_warnings), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_summaries), ==, 1);
	assert_last_summary("connections closed at a limit: 1 connection(s) in the last minute, "
						"the last: stream data limit (smbd 192.0.2.7:3000)");
	g_assert_true(summary_armed);
	summary_now = summary_fires_at;
	log_summary_due(s);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_summaries), ==, 2);
	assert_last_summary("connections closed at a limit: 49 connection(s) in the last minute, "
						"the last: stream data limit (smbd 192.0.2.7:3049)");
	stub_summaries_reset();
}

static void stats(void)
{
	struct processor_stats before, after;
	processor_stats_get(&before);
	struct connection con;
	struct processor_data *pd;
	stub_instance(&con, &pd, &in_only);
	reset();
	stub_pool_new(1);
	processors_overload(&con, "test");
	stub_drain();
	processor_stats_get(&after);
	g_assert_cmpuint(after.overloads, ==, before.overloads + 1);
	g_assert_cmpuint(after.stream_bytes, ==, 0);
	g_assert_cmpuint(after.jobs_waiting, ==, 0);
	g_assert_cmpuint(after.jobs_peak_waiting, <=, THREADS_MAX_WAITING);
	g_assert_cmpuint(after.stream_peak_bytes, <=, BISTREAM_GLOBAL_BYTES);
	stub_dispose(&con, pd);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	stub_quiet_logs();
	stub_dionaea_init();
#ifdef PROCESSOR_TEST_TSAN
	tsan_g_thread_pool_refuse = refuse_push;
#endif
	g_test_add_func("/threads/pool-size", pool_size);
	g_test_add_func("/threads/admission", admission);
	g_test_add_func("/threads/surveillance", surveillance);
	g_test_add_func("/processor/one-job", one_job);
	g_test_add_func("/processor/no-consumer", no_consumer);
	g_test_add_func("/processor/done", done);
	g_test_add_func("/processor/stream-limit", stream_limit);
	g_test_add_func("/processor/enqueue-failure", enqueue_failure);
	g_test_add_func("/processor/queue-full", queue_full);
	g_test_add_func("/processor/resubmit-failure", resubmit_failure);
	g_test_add_func("/processor/close-guard", close_guard);
	g_test_add_func("/processor/teardown", teardown);
	g_test_add_func("/processor/overload-releases", overload_releases);
	g_test_add_func("/processor/stop-releases", stop_releases);
	g_test_add_func("/processor/unicode", unicode);
	g_test_add_func("/processor/give-up-stream-limit", give_up_stream_limit);
	g_test_add_func("/processor/give-up-global-limit", give_up_global_limit);
	g_test_add_func("/processor/give-up-queue", give_up_queue);
	g_test_add_func("/processor/give-up-waiting-job", give_up_waiting_job);
	g_test_add_func("/processor/give-up-done", give_up_done);
	g_test_add_func("/processor/unicode-give-up", unicode_give_up);
	g_test_add_func("/processor/stop-keeps-fed-instances", stop_keeps_fed_instances);
	g_test_add_func("/processor/give-up-summary", give_up_summary);
	g_test_add_func("/processor/overload-summary", overload_summary);
	g_test_add_func("/processor/stats", stats);
	g_test_add_func("/processor/drop-waiting-job", drop_waiting_job);
	g_test_add_func("/processor/drop-running-job", drop_running_job);
	int result = g_test_run();
	stub_dionaea_exit();
	return result;
}
