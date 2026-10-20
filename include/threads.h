/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_THREADS_H
#define HAVE_THREADS_H

#include <stdbool.h>
#include <glib.h>
#include <ev.h>


struct connection;

/*
 * Limits of the threadpool, documented internal constants: at most
 * THREADS_MAX_WORKERS workers, at most THREADS_MAX_WAITING jobs waiting for
 * one. The admission is shared by the processor jobs and the continuations of
 * the emulation; a job beyond the limit is refused (thread_submit()).
 */
#define THREADS_MAX_WORKERS 4
#define THREADS_MAX_WAITING 32

struct threads
{
	GThreadPool *pool;
	struct ev_async trigger;
	struct ev_periodic surveillance;
	GAsyncQueue *cmds;
};

void trigger_cb(struct ev_loop *loop, struct ev_async *w, int revents);
void surveillance_cb(struct ev_loop *loop, struct ev_periodic *w, int revents);
void threadpool_wrapper(gpointer data, gpointer user_data);


struct thread
{
	GFunc function;
	struct connection *con;
	void *data;
};

struct thread *thread_new(struct connection *con, void *data, GFunc function);
/*
 * Queue a job for the threadpool. false: refused (THREADS_MAX_WAITING jobs
 * wait already, or the pool refused it), the caller still owns t and what it
 * references. Never blocks on a running job.
 */
bool thread_submit(struct thread *t);

struct thread_stats
{
	unsigned waiting;         /* submitted, not yet started */
	unsigned peak_waiting;    /* largest value since the start */
	unsigned refused;         /* submissions refused since the start */
};
void thread_stats_get(struct thread_stats *stats);
/* the number of workers for this number of online CPUs */
int threads_pool_size(long cpus);


/**
 * prototype for callbacks and data which are meant to be run in
 * the main loop - from threads
 * @see threads.cmds
 */
typedef void (*async_cmd_cb)(void *data);


/**
 * data for async cmds
 * pointer to function and data,
 * insert into dionaea->threads.cmds
 * trigger dionaea->threads.trigger
 * and your function will be run in the main loop
 *
 * @see threads.cmds
 * @see threads.trigger
 */
struct async_cmd
{
	async_cmd_cb function;
	void *data;
};


struct async_cmd *async_cmd_new(async_cmd_cb function, void *data);
/*
void async_add_io(void *data);
void async_del_io(void *data);

void async_add_child(void *data);
void async_del_child(void *data);
*/
void async_incident_report(void *data);

#endif
