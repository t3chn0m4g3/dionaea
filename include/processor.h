/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Markus Koetter
 * SPDX-FileCopyrightText: 2016 PhiBo (DinoTools)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_STREAMPROCESSOR_H
#define HAVE_STREAMPROCESSOR_H

#include <stdbool.h>

#include "bistream.h"
#include "refcount.h"

struct connection;
struct lcfgx_tree_node;

struct processors
{
	GNode *tree;
	GHashTable *names;
};


enum processor_state
{
	processor_done,
	processor_continue
};

struct processor_data;


typedef void *(*processor_cfg_new)(gchar *);
typedef bool (*processor_process)(struct connection *con, void *config);
typedef void *(*processor_ctx_new)(void *cfg);
typedef void (*processor_ctx_free)(void *ctx);
typedef void (*processor_close)(struct connection *con, struct processor_data *pd);
typedef void (*processor_io)(struct connection *con, struct processor_data *pd, void *data, int size);
typedef void (*processor_thread_io)(struct connection *con, struct processor_data *pd);

struct processor
{
	const char *name;
	processor_cfg_new cfg;
	processor_process process;
	processor_ctx_new new;
	processor_ctx_free free;
	processor_io io_in;
	processor_io io_out;
	processor_thread_io thread_io_in;
	processor_thread_io thread_io_out;
	/*
	 * What a limit of the stream processing (the data of an instance or of the
	 * process, a full job queue) does to a threaded processor:
	 * false: the connection is closed (processors_overload()), for consumers
	 *        that need the whole history (xmatch, unicode and what it feeds)
	 * true:  only this instance stops (processor_give_up()), the connection goes
	 *        on; for consumers that can do without the rest (emu: shellcode
	 *        comes early, an upload must not be lost for its scan)
	 */
	bool give_up_on_limit;
	void *config;
	/* at the end of dionaea, before the logs are closed (processors_tree_shutdown()) */
	void (*shutdown)(void *config);
};


/*
 * Threaded processors (thread_io_in / thread_io_out) work on a copy of the
 * stream in their bistream, in jobs of the threadpool. Per instance there is
 * at most one job (waiting or running); data that arrives meanwhile only sets
 * the pending flag of its direction, the job runs again for it (queued anew,
 * or in the same worker if the queue is full).
 *
 * Lock order: a thread that holds one of these locks takes only locks
 * further down the list.
 *   1. processor_data.mutex   held by the worker for a whole job; never taken
 *                             by the eventloop, which so never waits for a
 *                             running emulation
 *   2. processor_data.queued.mutex  admission of a job, pending, state checks;
 *                             of one instance at a time
 *   3. bistream.mutex         the stream data, held for one add/copy/discard
 *   4. bistream budget mutex  the process wide counters (src/bistream.c)
 * The threadpool admission mutex (src/threads.c) is taken inside 2 and is a
 * leaf apart from the pool's own queue lock. The mutex of an emulation
 * (modules/emu, struct emu_emulate_ctx) is taken inside 1 or alone. The
 * refcount mutex of a connection and the async queue of the eventloop are
 * leaves.
 */
struct processor_data
{
	gint state;               /* enum processor_state, atomic */
	GMutex mutex;             /* serialises the jobs of this instance */
	struct refcount queued;   /* queued.refs: 1 while a job exists */
	unsigned pending;         /* directions with new data, under queued.mutex */
	gint closing;             /* root only, atomic: 1 after processors_overload() */
	gint gave_up;             /* atomic: 1 after processor_give_up() */
	gint ended;               /* root only, atomic: 1 after processors_stop() */
	struct processor *processor;
	void *ctx;
	struct bistream *bistream;

	GList *filters;	// of type struct stream_processor_data
};

struct processor_stats
{
	size_t stream_bytes;      /* stream data stored by all processors */
	size_t stream_chunks;
	size_t stream_peak_bytes;
	size_t stream_peak_chunks;
	size_t stream_refused_instance; /* stream data refused by a limit of one instance */
	size_t stream_refused_global;   /* stream data refused by the limits of the process */
	unsigned jobs_waiting;    /* threadpool jobs not yet started */
	unsigned jobs_peak_waiting;
	unsigned jobs_refused;
	unsigned overloads;       /* connections closed by processors_overload() */
	unsigned gave_up;         /* instances given up at a limit (processor_give_up()) */
};

bool processors_tree_create(GNode *tree, gchar *);
void processors_tree_dump(GNode *tree, int indent);
/* the end of dionaea: every processor of the tree with a shutdown gets it, once per reference */
void processors_tree_shutdown(GNode *tree);

void processors_init(struct connection *con);
void processors_clear(struct connection *con);

/*
 * A limit of the stream processing was reached for a processor of this
 * connection that needs the whole history (no give_up_on_limit): stop its
 * processing and close it from the eventloop. Callable from any thread; only
 * the first call per connection logs and closes.
 */
void processors_overload(struct connection *con, const char *reason);
/*
 * Stop one instance: it is processor_done, its stream data (and that of the
 * instances it feeds) is given back now, nothing more is kept or queued for
 * it; the connection and the other instances go on. A job of it that runs
 * finishes its current step on its copy. Callable from any thread, without a
 * lock of the instance; only the first call per instance logs (reason and
 * address, none of the data).
 * limit true: a limit of the stream processing stopped a give_up_on_limit
 *             processor (a warning, counted in processor_stats.gave_up)
 * limit false: the processor is done with what it wants to read (the scan
 *             limit of the emu; info)
 */
void processor_give_up(struct connection *con, struct processor_data *pd, const char *reason, bool limit);
/*
 * The connection ends (connection_free()): no more stream data is kept. An
 * instance with a job (waiting or running) still reads what arrived before
 * the end, its data is given back when that job ends; the data of the others
 * is given back now. Eventloop; no log, no close.
 */
void processors_stop(struct connection *con);
/*
 * The event loop of dionaea ended (drop true): a job of a threaded processor
 * that has not started yet runs none of its processors, a running one ends
 * after its current step without queueing the next; both give back their
 * stream data. The wait for the threadpool then waits for the running steps
 * only. drop false undoes it (tests).
 */
void processors_jobs_drop(bool drop);
void processors_io_out(struct connection *con, void *data, int size);
void processors_io_in(struct connection *con, void *data, int size);
struct processor_data *processor_data_new(void);
void processor_data_free(struct processor_data *pd);
void processor_stats_get(struct processor_stats *stats);

#endif
