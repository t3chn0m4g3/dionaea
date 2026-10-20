/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * Stand-ins for the parts of dionaea the processor tests do not link
 * (connections, incidents, temp files) and the eventloop of the tests.
 */
#ifndef PROCESSOR_TEST_STUBS_H
#define PROCESSOR_TEST_STUBS_H

#include <glib.h>
#include <stdbool.h>

#include "dionaea.h"
#include "connection.h"
#include "processor.h"
#include "threads.h"

extern gint stub_refs;          /* connection_ref - connection_unref */
extern gint stub_closes;        /* connection_close calls */
extern gint stub_incidents;     /* incidents reported */
extern gint stub_overload_logs; /* "Stream processing limit" warnings */
extern gint stub_give_up_logs;  /* "<name> scan stopped" warnings (a limit) */
extern gint stub_scan_done_logs; /* "<name> scan stopped" infos (done reading) */
extern gint stub_trim_thread_logs; /* "no thread for the trailing trim" warnings of the emu */

/* g_dionaea with a threadpool of workers workers, an eventloop and its async queue */
void stub_dionaea_init(void);
void stub_dionaea_exit(void);
void stub_pool_new(int workers);
/* wait for all jobs, free the pool, run the async commands of the eventloop */
void stub_drain(void);
/* run the async commands of the eventloop */
void stub_run_async(void);
void stub_quiet_logs(void);

/* a connection with its processor root and one instance of p */
void stub_instance(struct connection *con, struct processor_data **pd, struct processor *p);
/* free both; asserts that no stream data is left in the process */
void stub_dispose(struct connection *con, struct processor_data *pd);
void stub_assert_budget_empty(void);

/* a gate a job can wait at */
struct stub_gate
{
	GMutex mutex;
	GCond cond;
	int entered;
	bool released;
};
void stub_gate_reset(struct stub_gate *gate);
void stub_gate_wait(struct stub_gate *gate);
void stub_gate_await(struct stub_gate *gate, int entered);
void stub_gate_release(struct stub_gate *gate);

/* processor.c, not in processor.h */
void processor_io_single(struct connection *con, struct processor_data *pd, void *data, int size, enum bistream_direction direction);

#endif
