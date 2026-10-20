/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2026 T-Pot contributors
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The memory of a scan back to the system.
 *
 * emu_shellcode_test() builds a static instruction graph of the window when it
 * has a GetPC candidate: about 385 bytes per byte, 24 MiB for a 64 KiB window,
 * in the glibc arena of the emu worker. After emu_free() glibc keeps it: a
 * thread heap shrinks only from its top, and a few small chunks allocated
 * later keep the free space below them resident. Each of the four workers
 * held 18 to 24 MiB (up to 32) with almost nothing in use, 60 to 75 MiB of a
 * floor of 160 MiB under the replay load (tests/load/README.md). malloc_trim(0)
 * gives the free pages of every arena back (MADV_DONTNEED), the arena keeps
 * its address space.
 *
 * The trim walks all arenas and takes the lock of each in turn, so it runs at
 * most once per EMU_TRIM_INTERVAL_US in the process: the worker that ends a
 * scan with a graph claims the slot with an atomic compare and swap, the
 * others go on. A scan whose trim the limit skipped leaves the trim pending:
 * the next scan to end after the interval makes it, and when the emu goes idle
 * first, a thread of this file makes it once the interval is over and no scan
 * runs (the trailing trim, off the event loop; otherwise the memory of the last
 * graphs before the traffic stops stayed resident). glibc only; other C
 * libraries (musl) have no malloc_trim and no trim is made.
 */

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

/* module.h declares the hooks of hooks.c with EV_P_ */
#include <ev.h>
#include <glib.h>

#if defined(__GLIBC__)
#include <malloc.h>
#endif

#include <emu/emu.h>
#include <emu/emu_memory.h>

#include "log.h"

#define D_LOG_DOMAIN "emu"

#include "module.h"

/* STATIC_OFFSET of libemu's emu_shellcode.c: emu_shellcode_test() writes the window there only when it
 * builds the graph (a GetPC candidate); emu_getpc_check() writes its copies at 0x1000 */
#define EMU_SHELLCODE_STATIC_OFFSET 0x00471000

/* the earliest monotonic time of the next trim (0: at once) */
static _Atomic int64_t trim_next;

struct emu_trim_stats emu_trim_stats;

/* the trailing trim: guarded by trailing.lock */
static struct
{
	GMutex lock;
	GCond cond;
	GThread *thread;
	bool pending;    /* a scan built a graph since the last trim */
	int scans;       /* scans running */
	bool stopping;
	bool thread_failed;   /* g_thread_try_new() failed once: warned */
} trailing;

bool emu_scan_built_graph(struct emu *e)
{
	struct emu_memory *mem = emu_memory_get(e);
	uint8_t byte;
	/* without a segment override, as libemu wrote it */
	emu_memory_segment_select(mem, s_cs);
	return emu_memory_read_byte(mem, EMU_SHELLCODE_STATIC_OFFSET, &byte) == 0;
}

bool emu_trim_claim(int64_t now)
{
	int64_t next = atomic_load_explicit(&trim_next, memory_order_relaxed);
	while( now >= next )
	{
		if( atomic_compare_exchange_weak_explicit(&trim_next, &next, now + EMU_TRIM_INTERVAL_US,
				memory_order_relaxed, memory_order_relaxed) )
			return true;
	}
	return false;
}

#if defined(__GLIBC__)
static void trim(bool deferred)
{
	/* counted before the trim: a reader that saw it start sees it counted */
	atomic_fetch_add_explicit(&emu_trim_stats.count, 1, memory_order_relaxed);
	if( deferred )
		atomic_fetch_add_explicit(&emu_trim_stats.deferred, 1, memory_order_relaxed);
	int64_t start = g_get_monotonic_time();
	malloc_trim(0);
	uint64_t took = (uint64_t)(g_get_monotonic_time() - start);
	atomic_fetch_add_explicit(&emu_trim_stats.total_us, took, memory_order_relaxed);
	uint64_t max = atomic_load_explicit(&emu_trim_stats.max_us, memory_order_relaxed);
	while( took > max &&
		   !atomic_compare_exchange_weak_explicit(&emu_trim_stats.max_us, &max, took,
				memory_order_relaxed, memory_order_relaxed) )
		;
}

/* the pending trim, if the limit allows it now; trailing.lock is held and released for the trim */
static bool trim_pending_locked(bool deferred)
{
	if( !trailing.pending || !emu_trim_claim(g_get_monotonic_time()) )
		return false;
	/* cleared before the trim: a graph freed during it stays pending */
	trailing.pending = false;
	g_mutex_unlock(&trailing.lock);
	trim(deferred);
	g_mutex_lock(&trailing.lock);
	return true;
}

static gpointer trailing_thread(gpointer data)
{
	(void)data;
	g_mutex_lock(&trailing.lock);
	while( !trailing.stopping )
	{
		if( !trailing.pending || trailing.scans > 0 )
		{
			/* a scan that ends makes the trim itself, or signals */
			g_cond_wait(&trailing.cond, &trailing.lock);
			continue;
		}
		int64_t next = atomic_load_explicit(&trim_next, memory_order_relaxed);
		if( g_get_monotonic_time() < next )
		{
			g_cond_wait_until(&trailing.cond, &trailing.lock, next);
			continue;
		}
		trim_pending_locked(true);
	}
	g_mutex_unlock(&trailing.lock);
	return NULL;
}
#endif

void emu_trim_scan_begin(void)
{
	g_mutex_lock(&trailing.lock);
	trailing.scans++;
	g_mutex_unlock(&trailing.lock);
}

void emu_trim_scan_end(bool graph)
{
	g_mutex_lock(&trailing.lock);
	trailing.scans--;
#if defined(__GLIBC__)
	if( graph )
		trailing.pending = true;
	if( trailing.pending && !trim_pending_locked(false) && trailing.scans == 0 )
	{
		/* skipped by the limit and the emu is idle: the trailing trim takes it */
		if( trailing.thread == NULL && !trailing.stopping )
		{
			/* g_thread_new() would abort when no thread can be made (the pids limit of the container) */
			GError *error = NULL;
			trailing.thread = g_thread_try_new("emu-trim", trailing_thread, NULL, &error);
			if( trailing.thread == NULL )
			{
				/* the trim stays pending, the next scan after the interval makes it */
				if( !trailing.thread_failed )
					g_warning("no thread for the trailing trim (%s), the next scan makes it",
							  error != NULL ? error->message : "unknown error");
				trailing.thread_failed = true;
				g_clear_error(&error);
			}
		}
		g_cond_signal(&trailing.cond);
	}
#else
	(void)graph;
#endif
	g_mutex_unlock(&trailing.lock);
}

void emu_trim_stop(void)
{
	g_mutex_lock(&trailing.lock);
	GThread *thread = trailing.thread;
	trailing.stopping = true;
	g_cond_broadcast(&trailing.cond);
	g_mutex_unlock(&trailing.lock);
	if( thread != NULL )
		g_thread_join(thread);
	g_mutex_lock(&trailing.lock);
	trailing.thread = NULL;
	/* the thread is joined: a later skipped trim may start a new one (after a reset of the tests;
	 * at the module's free no scan runs any more) */
	trailing.stopping = false;
	g_mutex_unlock(&trailing.lock);
}

void emu_trim_reset(void)
{
	emu_trim_stop();
	g_mutex_lock(&trailing.lock);
	trailing.pending = false;
	/* a thread that can not be made after the reset is warned about again */
	trailing.thread_failed = false;
	g_mutex_unlock(&trailing.lock);
	atomic_store_explicit(&trim_next, 0, memory_order_relaxed);
}
