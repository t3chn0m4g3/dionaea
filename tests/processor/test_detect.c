/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * The emu processor scans a long stream in windows (modules/emu/detect.c):
 * shellcode before, after and across window ends is found, the scanned data is
 * freed, the cursor and the window sizes stay within their bounds. After a scan
 * that built libemu's instruction graph the emu worker gives the free memory
 * back (malloc_trim, modules/emu/trim.c), at most once per 5 s in the process;
 * a trim the limit skipped is made once the emu is idle (the trailing trim).
 */
#include <string.h>

#include <emu/emu.h>
#include <emu/emu_shellcode.h>

#include "stubs.h"
#include "module.h"

#define OVERLAP 300
#define WINDOW 65535                  /* emu_shellcode_test() takes a uint16_t */
#define NEW_MAX (64 * 1024)
#define SCAN_LIMIT (4 * 1024 * 1024)      /* EMU_SCAN_LIMIT */

/* the windows emu_shellcode_test() got */
static GArray *windows;
static GMutex windows_mutex;

int32_t __real_emu_shellcode_test(struct emu *e, uint8_t *data, uint16_t size);
int32_t __wrap_emu_shellcode_test(struct emu *e, uint8_t *data, uint16_t size)
{
	g_mutex_lock(&windows_mutex);
	unsigned value = size;
	g_array_append_val(windows, value);
	g_mutex_unlock(&windows_mutex);
	return __real_emu_shellcode_test(e, data, size);
}

/* malloc_trim is wrapped to count the trims of the emu workers */
static gint trims;
static GThread *main_thread;
static gint trims_on_main;     /* trims on the thread of the event loop (the tests' main thread) */
static gint64 last_trim_at;    /* windows_mutex */

int __real_malloc_trim(size_t pad);
int __wrap_malloc_trim(size_t pad)
{
	g_assert_cmpuint(pad, ==, 0);
	if( g_thread_self() == main_thread )
		g_atomic_int_inc(&trims_on_main);
	g_mutex_lock(&windows_mutex);
	last_trim_at = g_get_monotonic_time();
	g_mutex_unlock(&windows_mutex);
	g_atomic_int_inc(&trims);
	return __real_malloc_trim(pad);
}

/* g_thread_try_new is wrapped to make the thread of the trailing trim fail (pids limit) */
static gint fail_threads;

GThread *__real_g_thread_try_new(const gchar *name, GThreadFunc func, gpointer data, GError **error);
GThread *__wrap_g_thread_try_new(const gchar *name, GThreadFunc func, gpointer data, GError **error)
{
	if( g_atomic_int_get(&fail_threads) )
	{
		g_set_error_literal(error, G_THREAD_ERROR, G_THREAD_ERROR_AGAIN, "Resource temporarily unavailable");
		return NULL;
	}
	return __real_g_thread_try_new(name, func, data, error);
}

static gint64 last_trim(void)
{
	g_mutex_lock(&windows_mutex);
	gint64 at = last_trim_at;
	g_mutex_unlock(&windows_mutex);
	return at;
}

/* profile() of profile.c runs the emulation; here it records what it got */
static gint profiled;
static GByteArray *profiled_code;

void profile(struct emu_config *conf, struct connection *con, void *data, unsigned int size, unsigned int offset)
{
	(void)conf;
	(void)con;
	g_assert_cmpuint(offset, <, size);
	g_atomic_int_inc(&profiled);
	/* the workers of a burst profile at the same time */
	g_mutex_lock(&windows_mutex);
	g_byte_array_set_size(profiled_code, 0);
	g_byte_array_append(profiled_code, (guint8 *)data + offset, size - offset);
	g_mutex_unlock(&windows_mutex);
}

/* GetPC, a loop of 64 x 2 steps, kernel32!WinExec (tests/functional/test_emu.py) */
static const guint8 shellcode[] =
	"\xe8\x00\x00\x00\x00\x5e\x31\xc9\xb1\x40\x83\xc3\x01\xe2\xfb\x6a\x01\x8d\x46\x18"
	"\x50\xb8\x6d\x13\x86\x7c\xff\xd0\xc3" "cmd.exe /c echo detect-test";

static struct emu_config config;

static struct stub_gate gate;
static void gate_job(gpointer con, gpointer data)
{
	(void)con;
	stub_gate_wait(data);
}

static void reset(void)
{
	g_mutex_lock(&windows_mutex);
	g_array_set_size(windows, 0);
	g_mutex_unlock(&windows_mutex);
	g_atomic_int_set(&profiled, 0);
	g_atomic_int_set(&stub_incidents, 0);
	g_atomic_int_set(&stub_closes, 0);
	g_atomic_int_set(&stub_overload_logs, 0);
	g_atomic_int_set(&stub_scan_stopped_logs, 0);
	stub_summaries_reset();
	/* stops the trailing trim of a test before */
	emu_trim_reset();
	g_atomic_int_set(&trims, 0);
	g_atomic_int_set(&trims_on_main, 0);
}

static void emu_instance(struct connection *con, struct processor_data **pd)
{
	stub_instance(con, pd, &proc_emu);
	(*pd)->ctx = proc_emu.new(&config);
}

static void emu_dispose(struct connection *con, struct processor_data *pd)
{
	proc_emu.free(pd->ctx);
	stub_dispose(con, pd);
}

/* filler ret (no GetPC; it can not run into the shellcode, as a sled of
 * inc ecx would, so libemu reports the start of the shellcode itself), with
 * the shellcode at offset at */
static guint8 *stream_with_shellcode(size_t size, size_t at)
{
	guint8 *data = g_malloc(size);
	memset(data, 0xc3, size);
	if( at != SIZE_MAX )
	{
		g_assert_cmpuint(at + sizeof(shellcode), <=, size);
		memcpy(data + at, shellcode, sizeof(shellcode));
	}
	return data;
}

/* every window: at most WINDOW bytes, at most NEW_MAX new ones, 300 of overlap */
static uint64_t check_windows(uint64_t scanned_before)
{
	uint64_t cursor = scanned_before;
	g_mutex_lock(&windows_mutex);
	for( unsigned i = 0; i < windows->len; i++ )
	{
		unsigned size = g_array_index(windows, unsigned, i);
		unsigned overlap = cursor > OVERLAP ? OVERLAP : (unsigned)cursor;
		g_assert_cmpuint(size, <=, WINDOW);
		g_assert_cmpuint(size, >, overlap);
		g_assert_cmpuint(size - overlap, <=, NEW_MAX);
		cursor += size - overlap;
	}
	g_mutex_unlock(&windows_mutex);
	return cursor;
}

static void run_emu(struct connection *con, struct processor_data *pd)
{
	proc_emu.thread_io_in(con, pd);
	stub_run_async();
}

/* the shellcode is found where it is, before and after several windows and across their ends */
static void positions(void)
{
	const size_t size = 6 * NEW_MAX;
	const size_t step = WINDOW - OVERLAP;
	const size_t at[] = {
		0, 100,
		WINDOW - sizeof(shellcode),          /* the end of the first window */
		WINDOW - 10,                         /* across the end of the first window */
		WINDOW,                              /* the start of the second */
		WINDOW + step - 20,                  /* across the end of the second */
		4 * step + 1234,                     /* after several windows */
		size - sizeof(shellcode),            /* the end of the stream */
	};
	for( unsigned i = 0; i < G_N_ELEMENTS(at); i++ )
	{
		struct connection con;
		struct processor_data *pd;
		emu_instance(&con, &pd);
		reset();
		guint8 *data = stream_with_shellcode(size, at[i]);
		g_assert_true(bistream_data_add(pd->bistream, bistream_in, data, BISTREAM_MAX_BYTES < size ? BISTREAM_MAX_BYTES : size));
		run_emu(&con, pd);
		g_test_message("shellcode at %zu: %u windows, profiled %u bytes from %02x %02x %02x %02x", at[i], windows->len,
					   profiled_code->len, profiled_code->data[0], profiled_code->data[1], profiled_code->data[2], profiled_code->data[3]);
		g_assert_cmpint(g_atomic_int_get(&profiled), ==, 1);
		g_assert_cmpint(g_atomic_int_get(&stub_incidents), ==, 1);
		g_assert_cmpint(g_atomic_int_get(&pd->state), ==, processor_done);
		g_assert_cmpuint(profiled_code->len, >=, sizeof(shellcode));
		g_assert_cmpmem(profiled_code->data, sizeof(shellcode), shellcode, sizeof(shellcode));
		struct emu_ctx *ctx = pd->ctx;
		g_assert_cmpuint(check_windows(0), ==, ctx->offset);
		g_assert_cmpuint(ctx->offset, >, at[i]);
		g_free(data);
		emu_dispose(&con, pd);
	}
}

/* no shellcode: the whole stream is scanned once, the scanned data is freed */
static void long_stream(void)
{
	struct connection con;
	struct processor_data *pd;
	emu_instance(&con, &pd);
	reset();
	struct emu_ctx *ctx = pd->ctx;
	guint8 *piece = stream_with_shellcode(BISTREAM_MAX_BYTES - OVERLAP, SIZE_MAX);
	uint64_t total = 0;
	/* 3 MiB through a buffer of 1 MiB */
	for( unsigned i = 0; i < 3; i++ )
	{
		g_assert_true(bistream_data_add(pd->bistream, bistream_in, piece, BISTREAM_MAX_BYTES - OVERLAP));
		total += BISTREAM_MAX_BYTES - OVERLAP;
		run_emu(&con, pd);
		g_assert_cmpuint(ctx->offset, ==, total);
		g_assert_cmpuint(pd->bistream->bytes, ==, OVERLAP);
		g_assert_cmpuint(pd->bistream->chunks, ==, 1);
	}
	g_assert_cmpuint(check_windows(0), ==, total);
	/* nothing new: the cursor does not move and nothing is scanned again */
	unsigned calls = windows->len;
	run_emu(&con, pd);
	g_assert_cmpuint(windows->len, ==, calls);
	g_assert_cmpuint(ctx->offset, ==, total);
	/* one byte more: one window of the overlap and that byte */
	g_assert_true(bistream_data_add(pd->bistream, bistream_in, piece, 1));
	run_emu(&con, pd);
	g_assert_cmpuint(windows->len, ==, calls + 1);
	g_assert_cmpuint(g_array_index(windows, unsigned, calls), ==, OVERLAP + 1);
	g_assert_cmpuint(ctx->offset, ==, total + 1);
	g_assert_cmpint(g_atomic_int_get(&profiled), ==, 0);
	g_free(piece);
	emu_dispose(&con, pd);
}

/* the first SCAN_LIMIT bytes are scanned, then the scan stops quietly; the connection goes on */
static void scan_limit(void)
{
	struct connection con;
	struct processor_data *pd;
	emu_instance(&con, &pd);
	reset();
	struct emu_ctx *ctx = pd->ctx;
	guint8 *piece = stream_with_shellcode(BISTREAM_MAX_BYTES - OVERLAP, SIZE_MAX);
	uint64_t total = 0;
	while( g_atomic_int_get(&pd->state) != processor_done )
	{
		g_assert_cmpuint(total, <, SCAN_LIMIT);
		g_assert_true(bistream_data_add(pd->bistream, bistream_in, piece, BISTREAM_MAX_BYTES - OVERLAP));
		total += BISTREAM_MAX_BYTES - OVERLAP;
		run_emu(&con, pd);
	}
	g_assert_cmpuint(total, >, SCAN_LIMIT);
	g_assert_cmpuint(ctx->offset, ==, SCAN_LIMIT);
	g_assert_cmpuint(check_windows(0), ==, SCAN_LIMIT);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	/* done reading: an info line, no give-up at a limit */
	g_assert_cmpint(g_atomic_int_get(&stub_scan_stopped_logs), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_give_up_summaries), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&profiled), ==, 0);
	stub_pool_new(1);
	processor_io_single(&con, pd, piece, 1000, bistream_in);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&con.processor_data->closing), ==, 0);
	g_free(piece);
	emu_dispose(&con, pd);

	/* a shellcode that ends just before the limit is found, although more data follows */
	emu_instance(&con, &pd);
	reset();
	const size_t size = SCAN_LIMIT + 2 * NEW_MAX;
	guint8 *data = stream_with_shellcode(size, SCAN_LIMIT - sizeof(shellcode) - 10);
	for( size_t sent = 0; sent < size && g_atomic_int_get(&pd->state) != processor_done; )
	{
		size_t part = MIN(size - sent, (size_t)(BISTREAM_MAX_BYTES - OVERLAP));
		g_assert_true(bistream_data_add(pd->bistream, bistream_in, data + sent, part));
		sent += part;
		run_emu(&con, pd);
	}
	g_assert_cmpint(g_atomic_int_get(&profiled), ==, 1);
	g_assert_cmpmem(profiled_code->data, sizeof(shellcode), shellcode, sizeof(shellcode));
	g_assert_cmpint(g_atomic_int_get(&stub_scan_stopped_logs), ==, 0);
	g_free(data);
	emu_dispose(&con, pd);
}

/* faster than the scan: at the limit of the instance the emu gives up, the connection goes on */
static void give_up(void)
{
	struct connection con;
	struct processor_data *pd;
	emu_instance(&con, &pd);
	reset();
	stub_pool_new(1);
	/* the worker is busy, nothing is scanned */
	struct stub_gate *busy = &gate;
	stub_gate_reset(busy);
	g_assert_true(thread_submit(thread_new(NULL, busy, gate_job)));
	stub_gate_await(busy, 1);
	guint8 *data = stream_with_shellcode(BISTREAM_MAX_BYTES + 1, BISTREAM_MAX_BYTES - 100);
	processor_io_single(&con, pd, data, BISTREAM_MAX_BYTES, bistream_in);
	g_assert_cmpint(g_atomic_int_get(&pd->state), ==, processor_continue);
	processor_io_single(&con, pd, data + BISTREAM_MAX_BYTES, 1, bistream_in);
	g_assert_cmpint(g_atomic_int_get(&pd->state), ==, processor_done);
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	/* an info line of the connection and the summary warning, no warning of the connection */
	g_assert_cmpint(g_atomic_int_get(&stub_scan_stopped_logs), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_connection_warnings), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_give_up_summaries), ==, 1);
	stub_gate_release(busy);
	stub_drain();
	/* the waiting job found nothing to scan */
	g_assert_cmpuint(windows->len, ==, 0);
	g_assert_cmpint(g_atomic_int_get(&profiled), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_logs), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&con.processor_data->closing), ==, 0);
	g_free(data);
	emu_dispose(&con, pd);
}

/* through the jobs of the threadpool, in fragments that cross the window ends */
static void fragments(void)
{
	const size_t size = 3 * WINDOW;
	const size_t at = 2 * (WINDOW - OVERLAP) + WINDOW - OVERLAP - 7;
	struct connection con;
	struct processor_data *pd;
	emu_instance(&con, &pd);
	reset();
	stub_pool_new(2);
	guint8 *data = stream_with_shellcode(size, at);
	GRand *rand = g_rand_new_with_seed(4711);
	size_t sent = 0;
	while( sent < size && g_atomic_int_get(&pd->state) != processor_done )
	{
		size_t piece = MIN(size - sent, (size_t)g_rand_int_range(rand, 1, 3000));
		processor_io_single(&con, pd, data + sent, (int)piece, bistream_in);
		processor_io_single(&con, pd, data, (int)piece, bistream_out);   /* not kept */
		sent += piece;
		if( g_rand_int_range(rand, 0, 8) == 0 )
			g_usleep(200);
	}
	/* the rest after the detection is not kept any more */
	if( sent < size )
		processor_io_single(&con, pd, data + sent, (int)(size - sent), bistream_in);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&pd->state), ==, processor_done);
	g_assert_cmpint(g_atomic_int_get(&profiled), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_incidents), ==, 1);
	g_assert_cmpmem(profiled_code->data, sizeof(shellcode), shellcode, sizeof(shellcode));
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 0);
	g_assert_cmpint(g_atomic_int_get(&stub_overload_logs), ==, 0);
	check_windows(0);
	g_rand_free(rand);
	g_free(data);
	emu_dispose(&con, pd);
}

/* the emu reads no outgoing data, closing stops the scan */
static void closing(void)
{
	struct connection con;
	struct processor_data *pd;
	emu_instance(&con, &pd);
	reset();
	stub_pool_new(1);
	guint8 *data = stream_with_shellcode(2 * WINDOW, WINDOW + 5);
	g_assert_true(bistream_data_add(pd->bistream, bistream_in, data, 2 * WINDOW));
	processors_overload(&con, "test");
	run_emu(&con, pd);
	g_assert_cmpuint(windows->len, ==, 0);
	g_assert_cmpint(g_atomic_int_get(&profiled), ==, 0);
	/* the overload gave the data back */
	g_assert_cmpuint(pd->bistream->bytes, ==, 0);
	stub_drain();
	g_assert_cmpint(g_atomic_int_get(&stub_closes), ==, 1);
	g_free(data);
	emu_dispose(&con, pd);
}

/* the graph of libemu is built for a window with a GetPC candidate only */
static bool graph_of(const guint8 *data, size_t size)
{
	struct emu *e = emu_new();
	emu_shellcode_test(e, (uint8_t *)data, (uint16_t)size);
	bool graph = emu_scan_built_graph(e);
	emu_free(e);
	return graph;
}

static void trim_graph(void)
{
	guint8 *data = stream_with_shellcode(4096, 1000);
	g_assert_true(graph_of(data, 4096));
	/* ret only: no candidate */
	g_free(data);
	data = stream_with_shellcode(4096, SIZE_MAX);
	g_assert_false(graph_of(data, 4096));
	/* a call with a displacement beyond 512 is no candidate, although libemu parses it */
	memcpy(data + 100, "\xe8\x00\x10\x00\x00", 5);
	g_assert_false(graph_of(data, 4096));
	/* fnstenv [esp-0xc] is one */
	memcpy(data + 200, "\xd9\x74\x24\xf4", 4);
	g_assert_true(graph_of(data, 4096));
	g_free(data);
}

/* at most one trim per interval, the first at once */
static void trim_interval(void)
{
	reset();
	const int64_t start = 1000 * G_USEC_PER_SEC;
	g_assert_true(emu_trim_claim(start));
	g_assert_false(emu_trim_claim(start));
	g_assert_false(emu_trim_claim(start + G_USEC_PER_SEC));
	g_assert_false(emu_trim_claim(start + EMU_TRIM_INTERVAL_US - 1));
	g_assert_true(emu_trim_claim(start + EMU_TRIM_INTERVAL_US));
	g_assert_false(emu_trim_claim(start + EMU_TRIM_INTERVAL_US + 1));
	/* a clock that went back (another thread read it earlier) claims nothing */
	g_assert_false(emu_trim_claim(start));
	g_assert_true(emu_trim_claim(start + 10 * EMU_TRIM_INTERVAL_US));
	g_assert_cmpint(EMU_TRIM_INTERVAL_US, ==, 5 * G_USEC_PER_SEC);
}

/* workers that finish a scan at the same moment claim one trim */
static gint claimed;
static int64_t claim_at;
static void claim_thread(gpointer data, gpointer user_data)
{
	(void)data;
	stub_gate_wait(user_data);
	if( emu_trim_claim(claim_at) )
		g_atomic_int_inc(&claimed);
}

static void trim_concurrent(void)
{
	for( int round = 0; round < 50; round++ )
	{
		reset();
		g_atomic_int_set(&claimed, 0);
		claim_at = (int64_t)(round + 1) * 1000 * G_USEC_PER_SEC;
		stub_gate_reset(&gate);
		GThreadPool *pool = g_thread_pool_new(claim_thread, &gate, 8, TRUE, NULL);
		for( int i = 0; i < 8; i++ )
			g_thread_pool_push(pool, GINT_TO_POINTER(i + 1), NULL);
		stub_gate_await(&gate, 8);
		stub_gate_release(&gate);
		g_thread_pool_free(pool, FALSE, TRUE);
		g_assert_cmpint(g_atomic_int_get(&claimed), ==, 1);
	}
}

/* emu_dispose for one of several connections: the others still keep their overlap */
static void burst_dispose(struct connection *con, struct processor_data *pd)
{
	proc_emu.free(pd->ctx);
	g_list_free(con->processor_data->filters);
	processor_data_free(pd);
	processor_data_free(con->processor_data);
	con->processor_data = NULL;
}

/* a burst of scans on the workers of the threadpool: one trim, and only after scans that built a graph */
static void trim_burst(void)
{
	enum { CONNECTIONS = 16, SIZE = 4096 };
	struct connection con[CONNECTIONS];
	struct processor_data *pd[CONNECTIONS];
	guint8 *plain = stream_with_shellcode(SIZE, SIZE_MAX);
	guint8 *code = stream_with_shellcode(SIZE, 1000);
	reset();
	stub_pool_new(4);

	/* no candidate in any window: no graph, no trim */
	for( int i = 0; i < CONNECTIONS; i++ )
	{
		emu_instance(&con[i], &pd[i]);
		processor_io_single(&con[i], pd[i], plain, SIZE, bistream_in);
	}
	stub_drain();
	g_assert_cmpuint(windows->len, ==, CONNECTIONS);
	g_assert_cmpint(g_atomic_int_get(&trims), ==, 0);
	for( int i = 0; i < CONNECTIONS; i++ )
		burst_dispose(&con[i], pd[i]);
	stub_assert_budget_empty();

	/* shellcode in every window: every scan built a graph, the first trims, the rest are within 5 s */
	reset();
	stub_pool_new(4);
	int64_t begin = g_get_monotonic_time();
	for( int i = 0; i < CONNECTIONS; i++ )
	{
		emu_instance(&con[i], &pd[i]);
		processor_io_single(&con[i], pd[i], code, SIZE, bistream_in);
	}
	stub_drain();
	int64_t took = g_get_monotonic_time() - begin;
	g_assert_cmpint(g_atomic_int_get(&profiled), ==, CONNECTIONS);
	int expected_max = 1 + (int)(took / EMU_TRIM_INTERVAL_US);
	g_test_message("%d scans with a graph in %" G_GINT64_FORMAT " us: %d trims", CONNECTIONS, took,
				   g_atomic_int_get(&trims));
#if defined(__GLIBC__)
	g_assert_cmpint(g_atomic_int_get(&trims), >=, 1);
	g_assert_cmpint(g_atomic_int_get(&trims), <=, expected_max);
	g_assert_cmpuint(emu_trim_stats.count, >=, 1);
#else
	(void)expected_max;
	g_assert_cmpint(g_atomic_int_get(&trims), ==, 0);
#endif
	for( int i = 0; i < CONNECTIONS; i++ )
		burst_dispose(&con[i], pd[i]);
	stub_assert_budget_empty();

	/* once the interval is over, the next scan with a graph trims again */
	reset();
	emu_instance(&con[0], &pd[0]);
	g_assert_true(bistream_data_add(pd[0]->bistream, bistream_in, code, SIZE));
	run_emu(&con[0], pd[0]);
#if defined(__GLIBC__)
	g_assert_cmpint(g_atomic_int_get(&trims), ==, 1);
#endif
	emu_dispose(&con[0], pd[0]);
	g_free(plain);
	g_free(code);
}

/* waits up to timeout_us for at least count trims */
static bool trims_reach(int count, gint64 timeout_us)
{
	gint64 deadline = g_get_monotonic_time() + timeout_us;
	while( g_atomic_int_get(&trims) < count )
	{
		if( g_get_monotonic_time() > deadline )
			return false;
		g_usleep(10000);
	}
	return true;
}

/* a trim the limit skipped is made once the emu is idle: once, not before the interval, not on the event loop */
static void trim_trailing(void)
{
	reset();
	emu_trim_scan_begin();
	emu_trim_scan_end(true);
#if defined(__GLIBC__)
	g_assert_cmpint(g_atomic_int_get(&trims), ==, 1);
	gint64 first = last_trim();
	uint64_t deferred = emu_trim_stats.deferred;
	/* within the interval: skipped, the emu goes idle */
	emu_trim_scan_begin();
	emu_trim_scan_end(true);
	g_assert_cmpint(g_atomic_int_get(&trims), ==, 1);
	/* the test calls the scans on its main thread, the event loop of the stubs */
	int on_main = g_atomic_int_get(&trims_on_main);
	g_assert_true(trims_reach(2, EMU_TRIM_INTERVAL_US + 3 * G_USEC_PER_SEC));
	g_assert_cmpint(last_trim() - first, >=, EMU_TRIM_INTERVAL_US);
	g_assert_cmpuint(emu_trim_stats.deferred, ==, deferred + 1);
	g_assert_cmpint(g_atomic_int_get(&trims_on_main), ==, on_main);
	/* nothing skipped since: no more trims */
	g_assert_false(trims_reach(3, EMU_TRIM_INTERVAL_US + G_USEC_PER_SEC));

	/* a scan without a graph after a skipped one: still trailing */
	reset();
	emu_trim_scan_begin();
	emu_trim_scan_end(true);
	emu_trim_scan_begin();
	emu_trim_scan_end(true);
	emu_trim_scan_begin();
	emu_trim_scan_end(false);
	g_assert_cmpint(g_atomic_int_get(&trims), ==, 1);
	g_assert_true(trims_reach(2, EMU_TRIM_INTERVAL_US + 3 * G_USEC_PER_SEC));
#else
	g_assert_cmpint(g_atomic_int_get(&trims), ==, 0);
#endif
	reset();
}

/* while a scan runs the emu is not idle: the skipped trim waits for the end of the scan, which makes it */
static void trim_trailing_busy(void)
{
	reset();
	emu_trim_scan_begin();
	emu_trim_scan_end(true);
	emu_trim_scan_begin();
	emu_trim_scan_end(true);
	/* a long scan is running when the interval ends */
	emu_trim_scan_begin();
#if defined(__GLIBC__)
	uint64_t deferred = emu_trim_stats.deferred;
	g_assert_false(trims_reach(2, EMU_TRIM_INTERVAL_US + G_USEC_PER_SEC));
	emu_trim_scan_end(false);
	g_assert_cmpint(g_atomic_int_get(&trims), ==, 2);
	g_assert_cmpuint(emu_trim_stats.deferred, ==, deferred);
	/* nothing is left for the trailing trim */
	g_assert_false(trims_reach(3, EMU_TRIM_INTERVAL_US + G_USEC_PER_SEC));
#else
	emu_trim_scan_end(false);
#endif
	reset();
}

/* no thread for the trailing trim: one warning, the trim stays pending for the next scan, no abort */
static void trim_trailing_no_thread(void)
{
	reset();
	g_atomic_int_set(&stub_trim_thread_logs, 0);
	g_atomic_int_set(&fail_threads, 1);
	emu_trim_scan_begin();
	emu_trim_scan_end(true);
	emu_trim_scan_begin();
	emu_trim_scan_end(true);
	emu_trim_scan_begin();
	emu_trim_scan_end(true);
#if defined(__GLIBC__)
	g_assert_cmpint(g_atomic_int_get(&trims), ==, 1);
	g_assert_cmpint(g_atomic_int_get(&stub_trim_thread_logs), ==, 1);
	g_assert_false(trims_reach(2, EMU_TRIM_INTERVAL_US + G_USEC_PER_SEC));
	/* still pending: the next scan after the interval makes it */
	g_atomic_int_set(&fail_threads, 0);
	emu_trim_scan_begin();
	emu_trim_scan_end(false);
	g_assert_cmpint(g_atomic_int_get(&trims), ==, 2);
	g_assert_cmpint(g_atomic_int_get(&stub_trim_thread_logs), ==, 1);

	/* after a reset a thread that can not be made is warned about again */
	reset();
	g_atomic_int_set(&fail_threads, 1);
	emu_trim_scan_begin();
	emu_trim_scan_end(true);
	emu_trim_scan_begin();
	emu_trim_scan_end(true);
	g_assert_cmpint(g_atomic_int_get(&stub_trim_thread_logs), ==, 2);
#endif
	g_atomic_int_set(&fail_threads, 0);
	reset();
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	main_thread = g_thread_self();
	stub_quiet_logs();
	stub_dionaea_init();
	windows = g_array_new(FALSE, FALSE, sizeof(unsigned));
	profiled_code = g_byte_array_new();
	g_test_add_func("/emu/positions", positions);
	g_test_add_func("/emu/long-stream", long_stream);
	g_test_add_func("/emu/scan-limit", scan_limit);
	g_test_add_func("/emu/give-up", give_up);
	g_test_add_func("/emu/fragments", fragments);
	g_test_add_func("/emu/closing", closing);
	g_test_add_func("/emu/trim/graph", trim_graph);
	g_test_add_func("/emu/trim/interval", trim_interval);
	g_test_add_func("/emu/trim/concurrent", trim_concurrent);
	g_test_add_func("/emu/trim/burst", trim_burst);
	g_test_add_func("/emu/trim/trailing", trim_trailing);
	g_test_add_func("/emu/trim/trailing-busy", trim_trailing_busy);
	g_test_add_func("/emu/trim/trailing-no-thread", trim_trailing_no_thread);
	int result = g_test_run();
	g_array_free(windows, TRUE);
	g_byte_array_free(profiled_code, TRUE);
	stub_dionaea_exit();
	return result;
}
