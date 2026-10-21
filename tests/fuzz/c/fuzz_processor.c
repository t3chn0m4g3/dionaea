/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * libFuzzer target of the entry of the stream processing (src/processor.c)
 * and the limits of the streamdumper (src/streamcap.c), without the event
 * loop: the processors of T-Pot's dionaea.cfg for every connection, the
 * streamdumper with config.max_size / config.max_files in a temporary folder,
 * and unicode with a threaded reader behind it, in the threadpool of the
 * tests (tests/processor/stubs.c).
 *
 * The input chooses the limits, then a sequence of operations: data of up to
 * four connections in either direction (the sizes of a TCP read, up to the
 * receive buffer of a host), and the end of a connection. At the end:
 *   - the reader got every byte that came in, in order (or a prefix, when a
 *     limit of the stream processing closed the connection);
 *   - every dump is the Python literal of its stream, or a prefix of it at
 *     a chunk when max_size stopped it;
 *   - the folder holds no more than the limits, and the running total of
 *     the streamdumper is what the folder holds.
 */
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "stubs.h"
#include "streamcap.h"
#include "fuzz_input.h"

#define CONNECTIONS 4
/* net.ipv4.tcp_rmem: a read takes what the socket holds and one byte (connection_tcp.c) */
#define MAX_READ (6 * 1024 * 1024 + 1)

extern struct processor proc_streamdumper;
extern struct processor proc_unicode;
void proc_streamdumper_cfg_free(void *cfg);
struct streamcap *proc_streamdumper_cap(void *cfg);

/* what the reader behind unicode got, per connection */
struct reader_ctx
{
	GByteArray *got;
	uint64_t offset;
};

static void *reader_new(void *cfg)
{
	(void)cfg;
	struct reader_ctx *ctx = g_malloc0(sizeof(*ctx));
	ctx->got = g_byte_array_new();
	return ctx;
}

static void reader_free(void *ctx0)
{
	struct reader_ctx *ctx = ctx0;
	g_byte_array_free(ctx->got, TRUE);
	g_free(ctx);
}

static void reader_io_in(struct connection *con, struct processor_data *pd)
{
	(void)con;
	struct reader_ctx *ctx = pd->ctx;
	void *data = NULL;
	int32_t size = bistream_get_stream(pd->bistream, bistream_in, ctx->offset, -1, &data);
	if( size <= 0 )
		return;
	g_byte_array_append(ctx->got, data, (guint)size);
	ctx->offset += (uint64_t)size;
	g_free(data);
	bistream_discard_before(pd->bistream, bistream_in, ctx->offset);
}

static struct processor reader = {
	.name = "reader", .new = reader_new, .free = reader_free, .thread_io_in = reader_io_in,
};

struct fconn
{
	struct connection con;
	struct processor_data *dump_pd, *unicode_pd, *reader_pd;
	bool open, ended;
	GByteArray *fed_in;           /* every byte that came in */
	GPtrArray *events;            /* GByteArray per chunk, direction in events_dir */
	GArray *events_dir;
	int port;
};

static struct processor *dumper;

static void quiet(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data)
{
	(void)domain;
	(void)data;
	if( level & (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL) )
	{
		fprintf(stderr, "%s\n", message);
		abort();
	}
}

static void conn_open(struct fconn *c, int index)
{
	memset(&c->con, 0, sizeof(c->con));
	c->con.state = connection_state_established;
	c->con.protocol.name = "smbd";
	g_strlcpy(c->con.local.ip_string, "192.0.2.1", sizeof(c->con.local.ip_string));
	g_strlcpy(c->con.remote.ip_string, "198.51.100.7", sizeof(c->con.remote.ip_string));
	c->port = 40000 + index;
	c->con.local.port = htons(445);
	c->con.remote.port = htons(c->port);
	gettimeofday(&c->con.stats.start, NULL);

	/* the tree of T-Pot: filter -> streamdumper, filter -> emu (here unicode -> reader) */
	c->con.processor_data = processor_data_new();
	c->dump_pd = processor_data_new();
	c->dump_pd->processor = dumper;
	c->dump_pd->ctx = dumper->new(dumper->config);
	c->unicode_pd = processor_data_new();
	c->unicode_pd->processor = &proc_unicode;
	c->unicode_pd->ctx = proc_unicode.new(NULL);
	c->reader_pd = processor_data_new();
	c->reader_pd->processor = &reader;
	c->reader_pd->ctx = reader.new(NULL);
	c->unicode_pd->filters = g_list_append(NULL, c->reader_pd);
	c->con.processor_data->filters = g_list_append(g_list_append(NULL, c->dump_pd), c->unicode_pd);

	c->fed_in = g_byte_array_new();
	c->events = g_ptr_array_new_with_free_func((GDestroyNotify)g_byte_array_unref);
	c->events_dir = g_array_new(FALSE, FALSE, sizeof(int));
	c->open = true;
	c->ended = false;
}

static void conn_io(struct fconn *c, struct fuzz_input *in)
{
	uint8_t how = fuzz_u8(in);
	int dir = how & 1;
	size_t size;
	if( how & 0x80 )
	{
		/* a large read, mostly a pattern */
		uint32_t scale = (how >> 1) & 7;
		size = ((size_t)fuzz_u16(in) << scale) % MAX_READ;
	} else
		size = fuzz_u8(in) + 1;
	if( size == 0 )
		return;
	guint8 *data = g_malloc(size);
	size_t taken = fuzz_bytes(in, data, MIN(size, (size_t)256));
	for( size_t i = taken; i < size; i++ )
		data[i] = taken > 0 ? data[i % taken] : (guint8)i;

	if( dir == bistream_in )
		processors_io_in(&c->con, data, (int)size);
	else
		processors_io_out(&c->con, data, (int)size);

	if( dir == bistream_in )
		g_byte_array_append(c->fed_in, data, (guint)size);
	GByteArray *event = g_byte_array_sized_new((guint)size);
	g_byte_array_append(event, data, (guint)size);
	g_ptr_array_add(c->events, event);
	g_array_append_val(c->events_dir, dir);
	g_free(data);
}

/* the end of a connection: no more data, its dump is closed */
static void conn_end(struct fconn *c)
{
	processors_stop(&c->con);
	dumper->free(c->dump_pd->ctx);
	/* an empty context for processors_clear() */
	c->dump_pd->ctx = dumper->new(dumper->config);
	c->ended = true;
}

static char *dump_of_port(const char *dir, int port)
{
	char *needle = g_strdup_printf("-%d-", port);
	char *found = NULL;
	GDir *days = g_dir_open(dir, 0, NULL);
	g_assert_nonnull(days);
	const char *day;
	while( found == NULL && (day = g_dir_read_name(days)) != NULL )
	{
		char *day_path = g_build_filename(dir, day, NULL);
		GDir *files = g_dir_open(day_path, 0, NULL);
		const char *name;
		while( files != NULL && (name = g_dir_read_name(files)) != NULL )
		{
			/* smbd-192.0.2.1-445-198.51.100.7-<port>-<time>-<random> */
			if( strstr(name, needle) != NULL && g_str_has_prefix(name, "smbd-192.0.2.1-445-198.51.100.7") )
			{
				g_assert_null(found);
				found = g_build_filename(day_path, name, NULL);
			}
		}
		if( files != NULL )
			g_dir_close(files);
		g_free(day_path);
	}
	g_dir_close(days);
	g_free(needle);
	return found;
}

/* the escaping of the streamdumper: a printable byte but ' and \ as it is, else \xNN */
static void escape(GString *out, const guint8 *data, size_t size)
{
	for( size_t i = 0; i < size; i++ )
	{
		guint8 c = data[i];
		if( c >= 0x20 && c <= 0x7e && c != '\'' && c != '\\' )
			g_string_append_c(out, (char)c);
		else
			g_string_append_printf(out, "\\x%02x", c);
	}
}

/*
 * the dump of c is the literal of its stream, all of it or up to the end of a
 * chunk (may_stop: max_size, or a limit of the stream processing closed the
 * connection and nothing after it was processed)
 */
static void check_dump(struct fconn *c, const char *dir, bool limited, bool may_stop)
{
	char *path = dump_of_port(dir, c->port);
	if( c->events->len == 0 )
	{
		g_assert_null(path);
		return;
	}
	if( path == NULL )
	{
		/* refused at the start of its stream */
		g_assert_true(limited);
		return;
	}
	gchar *content = NULL;
	gsize length = 0;
	g_assert_true(g_file_get_contents(path, &content, &length, NULL));
	g_free(path);

	GString *want = g_string_new("stream = [");
	int last = -1;
	bool whole = false;
	for( guint i = 0; i < c->events->len; i++ )
	{
		GByteArray *event = g_ptr_array_index(c->events, i);
		int d = g_array_index(c->events_dir, int, i);
		if( d != last )
		{
			if( last != -1 )
				g_string_append(want, "'),\n");
			g_string_append(want, d == bistream_in ? "('in', " : "('out', ");
			g_string_append(want, "b'");
			last = d;
		}
		escape(want, event->data, event->len);
		/* a dump stopped at max_size ends after a whole chunk */
		if( i + 1 < c->events->len && length == want->len + 3 &&
			memcmp(content, want->str, want->len) == 0 && memcmp(content + want->len, "')]", 3) == 0 )
		{
			g_assert_true(may_stop);
			whole = true;
			break;
		}
	}
	if( !whole )
	{
		g_string_append(want, "')]");
		if( length != want->len || memcmp(content, want->str, length) != 0 )
		{
			fprintf(stderr, "dump of port %d: %zu bytes, want %zu\n", c->port, (size_t)length, want->len);
			abort();
		}
	}
	g_string_free(want, TRUE);
	g_free(content);
}

static void count_files(const char *dir, guint64 *files, guint64 *bytes)
{
	GDir *it = g_dir_open(dir, 0, NULL);
	if( it == NULL )
		return;
	const char *name;
	while( (name = g_dir_read_name(it)) != NULL )
	{
		char *path = g_build_filename(dir, name, NULL);
		struct stat st;
		if( lstat(path, &st) == 0 )
		{
			if( S_ISDIR(st.st_mode) )
				count_files(path, files, bytes);
			else if( S_ISREG(st.st_mode) )
			{
				(*files)++;
				*bytes += (guint64)st.st_size;
			}
		}
		g_free(path);
	}
	g_dir_close(it);
}

static void rm_rf(const char *dir)
{
	GDir *it = g_dir_open(dir, 0, NULL);
	if( it != NULL )
	{
		const char *name;
		while( (name = g_dir_read_name(it)) != NULL )
		{
			char *path = g_build_filename(dir, name, NULL);
			if( g_file_test(path, G_FILE_TEST_IS_DIR) && !g_file_test(path, G_FILE_TEST_IS_SYMLINK) )
				rm_rf(path);
			else
				g_unlink(path);
			g_free(path);
		}
		g_dir_close(it);
	}
	g_rmdir(dir);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	g_log_set_always_fatal(G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
	stub_dionaea_init();
	g_log_set_default_handler(quiet, NULL);
	return 0;
}

static const char *const SIZES[] = { "", "config.max_size=0.01\n", "config.max_size=0.1\n", "config.max_size=1\n" };
static const char *const FILES[] = { "", "config.max_files=1\n", "config.max_files=2\n", "config.max_files=3\n" };

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_input in = { data, size };
	uint8_t limits = fuzz_u8(&in);

	char *dir = g_dir_make_tmp("dionaea-fuzz-XXXXXX", NULL);
	g_assert_nonnull(dir);
	char *cfg = g_strdup_printf("[processor.streamdumper]\nname=streamdumper\nconfig.path=%s/%%Y-%%m-%%d/\n%s%s",
								dir, SIZES[limits & 3], FILES[(limits >> 2) & 3]);
	if( g_dionaea->config != NULL )
		g_key_file_free(g_dionaea->config);
	g_dionaea->config = g_key_file_new();
	g_assert_true(g_key_file_load_from_data(g_dionaea->config, cfg, -1, G_KEY_FILE_NONE, NULL));
	g_free(cfg);
	dumper = g_malloc0(sizeof(*dumper));
	memcpy(dumper, &proc_streamdumper, sizeof(*dumper));
	dumper->config = dumper->cfg("processor.streamdumper");
	struct streamcap *cap = proc_streamdumper_cap(dumper->config);
	bool limited = cap != NULL;
	if( cap != NULL )
	{
		/* the first count of the (empty) folder */
		struct streamcap_usage u;
		gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
		do
		{
			streamcap_usage_get(cap, &u);
			if( u.counts >= 1 )
				break;
			g_usleep(100);
		} while( g_get_monotonic_time() < deadline );
		g_assert_cmpuint(u.counts, >=, 1);
	}
	stub_pool_new(1);

	struct fconn conns[CONNECTIONS];
	memset(conns, 0, sizeof(conns));
	struct processor_stats before;
	processor_stats_get(&before);

	for( int ops = 0; ops < 64 && fuzz_left(&in) > 0; ops++ )
	{
		uint8_t op = fuzz_u8(&in);
		int index = op & (CONNECTIONS - 1);
		struct fconn *c = &conns[index];
		if( (op >> 2) % 8 == 7 )
		{
			if( c->open && !c->ended )
				conn_end(c);
			continue;
		}
		if( !c->open )
			conn_open(c, index);
		if( c->ended )
			continue;
		conn_io(c, &in);
	}

	/* the jobs end (each holds a reference of its connection, as the closes of the
	 * event loop), then the pool and the connections are freed (connection_free()) */
	for( int i = 0; i < CONNECTIONS; i++ )
		if( conns[i].open && !conns[i].ended )
			conn_end(&conns[i]);
	gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	for( ;; )
	{
		stub_run_async();
		if( g_atomic_int_get(&stub_refs) == 0 )
			break;
		g_assert_cmpint(g_get_monotonic_time(), <, deadline);
		g_usleep(50);
	}
	stub_drain();

	for( int i = 0; i < CONNECTIONS; i++ )
	{
		struct fconn *c = &conns[i];
		if( !c->open )
			continue;
		struct reader_ctx *rc = c->reader_pd->ctx;
		bool closing = g_atomic_int_get(&c->con.processor_data->closing) != 0;
		g_assert_cmpuint(rc->got->len, <=, c->fed_in->len);
		g_assert_cmpmem(rc->got->data, rc->got->len, c->fed_in->data, rc->got->len);
		if( !closing )
			g_assert_cmpuint(rc->got->len, ==, c->fed_in->len);
		processors_clear(&c->con);
		check_dump(c, dir, limited, limited || closing);
	}
	stub_assert_budget_empty();

	guint64 files = 0, bytes = 0;
	count_files(dir, &files, &bytes);
	if( cap != NULL )
	{
		struct streamcap_usage u;
		streamcap_usage_get(cap, &u);
		g_assert_cmpuint(u.open_files, ==, 0);
		g_assert_cmpuint(u.files, ==, files);
		g_assert_cmpuint(u.bytes, ==, bytes);
		if( u.max_files > 0 )
			g_assert_cmpuint(files, <=, u.max_files);
		if( u.max_bytes > 0 )
			g_assert_cmpuint(bytes, <=, u.max_bytes);
	}

	for( int i = 0; i < CONNECTIONS; i++ )
	{
		if( !conns[i].open )
			continue;
		g_byte_array_free(conns[i].fed_in, TRUE);
		g_ptr_array_free(conns[i].events, TRUE);
		g_array_free(conns[i].events_dir, TRUE);
	}
	proc_streamdumper_cfg_free(dumper->config);
	g_free(dumper);
	dumper = NULL;
	rm_rf(dir);
	g_free(dir);
	g_atomic_int_set(&stub_closes, 0);
	return 0;
}
