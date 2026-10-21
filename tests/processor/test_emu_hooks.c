/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * The file hooks of the emulation (modules/emu/hooks.c): CreateFile and
 * _lcreat when no temp file can be made (no descriptor left, a full disk).
 * The emulation fails and the hook returns the error of the API. That and a
 * write of WriteFile that fails (a full disk) are an info line each; one
 * warning a minute sums them up for all emulations (log_summary.h).
 *
 * The success path: CreateFile, WriteFile and CloseHandle on the real temp
 * files of src/util.c (tempdownload_new makes them in /tmp), then the real
 * emulate_ctx_free of modules/emu/emulate.c. The file the emulated program
 * closed is reported as a sample (dionaea.download.complete, url emulate://)
 * with the bytes it wrote, and it is gone afterwards. This needs a writable
 * /tmp, in the container of the processor-test stage as in T-Pot (a tmpfs on
 * /tmp under a read-only root file system); without one the test fails:
 *   docker run --read-only --tmpfs /tmp <image> test_emu_hooks
 */
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>
#include <emu/emu.h>
#include <emu/environment/emu_env.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include "dionaea.h"
#include "connection.h"
#include "incident.h"
#include "threads.h"
#include "util.h"
#include "module.h"
#include "log_summary.h"

struct dionaea *g_dionaea;

/* ---- the temp files: /dev/null, none (-Wl,--wrap=tempdownload_new), or the real ones in /tmp ---- */

struct tempfile *__real_tempdownload_new(char *prefix);

static bool tempfiles_fail;
static bool tempfiles_real;
static gint tempfiles_made;

struct tempfile *__wrap_tempdownload_new(char *prefix)
{
	if( tempfiles_fail )
		return NULL;
	if( tempfiles_real )
		return __real_tempdownload_new(prefix);
	struct tempfile *tf = g_malloc0(sizeof(*tf));
	tf->fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
	g_assert_cmpint(tf->fd, !=, -1);
	tf->fh = fdopen(tf->fd, "w");
	tf->path = g_strdup("/dev/null");
	g_atomic_int_inc(&tempfiles_made);
	return tf;
}

/* ---- the incidents: kept as strings, the file is read when it is reported ---- */

struct incident *incident_new(const char *origin)
{
	struct incident *e = g_malloc0(sizeof(*e));
	e->origin = g_strdup(origin);
	e->data = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	return e;
}

void incident_free(struct incident *e)
{
	GHashTableIter iter;
	gpointer value;
	g_hash_table_iter_init(&iter, e->data);
	while( g_hash_table_iter_next(&iter, NULL, &value) )
		g_string_free(value, TRUE);
	g_hash_table_destroy(e->data);
	g_free(e->origin);
	g_free(e);
}

bool incident_value_string_set(struct incident *e, const char *name, GString *str)
{
	g_hash_table_insert(e->data, g_strdup(name), str);
	return true;
}

struct reported
{
	char *origin;
	char *url;
	char *path;
	char *content;      /* of the file at the time of the report */
	gsize length;
	gboolean read;
};

static GPtrArray *reports;

void incident_report(struct incident *e)
{
	struct reported *r = g_malloc0(sizeof(*r));
	GString *s;
	r->origin = g_strdup(e->origin);
	if( (s = g_hash_table_lookup(e->data, "url")) != NULL )
		r->url = g_strdup(s->str);
	if( (s = g_hash_table_lookup(e->data, "path")) != NULL )
	{
		r->path = g_strdup(s->str);
		r->read = g_file_get_contents(r->path, &r->content, &r->length, NULL);
	}
	g_ptr_array_add(reports, r);
}

static void reported_free(gpointer data)
{
	struct reported *r = data;
	g_free(r->origin);
	g_free(r->url);
	g_free(r->path);
	g_free(r->content);
	g_free(r);
}

/* ---- what else hooks.c calls, never reached by these tests ---- */

#define NOT_REACHED(ret, name, ...) ret name(__VA_ARGS__) { g_assert_not_reached(); }
NOT_REACHED(struct async_cmd *, async_cmd_new, async_cmd_cb function, void *data)
NOT_REACHED(void, async_incident_report, void *data)
NOT_REACHED(bool, bind_local, struct connection *con)
NOT_REACHED(bool, connection_bind, struct connection *con, const char *addr, uint16_t port, const char *iface_scope)
NOT_REACHED(void, connection_connect, struct connection *con, const char *addr, uint16_t port, const char *iface_scope)
NOT_REACHED(void, connection_listen_timeout_cb, struct ev_loop *loop, struct ev_timer *w, int revents)
NOT_REACHED(struct connection *, connection_new, enum connection_transport type)
NOT_REACHED(void, connection_protocol_set, struct connection *con, struct protocol *proto)
NOT_REACHED(void, connection_send, struct connection *con, const void *data, uint32_t size)
NOT_REACHED(void, connection_set_nonblocking, struct connection *con)
NOT_REACHED(const char *, connection_state_to_string, enum connection_state state)
NOT_REACHED(void, connection_stop, struct connection *con)
NOT_REACHED(void, connection_sustain_timeout_set, struct connection *con, double timeout_interval_ms)
NOT_REACHED(void, connection_tcp_accept_cb, struct ev_loop *loop, struct ev_io *w, int revents)
NOT_REACHED(void, connection_tcp_io_in_cb, struct ev_loop *loop, struct ev_io *w, int revents)
NOT_REACHED(void, connection_tls_accept_cb, struct ev_loop *loop, struct ev_io *w, int revents)
NOT_REACHED(int, connection_ref, struct connection *con)
NOT_REACHED(int, connection_unref, struct connection *con)
NOT_REACHED(void, connection_free, struct connection *con)
NOT_REACHED(const char *, connection_type_to_string, enum connection_type type)
NOT_REACHED(void, connection_close, struct connection *con)
NOT_REACHED(bool, incident_value_con_set, struct incident *e, const char *name, struct connection *val)
NOT_REACHED(struct thread *, thread_new, struct connection *con, void *data, GFunc function)
NOT_REACHED(bool, thread_submit, struct thread *t)

/* ---- the tests ---- */

static GPtrArray *warnings;
static GPtrArray *infos;

static void log_handler(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data)
{
	if( level & G_LOG_LEVEL_INFO )
	{
		g_ptr_array_add(infos, g_strdup(message));
		return;
	}
	if( level & (G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_MESSAGE) )
		return;
	if( level & G_LOG_LEVEL_WARNING )
	{
		g_ptr_array_add(warnings, g_strdup(message));
		return;
	}
	g_log_default_handler(domain, level, message, data);
}

struct emulation
{
	struct emu_config conf;
	struct emu_emulate_ctx ctx;
	struct emu_env env;
};

static void emulation_init(struct emulation *e)
{
	memset(e, 0, sizeof(*e));
	e->conf.limits.files = 3;
	e->ctx.config = &e->conf;
	e->ctx.files = g_hash_table_new(g_int_hash, g_int_equal);
	e->ctx.state = running;
	e->env.userdata = &e->ctx;
}

static void emulation_clear(struct emulation *e)
{
	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, e->ctx.files);
	while( g_hash_table_iter_next(&iter, &key, &value) )
	{
		struct tempfile *tf = value;
		tempfile_close(tf);
		g_free(tf->path);
		g_free(tf);
	}
	g_hash_table_destroy(e->ctx.files);
}

static uint32_t create_file(struct emulation *e)
{
	return user_hook_CreateFile(&e->env, NULL, "C:\\x.exe", 0, 0, 0, 0, 0, 0);
}

static uint32_t lcreat(struct emulation *e)
{
	return user_hook__lcreat(&e->env, NULL, "C:\\x.exe", 0);
}

/* the summaries with a clock the test moves and no timer */
static gint64 summary_now;
static gint64 summary_clock(void)
{
	return summary_now;
}

static bool no_timer(struct log_summary *s, double after)
{
	(void)s;
	(void)after;
	return true;
}

static const struct log_summary_hooks summary_hooks = { summary_clock, no_timer };

static void summaries_start(void)
{
	struct log_summary *summaries[] = { &emu_no_file_summary, &emu_write_failed_summary };
	for( size_t i = 0; i < G_N_ELEMENTS(summaries); i++ )
	{
		log_summary_set_hooks(summaries[i], &summary_hooks);
		log_summary_reset(summaries[i]);
	}
	summary_now = 1000 * G_USEC_PER_SEC;
	g_ptr_array_set_size(warnings, 0);
	g_ptr_array_set_size(infos, 0);
}

static guint lines_with(GPtrArray *lines, const char *text)
{
	guint n = 0;
	for( guint i = 0; i < lines->len; i++ )
		if( strstr(g_ptr_array_index(lines, i), text) != NULL )
			n++;
	return n;
}

static void no_tempfile(uint32_t (*hook)(struct emulation *))
{
	struct emulation e;
	emulation_init(&e);
	summaries_start();

	/* a file that can be made is a handle in the table of files */
	tempfiles_fail = false;
	uint32_t fd = hook(&e);
	g_assert_cmpuint(fd, !=, (uint32_t)-1);
	g_assert_nonnull(g_hash_table_lookup(e.ctx.files, &fd));
	g_assert_cmpint(e.ctx.state, ==, running);

	/* none: the error of the API, the emulation fails, the table stays as it was */
	tempfiles_fail = true;
	g_assert_cmpuint(hook(&e), ==, (uint32_t)-1);
	g_assert_cmpint(e.ctx.state, ==, failed);
	g_assert_cmpuint(g_hash_table_size(e.ctx.files), ==, 1);
	g_assert_cmpuint(lines_with(infos, "Could not create a file for the emulation"), ==, 1);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_true(g_str_has_prefix(g_ptr_array_index(warnings, 0), "emulations stopped without a file: "
																	"1 emulation(s) in the last minute, the last: "));
	/* without the connection of the emulation the client is "-" */
	g_assert_true(g_str_has_suffix(g_ptr_array_index(warnings, 0), " (-)"));
	/* more emulations in the minute: info lines, one more warning when it ends */
	for( int i = 0; i < 3; i++ )
	{
		e.ctx.state = running;
		summary_now += G_USEC_PER_SEC;
		g_assert_cmpuint(hook(&e), ==, (uint32_t)-1);
	}
	g_assert_cmpuint(lines_with(infos, "Could not create a file for the emulation"), ==, 4);
	g_assert_cmpuint(warnings->len, ==, 1);
	summary_now += 60 * G_USEC_PER_SEC;
	log_summary_due(&emu_no_file_summary);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_true(g_str_has_prefix(g_ptr_array_index(warnings, 1), "emulations stopped without a file: "
																	"3 emulation(s) in the last minute, "));
	tempfiles_fail = false;

	emulation_clear(&e);
}

static void create_file_no_tempfile(void)
{
	no_tempfile(create_file);
}

static void lcreat_no_tempfile(void)
{
	no_tempfile(lcreat);
}

/* ---- the success path: a file the emulated program writes and closes is a sample ---- */

/* an emulation as emulate() makes it, for the real emulate_ctx_free */
static struct emu_emulate_ctx *emulation_new(void)
{
	struct emu_emulate_ctx *ctx = g_malloc0(sizeof(*ctx));
	ctx->config = g_malloc0(sizeof(*ctx->config));
	ctx->config->limits.files = 3;
	ctx->config->limits.filesize = 1024 * 1024;
	ctx->sockets = g_hash_table_new(g_int_hash, g_int_equal);
	ctx->processes = g_hash_table_new(g_int_hash, g_int_equal);
	ctx->files = g_hash_table_new(g_int_hash, g_int_equal);
	ctx->emu = emu_new();
	ctx->env = emu_env_new(ctx->emu);
	ctx->env->userdata = ctx;
	g_mutex_init(&ctx->mutex);
	ctx->state = running;
	return ctx;
}

static void emulation_done(struct emu_emulate_ctx *ctx)
{
	struct emu_config *conf = ctx->config;
	emulate_ctx_free(ctx);
	g_free(conf);
}

static const char SAMPLE[] = "MZ\x90\x00 the bytes of the emulated program\r\n\x00\xff";

/* the program creates, writes and closes: a sample with its bytes, the file gone afterwards */
static void create_write_close_is_a_sample(void)
{
	struct emu_emulate_ctx *ctx = emulation_new();
	struct emu_env *env = ctx->env;
	g_ptr_array_set_size(reports, 0);
	tempfiles_real = true;

	uint32_t fd = user_hook_CreateFile(env, NULL, "C:\\x.exe", 0, 0, 0, 0, 0, 0);
	g_assert_cmpuint(fd, !=, (uint32_t)-1);
	struct tempfile *tf = g_hash_table_lookup(ctx->files, &fd);
	g_assert_nonnull(tf);
	g_assert_true(g_str_has_prefix(tf->path, "/tmp/emu-"));
	g_assert_true(g_file_test(tf->path, G_FILE_TEST_IS_REGULAR));
	char *path = g_strdup(tf->path);

	g_assert_cmpuint(user_hook_WriteFile(env, NULL, fd, (void *)SAMPLE, (int)sizeof(SAMPLE), (int *)NULL, (int *)NULL), ==, 1);
	g_assert_cmpuint(user_hook_CloseHandle(env, NULL, fd), ==, 0);
	g_assert_null(tf->fh);
	g_assert_cmpint(ctx->state, ==, running);
	/* closed by the program: nothing is reported before the emulation is done */
	g_assert_cmpuint(reports->len, ==, 0);

	emulation_done(ctx);
	tempfiles_real = false;

	g_assert_cmpuint(reports->len, ==, 1);
	struct reported *r = g_ptr_array_index(reports, 0);
	g_assert_cmpstr(r->origin, ==, "dionaea.download.complete");
	g_assert_true(g_str_has_prefix(r->url, "emulate://"));
	g_assert_cmpstr(r->path, ==, path);
	g_assert_true(r->read);
	g_assert_cmpuint(r->length, ==, sizeof(SAMPLE));
	g_assert_cmpmem(r->content, r->length, SAMPLE, sizeof(SAMPLE));
	/* the real code removes the file after the report, and closed its descriptor */
	g_assert_false(g_file_test(path, G_FILE_TEST_EXISTS));
	errno = 0;
	g_assert_cmpint(fcntl((int)fd, F_GETFD), ==, -1);
	g_assert_cmpint(errno, ==, EBADF);
	g_free(path);
}

/* a write of WriteFile that fails (a full disk: /dev/full without a buffer): info, one warning a minute */
static void write_failures_are_info_and_one_warning_a_minute(void)
{
	struct emulation e;
	emulation_init(&e);
	e.conf.limits.filesize = 1024 * 1024;
	/* the connection of the client whose code is emulated */
	struct connection con;
	memset(&con, 0, sizeof(con));
	g_strlcpy(con.remote.ip_string, "198.51.100.8", sizeof(con.remote.ip_string));
	e.ctx.ctxcon = &con;
	summaries_start();
	struct tempfile *tf = g_malloc0(sizeof(*tf));
	tf->fd = open("/dev/full", O_WRONLY | O_CLOEXEC);
	g_assert_cmpint(tf->fd, !=, -1);
	tf->fh = fdopen(tf->fd, "w");
	g_assert_cmpint(setvbuf(tf->fh, NULL, _IONBF, 0), ==, 0);
	tf->path = g_strdup("/dev/full");
	uint32_t fd = (uint32_t)tf->fd;
	g_hash_table_insert(e.ctx.files, &tf->fd, tf);
	for( int i = 0; i < 5; i++ )
	{
		g_assert_cmpuint(user_hook_WriteFile(&e.env, NULL, fd, (void *)SAMPLE, (int)sizeof(SAMPLE), (int *)NULL,
											 (int *)NULL), ==, 1);
		summary_now += G_USEC_PER_SEC;
	}
	g_assert_cmpuint(lines_with(infos, "fwrite failed No space left on device (198.51.100.8)"), ==, 5);
	g_assert_cmpuint(warnings->len, ==, 1);
	g_assert_cmpstr(g_ptr_array_index(warnings, 0), ==, "writes of emulations failed: 1 write(s) in the last minute, "
														"the last: No space left on device (198.51.100.8)");
	summary_now += 60 * G_USEC_PER_SEC;
	log_summary_due(&emu_write_failed_summary);
	g_assert_cmpuint(warnings->len, ==, 2);
	g_assert_cmpstr(g_ptr_array_index(warnings, 1), ==, "writes of emulations failed: 4 write(s) in the last minute, "
														"the last: No space left on device (198.51.100.8)");
	emulation_clear(&e);
}

/* a file still open when the emulation ends is no sample, and it is removed too */
static void open_file_is_no_sample(void)
{
	struct emu_emulate_ctx *ctx = emulation_new();
	struct emu_env *env = ctx->env;
	g_ptr_array_set_size(reports, 0);
	tempfiles_real = true;

	uint32_t fd = user_hook_CreateFile(env, NULL, "C:\\x.exe", 0, 0, 0, 0, 0, 0);
	g_assert_cmpuint(fd, !=, (uint32_t)-1);
	struct tempfile *tf = g_hash_table_lookup(ctx->files, &fd);
	g_assert_nonnull(tf);
	char *path = g_strdup(tf->path);
	g_assert_cmpuint(user_hook_WriteFile(env, NULL, fd, (void *)SAMPLE, (int)sizeof(SAMPLE), (int *)NULL, (int *)NULL), ==, 1);

	emulation_done(ctx);
	tempfiles_real = false;

	g_assert_cmpuint(reports->len, ==, 0);
	g_assert_false(g_file_test(path, G_FILE_TEST_EXISTS));
	errno = 0;
	g_assert_cmpint(fcntl((int)fd, F_GETFD), ==, -1);
	g_assert_cmpint(errno, ==, EBADF);
	g_free(path);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	warnings = g_ptr_array_new_with_free_func(g_free);
	infos = g_ptr_array_new_with_free_func(g_free);
	reports = g_ptr_array_new_with_free_func(reported_free);
	g_log_set_always_fatal(G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
	g_log_set_default_handler(log_handler, NULL);
	g_test_add_func("/emu-hooks/CreateFile/no-tempfile", create_file_no_tempfile);
	g_test_add_func("/emu-hooks/_lcreat/no-tempfile", lcreat_no_tempfile);
	g_test_add_func("/emu-hooks/files/create-write-close-is-a-sample", create_write_close_is_a_sample);
	g_test_add_func("/emu-hooks/files/open-file-is-no-sample", open_file_is_no_sample);
	g_test_add_func("/emu-hooks/WriteFile/write-failures", write_failures_are_info_and_one_warning_a_minute);
	int result = g_test_run();
	g_ptr_array_free(reports, TRUE);
	g_ptr_array_free(warnings, TRUE);
	g_ptr_array_free(infos, TRUE);
	return result;
}
