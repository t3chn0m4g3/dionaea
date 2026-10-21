/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * The streamdumper (src/processor.c) and its temp files (src/util.c): every
 * file is closed once; its limits config.max_size and config.max_files
 * (src/streamcap.c): no dump past them, the counting thread, the warnings.
 */
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "stubs.h"
#include "util.h"
#include "streamcap.h"

/*
 * close() of the code under test is wrapped (-Wl,--wrap=close): a close of a
 * descriptor that is not open is counted. fclose() closes its descriptor inside
 * libc, past the wrapper. A second close of the same number closes whatever was
 * opened under it meanwhile, by another thread or connection.
 */
static gint closes_of_closed_fds;

int __real_close(int fd);
int __wrap_close(int fd)
{
	if( fcntl(fd, F_GETFD) == -1 && errno == EBADF )
		g_atomic_int_inc(&closes_of_closed_fds);
	return __real_close(fd);
}

/*
 * fstatat() and readdir() of the code under test are wrapped
 * (-Wl,--wrap=fstatat,--wrap=readdir): the calls are counted, and every fstatat
 * can take fs_delay_us, a slow filesystem (a cold Docker Desktop bind mount
 * takes milliseconds per entry). The tests themselves read folders with GLib and
 * lstat, past the wrappers.
 */
static gint fstatat_calls;
static gint readdir_calls;
static gint fs_delay_us;

int __real_fstatat(int dirfd, const char *path, struct stat *st, int flags);
int __wrap_fstatat(int dirfd, const char *path, struct stat *st, int flags)
{
	g_atomic_int_inc(&fstatat_calls);
	gint delay = g_atomic_int_get(&fs_delay_us);
	if( delay > 0 )
		g_usleep(delay);
	return __real_fstatat(dirfd, path, st, flags);
}

/* readdir() of the folder with this inode fails with EIO (0: none), a folder that can not be read */
static gint64 fail_dir_ino;
/* the readdir() calls of two folders, by inode (0: none) */
static gint64 watch_ino[2];
static gint watch_reads[2];

/*
 * The readdir() that ends the listing of the folder with this inode (0: none)
 * waits until the test releases it, once: the counting thread stands between
 * its listing of the base and what it does with it.
 */
static gint64 pause_ino;
static GMutex pause_lock;
static GCond pause_cond;
static bool pause_reached;
static bool pause_released;

static void pause_at_end(void)
{
	g_mutex_lock(&pause_lock);
	__atomic_store_n(&pause_ino, 0, __ATOMIC_SEQ_CST);
	pause_reached = true;
	g_cond_broadcast(&pause_cond);
	while( !pause_released )
		g_cond_wait(&pause_cond, &pause_lock);
	g_mutex_unlock(&pause_lock);
}

struct dirent *__real_readdir(DIR *dir);
struct dirent *__wrap_readdir(DIR *dir)
{
	g_atomic_int_inc(&readdir_calls);
	gint64 fail = __atomic_load_n(&fail_dir_ino, __ATOMIC_SEQ_CST);
	gint64 w0 = __atomic_load_n(&watch_ino[0], __ATOMIC_SEQ_CST);
	gint64 w1 = __atomic_load_n(&watch_ino[1], __ATOMIC_SEQ_CST);
	gint64 pause = __atomic_load_n(&pause_ino, __ATOMIC_SEQ_CST);
	bool pausing = false;
	if( fail != 0 || w0 != 0 || w1 != 0 || pause != 0 )
	{
		struct stat st;
		if( fstat(dirfd(dir), &st) == 0 )
		{
			if( w0 != 0 && (gint64)st.st_ino == w0 )
				g_atomic_int_inc(&watch_reads[0]);
			if( w1 != 0 && (gint64)st.st_ino == w1 )
				g_atomic_int_inc(&watch_reads[1]);
			if( fail != 0 && (gint64)st.st_ino == fail )
			{
				errno = EIO;
				return NULL;
			}
			pausing = pause != 0 && (gint64)st.st_ino == pause;
		}
	}
	struct dirent *entry = __real_readdir(dir);
	if( entry == NULL && pausing )
	{
		int error = errno;
		pause_at_end();
		errno = error;
	}
	return entry;
}

static void fs_calls_reset(void)
{
	g_atomic_int_set(&fstatat_calls, 0);
	g_atomic_int_set(&readdir_calls, 0);
}

/* warnings are kept, not fatal: the tests look for them; and the info lines */
static GMutex warnings_lock;
static GPtrArray *warnings;
static GPtrArray *infos;

static void log_handler(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data)
{
	if( level & G_LOG_LEVEL_INFO )
	{
		g_mutex_lock(&warnings_lock);
		g_ptr_array_add(infos, g_strdup(message));
		g_mutex_unlock(&warnings_lock);
		return;
	}
	if( level & (G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_MESSAGE) )
		return;
	if( level & G_LOG_LEVEL_WARNING )
	{
		g_mutex_lock(&warnings_lock);
		g_ptr_array_add(warnings, g_strdup(message));
		g_mutex_unlock(&warnings_lock);
		return;
	}
	g_log_default_handler(domain, level, message, data);
}

static void warnings_reset(void)
{
	g_mutex_lock(&warnings_lock);
	g_ptr_array_set_size(warnings, 0);
	g_ptr_array_set_size(infos, 0);
	g_mutex_unlock(&warnings_lock);
}

/* the info lines that are exactly text */
static guint infos_equal(const char *text)
{
	guint n = 0;
	g_mutex_lock(&warnings_lock);
	for( guint i = 0; i < infos->len; i++ )
		if( strcmp(g_ptr_array_index(infos, i), text) == 0 )
			n++;
	g_mutex_unlock(&warnings_lock);
	return n;
}

/* the info lines that begin with prefix */
static guint infos_with_prefix(const char *prefix)
{
	guint n = 0;
	g_mutex_lock(&warnings_lock);
	for( guint i = 0; i < infos->len; i++ )
		if( g_str_has_prefix(g_ptr_array_index(infos, i), prefix) )
			n++;
	g_mutex_unlock(&warnings_lock);
	return n;
}

/* the warnings that contain text */
static guint warnings_with(const char *text)
{
	guint n = 0;
	g_mutex_lock(&warnings_lock);
	for( guint i = 0; i < warnings->len; i++ )
		if( strstr(g_ptr_array_index(warnings, i), text) != NULL )
			n++;
	g_mutex_unlock(&warnings_lock);
	return n;
}

static bool fd_open(int fd)
{
	return fcntl(fd, F_GETFD) != -1;
}

static char *tmp_dir(void)
{
	GError *error = NULL;
	char *dir = g_dir_make_tmp("streamdumper-XXXXXX", &error);
	g_assert_no_error(error);
	return dir;
}

static void rm_rf(const char *path)
{
	char *cmd = g_strdup_printf("rm -rf '%s'", path);
	g_assert_cmpint(system(cmd), ==, 0);
	g_free(cmd);
}

static void tempfile_closes_once(void)
{
	char *dir = tmp_dir();
	g_atomic_int_set(&closes_of_closed_fds, 0);

	struct tempfile *tf = tempfile_new(dir, "x-");
	g_assert_nonnull(tf);
	g_assert_nonnull(tf->fh);
	int fd = tf->fd;
	g_assert_true(fd_open(fd));
	g_assert_cmpint(fwrite("abc", 1, 3, tf->fh), ==, 3);
	tempfile_close(tf);
	g_assert_false(fd_open(fd));
	g_assert_cmpint(tf->fd, ==, -1);
	g_assert_null(tf->fh);
	/* a second close of the struct is harmless */
	tempfile_close(tf);
	g_assert_cmpint(g_atomic_int_get(&closes_of_closed_fds), ==, 0);

	char *content = NULL;
	g_assert_true(g_file_get_contents(tf->path, &content, NULL, NULL));
	g_assert_cmpstr(content, ==, "abc");
	g_free(content);
	tempfile_unlink(tf);
	tempfile_free(tf);
	rm_rf(dir);
	g_free(dir);
}

/*
 * fclose() is wrapped as well: with other_path set, a file is opened right
 * after it, as another thread or connection could do. It gets the number that
 * fclose() gave back; a second close of that number would close it.
 */
static const char *other_path;
static int other_fd = -1;

int __real_fclose(FILE *fh);
int __wrap_fclose(FILE *fh)
{
	int fd = fileno(fh);
	int rc = __real_fclose(fh);
	if( other_path != NULL && other_fd == -1 )
	{
		other_fd = open(other_path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
		g_assert_cmpint(other_fd, ==, fd);
	}
	return rc;
}

static void tempfile_close_keeps_the_next_file(void)
{
	char *dir = tmp_dir();
	char *other = g_build_filename(dir, "other", NULL);
	g_atomic_int_set(&closes_of_closed_fds, 0);

	struct tempfile *tf = tempfile_new(dir, "x-");
	g_assert_nonnull(tf);
	other_path = other;
	other_fd = -1;
	tempfile_close(tf);
	other_path = NULL;
	g_assert_cmpint(other_fd, !=, -1);
	/* the file opened after the fclose() is still open */
	g_assert_true(fd_open(other_fd));
	g_assert_cmpint(__real_close(other_fd), ==, 0);
	other_fd = -1;

	tempfile_unlink(tf);
	tempfile_free(tf);
	g_free(other);
	rm_rf(dir);
	g_free(dir);
}

static void tempfile_new_fails_cleanly(void)
{
	char *dir = tmp_dir();
	char *missing = g_build_filename(dir, "missing", NULL);
	/* the path of the failed file is not leaked (ASan) */
	warnings_reset();
	g_assert_null(tempfile_new(missing, "x-"));
	g_assert_cmpuint(warnings_with("could not open path"), ==, 1);
	g_free(missing);
	rm_rf(dir);
	g_free(dir);
}

/* the streamdumper of one connection: [processor.streamdumper] with config.path below base */
static struct processor *streamdumper_new(const char *base, const char *extra)
{
	extern struct processor proc_streamdumper;
	char *cfg = g_strdup_printf("[processor.streamdumper]\nname=streamdumper\nconfig.path=%s/%%Y-%%m-%%d/\n%s",
								base, extra != NULL ? extra : "");
	GError *error = NULL;
	if( g_dionaea->config != NULL )
		g_key_file_free(g_dionaea->config);
	g_dionaea->config = g_key_file_new();
	g_assert_true(g_key_file_load_from_data(g_dionaea->config, cfg, -1, G_KEY_FILE_NONE, &error));
	g_assert_no_error(error);
	g_free(cfg);

	struct processor *p = g_malloc0(sizeof(*p));
	memcpy(p, &proc_streamdumper, sizeof(*p));
	p->config = p->cfg("processor.streamdumper");
	g_assert_nonnull(p->config);
	return p;
}

void proc_streamdumper_cfg_free(void *cfg);

static void streamdumper_free(struct processor *p)
{
	proc_streamdumper_cfg_free(p->config);
	g_free(p);
}

static void connection_init(struct connection *con, int port)
{
	memset(con, 0, sizeof(*con));
	con->protocol.name = "test";
	g_strlcpy(con->local.ip_string, "10.0.0.1", sizeof(con->local.ip_string));
	g_strlcpy(con->remote.ip_string, "10.0.0.2", sizeof(con->remote.ip_string));
	con->local.port = htons(445);
	con->remote.port = htons(port);
	gettimeofday(&con->stats.start, NULL);
}

struct dump
{
	struct connection con;
	struct processor_data pd;
};

static void dump_open(struct dump *d, struct processor *p, int port)
{
	connection_init(&d->con, port);
	memset(&d->pd, 0, sizeof(d->pd));
	d->pd.processor = p;
	d->pd.ctx = p->new(p->config);
}

static void dump_io(struct dump *d, enum bistream_direction dir, const char *data, size_t size)
{
	if( dir == bistream_in )
		d->pd.processor->io_in(&d->con, &d->pd, (void *)data, (int)size);
	else
		d->pd.processor->io_out(&d->con, &d->pd, (void *)data, (int)size);
}

static void dump_close(struct dump *d)
{
	d->pd.processor->free(d->pd.ctx);
	d->pd.ctx = NULL;
}

/* the content of the only dump below dir */
static char *only_dump(const char *dir)
{
	GDir *days = g_dir_open(dir, 0, NULL);
	g_assert_nonnull(days);
	const char *day = g_dir_read_name(days);
	g_assert_nonnull(day);
	char *day_path = g_build_filename(dir, day, NULL);
	GDir *files = g_dir_open(day_path, 0, NULL);
	g_assert_nonnull(files);
	const char *name = g_dir_read_name(files);
	g_assert_nonnull(name);
	g_assert_null(g_dir_read_name(files));
	char *path = g_build_filename(day_path, name, NULL);
	char *content = NULL;
	g_assert_true(g_file_get_contents(path, &content, NULL, NULL));
	g_free(path);
	g_dir_close(files);
	g_free(day_path);
	g_dir_close(days);
	return content;
}

static void streamdumper_closes_once(void)
{
	char *dir = tmp_dir();
	g_atomic_int_set(&closes_of_closed_fds, 0);
	struct processor *p = streamdumper_new(dir, NULL);

	struct dump d;
	dump_open(&d, p, 1000);
	dump_io(&d, bistream_in, "GET /\r\n", 7);
	dump_io(&d, bistream_out, "200 'ok'", 8);
	dump_io(&d, bistream_in, "x", 1);
	dump_close(&d);
	g_assert_cmpint(g_atomic_int_get(&closes_of_closed_fds), ==, 0);

	/* the format of a dump stays as it was */
	char *content = only_dump(dir);
	g_assert_cmpstr(content, ==,
					"stream = [('in', b'GET /\\x0d\\x0a'),\n"
					"('out', b'200 \\x27ok\\x27'),\n"
					"('in', b'x')]");
	g_free(content);

	streamdumper_free(p);
	rm_rf(dir);
	g_free(dir);
}

#define KIB 1024
#define MIB (1024 * 1024)

struct large_read
{
	struct dump *dump;
	const char *data;
	size_t size;
};

static void *large_read_thread(void *arg)
{
	struct large_read *read = arg;
	dump_io(read->dump, bistream_in, read->data, read->size);
	return NULL;
}

/*
 * A TCP read takes what the socket holds and one byte (connection_tcp.c); the
 * receive buffer of a host holds up to net.ipv4.tcp_rmem, 6 MiB by default.
 * Such a read is dumped in full, from a thread with a stack of 512 KiB.
 */
static void streamdumper_large_read(void)
{
	char *dir = tmp_dir();
	struct processor *p = streamdumper_new(dir, NULL);
	const size_t size = 6 * MIB + 1;
	char *data = g_malloc(size);
	for( size_t i = 0; i < size; i++ )
		data[i] = (i % 3 == 0) ? (char)(i & 0xff) : (char)('a' + i % 26);

	struct dump d;
	dump_open(&d, p, 1001);
	struct large_read read = { &d, data, size };
	pthread_attr_t attr;
	g_assert_cmpint(pthread_attr_init(&attr), ==, 0);
	g_assert_cmpint(pthread_attr_setstacksize(&attr, 512 * KIB), ==, 0);
	pthread_t thread;
	g_assert_cmpint(pthread_create(&thread, &attr, large_read_thread, &read), ==, 0);
	g_assert_cmpint(pthread_join(thread, NULL), ==, 0);
	pthread_attr_destroy(&attr);
	dump_close(&d);

	GString *want = g_string_new("stream = [('in', b'");
	for( size_t i = 0; i < size; i++ )
	{
		unsigned char c = (unsigned char)data[i];
		if( c >= 0x20 && c <= 0x7e && c != '\'' && c != '\\' )
			g_string_append_c(want, (char)c);
		else
			g_string_append_printf(want, "\\x%02x", c);
	}
	g_string_append(want, "')]");
	char *content = only_dump(dir);
	g_assert_cmpuint(strlen(content), ==, want->len);
	g_assert_true(strcmp(content, want->str) == 0);
	g_free(content);
	g_string_free(want, TRUE);
	g_free(data);

	streamdumper_free(p);
	rm_rf(dir);
	g_free(dir);
}

/*
 * The dump has a byte of 0x20..0x7e other than ' and \ as it is and every other byte as \xNN,
 * in every locale: Python sets LC_CTYPE of the process from the environment, and in a locale
 * of one byte per character isprint() takes bytes above 0x7e as well (the processor-test stage
 * of the Dockerfile makes en_US.ISO-8859-1).
 */
static void streamdumper_locale(void)
{
	if( setlocale(LC_CTYPE, "en_US.ISO-8859-1") == NULL )
	{
		g_test_skip("no locale en_US.ISO-8859-1");
		return;
	}
	g_assert_true(isprint(0xe4));
	char *dir = tmp_dir();
	struct processor *p = streamdumper_new(dir, NULL);
	char data[256];
	for( int i = 0; i < 256; i++ )
		data[i] = (char)i;
	struct dump d;
	dump_open(&d, p, 1002);
	dump_io(&d, bistream_in, data, sizeof(data));
	dump_close(&d);
	setlocale(LC_CTYPE, "C");

	GString *want = g_string_new("stream = [('in', b'");
	for( int i = 0; i < 256; i++ )
	{
		unsigned char c = (unsigned char)i;
		if( c >= 0x20 && c <= 0x7e && c != '\'' && c != '\\' )
			g_string_append_c(want, (char)c);
		else
			g_string_append_printf(want, "\\x%02x", c);
	}
	g_string_append(want, "')]");
	char *content = only_dump(dir);
	g_assert_cmpstr(content, ==, want->str);
	g_free(content);
	g_string_free(want, TRUE);
	streamdumper_free(p);
	rm_rf(dir);
	g_free(dir);
}

/* ---- the limits (config.max_size, config.max_files, src/streamcap.c) ---- */

struct streamcap *proc_streamdumper_cap(void *cfg);

static void parse(void)
{
	guint64 v;
	struct { const char *value; bool ok; guint64 bytes; } sizes[] = {
		{ NULL, true, 0 }, { "", true, 0 }, { "0", true, 0 }, { " 2 ", true, 2 * MIB },
		{ "1.5", true, 3 * MIB / 2 }, { "2048", true, 2048ULL * MIB },
		{ "-1", false, 0 }, { "abc", false, 0 }, { "1x", false, 0 }, { "nan", false, 0 },
		{ "inf", false, 0 }, { "1e300", false, 0 }, { "1 # MiB", false, 0 },
		/* a limit below one byte is one byte, not 0 (= no limit) */
		{ "0.0000001", true, 1 }, { "1e-300", true, 1 }, { "0.000001", true, 1 },
	};
	for( size_t i = 0; i < G_N_ELEMENTS(sizes); i++ )
	{
		v = 7;
		g_assert_cmpint(streamcap_parse_mib(sizes[i].value, &v), ==, sizes[i].ok);
		if( sizes[i].ok )
			g_assert_cmpuint(v, ==, sizes[i].bytes);
	}
	struct { const char *value; bool ok; guint64 count; } counts[] = {
		{ NULL, true, 0 }, { "", true, 0 }, { "0", true, 0 }, { "200000", true, 200000 }, { " 5", true, 5 },
		{ "-1", false, 0 }, { "+1", false, 0 }, { "1.5", false, 0 }, { "x", false, 0 },
		{ "99999999999999999999999", false, 0 },
	};
	for( size_t i = 0; i < G_N_ELEMENTS(counts); i++ )
	{
		v = 7;
		g_assert_cmpint(streamcap_parse_count(counts[i].value, &v), ==, counts[i].ok);
		if( counts[i].ok )
			g_assert_cmpuint(v, ==, counts[i].count);
	}
}

/*
 * DIONAEA_STREAMDUMPER_MAX_SIZE (MiB) and _MAX_FILES: decimal digits only, in the range
 * of config.max_size and config.max_files; 0 is no limit as in the config
 */
static void parse_env(void)
{
	guint64 v;
	struct { const char *value; bool ok; guint64 bytes; } sizes[] = {
		{ "0", true, 0 }, { "1", true, MIB }, { "2048", true, 2048ULL * MIB }, { "007", true, 7ULL * MIB },
		/* the largest config.max_size, 2^40 MiB */
		{ "1099511627776", true, 1099511627776ULL * MIB },
		{ "1099511627777", false, 0 }, { "99999999999999999999999999999", false, 0 },
		{ "", false, 0 }, { " 2", false, 0 }, { "2 ", false, 0 }, { "\t2", false, 0 }, { "2\n", false, 0 },
		{ "+2", false, 0 }, { "-2", false, 0 }, { "1.5", false, 0 }, { "2M", false, 0 }, { "2MiB", false, 0 },
		{ "0x10", false, 0 }, { "1e3", false, 0 }, { "inf", false, 0 }, { "nan", false, 0 }, { "abc", false, 0 },
		{ "\xd9\xa3", false, 0 },
	};
	for( size_t i = 0; i < G_N_ELEMENTS(sizes); i++ )
	{
		v = 7;
		g_assert_cmpint(streamcap_parse_env_mib(sizes[i].value, &v), ==, sizes[i].ok);
		if( sizes[i].ok )
			g_assert_cmpuint(v, ==, sizes[i].bytes);
	}
	struct { const char *value; bool ok; guint64 count; } counts[] = {
		{ "0", true, 0 }, { "40", true, 40 }, { "200000", true, 200000 }, { "0040", true, 40 },
		{ "18446744073709551615", true, G_MAXUINT64 },
		{ "18446744073709551616", false, 0 }, { "99999999999999999999999", false, 0 },
		{ "", false, 0 }, { " 5", false, 0 }, { "5 ", false, 0 }, { "+1", false, 0 }, { "-1", false, 0 },
		{ "1.5", false, 0 }, { "1e3", false, 0 }, { "5k", false, 0 }, { "0x10", false, 0 }, { "x", false, 0 },
	};
	for( size_t i = 0; i < G_N_ELEMENTS(counts); i++ )
	{
		v = 7;
		g_assert_cmpint(streamcap_parse_env_count(counts[i].value, &v), ==, counts[i].ok);
		if( counts[i].ok )
			g_assert_cmpuint(v, ==, counts[i].count);
	}
}

/* a rejected value in the warning: printable characters only, at most 64 */
static void env_shown(void)
{
	char *s = streamcap_env_shown("2048 MiB");
	g_assert_cmpstr(s, ==, "2048 MiB");
	g_free(s);
	s = streamcap_env_shown("a\nb\tc\x1b[31m\xc3\xa4");
	g_assert_cmpstr(s, ==, "a?b?c?[31m??");
	g_free(s);
	char *long_value = g_strnfill(100, '9');
	s = streamcap_env_shown(long_value);
	g_assert_cmpuint(strlen(s), ==, 64);
	g_assert_true(strspn(s, "9") == 64);
	g_free(s);
	g_free(long_value);
	s = streamcap_env_shown("");
	g_assert_cmpstr(s, ==, "");
	g_free(s);
}

static void base(void)
{
	struct { const char *path; const char *base; } cases[] = {
		{ "/opt/dionaea/var/dionaea/bistreams/%Y-%m-%d/", "/opt/dionaea/var/dionaea/bistreams" },
		{ "/data/bistreams//%Y/%m/%d/", "/data/bistreams" },
		{ "bistreams/%Y-%m-%d", "bistreams" },
		{ "/data/day-%Y/", "/data" },
		{ "/%Y/", "/" },
		{ "%Y/", "." },
	};
	for( size_t i = 0; i < G_N_ELEMENTS(cases); i++ )
	{
		char *b = streamcap_base(cases[i].path);
		g_assert_cmpstr(b, ==, cases[i].base);
		g_free(b);
	}
}

/* the files below dir (recursive), their number and total size */
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
				*bytes += st.st_size;
			}
		}
		g_free(path);
	}
	g_dir_close(it);
}

static void put_file(const char *dir, const char *name, size_t size)
{
	g_assert_cmpint(g_mkdir_with_parents(dir, 0700), ==, 0);
	char *path = g_build_filename(dir, name, NULL);
	char *content = g_malloc(size + 1);
	memset(content, 'o', size);
	g_assert_true(g_file_set_contents(path, content, size, NULL));
	g_free(content);
	g_free(path);
}

static char *filled(size_t size, char c)
{
	char *data = g_malloc(size);
	memset(data, c, size);
	return data;
}

static void assert_usage(struct streamcap *cap, const char *dir)
{
	guint64 files = 0, bytes = 0;
	count_files(dir, &files, &bytes);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, files);
	g_assert_cmpuint(u.bytes, ==, bytes);
}

/* files files of size bytes in dir/day */
static void put_files(const char *dir, const char *day, int files, size_t size)
{
	char *path = g_build_filename(dir, day, NULL);
	for( int i = 0; i < files; i++ )
	{
		char name[32];
		g_snprintf(name, sizeof(name), "dump-%d", i);
		put_file(path, name, size);
	}
	g_free(path);
}

/* wait (at most 10 s) until the first count of the folder ended */
static void wait_counted(struct streamcap *cap)
{
	gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	struct streamcap_usage u;
	for( ;; )
	{
		streamcap_usage_get(cap, &u);
		if( u.counts >= 1 )
			return;
		g_assert_cmpint(g_get_monotonic_time(), <, deadline);
		g_usleep(G_TIME_SPAN_MILLISECOND);
	}
}

/* wait (at most 10 s) until the total holds files files */
static void wait_files(struct streamcap *cap, guint64 files)
{
	gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	struct streamcap_usage u;
	for( ;; )
	{
		streamcap_usage_get(cap, &u);
		if( u.files == files )
			return;
		if( g_get_monotonic_time() >= deadline )
			g_assert_cmpuint(u.files, ==, files);
		g_usleep(G_TIME_SPAN_MILLISECOND);
	}
}

/* wait (at most 10 s) until the counting thread ended n more checks of the folder */
static void wait_checks(struct streamcap *cap, guint64 n)
{
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	guint64 until = u.counts + n;
	gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	while( u.counts < until )
	{
		g_assert_cmpint(g_get_monotonic_time(), <, deadline);
		g_usleep(G_TIME_SPAN_MILLISECOND);
		streamcap_usage_get(cap, &u);
	}
}

/* wait (at most 10 s) until the counting thread ended a check after the one with the number counts */
static void wait_check_after(struct streamcap *cap, guint64 counts)
{
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	while( u.counts <= counts )
	{
		g_assert_cmpint(g_get_monotonic_time(), <, deadline);
		g_usleep(G_TIME_SPAN_MILLISECOND);
		streamcap_usage_get(cap, &u);
	}
}

/*
 * An mtime long ago for the folder: a change in it from now on gives it another
 * one, however coarse the clock of the filesystem is.
 */
static void old_mtime(const char *path)
{
	struct timespec times[2] = { { .tv_sec = 1, .tv_nsec = 0 }, { .tv_sec = 1, .tv_nsec = 0 } };
	g_assert_cmpint(utimensat(AT_FDCWD, path, times, 0), ==, 0);
}

static void unlimited(void)
{
	const char *options[] = { NULL, "config.max_size=0\nconfig.max_files=0\n", "config.max_size=\nconfig.max_files=\n" };
	for( size_t o = 0; o < G_N_ELEMENTS(options); o++ )
	{
		char *dir = tmp_dir();
		warnings_reset();
		struct processor *p = streamdumper_new(dir, options[o]);
		/* no limit, no thread, no counting */
		g_assert_null(proc_streamdumper_cap(p->config));
		for( int i = 0; i < 20; i++ )
		{
			struct dump d;
			dump_open(&d, p, 2000 + i);
			dump_io(&d, bistream_in, "hello", 5);
			dump_close(&d);
		}
		guint64 files = 0, bytes = 0;
		count_files(dir, &files, &bytes);
		g_assert_cmpuint(files, ==, 20);
		g_assert_cmpuint(warnings->len, ==, 0);
		streamdumper_free(p);
		rm_rf(dir);
		g_free(dir);
	}
}

static void invalid_options(void)
{
	char *dir = tmp_dir();
	warnings_reset();
	struct processor *p = streamdumper_new(dir, "config.max_size=lots\nconfig.max_files=-5\n");
	g_assert_cmpuint(warnings_with("config.max_size"), ==, 1);
	g_assert_cmpuint(warnings_with("config.max_files"), ==, 1);
	g_assert_null(proc_streamdumper_cap(p->config));
	struct dump d;
	dump_open(&d, p, 3000);
	dump_io(&d, bistream_in, "hello", 5);
	dump_close(&d);
	guint64 files = 0, bytes = 0;
	count_files(dir, &files, &bytes);
	g_assert_cmpuint(files, ==, 1);
	streamdumper_free(p);

	/* one valid limit stays when the other one is invalid */
	warnings_reset();
	p = streamdumper_new(dir, "config.max_size=x\nconfig.max_files=2\n");
	g_assert_cmpuint(warnings_with("config.max_size"), ==, 1);
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	g_assert_nonnull(cap);
	wait_counted(cap);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.max_bytes, ==, 0);
	g_assert_cmpuint(u.max_files, ==, 2);
	g_assert_cmpuint(u.files, ==, 1);
	streamdumper_free(p);
	rm_rf(dir);
	g_free(dir);
}

#define ENV_SIZE "DIONAEA_STREAMDUMPER_MAX_SIZE"
#define ENV_FILES "DIONAEA_STREAMDUMPER_MAX_FILES"

static void env_set(const char *size, const char *files)
{
	if( size != NULL )
		g_assert_true(g_setenv(ENV_SIZE, size, TRUE));
	else
		g_unsetenv(ENV_SIZE);
	if( files != NULL )
		g_assert_true(g_setenv(ENV_FILES, files, TRUE));
	else
		g_unsetenv(ENV_FILES);
}

/* the limits of the config and of the cap */
static void assert_limits(struct processor *p, guint64 max_bytes, guint64 max_files)
{
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	if( max_bytes == 0 && max_files == 0 )
	{
		g_assert_null(cap);
		return;
	}
	g_assert_nonnull(cap);
	wait_counted(cap);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.max_bytes, ==, max_bytes);
	g_assert_cmpuint(u.max_files, ==, max_files);
}

/* without the variables: the config, one line per limit names it */
static void startup_lines_config(void)
{
	char *dir = tmp_dir();
	env_set(NULL, NULL);
	warnings_reset();
	struct processor *p = streamdumper_new(dir, "config.max_size=2048\nconfig.max_files=200000\n");
	assert_limits(p, 2048ULL * MIB, 200000);
	g_assert_cmpuint(infos_equal("streamdumper: max_size 2048 MiB (from dionaea.cfg)"), ==, 1);
	g_assert_cmpuint(infos_equal("streamdumper: max_files 200000 (from dionaea.cfg)"), ==, 1);
	g_assert_cmpuint(infos_with_prefix("streamdumper: max_size "), ==, 1);
	g_assert_cmpuint(infos_with_prefix("streamdumper: max_files "), ==, 1);
	g_assert_cmpuint(warnings->len, ==, 0);
	streamdumper_free(p);

	/* no limit is 0, also without the options, and a fraction of the config as it is */
	warnings_reset();
	p = streamdumper_new(dir, NULL);
	assert_limits(p, 0, 0);
	g_assert_cmpuint(infos_equal("streamdumper: max_size 0 MiB (from dionaea.cfg)"), ==, 1);
	g_assert_cmpuint(infos_equal("streamdumper: max_files 0 (from dionaea.cfg)"), ==, 1);
	streamdumper_free(p);
	warnings_reset();
	p = streamdumper_new(dir, "config.max_size=0.25\n");
	assert_limits(p, MIB / 4, 0);
	g_assert_cmpuint(infos_equal("streamdumper: max_size 0.25 MiB (from dionaea.cfg)"), ==, 1);
	streamdumper_free(p);
	rm_rf(dir);
	g_free(dir);
}

/* a set variable replaces the value of the config */
static void env_limits(void)
{
	char *dir = tmp_dir();
	env_set("3", "2");
	warnings_reset();
	struct processor *p = streamdumper_new(dir, "config.max_size=2048\nconfig.max_files=200000\n");
	assert_limits(p, 3 * MIB, 2);
	g_assert_cmpuint(infos_equal("streamdumper: max_size 3 MiB (from DIONAEA_STREAMDUMPER_MAX_SIZE)"), ==, 1);
	g_assert_cmpuint(infos_equal("streamdumper: max_files 2 (from DIONAEA_STREAMDUMPER_MAX_FILES)"), ==, 1);
	g_assert_cmpuint(warnings->len, ==, 0);
	/* the limit of the variable is the one that holds: the third dump is refused */
	struct dump a, b, c;
	dump_open(&a, p, 6001);
	dump_io(&a, bistream_in, "a", 1);
	dump_open(&b, p, 6002);
	dump_io(&b, bistream_in, "b", 1);
	dump_open(&c, p, 6003);
	dump_io(&c, bistream_in, "c", 1);
	guint64 files = 0, bytes = 0;
	count_files(dir, &files, &bytes);
	g_assert_cmpuint(files, ==, 2);
	g_assert_cmpuint(warnings_with("max_files 2"), ==, 1);
	dump_close(&a);
	dump_close(&b);
	dump_close(&c);
	streamdumper_free(p);
	rm_rf(dir);
	g_free(dir);

	/* without the options in the config, and only one of them */
	dir = tmp_dir();
	env_set(NULL, "40");
	warnings_reset();
	p = streamdumper_new(dir, "config.max_size=1\n");
	assert_limits(p, MIB, 40);
	g_assert_cmpuint(infos_equal("streamdumper: max_size 1 MiB (from dionaea.cfg)"), ==, 1);
	g_assert_cmpuint(infos_equal("streamdumper: max_files 40 (from DIONAEA_STREAMDUMPER_MAX_FILES)"), ==, 1);
	streamdumper_free(p);

	/* 0 is no limit, as in the config */
	env_set("0", "0");
	warnings_reset();
	p = streamdumper_new(dir, "config.max_size=1\nconfig.max_files=5\n");
	assert_limits(p, 0, 0);
	g_assert_cmpuint(infos_equal("streamdumper: max_size 0 MiB (from DIONAEA_STREAMDUMPER_MAX_SIZE)"), ==, 1);
	g_assert_cmpuint(infos_equal("streamdumper: max_files 0 (from DIONAEA_STREAMDUMPER_MAX_FILES)"), ==, 1);
	streamdumper_free(p);

	/* the variable replaces an invalid value of the config: that value is not read */
	env_set("5", "7");
	warnings_reset();
	p = streamdumper_new(dir, "config.max_size=lots\nconfig.max_files=-5\n");
	assert_limits(p, 5 * MIB, 7);
	g_assert_cmpuint(warnings->len, ==, 0);
	g_assert_cmpuint(infos_equal("streamdumper: max_size 5 MiB (from DIONAEA_STREAMDUMPER_MAX_SIZE)"), ==, 1);
	streamdumper_free(p);
	env_set(NULL, NULL);
	rm_rf(dir);
	g_free(dir);
}

/* an invalid variable: one warning with its name and value, the config value stays */
static void env_invalid(void)
{
	const char *values[] = { "2048 MiB", "-1", "+3", " 3", "1.5", "1e3", "abc", "99999999999999999999999999999" };
	for( size_t i = 0; i < G_N_ELEMENTS(values); i++ )
	{
		char *dir = tmp_dir();
		env_set(values[i], values[i]);
		warnings_reset();
		struct processor *p = streamdumper_new(dir, "config.max_size=2\nconfig.max_files=3\n");
		assert_limits(p, 2 * MIB, 3);
		char *size = g_strdup_printf("Ignoring DIONAEA_STREAMDUMPER_MAX_SIZE='%s'", values[i]);
		char *files = g_strdup_printf("Ignoring DIONAEA_STREAMDUMPER_MAX_FILES='%s'", values[i]);
		g_assert_cmpuint(warnings_with(size), ==, 1);
		g_assert_cmpuint(warnings_with(files), ==, 1);
		g_assert_cmpuint(warnings_with("dionaea.cfg"), ==, 2);
		g_assert_cmpuint(warnings->len, ==, 2);
		g_assert_cmpuint(infos_equal("streamdumper: max_size 2 MiB (from dionaea.cfg)"), ==, 1);
		g_assert_cmpuint(infos_equal("streamdumper: max_files 3 (from dionaea.cfg)"), ==, 1);
		g_free(size);
		g_free(files);
		streamdumper_free(p);
		rm_rf(dir);
		g_free(dir);
	}

	/* the value in the warning: printable characters, at most 64 */
	char *dir = tmp_dir();
	char *long_value = g_strnfill(200, '7');
	long_value[0] = 'x';
	long_value[1] = '\n';
	env_set(long_value, NULL);
	warnings_reset();
	struct processor *p = streamdumper_new(dir, "config.max_size=2\n");
	assert_limits(p, 2 * MIB, 0);
	char *shown = g_strdup_printf("Ignoring DIONAEA_STREAMDUMPER_MAX_SIZE='x?%.62s'", long_value + 2);
	g_assert_cmpuint(warnings_with(shown), ==, 1);
	g_assert_cmpuint(warnings_with("\n"), ==, 0);
	g_assert_cmpuint(warnings_with(long_value + 2), ==, 0);
	g_free(shown);
	g_free(long_value);
	streamdumper_free(p);
	env_set(NULL, NULL);
	rm_rf(dir);
	g_free(dir);
}

/* an empty variable counts as unset: no warning, the config */
static void env_empty(void)
{
	char *dir = tmp_dir();
	env_set("", "");
	warnings_reset();
	struct processor *p = streamdumper_new(dir, "config.max_size=2\nconfig.max_files=3\n");
	assert_limits(p, 2 * MIB, 3);
	g_assert_cmpuint(warnings->len, ==, 0);
	g_assert_cmpuint(infos_equal("streamdumper: max_size 2 MiB (from dionaea.cfg)"), ==, 1);
	g_assert_cmpuint(infos_equal("streamdumper: max_files 3 (from dionaea.cfg)"), ==, 1);
	streamdumper_free(p);
	env_set(NULL, NULL);
	rm_rf(dir);
	g_free(dir);
}

static gint64 fake_now;
static gint64 fake_clock(void)
{
	return fake_now;
}

static void max_files(void)
{
	char *dir = tmp_dir();
	char *old = g_build_filename(dir, "2020-01-01", NULL);
	put_file(old, "old-dump", 10);
	warnings_reset();
	struct processor *p = streamdumper_new(dir, "config.max_files=3\n");
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	g_assert_nonnull(cap);
	wait_counted(cap);
	fake_now = 1000 * G_TIME_SPAN_SECOND;
	streamcap_clock_set(cap, fake_clock);
	/* the old dump in another date folder counts */
	assert_usage(cap, dir);

	struct dump a, b, c, e;
	dump_open(&a, p, 4001);
	dump_io(&a, bistream_in, "a", 1);
	dump_open(&b, p, 4002);
	dump_io(&b, bistream_in, "b", 1);
	/* 3 of 3 files: c gets no file, and nothing later, the connection goes on */
	dump_open(&c, p, 4003);
	dump_io(&c, bistream_in, "c", 1);
	guint64 files = 0, bytes = 0;
	count_files(dir, &files, &bytes);
	g_assert_cmpuint(files, ==, 3);
	g_assert_cmpuint(warnings_with("Not dumping"), ==, 1);
	g_assert_cmpuint(warnings_with("3 of 3 files"), ==, 1);
	g_assert_cmpuint(warnings_with("max_files 3"), ==, 1);
	g_assert_cmpuint(warnings_with("max_size unlimited"), ==, 1);

	/* within the period: no second warning */
	dump_open(&e, p, 4004);
	dump_io(&e, bistream_in, "e", 1);
	dump_close(&e);
	g_assert_cmpuint(warnings_with("Not dumping"), ==, 1);

	/* a closed dump stays in the folder and counts */
	dump_close(&a);
	dump_open(&e, p, 4007);
	dump_io(&e, bistream_in, "e", 1);
	dump_close(&e);
	/* the old dump is removed, the next count notices: a slot is free again */
	rm_rf(old);
	streamcap_recount(cap);
	/* c stays without a dump, its stream began without one */
	dump_io(&c, bistream_out, "c2", 2);
	dump_io(&c, bistream_in, "c3", 2);
	files = bytes = 0;
	count_files(dir, &files, &bytes);
	g_assert_cmpuint(files, ==, 2);
	dump_close(&c);

	/* the free slot goes to a new connection */
	struct dump f;
	dump_open(&f, p, 4005);
	dump_io(&f, bistream_in, "f", 1);
	files = bytes = 0;
	count_files(dir, &files, &bytes);
	g_assert_cmpuint(files, ==, 3);

	/* after the period the next refusal is logged, with the refusals in between */
	fake_now += 61 * G_TIME_SPAN_SECOND;
	dump_open(&e, p, 4006);
	dump_io(&e, bistream_in, "e", 1);
	dump_close(&e);
	g_assert_cmpuint(warnings_with("Not dumping"), ==, 2);
	g_assert_cmpuint(warnings_with("of 2 new connection"), ==, 0);
	g_assert_cmpuint(warnings_with("of 3 new connection"), ==, 1);

	dump_close(&b);
	dump_close(&f);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.refused, ==, 4);
	g_assert_cmpuint(u.open_files, ==, 0);
	assert_usage(cap, dir);
	streamcap_recount(cap);
	assert_usage(cap, dir);

	streamdumper_free(p);
	g_free(old);
	rm_rf(dir);
	g_free(dir);
}

static void max_size(void)
{
	char *dir = tmp_dir();
	warnings_reset();
	struct processor *p = streamdumper_new(dir, "config.max_size=1\n");
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	g_assert_nonnull(cap);
	wait_counted(cap);
	char *data = filled(700 * KIB, 'A');

	struct dump a, b, c, d;
	dump_open(&a, p, 5001);
	dump_io(&a, bistream_in, data, 700 * KIB);
	dump_close(&a);
	assert_usage(cap, dir);

	/* 700 KiB + 400 KiB do not fit into 1 MiB */
	dump_open(&b, p, 5002);
	dump_io(&b, bistream_in, data, 400 * KIB);
	dump_close(&b);
	g_assert_cmpuint(warnings_with("Not dumping"), ==, 1);
	g_assert_cmpuint(warnings_with("max_size 1 MiB"), ==, 1);
	/* the payload is not in the log */
	g_assert_cmpuint(warnings_with("AAAA"), ==, 0);

	/* the escaped size counts: 100 KiB of \x00 are 400 KiB in the dump */
	char *zeros = filled(100 * KIB, 0);
	dump_open(&b, p, 5003);
	dump_io(&b, bistream_in, zeros, 100 * KIB);
	dump_close(&b);
	g_free(zeros);

	/* 100 KiB fit; the answer of 500 KiB does not: the dump stops and is closed */
	dump_open(&c, p, 5004);
	dump_io(&c, bistream_in, data, 100 * KIB);
	dump_io(&c, bistream_out, data, 500 * KIB);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.bytes, <=, 1 * MIB);
	g_assert_cmpuint(u.open_files, ==, 0);
	g_assert_cmpuint(u.stopped, ==, 1);
	g_assert_cmpuint(warnings_with("Stopped dumping"), ==, 1);
	g_assert_cmpuint(warnings_with("AAAA"), ==, 0);
	assert_usage(cap, dir);
	/* the room that is left goes to a new connection */
	dump_open(&d, p, 5005);
	dump_io(&d, bistream_in, "x", 1);
	dump_close(&d);
	dump_io(&c, bistream_in, "more", 4);
	dump_close(&c);

	guint64 files = 0, bytes = 0;
	count_files(dir, &files, &bytes);
	g_assert_cmpuint(files, ==, 3);
	g_assert_cmpuint(bytes, <=, 1 * MIB);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.refused, ==, 2);
	assert_usage(cap, dir);
	streamcap_recount(cap);
	assert_usage(cap, dir);

	g_free(data);
	streamdumper_free(p);
	rm_rf(dir);
	g_free(dir);
}

/* an open dump counts with the bytes written to it, once, whatever stdio has flushed */
static void open_dump_counted(void)
{
	char *dir = tmp_dir();
	char *day = g_build_filename(dir, "2020-01-01", NULL);
	put_file(day, "old", 1000);
	struct processor *p = streamdumper_new(dir, "config.max_files=100\n");
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	wait_counted(cap);

	struct dump a;
	dump_open(&a, p, 6001);
	for( int i = 0; i < 10; i++ )
		dump_io(&a, i % 2 ? bistream_out : bistream_in, "0123456789", 10);
	struct streamcap_usage before, after;
	streamcap_usage_get(cap, &before);
	streamcap_recount(cap);
	streamcap_usage_get(cap, &after);
	g_assert_cmpuint(after.files, ==, 2);
	g_assert_cmpuint(after.bytes, ==, before.bytes);
	g_assert_cmpuint(after.counts, >, before.counts);
	dump_close(&a);
	assert_usage(cap, dir);

	streamdumper_free(p);
	g_free(day);
	rm_rf(dir);
	g_free(dir);
}

/* a folder that is emptied from outside is noticed by the next count (every period) */
static void notices_deletion(void)
{
	char *dir = tmp_dir();
	char *day = g_build_filename(dir, "2020-01-01", NULL);
	put_file(day, "a", 100);
	put_file(day, "b", 100);
	struct streamcap *cap = streamcap_new(dir, 0, 2, 50 * G_TIME_SPAN_MILLISECOND);
	g_assert_nonnull(cap);
	wait_counted(cap);
	g_assert_null(streamcap_open(cap, 10));

	rm_rf(day);
	gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	struct streamcap_dump *dump;
	while( (dump = streamcap_open(cap, 10)) == NULL )
	{
		g_assert_cmpint(g_get_monotonic_time(), <, deadline);
		g_usleep(10 * G_TIME_SPAN_MILLISECOND);
	}
	streamcap_close(cap, dump, false);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 0);
	g_assert_cmpuint(u.bytes, ==, 0);
	streamcap_free(cap);

	/* the base folder itself is gone */
	rm_rf(dir);
	cap = streamcap_new(dir, 1 * MIB, 0, STREAMCAP_PERIOD);
	wait_counted(cap);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.bytes, ==, 0);
	streamcap_free(cap);

	g_free(day);
	g_free(dir);
}

/* dumps closed and made while the folder is counted are counted once */
struct gate_hook
{
	struct stub_gate gate;
	gint calls;
};

static void gate_hook(struct streamcap *cap, const char *name, void *data)
{
	(void)cap;
	(void)name;
	struct gate_hook *h = data;
	if( g_atomic_int_add(&h->calls, 1) == 0 )
		stub_gate_wait(&h->gate);
}

static gpointer recount_thread(gpointer cap)
{
	streamcap_recount(cap);
	return NULL;
}

static void close_during_count(void)
{
	char *dir = tmp_dir();
	char *day = g_build_filename(dir, "2020-01-01", NULL);
	for( int i = 0; i < 5; i++ )
	{
		char name[16];
		g_snprintf(name, sizeof(name), "old-%d", i);
		put_file(day, name, 100 + i);
	}
	struct processor *p = streamdumper_new(dir, "config.max_files=100\n");
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	wait_counted(cap);
	struct dump a, b, c;
	dump_open(&a, p, 7001);
	dump_io(&a, bistream_in, "aaaa", 4);
	dump_open(&b, p, 7002);
	dump_io(&b, bistream_in, "bbbb", 4);

	struct gate_hook h = { 0 };
	stub_gate_reset(&h.gate);
	streamcap_count_hook_set(cap, gate_hook, &h);
	GThread *t = g_thread_new("recount", recount_thread, cap);
	stub_gate_await(&h.gate, 1);
	/* the count stands at its first file: dumps close, a new one is made and closed */
	dump_io(&a, bistream_out, "more", 4);
	dump_close(&a);
	dump_open(&c, p, 7003);
	dump_io(&c, bistream_in, "cccc", 4);
	dump_close(&c);
	stub_gate_release(&h.gate);
	g_thread_join(t);
	streamcap_count_hook_set(cap, NULL, NULL);

	/* b is still open */
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.open_files, ==, 1);
	dump_close(&b);
	assert_usage(cap, dir);

	streamdumper_free(p);
	g_free(day);
	rm_rf(dir);
	g_free(dir);
}

/* the counting thread against the eventloop (ThreadSanitizer) */
static void concurrent(void)
{
	char *dir = tmp_dir();
	struct streamcap *cap = streamcap_new(dir, 64 * MIB, 100000, 1 * G_TIME_SPAN_MILLISECOND);
	char *day = g_build_filename(dir, "day", NULL);
	g_assert_cmpint(g_mkdir_with_parents(day, 0700), ==, 0);
	for( int i = 0; i < 400; i++ )
	{
		struct streamcap_dump *dump = streamcap_open(cap, 0);
		g_assert_nonnull(dump);
		char *path = g_strdup_printf("%s/f-%d", day, i);
		FILE *fh = fopen(path, "w");
		g_assert_nonnull(fh);
		streamcap_opened(cap, dump, fileno(fh), day);
		for( int j = 0; j < i % 7; j++ )
		{
			g_assert_true(streamcap_reserve(cap, dump, 10));
			g_assert_cmpint(fwrite("0123456789", 10, 1, fh), ==, 1);
		}
		fclose(fh);
		streamcap_close(cap, dump, true);
		g_free(path);
		if( i % 50 == 0 )
			g_usleep(2 * G_TIME_SPAN_MILLISECOND);
	}
	streamcap_recount(cap);
	assert_usage(cap, dir);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.counts, >, 1);
	streamcap_free(cap);
	g_free(day);
	rm_rf(dir);
	g_free(dir);
}

/* the dumps below dir, sorted by name */
static GPtrArray *all_dumps(const char *dir)
{
	GPtrArray *dumps = g_ptr_array_new_with_free_func(g_free);
	GDir *days = g_dir_open(dir, 0, NULL);
	g_assert_nonnull(days);
	const char *day;
	while( (day = g_dir_read_name(days)) != NULL )
	{
		char *day_path = g_build_filename(dir, day, NULL);
		GDir *files = g_dir_open(day_path, 0, NULL);
		g_assert_nonnull(files);
		const char *name;
		while( (name = g_dir_read_name(files)) != NULL )
			g_ptr_array_add(dumps, g_build_filename(day_path, name, NULL));
		g_dir_close(files);
		g_free(day_path);
	}
	g_dir_close(days);
	return dumps;
}

static char *dump_of_port(const char *dir, int port)
{
	GPtrArray *dumps = all_dumps(dir);
	char *needle = g_strdup_printf("-10.0.0.2-%d-", port);
	char *content = NULL;
	for( guint i = 0; i < dumps->len; i++ )
	{
		const char *path = g_ptr_array_index(dumps, i);
		if( strstr(path, needle) != NULL )
		{
			g_assert_null(content);
			g_assert_true(g_file_get_contents(path, &content, NULL, NULL));
		}
	}
	g_assert_nonnull(content);
	g_free(needle);
	g_ptr_array_free(dumps, TRUE);
	return content;
}

/* the path of the dump of port (newly allocated) */
static char *dump_path_of_port(const char *dir, int port)
{
	GPtrArray *dumps = all_dumps(dir);
	char *needle = g_strdup_printf("-10.0.0.2-%d-", port);
	char *found = NULL;
	for( guint i = 0; i < dumps->len; i++ )
		if( strstr(g_ptr_array_index(dumps, i), needle) != NULL )
			found = g_strdup(g_ptr_array_index(dumps, i));
	g_assert_nonnull(found);
	g_free(needle);
	g_ptr_array_free(dumps, TRUE);
	return found;
}

/*
 * An open dump counts with the bytes it will have when it is closed; a chunk
 * that does not fit below max_size stops the dump: it is closed as at the end
 * of its connection, in the format of a dump, and nothing more is written to it.
 */
static void stops_at_max_size(void)
{
	char *dir = tmp_dir();
	warnings_reset();
	/* 0.0001 MiB: 104 bytes */
	struct processor *p = streamdumper_new(dir, "config.max_size=0.0001\n");
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	g_assert_nonnull(cap);
	wait_counted(cap);
	fake_now = 5000 * G_TIME_SPAN_SECOND;
	streamcap_clock_set(cap, fake_clock);

	struct dump a, b, c;
	dump_open(&a, p, 8001);
	dump_io(&a, bistream_in, "hello", 5);
	/* stream = [('in', b'hello')] : 27 bytes once closed, counted so already */
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.bytes, ==, 27);
	dump_io(&a, bistream_out, "world", 5);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.bytes, ==, 46);
	/* 73 more bytes do not fit into 104 */
	char *xs = filled(60, 'x');
	dump_io(&a, bistream_in, xs, 60);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.bytes, ==, 46);
	g_assert_cmpuint(u.open_files, ==, 0);
	g_assert_cmpuint(u.files, ==, 1);
	g_assert_cmpuint(u.stopped, ==, 1);
	assert_usage(cap, dir);
	char *content = dump_of_port(dir, 8001);
	g_assert_cmpstr(content, ==, "stream = [('in', b'hello'),\n('out', b'world')]");
	g_free(content);
	g_assert_cmpuint(warnings_with("Stopped dumping the streams of 1 connection(s)"), ==, 1);
	g_assert_cmpuint(warnings_with("46 of 104 bytes"), ==, 1);
	g_assert_cmpuint(warnings_with("hello"), ==, 0);
	g_assert_cmpuint(warnings_with("xxxx"), ==, 0);

	/* nothing more goes into the stopped dump, the connection goes on */
	dump_io(&a, bistream_out, "y", 1);
	dump_io(&a, bistream_in, "z", 1);

	/* the room left goes to a new connection, which stops at the limit as well */
	dump_open(&b, p, 8002);
	dump_io(&b, bistream_in, "b", 1);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.bytes, ==, 46 + 23);
	dump_io(&b, bistream_in, xs, 60);
	dump_io(&b, bistream_in, "bb", 2);
	/* within the period: one warning */
	g_assert_cmpuint(warnings_with("Stopped dumping"), ==, 1);
	content = dump_of_port(dir, 8002);
	g_assert_cmpstr(content, ==, "stream = [('in', b'b')]");
	g_free(content);

	/* after the period the next stop is logged with the stops in between */
	fake_now += 61 * G_TIME_SPAN_SECOND;
	dump_open(&c, p, 8003);
	dump_io(&c, bistream_in, "c", 1);
	dump_io(&c, bistream_out, xs, 60);
	g_assert_cmpuint(warnings_with("Stopped dumping"), ==, 2);
	g_assert_cmpuint(warnings_with("Stopped dumping the streams of 2 connection(s)"), ==, 1);

	dump_close(&a);
	dump_close(&b);
	dump_close(&c);
	content = dump_of_port(dir, 8003);
	g_assert_cmpstr(content, ==, "stream = [('in', b'c')]");
	g_free(content);
	guint64 files = 0, bytes = 0;
	count_files(dir, &files, &bytes);
	g_assert_cmpuint(files, ==, 3);
	g_assert_cmpuint(bytes, <=, 104);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.stopped, ==, 3);
	g_assert_cmpuint(u.bytes, ==, bytes);
	assert_usage(cap, dir);
	streamcap_recount(cap);
	assert_usage(cap, dir);

	g_free(xs);
	streamdumper_free(p);
	rm_rf(dir);
	g_free(dir);
}

/* a cap with max_files only stops no dump */
static void max_files_does_not_stop(void)
{
	char *dir = tmp_dir();
	struct processor *p = streamdumper_new(dir, "config.max_files=10\n");
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	char *data = filled(256 * KIB, 0);
	struct dump a;
	dump_open(&a, p, 8101);
	for( int i = 0; i < 8; i++ )
		dump_io(&a, i % 2 ? bistream_out : bistream_in, data, 256 * KIB);
	dump_close(&a);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.stopped, ==, 0);
	g_assert_cmpuint(u.bytes, >, 8 * MIB);
	assert_usage(cap, dir);
	g_free(data);
	streamdumper_free(p);
	rm_rf(dir);
	g_free(dir);
}

/* streamcap_stop() ends the counting thread at once; the cap still counts what is written */
static void stop(void)
{
	char *dir = tmp_dir();
	char *day = g_build_filename(dir, "day", NULL);
	put_file(day, "a", 10);
	struct streamcap *cap = streamcap_new(dir, 1 * MIB, 0, 1 * G_TIME_SPAN_MILLISECOND);
	/* the thread checks the folder every period */
	wait_checks(cap, 3);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_true(u.counting_thread);
	streamcap_stop(cap);
	streamcap_usage_get(cap, &u);
	g_assert_false(u.counting_thread);
	guint64 checks = u.counts;
	g_usleep(30 * G_TIME_SPAN_MILLISECOND);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.counts, ==, checks);
	/* a second stop and the free after it are harmless */
	streamcap_stop(cap);
	struct streamcap_dump *dump = streamcap_open(cap, 10);
	g_assert_nonnull(dump);
	streamcap_close(cap, dump, false);
	streamcap_free(cap);
	g_free(day);
	rm_rf(dir);
	g_free(dir);
}

/* at the end of dionaea the counting threads stop before the loggers are closed */
static void tree_shutdown(void)
{
	char *dir = tmp_dir();
	struct processor *p = streamdumper_new(dir, "config.max_files=10\n");
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	extern struct processor proc_filter;
	struct processor filter = proc_filter;
	GNode *tree = g_node_new(NULL);
	GNode *f = g_node_append_data(tree, &filter);
	g_node_append_data(f, p);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_true(u.counting_thread);
	processors_tree_shutdown(tree);
	streamcap_usage_get(cap, &u);
	g_assert_false(u.counting_thread);
	/* a connection that is still open closes its dump */
	struct dump a;
	dump_open(&a, p, 8201);
	dump_io(&a, bistream_in, "a", 1);
	dump_close(&a);
	assert_usage(cap, dir);
	g_node_destroy(tree);
	streamdumper_free(p);
	rm_rf(dir);
	g_free(dir);
}

/*
 * At the end of dionaea the connections that are still open are never freed, so
 * their dumps used to end without the closing "')]" (no Python literal). The
 * shutdown of the streamdumper closes them as at the end of their connection; a
 * free of the connection afterwards writes nothing more, closes nothing twice.
 */
static void shutdown_closes_open_dumps(gconstpointer limited)
{
	char *dir = tmp_dir();
	g_atomic_int_set(&closes_of_closed_fds, 0);
	struct processor *p = streamdumper_new(dir, limited != NULL ? "config.max_files=10\n" : NULL);
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	extern struct processor proc_filter;
	struct processor filter = proc_filter;
	GNode *tree = g_node_new(NULL);
	GNode *f = g_node_append_data(tree, &filter);
	g_node_append_data(f, p);

	struct dump a, b, closed, none;
	dump_open(&a, p, 8301);
	dump_io(&a, bistream_in, "GET /", 5);
	dump_io(&a, bistream_out, "200", 3);
	dump_open(&b, p, 8302);
	dump_io(&b, bistream_out, "220 banner", 10);
	/* one closed before the stop, one without data (no dump) */
	dump_open(&closed, p, 8303);
	dump_io(&closed, bistream_in, "x", 1);
	dump_close(&closed);
	dump_open(&none, p, 8304);

	processors_tree_shutdown(tree);

	char *content = dump_of_port(dir, 8301);
	g_assert_cmpstr(content, ==, "stream = [('in', b'GET /'),\n('out', b'200')]");
	g_free(content);
	content = dump_of_port(dir, 8302);
	g_assert_cmpstr(content, ==, "stream = [('out', b'220 banner')]");
	g_free(content);
	content = dump_of_port(dir, 8303);
	g_assert_cmpstr(content, ==, "stream = [('in', b'x')]");
	g_free(content);
	if( cap != NULL )
		assert_usage(cap, dir);

	/* data after the stop starts no dump of the closed ones; the free writes nothing */
	dump_io(&a, bistream_in, "late", 4);
	dump_close(&a);
	dump_close(&b);
	dump_close(&none);
	content = dump_of_port(dir, 8301);
	g_assert_cmpstr(content, ==, "stream = [('in', b'GET /'),\n('out', b'200')]");
	g_free(content);
	content = dump_of_port(dir, 8302);
	g_assert_cmpstr(content, ==, "stream = [('out', b'220 banner')]");
	g_free(content);
	GPtrArray *dumps = all_dumps(dir);
	g_assert_cmpuint(dumps->len, ==, 3);
	g_ptr_array_free(dumps, TRUE);
	g_assert_cmpint(g_atomic_int_get(&closes_of_closed_fds), ==, 0);
	if( cap != NULL )
		assert_usage(cap, dir);

	g_node_destroy(tree);
	streamdumper_free(p);
	rm_rf(dir);
	g_free(dir);
}

/* ---- the cost of the counts: no walk of the whole folder per period ---- */

/*
 * The folder is counted once, in the counting thread: streamcap_new() returns
 * at once however slow the folder is (dionaea listens), and meanwhile a new
 * dump is admitted from what this process counted (the dumps of an earlier run
 * are not in the total yet).
 */
static void starts_at_once(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 100, 10);
	put_files(dir, "2020-01-02", 100, 10);
	/* 200 entries of 10 ms: a count of 2 s */
	g_atomic_int_set(&fs_delay_us, 10000);
	gint64 start = g_get_monotonic_time();
	struct streamcap *cap = streamcap_new(dir, 0, 150, STREAMCAP_PERIOD);
	gint64 took = g_get_monotonic_time() - start;
	g_assert_cmpint(took, <, 500 * G_TIME_SPAN_MILLISECOND);
	/* 200 of 150 files, but not counted yet: the dump is admitted */
	struct streamcap_dump *dump = streamcap_open(cap, 10);
	g_assert_nonnull(dump);
	streamcap_close(cap, dump, false);
	g_atomic_int_set(&fs_delay_us, 0);
	wait_counted(cap);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 200);
	g_assert_cmpuint(u.bytes, ==, 2000);
	g_assert_null(streamcap_open(cap, 10));
	streamcap_free(cap);
	rm_rf(dir);
	g_free(dir);
}

/* streamcap_stop() during a slow count of the folder returns after the entry it reads */
static void stop_during_count(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 300, 10);
	/* 300 entries of 10 ms: a count of 3 s; the period of 1 ms counts again at once */
	g_atomic_int_set(&fs_delay_us, 10000);
	struct streamcap *cap = streamcap_new(dir, 0, 1000, 1 * G_TIME_SPAN_MILLISECOND);
	/* a count runs */
	gint calls = g_atomic_int_get(&fstatat_calls);
	gint64 deadline = g_get_monotonic_time() + 10 * G_TIME_SPAN_SECOND;
	while( g_atomic_int_get(&fstatat_calls) < calls + 5 )
	{
		g_assert_cmpint(g_get_monotonic_time(), <, deadline);
		g_usleep(G_TIME_SPAN_MILLISECOND);
	}
	gint64 start = g_get_monotonic_time();
	streamcap_stop(cap);
	gint64 took = g_get_monotonic_time() - start;
	g_atomic_int_set(&fs_delay_us, 0);
	g_assert_cmpint(took, <, 1 * G_TIME_SPAN_SECOND);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_false(u.counting_thread);
	streamcap_free(cap);
	rm_rf(dir);
	g_free(dir);
}

/*
 * After the first count a period looks only at the date folders directly in
 * the base: a folder of 200 dumps is not read again (on a cold Docker Desktop
 * bind mount a walk of 188,000 dumps took minutes, and the eventloop's file
 * requests waited behind it).
 */
static void no_walk_per_period(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 100, 10);
	put_files(dir, "2020-01-02", 100, 10);
	struct streamcap *cap = streamcap_new(dir, 0, 1000, 5 * G_TIME_SPAN_MILLISECOND);
	wait_counted(cap);
	wait_checks(cap, 1);
	fs_calls_reset();
	/* 20 periods */
	wait_checks(cap, 20);
	gint stats = g_atomic_int_get(&fstatat_calls);
	gint reads = g_atomic_int_get(&readdir_calls);
	streamcap_stop(cap);
	/* one walk alone would take 200; every period reads the base (2 entries): a missed --wrap would give 0 */
	g_assert_cmpint(stats, >=, 20);
	g_assert_cmpint(stats, <, 100);
	g_assert_cmpint(reads, >=, 20);
	g_assert_cmpint(reads, <, 200);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.full_counts, ==, 1);
	g_assert_cmpuint(u.dir_counts, ==, 0);
	g_assert_cmpuint(u.files, ==, 200);
	g_assert_cmpuint(u.bytes, ==, 2000);
	streamcap_free(cap);
	rm_rf(dir);
	g_free(dir);
}

/* a date folder that vanishes takes its dumps out of the total; the other folders are not read again */
static void vanished_dir(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 50, 10);
	put_files(dir, "2020-01-02", 50, 20);
	struct streamcap *cap = streamcap_new(dir, 0, 1000, 5 * G_TIME_SPAN_MILLISECOND);
	wait_counted(cap);
	wait_checks(cap, 1);
	fs_calls_reset();
	char *day = g_build_filename(dir, "2020-01-01", NULL);
	rm_rf(day);
	wait_files(cap, 50);
	wait_checks(cap, 3);
	gint stats = g_atomic_int_get(&fstatat_calls);
	streamcap_stop(cap);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.bytes, ==, 1000);
	/* 2020-01-02 was not read again, the base was (3 checks) */
	g_assert_cmpint(stats, >=, 3);
	g_assert_cmpint(stats, <, 50);
	g_assert_cmpuint(u.full_counts, ==, 1);
	g_assert_cmpuint(u.dir_counts, ==, 0);
	streamcap_free(cap);
	g_free(day);
	rm_rf(dir);
	g_free(dir);
}

/* the base folder replaced (as T-Pot's clean.sh does: rm -rf, mkdir): counted again */
static void base_replaced(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 20, 10);
	struct streamcap *cap = streamcap_new(dir, 0, 1000, 5 * G_TIME_SPAN_MILLISECOND);
	wait_counted(cap);
	/* the new base is made beside it and moved in whole: a count sees all of it */
	char *old = g_strdup_printf("%s.old", dir);
	char *new = g_strdup_printf("%s.new", dir);
	put_files(new, "2020-01-01", 3, 7);
	g_assert_cmpint(rename(dir, old), ==, 0);
	g_assert_cmpint(rename(new, dir), ==, 0);
	g_free(new);
	wait_files(cap, 3);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.bytes, ==, 21);
	g_assert_cmpuint(u.full_counts, >=, 2);
	/* emptied: the base and its date folder are gone */
	rm_rf(dir);
	wait_files(cap, 0);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.bytes, ==, 0);
	streamcap_free(cap);
	rm_rf(old);
	g_free(old);
	g_free(dir);
}

/* a date folder made from outside after the start is counted, once */
static void new_dir_counted(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 20, 10);
	struct streamcap *cap = streamcap_new(dir, 0, 1000, 5 * G_TIME_SPAN_MILLISECOND);
	wait_counted(cap);
	/* made beside the base and moved in whole: the count of it sees all of it */
	char *beside = g_strdup_printf("%s.new", dir);
	put_files(beside, "2020-02-01", 5, 3);
	char *from = g_build_filename(beside, "2020-02-01", NULL);
	char *to = g_build_filename(dir, "2020-02-01", NULL);
	g_assert_cmpint(rename(from, to), ==, 0);
	rm_rf(beside);
	g_free(from);
	g_free(to);
	g_free(beside);
	wait_files(cap, 25);
	fs_calls_reset();
	wait_checks(cap, 5);
	gint stats = g_atomic_int_get(&fstatat_calls);
	streamcap_stop(cap);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.bytes, ==, 215);
	/* 5 checks of the base (2 entries; the first may have begun before the reset), no folder read */
	g_assert_cmpint(stats, >=, 8);
	g_assert_cmpint(stats, <, 25);
	g_assert_cmpuint(u.full_counts, ==, 1);
	g_assert_cmpuint(u.dir_counts, ==, 1);
	streamcap_free(cap);
	rm_rf(dir);
	g_free(dir);
}

/*
 * A dump deleted from outside in a date folder that stays is still counted
 * (until that folder or the base goes, or a restart): the total counts more
 * than the folder holds, dionaea writes fewer dumps, never more than the limits.
 */
static void outside_deletion_counted(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 10, 10);
	struct streamcap *cap = streamcap_new(dir, 0, 1000, 5 * G_TIME_SPAN_MILLISECOND);
	wait_counted(cap);
	char *one = g_build_filename(dir, "2020-01-01", "dump-0", NULL);
	g_assert_cmpint(unlink(one), ==, 0);
	wait_checks(cap, 5);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 10);
	g_assert_cmpuint(u.bytes, ==, 100);
	streamcap_free(cap);
	g_free(one);
	rm_rf(dir);
	g_free(dir);
}

/* the date folder of the dumps of this process: gone, with a dump still open in it, and made again */
static void own_dumps_in_vanished_dir(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 4, 10);
	struct processor *p = streamdumper_new(dir, "config.max_files=100\n");
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	wait_counted(cap);
	struct dump a, b;
	dump_open(&a, p, 9001);
	dump_io(&a, bistream_in, "aaaa", 4);
	dump_open(&b, p, 9002);
	dump_io(&b, bistream_in, "bbbb", 4);
	dump_close(&b);
	streamcap_check(cap);
	/* a is open: its bytes are counted before stdio wrote them */
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 6);

	/* the folder of today goes, a is still open in it */
	GPtrArray *dumps = all_dumps(dir);
	char *today = NULL;
	for( guint i = 0; i < dumps->len; i++ )
		if( strstr(g_ptr_array_index(dumps, i), "-10.0.0.2-9001-") != NULL )
			today = g_path_get_dirname(g_ptr_array_index(dumps, i));
	g_assert_nonnull(today);
	g_assert_null(strstr(today, "2020-01-01"));
	g_ptr_array_free(dumps, TRUE);
	rm_rf(today);
	streamcap_check(cap);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 5);
	g_assert_cmpuint(u.open_files, ==, 1);
	/* a is closed into the folder that is gone: the next check takes it out */
	dump_close(&a);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 5);
	streamcap_check(cap);
	assert_usage(cap, dir);

	/* a new dump makes the folder again: it is taken as it is, exactly */
	streamcap_usage_get(cap, &u);
	guint64 dir_counts = u.dir_counts;
	struct dump c;
	dump_open(&c, p, 9003);
	dump_io(&c, bistream_in, "cccc", 4);
	dump_close(&c);
	streamcap_check(cap);
	assert_usage(cap, dir);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 5);
	g_assert_cmpuint(u.full_counts, ==, 1);
	/* the folders of today were made by the dumps of this process: never read */
	g_assert_cmpuint(dir_counts, ==, 0);
	g_assert_cmpuint(u.dir_counts, ==, 0);
	streamcap_check(cap);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.dir_counts, ==, 0);
	assert_usage(cap, dir);

	streamdumper_free(p);
	g_free(today);
	rm_rf(dir);
	g_free(dir);
}

/* a recount that waits returns at the stop, and the stop waits for one entry of the count */
static gint64 stop_took;

static gpointer stopper(gpointer cap)
{
	g_usleep(100 * G_TIME_SPAN_MILLISECOND);
	gint64 start = g_get_monotonic_time();
	streamcap_stop(cap);
	stop_took = g_get_monotonic_time() - start;
	return NULL;
}

static void recount_returns_at_stop(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 300, 10);
	struct streamcap *cap = streamcap_new(dir, 0, 1000, STREAMCAP_PERIOD);
	wait_counted(cap);
	/* 300 entries of 10 ms */
	g_atomic_int_set(&fs_delay_us, 10000);
	GThread *t = g_thread_new("stopper", stopper, cap);
	gint64 start = g_get_monotonic_time();
	streamcap_recount(cap);
	gint64 took = g_get_monotonic_time() - start;
	g_thread_join(t);
	g_atomic_int_set(&fs_delay_us, 0);
	g_assert_cmpint(took, <, 1 * G_TIME_SPAN_SECOND);
	g_assert_cmpint(stop_took, <, 1 * G_TIME_SPAN_SECOND);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	/* the cancelled count changed nothing */
	g_assert_cmpuint(u.files, ==, 300);
	g_assert_cmpuint(u.full_counts, ==, 1);
	streamcap_free(cap);
	rm_rf(dir);
	g_free(dir);
}

/*
 * A check asked for while a count runs, and the stop comes before it began:
 * the thread ends without it, and the caller of streamcap_check() returns at
 * the stop instead of waiting for a check that never comes.
 */
static gint check_done;

static gpointer check_thread(gpointer cap)
{
	streamcap_check(cap);
	g_atomic_int_set(&check_done, 1);
	return NULL;
}

static gpointer stop_thread(gpointer cap)
{
	streamcap_stop(cap);
	return NULL;
}

static void check_returns_at_stop(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 5, 10);
	struct streamcap *cap = streamcap_new(dir, 0, 1000, STREAMCAP_PERIOD);
	wait_counted(cap);
	struct gate_hook h = { 0 };
	stub_gate_reset(&h.gate);
	streamcap_count_hook_set(cap, gate_hook, &h);
	/* a recount stands at its first file */
	GThread *recount = g_thread_new("recount", recount_thread, cap);
	stub_gate_await(&h.gate, 1);
	/* a check is asked for meanwhile: it would begin after the recount */
	g_atomic_int_set(&check_done, 0);
	GThread *check = g_thread_new("check", check_thread, cap);
	g_usleep(50 * G_TIME_SPAN_MILLISECOND);
	g_assert_cmpint(g_atomic_int_get(&check_done), ==, 0);
	/* the stop: the recount ends after its entry, the thread ends without the check */
	GThread *stop = g_thread_new("stop", stop_thread, cap);
	g_usleep(20 * G_TIME_SPAN_MILLISECOND);
	stub_gate_release(&h.gate);
	g_thread_join(stop);
	g_thread_join(recount);
	gint64 deadline = g_get_monotonic_time() + 5 * G_TIME_SPAN_SECOND;
	while( g_atomic_int_get(&check_done) == 0 )
	{
		g_assert_cmpint(g_get_monotonic_time(), <, deadline);
		g_usleep(G_TIME_SPAN_MILLISECOND);
	}
	g_thread_join(check);
	streamcap_count_hook_set(cap, NULL, NULL);
	streamcap_free(cap);
	rm_rf(dir);
	g_free(dir);
}

/*
 * Dumps removed from outside in a date folder that stays are not seen by the
 * running total. A refused dump
 * makes the counting thread look at the date folders: one whose mtime changed
 * since its count is counted again, and the next dump is admitted.
 */
static void refusal_counts_changed_dir(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 10, 10);
	put_files(dir, "2020-01-02", 10, 10);
	char *day = g_build_filename(dir, "2020-01-01", NULL);
	char *other = g_build_filename(dir, "2020-01-02", NULL);
	old_mtime(day);
	old_mtime(other);
	/* a period of a minute: no check but the first one and the ones the refusals ask for */
	struct streamcap *cap = streamcap_new(dir, 0, 20, STREAMCAP_PERIOD);
	fake_now = 1000 * G_TIME_SPAN_SECOND;
	streamcap_clock_set(cap, fake_clock);
	wait_counted(cap);
	for( int i = 0; i < 3; i++ )
	{
		char *one = g_strdup_printf("%s/dump-%d", day, i);
		g_assert_cmpint(unlink(one), ==, 0);
		g_free(one);
	}
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	guint64 counts = u.counts;
	fs_calls_reset();
	g_assert_null(streamcap_open(cap, 10));
	wait_check_after(cap, counts);
	gint stats = g_atomic_int_get(&fstatat_calls);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 17);
	g_assert_cmpuint(u.bytes, ==, 170);
	g_assert_cmpuint(u.full_counts, ==, 1);
	g_assert_cmpuint(u.dir_counts, ==, 1);
	/* the base (2 entries) and the changed folder (7 dumps), not the other one */
	g_assert_cmpint(stats, >=, 9);
	g_assert_cmpint(stats, <, 19);
	struct streamcap_dump *dump = streamcap_open(cap, 10);
	g_assert_nonnull(dump);
	streamcap_close(cap, dump, false);
	streamcap_free(cap);
	g_free(day);
	g_free(other);
	rm_rf(dir);
	g_free(dir);
}

/*
 * A folder that is really full does not change: a refused dump reads only the
 * base, at most once per period, and no date folder.
 */
static void refusal_unchanged_no_walk(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 10, 10);
	char *day = g_build_filename(dir, "2020-01-01", NULL);
	old_mtime(day);
	struct streamcap *cap = streamcap_new(dir, 0, 10, STREAMCAP_PERIOD);
	fake_now = 1000 * G_TIME_SPAN_SECOND;
	streamcap_clock_set(cap, fake_clock);
	wait_counted(cap);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	guint64 counts = u.counts;
	fs_calls_reset();
	g_assert_null(streamcap_open(cap, 10));
	wait_check_after(cap, counts);
	/* more refusals in the same period ask for nothing */
	for( int i = 0; i < 100; i++ )
		g_assert_null(streamcap_open(cap, 10));
	g_usleep(50 * G_TIME_SPAN_MILLISECOND);
	gint stats = g_atomic_int_get(&fstatat_calls);
	gint reads = g_atomic_int_get(&readdir_calls);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.counts, ==, counts + 1);
	g_assert_cmpuint(u.dir_counts, ==, 0);
	g_assert_cmpuint(u.full_counts, ==, 1);
	g_assert_cmpuint(u.files, ==, 10);
	/* the base: one entry, read once */
	g_assert_cmpint(stats, >=, 1);
	g_assert_cmpint(stats, <, 5);
	g_assert_cmpint(reads, >=, 1);
	g_assert_cmpint(reads, <, 10);
	/* a period later a refusal asks again */
	fake_now += STREAMCAP_PERIOD;
	g_assert_null(streamcap_open(cap, 10));
	wait_check_after(cap, counts + 1);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.dir_counts, ==, 0);
	streamcap_free(cap);
	g_free(day);
	rm_rf(dir);
	g_free(dir);
}

/* a refused dump counts a changed date folder again at most once per STREAMCAP_RECOUNT_INTERVAL */
static void refusal_recount_rate_limited(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 10, 10);
	char *day = g_build_filename(dir, "2020-01-01", NULL);
	old_mtime(day);
	struct streamcap *cap = streamcap_new(dir, 0, 10, STREAMCAP_PERIOD);
	fake_now = 1000 * G_TIME_SPAN_SECOND;
	gint64 first = fake_now;
	streamcap_clock_set(cap, fake_clock);
	wait_counted(cap);
	char *one = g_strdup_printf("%s/dump-0", day);
	g_assert_cmpint(unlink(one), ==, 0);
	g_free(one);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_null(streamcap_open(cap, 10));
	wait_check_after(cap, u.counts);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.dir_counts, ==, 1);
	/* 9 dumps and an open one: at the limit again */
	struct streamcap_dump *held = streamcap_open(cap, 10);
	g_assert_nonnull(held);
	old_mtime(day);
	one = g_strdup_printf("%s/dump-1", day);
	g_assert_cmpint(unlink(one), ==, 0);
	g_free(one);
	/* periods later, but within the interval: no count */
	for( gint64 at = STREAMCAP_PERIOD; at < STREAMCAP_RECOUNT_INTERVAL; at += STREAMCAP_PERIOD )
	{
		fake_now = first + at;
		g_assert_null(streamcap_open(cap, 10));
	}
	g_usleep(50 * G_TIME_SPAN_MILLISECOND);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.dir_counts, ==, 1);
	g_assert_cmpuint(u.files, ==, 10);
	/* the interval is over */
	fake_now = first + STREAMCAP_RECOUNT_INTERVAL;
	guint64 counts = u.counts;
	g_assert_null(streamcap_open(cap, 10));
	wait_check_after(cap, counts);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.dir_counts, ==, 2);
	g_assert_cmpuint(u.files, ==, 9);
	streamcap_close(cap, held, false);
	streamcap_free(cap);
	g_free(day);
	rm_rf(dir);
	g_free(dir);
}

/*
 * A date folder that can not be read (EIO, EACCES) keeps the others: the count
 * takes the folders it read, and only that folder is tried again, less and
 * less often.
 */
static void count_error_keeps_the_rest(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 5, 10);
	put_files(dir, "2020-01-02", 7, 10);
	char *bad = g_build_filename(dir, "2020-01-02", NULL);
	struct stat st;
	g_assert_cmpint(lstat(bad, &st), ==, 0);
	__atomic_store_n(&fail_dir_ino, (gint64)st.st_ino, __ATOMIC_SEQ_CST);
	warnings_reset();
	struct streamcap *cap = streamcap_new(dir, 0, 1000, 5 * G_TIME_SPAN_MILLISECOND);
	wait_counted(cap);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 5);
	g_assert_cmpuint(u.full_counts, ==, 1);
	/* 40 periods: no full count, the folder tried again less and less often */
	wait_checks(cap, 40);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.full_counts, ==, 1);
	g_assert_cmpuint(u.dir_counts, ==, 0);
	g_assert_cmpuint(u.files, ==, 5);
	guint failed = warnings_with("2020-01-02");
	g_assert_cmpuint(failed, >=, 2);
	g_assert_cmpuint(failed, <=, 7);
	/* readable again: counted at the next try */
	__atomic_store_n(&fail_dir_ino, 0, __ATOMIC_SEQ_CST);
	wait_files(cap, 12);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.full_counts, ==, 1);
	g_assert_cmpuint(u.dir_counts, ==, 1);
	failed = warnings_with("2020-01-02");
	wait_checks(cap, 10);
	g_assert_cmpuint(warnings_with("2020-01-02"), ==, failed);
	streamcap_free(cap);
	g_free(bad);
	rm_rf(dir);
	g_free(dir);
}

/*
 * At the cap a refusal never reads a date folder that the dumps of this
 * process made (on a Docker Desktop bind mount it can hold 200,000 dumps): its
 * total is exact for the own dumps, a dump removed from it from outside is not
 * seen (it stays counted: fewer dumps, never more). A folder this process did
 * not make, whose mtime changed,
 * is counted again.
 */
static gint64 ino_of(const char *path)
{
	struct stat st;
	g_assert_cmpint(lstat(path, &st), ==, 0);
	return (gint64)st.st_ino;
}

static void refusal_skips_own_dir(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 5, 10);
	char *foreign = g_build_filename(dir, "2020-01-01", NULL);
	old_mtime(foreign);
	struct processor *p = streamdumper_new(dir, "config.max_files=8\n");
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	wait_counted(cap);
	fake_now = 1000 * G_TIME_SPAN_SECOND;
	streamcap_clock_set(cap, fake_clock);
	/* 3 dumps of this process: today's folder, made by it */
	for( int i = 0; i < 3; i++ )
	{
		struct dump d;
		dump_open(&d, p, 9100 + i);
		dump_io(&d, bistream_in, "dddd", 4);
		dump_close(&d);
	}
	char *one = dump_path_of_port(dir, 9100);
	char *today = g_path_get_dirname(one);
	/* the next check takes today's folder as it is */
	streamcap_check(cap);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 8);
	g_assert_cmpuint(u.dir_counts, ==, 0);
	/* dumps removed from outside in both: both mtimes change */
	old_mtime(today);
	g_assert_cmpint(unlink(one), ==, 0);
	for( int i = 0; i < 2; i++ )
	{
		char *f = g_strdup_printf("%s/dump-%d", foreign, i);
		g_assert_cmpint(unlink(f), ==, 0);
		g_free(f);
	}
	__atomic_store_n(&watch_ino[0], ino_of(today), __ATOMIC_SEQ_CST);
	__atomic_store_n(&watch_ino[1], ino_of(foreign), __ATOMIC_SEQ_CST);
	g_atomic_int_set(&watch_reads[0], 0);
	g_atomic_int_set(&watch_reads[1], 0);
	streamcap_usage_get(cap, &u);
	guint64 counts = u.counts;
	g_assert_null(streamcap_open(cap, 10));
	wait_check_after(cap, counts);
	gint own_reads = g_atomic_int_get(&watch_reads[0]);
	gint foreign_reads = g_atomic_int_get(&watch_reads[1]);
	__atomic_store_n(&watch_ino[0], 0, __ATOMIC_SEQ_CST);
	__atomic_store_n(&watch_ino[1], 0, __ATOMIC_SEQ_CST);
	streamcap_usage_get(cap, &u);
	/* the foreign folder was read (the counter works), today's was not */
	g_assert_cmpint(foreign_reads, >=, 1);
	g_assert_cmpint(own_reads, ==, 0);
	g_assert_cmpuint(u.dir_counts, ==, 1);
	/* 3 foreign dumps and the 3 own ones: the one removed from today's folder is still counted */
	g_assert_cmpuint(u.files, ==, 6);
	streamdumper_free(p);
	g_free(one);
	g_free(today);
	g_free(foreign);
	rm_rf(dir);
	g_free(dir);
}

/*
 * dionaea alone restarts (autoheal, the restart policy; T-Pot's clean.sh does
 * not run): today's date folder holds the dumps of the run before and was not
 * made by this process. Its dumps change its mtime, so at the cap a refusal
 * read it every 10 minutes (200,000 dumps on a Docker Desktop bind mount). The folder that config.path names now is dionaea's: counted by the
 * first count, never read again at a refusal.
 */
static char *today_name(void)
{
	time_t now = time(NULL);
	struct tm t;
	localtime_r(&now, &t);
	char name[32];
	g_assert_cmpuint(strftime(name, sizeof(name), "%Y-%m-%d", &t), >, 0);
	return g_strdup(name);
}

static void restart_today_is_own(void)
{
	char *dir = tmp_dir();
	char *name = today_name();
	/* the dumps of the run before, and an older folder of it */
	put_files(dir, name, 5, 10);
	put_files(dir, "2020-01-01", 2, 10);
	char *today = g_build_filename(dir, name, NULL);
	old_mtime(today);
	struct processor *p = streamdumper_new(dir, "config.max_files=10\n");
	struct streamcap *cap = proc_streamdumper_cap(p->config);
	wait_counted(cap);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 7);
	fake_now = 1000 * G_TIME_SPAN_SECOND;
	streamcap_clock_set(cap, fake_clock);
	/* 3 dumps of this run into the folder that is there: no mkdir, its mtime changes */
	for( int i = 0; i < 3; i++ )
	{
		struct dump d;
		dump_open(&d, p, 9200 + i);
		dump_io(&d, bistream_in, "dddd", 4);
		dump_close(&d);
	}
	char *one = dump_path_of_port(dir, 9200);
	char *parent = g_path_get_dirname(one);
	g_free(one);
	char *later = today_name();
	if( strcmp(parent, today) != 0 || strcmp(later, name) != 0 )
	{
		/* midnight passed */
		g_test_skip("the day changed during the test");
		g_free(later);
		g_free(parent);
		streamdumper_free(p);
		g_free(today);
		g_free(name);
		rm_rf(dir);
		g_free(dir);
		return;
	}
	g_free(later);
	g_free(parent);
	/* at the cap: 10 dumps, a refusal asks for a refresh */
	__atomic_store_n(&watch_ino[0], ino_of(today), __ATOMIC_SEQ_CST);
	g_atomic_int_set(&watch_reads[0], 0);
	for( int round = 0; round < 3; round++ )
	{
		streamcap_usage_get(cap, &u);
		guint64 counts = u.counts;
		g_assert_null(streamcap_open(cap, 10));
		wait_check_after(cap, counts);
		fake_now += STREAMCAP_RECOUNT_INTERVAL;
	}
	gint reads = g_atomic_int_get(&watch_reads[0]);
	__atomic_store_n(&watch_ino[0], 0, __ATOMIC_SEQ_CST);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 10);
	g_assert_cmpuint(u.full_counts, ==, 1);
	g_assert_cmpuint(u.dir_counts, ==, 0);
	g_assert_cmpint(reads, ==, 0);
	streamdumper_free(p);
	g_free(today);
	g_free(name);
	rm_rf(dir);
	g_free(dir);
}

/*
 * A date folder that is gone at a check, and made again by the dumps of this
 * process (streamcap_made(), streamcap_opened()) after the check listed the
 * base but before it took the listing: it stays this process's own folder.
 */
static gpointer check_in_thread(gpointer cap)
{
	streamcap_check(cap);
	return NULL;
}

static void made_during_a_check_stays_own(void)
{
	char *dir = tmp_dir();
	put_files(dir, "2020-01-01", 3, 10);
	char *day = g_build_filename(dir, "2020-01-01", NULL);
	struct streamcap *cap = streamcap_new(dir, 0, 4, STREAMCAP_PERIOD);
	fake_now = 1000 * G_TIME_SPAN_SECOND;
	streamcap_clock_set(cap, fake_clock);
	wait_counted(cap);
	/* the folder of the dumps of this process */
	streamcap_made(cap, day);
	/* it goes; the next check lists the base without it and stands still there */
	rm_rf(day);
	g_mutex_lock(&pause_lock);
	pause_reached = false;
	pause_released = false;
	g_mutex_unlock(&pause_lock);
	__atomic_store_n(&pause_ino, ino_of(dir), __ATOMIC_SEQ_CST);
	GThread *checker = g_thread_new("check", check_in_thread, cap);
	g_mutex_lock(&pause_lock);
	while( !pause_reached )
		g_cond_wait(&pause_cond, &pause_lock);
	g_mutex_unlock(&pause_lock);
	/* meanwhile a dump makes the folder again and opens its file in it, as proc_streamdumper does */
	g_assert_cmpint(mkdir(day, 0700), ==, 0);
	streamcap_made(cap, day);
	struct streamcap_dump *dump = streamcap_open(cap, 4);
	g_assert_nonnull(dump);
	char *path = g_build_filename(day, "dump-new", NULL);
	int fd = open(path, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
	g_assert_cmpint(fd, !=, -1);
	streamcap_opened(cap, dump, fd, day);
	g_mutex_lock(&pause_lock);
	pause_released = true;
	g_cond_broadcast(&pause_cond);
	g_mutex_unlock(&pause_lock);
	g_thread_join(checker);
	/* the 3 dumps of the folder that went are out of the total, the new one is in */
	g_assert_cmpint(write(fd, "abcd", 4), ==, 4);
	g_assert_cmpint(close(fd), ==, 0);
	streamcap_close(cap, dump, true);
	struct streamcap_usage u;
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.files, ==, 1);
	/* the next check takes the new folder as it is */
	streamcap_check(cap);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.dir_counts, ==, 0);
	/* at the cap (3 open dumps and the closed one), the folder changed: a refusal does not read it */
	struct streamcap_dump *held[3];
	for( int i = 0; i < 3; i++ )
	{
		held[i] = streamcap_open(cap, 4);
		g_assert_nonnull(held[i]);
	}
	old_mtime(day);
	put_file(day, "from-outside", 10);
	__atomic_store_n(&watch_ino[0], ino_of(day), __ATOMIC_SEQ_CST);
	g_atomic_int_set(&watch_reads[0], 0);
	streamcap_usage_get(cap, &u);
	guint64 counts = u.counts;
	g_assert_null(streamcap_open(cap, 4));
	wait_check_after(cap, counts);
	gint reads = g_atomic_int_get(&watch_reads[0]);
	__atomic_store_n(&watch_ino[0], 0, __ATOMIC_SEQ_CST);
	streamcap_usage_get(cap, &u);
	g_assert_cmpuint(u.dir_counts, ==, 0);
	g_assert_cmpint(reads, ==, 0);
	g_assert_cmpuint(u.files, ==, 4);
	for( int i = 0; i < 3; i++ )
		streamcap_close(cap, held[i], false);
	streamcap_free(cap);
	g_free(path);
	g_free(day);
	rm_rf(dir);
	g_free(dir);
}

/* ---- the temporary files of samples: <download.dir>/.incoming (src/util.c) ---- */

static guint mode_of(const char *path)
{
	struct stat st;
	g_assert_cmpint(lstat(path, &st), ==, 0);
	return st.st_mode & 07777;
}

/*
 * At the start: the folder is made (0700) or set to 0700, the files an earlier
 * run left in it are removed, and download.dir itself is not read (it can hold
 * 35,000 samples on a slow share).
 */
static void incoming_prepare_cleans(void)
{
	char *dir = tmp_dir();
	put_file(dir, "0123456789abcdef0123456789abcdef", 10);
	char *incoming = g_build_filename(dir, ".incoming", NULL);
	/* none yet: made */
	__atomic_store_n(&watch_ino[0], ino_of(dir), __ATOMIC_SEQ_CST);
	g_atomic_int_set(&watch_reads[0], 0);
	incoming_prepare(dir);
	g_assert_cmpuint(mode_of(incoming), ==, 0700);
	/* an earlier run left files, and the folder got 0770 (T-Pot's clean.sh: find -type d -exec chmod 770) */
	put_file(incoming, "http-a1b2c3.tmp", 10);
	put_file(incoming, "ftp-d4e5f6.tmp", 10);
	char *sub = g_build_filename(incoming, "keep", NULL);
	g_assert_cmpint(mkdir(sub, 0700), ==, 0);
	g_assert_cmpint(chmod(incoming, 0770), ==, 0);
	warnings_reset();
	incoming_prepare(dir);
	gint base_reads = g_atomic_int_get(&watch_reads[0]);
	__atomic_store_n(&watch_ino[0], 0, __ATOMIC_SEQ_CST);
	g_assert_cmpuint(mode_of(incoming), ==, 0700);
	guint64 files = 0, bytes = 0;
	count_files(incoming, &files, &bytes);
	g_assert_cmpuint(files, ==, 0);
	g_assert_true(g_file_test(sub, G_FILE_TEST_IS_DIR));
	g_assert_cmpuint(warnings->len, ==, 0);
	/* the sample is there, and download.dir was not read */
	files = 0;
	count_files(dir, &files, &bytes);
	g_assert_cmpuint(files, ==, 1);
	g_assert_cmpint(base_reads, ==, 0);
	/* a file of that name becomes the folder */
	rm_rf(incoming);
	put_file(dir, ".incoming", 3);
	incoming_prepare(dir);
	g_assert_true(g_file_test(incoming, G_FILE_TEST_IS_DIR));
	g_assert_cmpuint(mode_of(incoming), ==, 0700);
	incoming_prepare(NULL);
	g_free(sub);
	g_free(incoming);
	rm_rf(dir);
	g_free(dir);
}

/* a temporary file of a sample is in .incoming; the folder is made again if it is gone, download.dir is not */
static void incoming_tempfile(void)
{
	char *dir = tmp_dir();
	char *incoming = g_build_filename(dir, ".incoming", NULL);
	incoming_prepare(dir);
	struct stat before;
	g_assert_cmpint(lstat(dir, &before), ==, 0);
	struct tempfile *tf = tempincoming_new(dir, "http-");
	g_assert_nonnull(tf);
	char *parent = g_path_get_dirname(tf->path);
	g_assert_cmpstr(parent, ==, incoming);
	g_free(parent);
	tempfile_close(tf);
	tempfile_unlink(tf);
	tempfile_free(tf);
	/* the file came and went: download.dir did not change */
	struct stat after;
	g_assert_cmpint(lstat(dir, &after), ==, 0);
	g_assert_cmpint(after.st_mtim.tv_sec, ==, before.st_mtim.tv_sec);
	g_assert_cmpint(after.st_mtim.tv_nsec, ==, before.st_mtim.tv_nsec);
	/* gone meanwhile: made again */
	rm_rf(incoming);
	warnings_reset();
	tf = tempincoming_new(dir, "http-");
	g_assert_nonnull(tf);
	g_assert_cmpuint(mode_of(incoming), ==, 0700);
	g_assert_cmpuint(warnings->len, ==, 0);
	tempfile_close(tf);
	tempfile_unlink(tf);
	tempfile_free(tf);
	/* no download.dir: none, one warning, nothing made */
	char *missing = g_build_filename(dir, "missing", NULL);
	g_assert_null(tempincoming_new(missing, "http-"));
	g_assert_cmpuint(warnings_with("could not open path"), ==, 1);
	g_assert_false(g_file_test(missing, G_FILE_TEST_EXISTS));
	g_free(missing);
	g_free(incoming);
	rm_rf(dir);
	g_free(dir);
}

/* two references of the streamdumper with the same base: each counts only its own dumps, a warning says so */
static void shared_base_warns(void)
{
	char *dir = tmp_dir();
	warnings_reset();
	struct streamcap *a = streamcap_new(dir, 0, 10, STREAMCAP_PERIOD);
	g_assert_cmpuint(warnings_with("reference"), ==, 0);
	struct streamcap *b = streamcap_new(dir, 0, 10, STREAMCAP_PERIOD);
	g_assert_cmpuint(warnings_with("reference"), ==, 1);
	streamcap_free(b);
	streamcap_free(a);
	a = streamcap_new(dir, 0, 10, STREAMCAP_PERIOD);
	g_assert_cmpuint(warnings_with("reference"), ==, 1);
	streamcap_free(a);
	rm_rf(dir);
	g_free(dir);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	warnings = g_ptr_array_new_with_free_func(g_free);
	infos = g_ptr_array_new_with_free_func(g_free);
	g_log_set_always_fatal(G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL);
	g_log_set_default_handler(log_handler, NULL);
	stub_dionaea_init();
	g_test_add_func("/tempfile/closes-once", tempfile_closes_once);
	g_test_add_func("/tempfile/close-keeps-the-next-file", tempfile_close_keeps_the_next_file);
	g_test_add_func("/tempfile/new-fails-cleanly", tempfile_new_fails_cleanly);
	g_test_add_func("/streamdumper/closes-once", streamdumper_closes_once);
	g_test_add_func("/streamdumper/large-read", streamdumper_large_read);
	g_test_add_func("/streamdumper/locale", streamdumper_locale);
	g_test_add_func("/streamcap/parse", parse);
	g_test_add_func("/streamcap/base", base);
	g_test_add_func("/streamcap/parse-env", parse_env);
	g_test_add_func("/streamcap/env-shown", env_shown);
	g_test_add_func("/streamdumper/unlimited", unlimited);
	g_test_add_func("/streamdumper/invalid-options", invalid_options);
	g_test_add_func("/streamdumper/startup-lines-config", startup_lines_config);
	g_test_add_func("/streamdumper/env-limits", env_limits);
	g_test_add_func("/streamdumper/env-invalid", env_invalid);
	g_test_add_func("/streamdumper/env-empty", env_empty);
	g_test_add_func("/streamdumper/max-files", max_files);
	g_test_add_func("/streamdumper/max-size", max_size);
	g_test_add_func("/streamcap/open-dump-counted", open_dump_counted);
	g_test_add_func("/streamcap/notices-deletion", notices_deletion);
	g_test_add_func("/streamcap/close-during-count", close_during_count);
	g_test_add_func("/streamcap/concurrent", concurrent);
	g_test_add_func("/streamdumper/stops-at-max-size", stops_at_max_size);
	g_test_add_func("/streamdumper/max-files-does-not-stop", max_files_does_not_stop);
	g_test_add_func("/streamcap/stop", stop);
	g_test_add_func("/streamdumper/tree-shutdown", tree_shutdown);
	g_test_add_data_func("/streamdumper/shutdown-closes-open-dumps", NULL, shutdown_closes_open_dumps);
	g_test_add_data_func("/streamdumper/shutdown-closes-open-dumps-limited", "", shutdown_closes_open_dumps);
	g_test_add_func("/streamcap/starts-at-once", starts_at_once);
	g_test_add_func("/streamcap/stop-during-count", stop_during_count);
	g_test_add_func("/streamcap/no-walk-per-period", no_walk_per_period);
	g_test_add_func("/streamcap/vanished-dir", vanished_dir);
	g_test_add_func("/streamcap/base-replaced", base_replaced);
	g_test_add_func("/streamcap/new-dir-counted", new_dir_counted);
	g_test_add_func("/streamcap/outside-deletion-counted", outside_deletion_counted);
	g_test_add_func("/streamdumper/own-dumps-in-vanished-dir", own_dumps_in_vanished_dir);
	g_test_add_func("/streamcap/recount-returns-at-stop", recount_returns_at_stop);
	g_test_add_func("/streamcap/check-returns-at-stop", check_returns_at_stop);
	g_test_add_func("/streamcap/refusal-counts-changed-dir", refusal_counts_changed_dir);
	g_test_add_func("/streamcap/refusal-unchanged-no-walk", refusal_unchanged_no_walk);
	g_test_add_func("/streamcap/refusal-recount-rate-limited", refusal_recount_rate_limited);
	g_test_add_func("/streamcap/count-error-keeps-the-rest", count_error_keeps_the_rest);
	g_test_add_func("/streamdumper/refusal-skips-own-dir", refusal_skips_own_dir);
	g_test_add_func("/streamcap/shared-base-warns", shared_base_warns);
	g_test_add_func("/streamdumper/restart-today-is-own", restart_today_is_own);
	g_test_add_func("/streamcap/made-during-a-check-stays-own", made_during_a_check_stays_own);
	g_test_add_func("/tempfile/incoming-prepare-cleans", incoming_prepare_cleans);
	g_test_add_func("/tempfile/incoming", incoming_tempfile);
	int result = g_test_run();
	stub_dionaea_exit();
	if( g_dionaea->config != NULL )
		g_key_file_free(g_dionaea->config);
	g_ptr_array_free(warnings, TRUE);
	g_ptr_array_free(infos, TRUE);
	return result;
}
