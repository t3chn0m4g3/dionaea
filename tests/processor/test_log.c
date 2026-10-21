/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * The buffering of the log files (src/log.c). A file whose levels have neither debug nor
 * info (T-Pot's errors.levels=warning,error) gets few lines and is written per line, so
 * a warning is in the file at once, not at the stop; a file with info or debug keeps the
 * buffer of stdio. A record of Python's logging at error is a glib critical (log_wrap of
 * modules/python/module.c): a file of warning,error,critical gets it at once, one of
 * warning,error does not get it.
 */
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "dionaea.h"
#include "log.h"

#define D_LOG_DOMAIN "test_log"

struct dionaea *g_dionaea = NULL;

struct opened {
	gchar *dir;
	struct logger_file_data *data;
	struct logger *logger;
};

static struct opened *open_log(const char *levels)
{
	struct opened *o = g_new0(struct opened, 1);
	o->dir = g_dir_make_tmp("test_log_XXXXXX", NULL);
	g_assert_nonnull(o->dir);
	o->data = g_new0(struct logger_file_data, 1);
	g_snprintf(o->data->file, sizeof(o->data->file), "%s/dionaea-errors.log", o->dir);
	o->data->filter = log_filter_new("*", levels);
	o->logger = logger_new(logger_file_log, logger_file_open, logger_file_hup, logger_file_close,
						   logger_file_flush, o->data);
	g_assert_true(logger_file_open(o->logger, o->data));
	return o;
}

/* the size of the file as another process sees it (no fflush of the stream) */
static goffset size_on_disk(struct opened *o)
{
	GStatBuf st;
	g_assert_cmpint(g_stat(o->data->file, &st), ==, 0);
	return st.st_size;
}

static void close_log(struct opened *o)
{
	logger_file_close(o->logger, o->data);
	g_unlink(o->data->file);
	g_rmdir(o->dir);
	g_free(o->dir);
	for( unsigned int i = 0; o->data->filter->domains[i] != NULL; i++ ) {
		g_pattern_spec_free(o->data->filter->domains[i]->pattern);
		g_free(o->data->filter->domains[i]->domain);
		g_free(o->data->filter->domains[i]);
	}
	g_free(o->data->filter->domains);
	g_free(o->data->filter);
	g_free(o->data);
	g_free(o->logger);
	g_free(o);
}

static void a_warning_is_written_at_once(void)
{
	struct opened *o = open_log("warning,error");
	logger_file_log("smb /dionaea/smb/smb.py:1", G_LOG_LEVEL_WARNING, "Invalid SMB request", o->data);
	g_assert_cmpint(size_on_disk(o), >, 0);
	goffset first = size_on_disk(o);
	logger_file_log("connection /src/connection_tcp.c:1", G_LOG_LEVEL_ERROR, "an error", o->data);
	g_assert_cmpint(size_on_disk(o), >, first);
	close_log(o);
}

static void after_a_hup_too(void)
{
	struct opened *o = open_log("warning,error");
	g_assert_true(logger_file_hup(o->logger, o->data));
	logger_file_log("smb /dionaea/smb/smb.py:1", G_LOG_LEVEL_WARNING, "Invalid SMB request", o->data);
	g_assert_cmpint(size_on_disk(o), >, 0);
	close_log(o);
}

static void a_critical_is_written_at_once(void)
{
	struct opened *o = open_log("warning,error,critical");
	logger_file_log("python /dionaea/binding.pyx:1", G_LOG_LEVEL_CRITICAL, "There was an error", o->data);
	g_assert_cmpint(size_on_disk(o), >, 0);
	close_log(o);

	o = open_log("warning,error");
	logger_file_log("python /dionaea/binding.pyx:1", G_LOG_LEVEL_CRITICAL, "There was an error", o->data);
	g_assert_true(logger_file_flush(o->logger, o->data));
	g_assert_cmpint(size_on_disk(o), ==, 0);
	close_log(o);
}

static void a_file_with_info_keeps_its_buffer(void)
{
	const char *levels[] = { "info,warning,error", "all", "debug,warning", "all,-debug" };
	for( unsigned int i = 0; i < G_N_ELEMENTS(levels); i++ ) {
		struct opened *o = open_log(levels[i]);
		logger_file_log("smb /dionaea/smb/smb.py:1", G_LOG_LEVEL_WARNING, "Invalid SMB request", o->data);
		g_assert_cmpint(size_on_disk(o), ==, 0);
		g_assert_true(logger_file_flush(o->logger, o->data));
		g_assert_cmpint(size_on_disk(o), >, 0);
		close_log(o);
	}
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_test_add_func("/log/warning-at-once", a_warning_is_written_at_once);
	g_test_add_func("/log/warning-at-once-after-hup", after_a_hup_too);
	g_test_add_func("/log/info-keeps-buffer", a_file_with_info_keeps_its_buffer);
	g_test_add_func("/log/critical-at-once", a_critical_is_written_at_once);
	return g_test_run();
}
