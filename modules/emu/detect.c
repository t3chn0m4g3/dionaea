/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ev.h>
#include <glib.h>

#include <emu/emu.h>
#include <emu/emu_shellcode.h>
#include <emu/emu_log.h>
#include <emu/emu_cpu.h>
#include <emu/emu_cpu_data.h>

#include "dionaea.h"
#include "processor.h"
#include "connection.h"
#include "log.h"
#include "incident.h"
#include "threads.h"

#define D_LOG_DOMAIN "emu"

#include "module.h"

struct processor proc_emu =
{
	.name = "emu",
	.new = proc_emu_ctx_new,
	.free = proc_emu_ctx_free,
	.cfg = proc_emu_ctx_cfg_new,
	.thread_io_in = proc_emu_on_io_in,
	/* at a limit the scan of the connection stops, the connection goes on */
	.give_up_on_limit = true,
};

void *proc_emu_ctx_cfg_new(gchar *group_name)
{
	g_debug("%s node", __PRETTY_FUNCTION__);
	struct emu_config *conf = g_malloc0(sizeof(struct emu_config));

	GError *error = NULL;

	conf->limits.files = g_key_file_get_integer(g_dionaea->config, group_name, "config.limits.files", &error);
	if (error != NULL)
		goto err;

	conf->limits.filesize = g_key_file_get_integer(g_dionaea->config, group_name, "config.limits.filesize", &error);
	if (error != NULL)
		goto err;

	conf->limits.sockets = g_key_file_get_integer(g_dionaea->config, group_name, "config.limits.sockets", &error);
	if (error != NULL)
		goto err;

	conf->limits.steps = g_key_file_get_integer(g_dionaea->config, group_name, "config.limits.steps", &error);
	if (error != NULL)
		goto err;

	conf->limits.idle = g_key_file_get_integer(g_dionaea->config, group_name, "config.limits.idle", &error);
	if (error != NULL)
		goto err;

	conf->limits.listen = g_key_file_get_double(g_dionaea->config, group_name, "config.limits.listen", &error);
	if (error != NULL)
		goto err;

	conf->limits.sustain = g_key_file_get_double(g_dionaea->config, group_name, "config.limits.sustain", &error);
	if (error != NULL)
		goto err;

	conf->limits.cpu = g_key_file_get_double(g_dionaea->config, group_name, "config.limits.cpu", &error);
	if (error != NULL)
		goto err;

	g_debug(
		" files %i filesize %i sockets %i steps %i idle %f listen %f sustain %f cpu %f ",
		conf->limits.files,
		conf->limits.filesize,
		conf->limits.sockets,
		conf->limits.steps,
		conf->limits.idle,
		conf->limits.listen,
		conf->limits.sustain,
		conf->limits.cpu
	);

//	g_error("STOP");
	return conf;

	err:
	g_warning("configuration for emulation is incomplete");
	if (error != NULL)
		g_warning("%s", error->message);

	g_clear_error(&error);
	g_free(conf);
	return NULL;
}

void *proc_emu_ctx_new(void *cfg)
{
	if( cfg == NULL )
	{
		g_error("emulation needs configuration");
	}
	struct emu_ctx *ctx = g_malloc0(sizeof(struct emu_ctx));
	ctx->config = cfg;
	return ctx;
}

void proc_emu_ctx_free(void *ctx)
{
	g_free(ctx);
}

/*
 * The incoming stream is scanned in windows: at most EMU_SCAN_NEW bytes of new
 * data plus the last EMU_SCAN_OVERLAP bytes of the window before, so a
 * shellcode that crosses the end of a window is found in the next one. The
 * window is at most EMU_SCAN_MAX bytes, emu_shellcode_test() takes the size as
 * uint16_t. Scanned data before the overlap is freed, so a long connection
 * keeps at most one window plus what arrives during the scan.
 *
 * A window that ends before the stored data (cut by its size) may cut a
 * shellcode off: one found in its last EMU_SCAN_OVERLAP bytes is left to the
 * next window, which starts EMU_SCAN_OVERLAP bytes before the cut and so holds
 * a shellcode of up to EMU_SCAN_OVERLAP bytes completely.
 *
 * Only the first EMU_SCAN_LIMIT bytes of a connection are scanned: an exploit
 * sends its shellcode early, the rest is mostly the file of an upload (SMB
 * WRITE_ANDX, DoublePulsar). libemu scans x86 code at 0.5 to 1.2 MB/s per core
 * (tests/load/README.md), so the limit also bounds the CPU time of one
 * connection. After it, and when a limit of the stream
 * processing is reached (processor_give_up(): the data of the instance or of
 * the process, a full job queue), the scan of this connection stops; the
 * connection and the upload go on.
 */
#define EMU_SCAN_OVERLAP 300
#define EMU_SCAN_NEW (64 * 1024)
#define EMU_SCAN_MAX UINT16_MAX
#define EMU_SCAN_LIMIT (4 * 1024 * 1024)

void proc_emu_on_io_in(struct connection *con, struct processor_data *pd)
{
	g_debug("%s con %p pd %p", __PRETTY_FUNCTION__, con, pd);
	struct emu_ctx *ctx = pd->ctx;

	/* a job can start after the one before already scanned its data */
	uint64_t available = bistream_end(pd->bistream, bistream_in);
	while( ctx->offset < available &&
		   g_atomic_int_get(&pd->state) != processor_done &&
		   !g_atomic_int_get(&con->processor_data->closing) )
	{
		uint64_t start = ctx->offset > EMU_SCAN_OVERLAP ? ctx->offset - EMU_SCAN_OVERLAP : 0;
		uint64_t end = MIN(available, MIN(ctx->offset + EMU_SCAN_NEW, start + EMU_SCAN_MAX));
		end = MIN(end, EMU_SCAN_LIMIT);
		void *streamdata = NULL;
		int32_t size = bistream_get_stream(pd->bistream, bistream_in, start, end, &streamdata);
		if( size < 0 )
		{
			/* given back meanwhile: the connection is closed (processors_release_all())
			 * or the scan gave up (processor_give_up()) */
			if( g_atomic_int_get(&con->processor_data->closing) ||
				g_atomic_int_get(&pd->state) == processor_done )
				return;
			/* otherwise the offsets are broken */
			g_critical("emu: stream offsets %" G_GUINT64_FORMAT "-%" G_GUINT64_FORMAT " are not stored", start, end);
			processor_give_up(con, pd, "stream offsets", true);
			return;
		}

		emu_trim_scan_begin();
		struct emu *e = emu_new();
#if 0
		emu_cpu_debugflag_set(emu_cpu_get(e), instruction_string);
		emu_log_level_set(emu_logging_get(e),EMU_LOG_DEBUG);
#endif
		int ret = emu_shellcode_test(e, streamdata, (uint16_t)size);
		bool graph = emu_scan_built_graph(e);
		emu_free(e);
		/* the cursor is the end of the scanned data, the overlap does not move it */
		ctx->offset = end;
		/* at the scan limit no window follows */
		if( ret >= 0 && end < available && end < EMU_SCAN_LIMIT && ret > size - EMU_SCAN_OVERLAP )
			ret = -1;

		if( ret >= 0 )
		{
			struct incident *ix = incident_new("dionaea.shellcode.detected");
			GAsyncQueue *aq = g_async_queue_ref(g_dionaea->threads->cmds);
			g_async_queue_push(aq, async_cmd_new(async_incident_report, ix));
			g_async_queue_unref(aq);
			ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);
			g_debug("shellcode found offset %i (stream offset %" G_GUINT64_FORMAT ")", ret, start + ret);
			profile(ctx->config, con, streamdata, size, ret);
			/* the job frees the stream data once this returns */
			g_atomic_int_set(&pd->state, processor_done);
		} else
		if( end >= EMU_SCAN_LIMIT )
		{
			/* gives the stream data back, nothing more is kept */
			processor_give_up(con, pd, "scan limit", false);
		} else
		{
			bistream_discard_before(pd->bistream, bistream_in, end > EMU_SCAN_OVERLAP ? end - EMU_SCAN_OVERLAP : 0);
		}
		g_free(streamdata);
		/* the graph and the emulation of profile() are freed, glibc keeps their pages (trim.c) */
		emu_trim_scan_end(graph);
	}
}
