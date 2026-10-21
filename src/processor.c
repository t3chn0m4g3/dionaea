/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009-2011 Markus Koetter
 * SPDX-FileCopyrightText: 2014-2020 PhiBo (DinoTools)
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "dionaea.h"
#include "connection.h"
#include "processor.h"
#include "threads.h"

#include "log.h"
#include "util.h"
#include "streamcap.h"

#define D_LOG_DOMAIN "processor"

bool processors_tree_create(GNode *tree, gchar *proc_conf_name)
{
	GError *error = NULL;
	g_debug("%s - processor: %s", __PRETTY_FUNCTION__, proc_conf_name);
	//g_debug("%s tree %p node %p key %s", __PRETTY_FUNCTION__, tree, node, node->key);

	gchar *group_name = g_strjoin(".", "processor", proc_conf_name, NULL);
	gchar *proc_name = g_key_file_get_string(g_dionaea->config, group_name, "name", &error);

	struct processor *p = g_hash_table_lookup(g_dionaea->processors->names, proc_name);

	if( p == NULL )
	{
		//g_error("Could not find processor '%s' (%s)", node->key, key);
	}

	struct processor *pt = g_malloc0(sizeof(struct processor));
	memcpy(pt, p, sizeof(struct processor));

	if( pt->cfg != NULL ) {
		if( (pt->config = pt->cfg(group_name)) == NULL ) {
			g_error("processor %s rejected config", "ToDo");
		}
	}

	GNode *me = g_node_new(pt);
	g_node_append(tree, me);

	gchar **proc_next_names, **proc_next_name;
	gsize num;

	proc_next_names = g_key_file_get_string_list(g_dionaea->config, group_name, "next", &num, &error);
	if(error == NULL) {
		for (proc_next_name = proc_next_names; *proc_next_name; proc_next_name++) {
			processors_tree_create(me, *proc_next_name);
		}
	}
	g_clear_error(&error);
	return true;
}

static gboolean processor_shutdown(GNode *node, gpointer data)
{
	(void)data;
	struct processor *p = node->data;
	if( p != NULL && p->shutdown != NULL && p->config != NULL )
		p->shutdown(p->config);
	return FALSE;
}

void processors_tree_shutdown(GNode *tree)
{
	g_node_traverse(tree, G_PRE_ORDER, G_TRAVERSE_ALL, -1, processor_shutdown, NULL);
}

void processors_tree_dump(GNode *tree, int indent)
{
	for( GNode *it = g_node_first_sibling(tree); it != NULL; it = it->next )
	{
#ifdef DEBUG
		if( it->data )
		{
			struct processor *p = it->data;
			g_debug("%*s %s", indent*4, " ", p->name);
    	}
#endif

		if( it->children )
			processors_tree_dump(g_node_first_child(it), indent+1);
	}
}

void processor_data_creation(struct connection *con, struct processor_data *pd, GNode *node)
{
	g_debug("%s con %p pd %p node %p", __PRETTY_FUNCTION__, con, pd, node);
	struct processor *p = node->data;

	if( p->process && !p->process(con, p->config) )
	{
		g_debug("skip %s", p->name);
		return;
	}

	g_debug("creating %s", p->name);
	struct processor_data *npd = processor_data_new();
	npd->processor = p;
	if( npd->processor->new )
		npd->ctx = npd->processor->new(p->config);
	pd->filters = g_list_append(pd->filters, npd);

	GNode *it;
	for( it = node->children; it != NULL; it = it->next )
	{
		processor_data_creation(con, npd, it);
	}
}

void processor_data_deletion(struct processor_data *pd)
{
	g_debug("%s pd %p", __PRETTY_FUNCTION__, pd);
	GList *it;
	while( (it = g_list_first(pd->filters)) != NULL )
	{
		struct processor_data *proc_data = it->data;
		processor_data_deletion(proc_data);
		pd->filters = g_list_delete_link(pd->filters, it);
	}
	pd->processor->free(pd->ctx);
	processor_data_free(pd);
}

void processors_init(struct connection *con)
{
	g_debug("%s con %p\n", __PRETTY_FUNCTION__, con);
	con->processor_data = processor_data_new();
	for( GNode *it = g_node_first_sibling(g_dionaea->processors->tree->children);
	   it != NULL;
	   it = it->next )
	{
		processor_data_creation(con, con->processor_data, it);
	}
}


void processors_clear(struct connection *con)
{
	g_debug("%s con %p", __PRETTY_FUNCTION__, con);

	GList *it;
	while( (it = g_list_first(con->processor_data->filters)) != NULL )
	{
		struct processor_data *proc_data = it->data;
		processor_data_deletion(proc_data);
		con->processor_data->filters = g_list_delete_link(con->processor_data->filters, it);
	}
	processor_data_free(con->processor_data);
	con->processor_data = NULL;

}

struct processor_data *processor_data_new(void)
{
	struct processor_data *pd = g_malloc0(sizeof(struct processor_data));
	g_mutex_init(&pd->mutex);
	refcount_init(&pd->queued);
	pd->state = processor_continue;
	pd->processor = NULL;
	pd->filters = NULL;
	pd->bistream = bistream_new();
	return pd;
}

void processor_data_free(struct processor_data *pd)
{
/*	g_debug("%s pd %p", __PRETTY_FUNCTION__, pd);
	if ( pd == NULL )
		return;
*/
	bistream_free(pd->bistream);
	g_mutex_clear(&pd->mutex);
	refcount_exit(&pd->queued);
	g_free(pd);
}

#define PROCESSOR_PENDING_IN  (1U << bistream_in)
#define PROCESSOR_PENDING_OUT (1U << bistream_out)

static gint processor_overloads;
static gint processor_gave_up;

void processor_stats_get(struct processor_stats *stats)
{
	struct bistream_stats streams;
	struct thread_stats jobs;
	bistream_stats_get(&streams);
	thread_stats_get(&jobs);
	stats->stream_bytes = streams.bytes;
	stats->stream_chunks = streams.chunks;
	stats->stream_peak_bytes = streams.peak_bytes;
	stats->stream_peak_chunks = streams.peak_chunks;
	stats->stream_refused_instance = streams.refused_instance;
	stats->stream_refused_global = streams.refused_global;
	stats->jobs_waiting = jobs.waiting;
	stats->jobs_peak_waiting = jobs.peak_waiting;
	stats->jobs_refused = jobs.refused;
	stats->overloads = (unsigned)g_atomic_int_get(&processor_overloads);
	stats->gave_up = (unsigned)g_atomic_int_get(&processor_gave_up);
}

/* atomic: 1 after processors_jobs_drop(true) */
static gint processor_jobs_dropped;

void processors_jobs_drop(bool drop)
{
	g_atomic_int_set(&processor_jobs_dropped, drop ? 1 : 0);
}

static bool processors_jobs_dropped(void)
{
	return g_atomic_int_get(&processor_jobs_dropped) != 0;
}

static bool processors_closing(struct connection *con)
{
	return g_atomic_int_get(&con->processor_data->closing) != 0;
}

static bool processors_ended(struct connection *con)
{
	return g_atomic_int_get(&con->processor_data->ended) != 0;
}

static bool processor_is_done(struct processor_data *pd)
{
	return g_atomic_int_get(&pd->state) == processor_done;
}

/* free the stream data of an instance and of the instances it feeds */
static void processor_data_release(struct processor_data *pd)
{
	bistream_clear(pd->bistream);
	for( GList *it = pd->filters; it != NULL; it = it->next )
		processor_data_release(it->data);
}

void recurse_io(GList *list, struct connection *con, enum bistream_direction dir);
void recurse_io_process(struct processor_data *pd, struct connection *con, enum bistream_direction dir)
{
	if( processor_is_done(pd) || processors_closing(con) )
		return;

	if( dir == bistream_in )
	{
		if( pd->processor->thread_io_in != NULL )
		{
			pd->processor->thread_io_in(con, pd);
			recurse_io(pd->filters, con, dir);
		}
	} else
	{
		if( pd->processor->thread_io_out != NULL )
		{
			pd->processor->thread_io_out(con, pd);
			recurse_io(pd->filters, con, dir);
		}
	}
}

void recurse_io(GList *list, struct connection *con, enum bistream_direction dir)
{
	GList *it;
	for( it = g_list_first(list); it != NULL; it = g_list_next(it) )
	{
		struct processor_data *pd = it->data;
		recurse_io_process(pd, con, dir);
	}
}

/*
 * closing is set: give back the stream data of every instance of the tree
 * now, also of those whose job still waits for a worker (that job then ends
 * without work) or runs (it works on a copy and stops before its next read).
 * The instances are locked one at a time; processor_io_single() checks
 * closing under the same lock, so nothing is added after this.
 */
static void processors_release_all(struct processor_data *pd)
{
	g_mutex_lock(&pd->queued.mutex);
	pd->pending = 0;
	bistream_clear(pd->bistream);
	g_mutex_unlock(&pd->queued.mutex);
	for( GList *it = pd->filters; it != NULL; it = it->next )
		processors_release_all(it->data);
}

/* eventloop: the close processors_overload() asked for */
static void processors_overload_close(void *data)
{
	struct connection *con = data;
	/* the peer or the service may have closed it in the meantime */
	if( con->state != connection_state_close &&
		con->state != connection_state_shutdown &&
		!connection_flag_isset(con, connection_busy_close) )
	{
		connection_close(con);
	}
	connection_unref(con);
}

void processors_overload(struct connection *con, const char *reason)
{
	if( !g_atomic_int_compare_and_exchange(&con->processor_data->closing, 0, 1) )
		return;

	g_atomic_int_inc(&processor_overloads);
	/* once per connection, without any of its data */
	g_warning("Stream processing limit reached (%s), closing connection %p %s %s:%i",
			  reason, con, con->protocol.name != NULL ? con->protocol.name : "-",
			  con->remote.ip_string, ntohs(con->remote.port));

	/* the budget is free for other connections before the close */
	processors_release_all(con->processor_data);

	/* workers never close a connection, the eventloop does */
	connection_ref(con);
	g_async_queue_push(g_dionaea->threads->cmds, async_cmd_new(processors_overload_close, con));
	ev_async_send(g_dionaea->loop, &g_dionaea->threads->trigger);
}

/*
 * processors_stop(): give back the data of the instances without a job. The
 * instances a job feeds (the filters of a threaded processor, unicode -> emu)
 * are read by that job: their data goes when it ends (processor_data_release()
 * in processors_io_thread()), not under its feet.
 */
static void processors_release_idle(struct processor_data *pd)
{
	g_mutex_lock(&pd->queued.mutex);
	bool idle = pd->queued.refs == 0;
	if( idle )
	{
		pd->pending = 0;
		bistream_clear(pd->bistream);
	}
	g_mutex_unlock(&pd->queued.mutex);
	if( !idle )
		return;
	for( GList *it = pd->filters; it != NULL; it = it->next )
		processors_release_idle(it->data);
}

/*
 * queued.mutex of pd held: pd gives up, its data (and that of the instances it
 * feeds) goes now, also while a job of it runs (that job works on a copy and
 * stops at processor_done). true for the first call of a running instance.
 */
static bool processor_give_up_locked(struct processor_data *pd)
{
	if( processor_is_done(pd) || !g_atomic_int_compare_and_exchange(&pd->gave_up, 0, 1) )
		return false;
	g_atomic_int_set(&pd->state, processor_done);
	pd->pending = 0;
	processor_data_release(pd);
	return true;
}

/* once per instance, without any of its data */
static void processor_give_up_log(struct connection *con, struct processor_data *pd, const char *reason, bool limit)
{
	const char *protocol = con->protocol.name != NULL ? con->protocol.name : "-";
	if( limit )
	{
		g_atomic_int_inc(&processor_gave_up);
		g_warning("%s scan stopped (%s), connection %p %s %s:%i goes on", pd->processor->name,
				  reason, con, protocol, con->remote.ip_string, ntohs(con->remote.port));
	} else
	{
		g_info("%s scan stopped (%s), connection %p %s %s:%i goes on", pd->processor->name,
			   reason, con, protocol, con->remote.ip_string, ntohs(con->remote.port));
	}
}

void processor_give_up(struct connection *con, struct processor_data *pd, const char *reason, bool limit)
{
	g_mutex_lock(&pd->queued.mutex);
	bool first = processor_give_up_locked(pd);
	g_mutex_unlock(&pd->queued.mutex);
	if( first )
		processor_give_up_log(con, pd, reason, limit);
}

/*
 * A limit of the stream processing was reached for pd (its queued.mutex is not
 * held): pd gives up, or the connection is closed (give_up_on_limit).
 */
static void processor_limit(struct connection *con, struct processor_data *pd, const char *reason)
{
	if( pd->processor->give_up_on_limit )
		processor_give_up(con, pd, reason, true);
	else
		processors_overload(con, reason);
}

void processors_stop(struct connection *con)
{
	if( con->processor_data == NULL )
		return;
	g_atomic_int_set(&con->processor_data->ended, 1);
	processors_release_idle(con->processor_data);
}

static void processors_io_thread(void *data, void *userdata);

/*
 * queued.mutex held, no job exists: queue one. false: refused, the connection
 * reference and the job are given back.
 */
static bool processor_job_submit(struct connection *con, struct processor_data *pd)
{
	struct thread *t = thread_new(con, pd, processors_io_thread);
	connection_ref(con);
	pd->queued.refs = 1;
	if( thread_submit(t) )
		return true;
	pd->queued.refs = 0;
	connection_unref(con);
	g_free(t);
	return false;
}

/*
 * A worker: one job of one instance, for every direction that has new data.
 * Data that arrives meanwhile queues the next run behind the jobs of the
 * other instances; if the queue is full (or the pool refuses the job), the
 * run goes on in this worker instead: the instance keeps its one job, and a
 * connection within its limits is not closed for the jobs of others.
 */
static void processors_io_thread(void *data, void *userdata)
{
	g_debug("%s data %p userdata %p", __PRETTY_FUNCTION__, data,  userdata);
	struct connection *con = data;
	struct processor_data *pd = userdata;

	g_mutex_lock(&pd->mutex);

	for( bool again = true; again; )
	{
		g_mutex_lock(&pd->queued.mutex);
		unsigned pending = pd->pending;
		pd->pending = 0;
		g_mutex_unlock(&pd->queued.mutex);

		/* dionaea stops: a job that waited for a worker runs nothing */
		bool dropped = processors_jobs_dropped();
		if( !dropped && (pending & PROCESSOR_PENDING_IN) )
			recurse_io_process(pd, con, bistream_in);
		if( !dropped && (pending & PROCESSOR_PENDING_OUT) )
			recurse_io_process(pd, con, bistream_out);

		g_mutex_lock(&pd->queued.mutex);
		again = false;
		pd->queued.refs = 0;
		if( processor_is_done(pd) || processors_closing(con) || processors_jobs_dropped() )
		{
			/* no more processing: give the stream data back now */
			pd->pending = 0;
			processor_data_release(pd);
		} else
		if( pd->pending != 0 )
		{
			if( !processor_job_submit(con, pd) )
			{
				pd->queued.refs = 1;
				again = true;
			}
		} else
		if( processors_ended(con) )
		{
			/* the connection ended, its last data is read */
			processor_data_release(pd);
		}
		g_mutex_unlock(&pd->queued.mutex);
	}

	g_mutex_unlock(&pd->mutex);
	connection_unref(con);
}

void processor_io_single(struct connection *con,  struct processor_data *pd, void *data, int size, enum bistream_direction direction)
{
//	g_warning("%s con %p pd %p data %p size %i dir %i", __PRETTY_FUNCTION__, con, pd, data, size, direction);
	if( size <= 0 || processors_closing(con) )
		return;

	processor_io io;
	processor_thread_io thread_io;
	if( direction == bistream_in )
	{
		io = pd->processor->io_in;
		thread_io = pd->processor->thread_io_in;
	} else
	{
		io = pd->processor->io_out;
		thread_io = pd->processor->thread_io_out;
	}

	if( io != NULL )
	{
		io(con, pd, data, size);
		return;
	}

	/* keep a direction only for a processor that reads it */
	if( thread_io == NULL )
		return;

	const char *failure = NULL;
	bool gave_up = false;
	g_mutex_lock(&pd->queued.mutex);
	if( !processor_is_done(pd) && !processors_closing(con) && !processors_ended(con) )
	{
		if( !bistream_data_add(pd->bistream, direction, data, size) )
			failure = "stream data limit";
		else
		{
			pd->pending |= 1U << direction;
			if( pd->queued.refs == 0 && !processor_job_submit(con, pd) )
				failure = "job queue full";
		}
		if( failure != NULL && pd->processor->give_up_on_limit )
			gave_up = processor_give_up_locked(pd);
		else
		/* without a job nothing reads the data any more */
		if( failure != NULL && pd->queued.refs == 0 )
		{
			pd->pending = 0;
			processor_data_release(pd);
		}
	}
	g_mutex_unlock(&pd->queued.mutex);

	if( failure == NULL )
		return;
	if( pd->processor->give_up_on_limit )
	{
		if( gave_up )
			processor_give_up_log(con, pd, failure, true);
	} else
		processors_overload(con, failure);
}


void processors_io_in(struct connection *con, void *data, int size)
{
//	g_debug("%s con %p", __PRETTY_FUNCTION__, con);
	GList *it;
	for( it = g_list_first(con->processor_data->filters);  it != NULL; it = g_list_next(it) )
	{
		struct processor_data *pd = it->data;
//		g_warning("doing %s",  pd->processor->name);
		processor_io_single(con, pd, data, size, bistream_in);
	}
}

void processors_io_out(struct connection *con, void *data, int size)
{
//	g_debug("%s con %p", __PRETTY_FUNCTION__, con);
	GList *it;
	for( it = g_list_first(con->processor_data->filters);  it != NULL; it = g_list_next(it) )
	{
		struct processor_data *pd = it->data;
		processor_io_single(con, pd, data, size, bistream_out);
	}
}

void *proc_streamdumper_cfg_new(gchar *);
void proc_streamdumper_cfg_free(void *cfg);
void proc_streamdumper_shutdown(void *cfg);
void *proc_streamdumper_ctx_new(void *cfg);
void proc_streamdumper_ctx_free(void *ctx);
void proc_streamdumper_on_io_in(struct connection *con, struct processor_data *pd, void *data, int size);
void proc_streamdumper_on_io_out(struct connection *con, struct processor_data *pd, void *data, int size);

struct streamdumper_config
{
	char *path;
	/* config.max_size / config.max_files, NULL without a limit */
	struct streamcap *cap;
	/* the dumps that are open (struct streamdumper_ctx): at the end of dionaea the
	 * connections are not freed, the shutdown closes their dumps */
	GMutex open_lock;
	GList *open;
	bool shut_down;
};

struct processor proc_streamdumper =
{
	.name = "streamdumper",
	.cfg = proc_streamdumper_cfg_new,
	.new = proc_streamdumper_ctx_new,
	.free = proc_streamdumper_ctx_free,
	.io_in = proc_streamdumper_on_io_in,
	.io_out = proc_streamdumper_on_io_out,
	.shutdown = proc_streamdumper_shutdown,
};


struct streamdumper_ctx
{
	struct streamdumper_config *cfg;
	struct tempfile *file;
	struct streamcap_dump *dump;  /* its slot below the limits */
	bool refused;                 /* over a limit when the stream began: no dump at all */
	bool stopped;                 /* at max_size later or at the shutdown: the dump was closed, nothing more */
	enum bistream_direction last_was;
	GList *open_link;             /* its entry in cfg->open while its dump is open */
};

static const char *streamdumper_stream_start = "stream = [";
static const char *streamdumper_new_data = "b'";
static const char *streamdumper_change_stream = "'),\n";
static const char *streamdumper_close_stream = "')]";
static const char *streamdumper_direction[] =
{
	"('in', ",
	"('out', ",
};

/* the source of a limit that is no variable of the environment, in its line at the start */
#define STREAMDUMPER_CONFIG_SOURCE "dionaea.cfg"

/*
 * A limit: the variable env of the environment when it is set and valid
 * (decimal digits in the range of the option; an empty one is unset), else
 * the option key of the config (invalid is a warning and no limit, as the
 * max_size of the store handler). An invalid variable is a warning and the
 * config holds. *source names where the limit came from.
 */
static guint64 streamdumper_limit(gchar *group_name, const char *key, const char *env, bool mib,
								  const char **source)
{
	guint64 limit = 0;
	const char *variable = g_getenv(env);
	if( variable != NULL && *variable != '\0' )
	{
		if( mib ? streamcap_parse_env_mib(variable, &limit) : streamcap_parse_env_count(variable, &limit) )
		{
			*source = env;
			return limit;
		}
		char *shown = streamcap_env_shown(variable);
		g_warning("Ignoring %s='%s': %s, the value of %s holds", env, shown,
				  mib ? "a whole number of MiB >= 0 (decimal digits) is expected"
					  : "a whole number >= 0 (decimal digits) is expected",
				  STREAMDUMPER_CONFIG_SOURCE);
		g_free(shown);
	}
	*source = STREAMDUMPER_CONFIG_SOURCE;
	gchar *value = g_key_file_get_string(g_dionaea->config, group_name, key, NULL);
	bool ok = mib ? streamcap_parse_mib(value, &limit) : streamcap_parse_count(value, &limit);
	if( !ok )
		g_warning("Ignoring %s=%s of the streamdumper, the bistreams have no %s limit: %s",
				  key, value, mib ? "size" : "file",
				  mib ? "a number of MiB >= 0 is expected" : "a whole number >= 0 is expected");
	g_free(value);
	return limit;
}

/* max_size in MiB for the line at the start: a whole number as it is, else 6 digits */
static char *streamdumper_mib_text(guint64 bytes)
{
	if( bytes % (1024 * 1024) == 0 )
		return g_strdup_printf("%" G_GUINT64_FORMAT, bytes / (1024 * 1024));
	return g_strdup_printf("%.6g", (double)bytes / (1024 * 1024));
}

void *proc_streamdumper_cfg_new(gchar *group_name)
{
	struct streamdumper_config *cfg = g_malloc0(sizeof(struct streamdumper_config));
	g_mutex_init(&cfg->open_lock);
	gchar *path;
	GError *error = NULL;
	path = g_key_file_get_string(g_dionaea->config, group_name, "config.path", &error);

	// test the path ...
	char test[256];
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(test, 255, path, timeinfo);
	if( strcmp(test, path) == 0 ) {
		g_error("streamdumper path does not have time based modifiers, all files end up in a single directory, which is not accepted.");
	}

	g_info("%s <-> %s", test, path);
	cfg->path = path;

	const char *size_source, *files_source;
	guint64 max_bytes = streamdumper_limit(group_name, "config.max_size", "DIONAEA_STREAMDUMPER_MAX_SIZE", true,
										   &size_source);
	guint64 max_files = streamdumper_limit(group_name, "config.max_files", "DIONAEA_STREAMDUMPER_MAX_FILES", false,
										   &files_source);
	/* one line per limit, in a fixed format (doc/source/processor/streamdumper.rst) */
	char *size_text = streamdumper_mib_text(max_bytes);
	g_info("streamdumper: max_size %s MiB (from %s)", size_text, size_source);
	g_info("streamdumper: max_files %" G_GUINT64_FORMAT " (from %s)", max_files, files_source);
	g_free(size_text);
	char *base = streamcap_base(path);
	cfg->cap = streamcap_new(base, max_bytes, max_files, STREAMCAP_PERIOD);
	if( cfg->cap != NULL )
	{
		/* today's folder holds the dumps of dionaea, also those of a run before a restart */
		streamcap_path_set(cfg->cap, path);
		char *size = max_bytes ? g_strdup_printf("%.6g MiB", (double)max_bytes / (1024 * 1024)) : g_strdup("unlimited");
		char *files = max_files ? g_strdup_printf("%" G_GUINT64_FORMAT, max_files) : g_strdup("unlimited");
		/* the counting thread logs what the folder holds once it is counted */
		g_info("streamdumper: the bistreams in %s are limited to max_size %s and max_files %s",
			   base, size, files);
		g_free(size);
		g_free(files);
	}
	g_free(base);
	return cfg;
}

struct streamcap *proc_streamdumper_cap(void *cfg)
{
	return ((struct streamdumper_config *)cfg)->cap;
}

static void streamdumper_finish(struct streamdumper_ctx *ctx);

/*
 * At the end of dionaea, before its logs are closed (the event loop has ended and the
 * threadpool is gone, nothing writes to a dump any more): the dumps of the connections
 * that are still open are closed as at the end of their connection (with the closing
 * "')]", a Python literal like every other dump; dionaea never frees these connections),
 * then the counting thread ends.
 */
void proc_streamdumper_shutdown(void *cfg0)
{
	struct streamdumper_config *cfg = cfg0;
	g_mutex_lock(&cfg->open_lock);
	GList *open = cfg->open;
	cfg->open = NULL;
	cfg->shut_down = true;
	for( GList *it = open; it != NULL; it = it->next )
		((struct streamdumper_ctx *)it->data)->open_link = NULL;
	g_mutex_unlock(&cfg->open_lock);

	for( GList *it = open; it != NULL; it = it->next )
	{
		struct streamdumper_ctx *ctx = it->data;
		streamdumper_finish(ctx);
		/* data after the stop starts no new dump of it */
		ctx->stopped = true;
	}
	g_list_free(open);
	streamcap_stop(cfg->cap);
}

/* dionaea keeps its processors to the end; the tests free them */
void proc_streamdumper_cfg_free(void *cfg0)
{
	struct streamdumper_config *cfg = cfg0;
	streamcap_free(cfg->cap);
	g_list_free(cfg->open);
	g_mutex_clear(&cfg->open_lock);
	g_free(cfg->path);
	g_free(cfg);
}

/* the dump of ctx is open: the shutdown closes it if its connection is not freed before */
static void streamdumper_remember(struct streamdumper_ctx *ctx)
{
	struct streamdumper_config *cfg = ctx->cfg;
	g_mutex_lock(&cfg->open_lock);
	if( !cfg->shut_down && ctx->open_link == NULL )
	{
		cfg->open = g_list_prepend(cfg->open, ctx);
		ctx->open_link = cfg->open;
	}
	g_mutex_unlock(&cfg->open_lock);
}

static void streamdumper_forget(struct streamdumper_ctx *ctx)
{
	struct streamdumper_config *cfg = ctx->cfg;
	g_mutex_lock(&cfg->open_lock);
	if( ctx->open_link != NULL )
	{
		cfg->open = g_list_delete_link(cfg->open, ctx->open_link);
		ctx->open_link = NULL;
	}
	g_mutex_unlock(&cfg->open_lock);
}

void *proc_streamdumper_ctx_new(void *cfg)
{
	struct streamdumper_ctx *ctx = g_malloc0(sizeof(struct streamdumper_ctx));
	ctx->cfg = cfg;
	return ctx;
}

/* write to the dump; with a limit its bytes were counted before (streamcap_open / _reserve) */
static bool streamdumper_write(struct streamdumper_ctx *ctx, const void *data, size_t size, const char *what)
{
	if( fwrite(data, size, 1, ctx->file->fh) != 1 )
	{
		g_warning("Could not write %s %s", what, strerror(errno));
		return false;
	}
	return true;
}

/* close the dump as at the end of its stream (its end was counted with its first write) */
static void streamdumper_finish(struct streamdumper_ctx *ctx)
{
	streamdumper_forget(ctx);
	bool kept = ctx->file != NULL;
	if( ctx->file != NULL )
	{
		streamdumper_write(ctx, streamdumper_close_stream, strlen(streamdumper_close_stream), "close_stream");
		tempfile_close(ctx->file);
		tempfile_free(ctx->file);
		ctx->file = NULL;
	}
	if( ctx->dump != NULL )
	{
		streamcap_close(ctx->cfg->cap, ctx->dump, kept);
		ctx->dump = NULL;
	}
}

void proc_streamdumper_ctx_free(void *ctx0)
{
	struct streamdumper_ctx *ctx = ctx0;
	streamdumper_finish(ctx);
	g_free(ctx);
}

ssize_t format_timeval(struct timeval *tv, char *buf, size_t sz)
{
	ssize_t written = -1;
	struct tm *gm = gmtime(&tv->tv_sec);

	if (gm) {
		written = (ssize_t)strftime(buf, sz, "%Y-%m-%dT%H:%M:%d", gm);
		if ((written > 0) && ((size_t)written < sz)) {
			int w = snprintf(buf+written, sz-(size_t)written, ".%06ld", tv->tv_usec);
			written = (w > 0) ? written + w : -1;
		}
	}
	return written;
}

/* create the dump of the connection; false if there is none (a limit, an error) */
static bool streamdumper_create(struct connection *con, struct streamdumper_ctx *ctx, enum bistream_direction dir, size_t first_data)
{
	struct streamdumper_config *cfg = ctx->cfg;
	if( cfg->cap != NULL && ctx->dump == NULL )
	{
		/* the dump as it would be if the stream ended after this data */
		size_t first_write = strlen(streamdumper_stream_start) + strlen(streamdumper_direction[dir]) +
			strlen(streamdumper_new_data) + first_data + strlen(streamdumper_close_stream);
		if( (ctx->dump = streamcap_open(cfg->cap, first_write)) == NULL )
		{
			ctx->refused = true;
			return false;
		}
	}

	time_t stamp;
	if( g_dionaea != NULL && g_dionaea->loop != NULL )
		stamp = ev_now(g_dionaea->loop);
	else
		stamp = time(NULL);
	struct tm t;
	localtime_r(&stamp, &t);
	char path[128];
	strftime(path, sizeof(path), cfg->path, &t);
	char prefix[512];
	char timebuf[28];
	format_timeval(&con->stats.start, timebuf, sizeof(timebuf));
	snprintf(prefix, sizeof(prefix), "%s-%s-%i-%s-%i-%s-",
			 con->protocol.name,
			 con->local.ip_string,
			 ntohs(con->local.port),
			 con->remote.ip_string,
			 ntohs(con->remote.port),
			 timebuf);

	struct stat s;
	if( stat(path, &s) != 0 )
	{
		if( mkdir(path, S_IRWXU|S_IRUSR|S_IWUSR|S_IXUSR|S_IRWXG|S_IRGRP|S_IWGRP|S_IXGRP|S_IRWXO|S_IROTH|S_IWOTH|S_IXOTH) != 0 )
			g_warning("Could not create %s %s",  path, strerror(errno));
		else if( cfg->cap != NULL )
			/* its dumps are all known: the limits never read it at a refusal */
			streamcap_made(cfg->cap, path);
	}

	if( (ctx->file = tempfile_new(path, prefix)) == NULL )
	{
		/* the next data tries again; the slot is free until then */
		if( ctx->dump != NULL )
		{
			streamcap_close(cfg->cap, ctx->dump, false);
			ctx->dump = NULL;
		}
		return false;
	}
	if( ctx->dump != NULL )
		streamcap_opened(cfg->cap, ctx->dump, ctx->file->fd, path);
	streamdumper_remember(ctx);
	return true;
}

/* a byte of the stream that the dump has as \xNN: all but 0x20..0x7e, and ' and \; in every
 * locale (isprint() of a locale of one byte per character takes bytes above 0x7e as well) */
static bool streamdumper_escaped(unsigned char c)
{
	return c < 0x20 || c > 0x7e || c == '\'' || c == '\\';
}

/*
 * write size bytes of the stream as the text of a Python bytes literal; in
 * pieces of a fixed buffer, as a read can be several MiB (connection_tcp.c
 * reads what the socket holds)
 */
static bool streamdumper_write_escaped(struct streamdumper_ctx *ctx, const unsigned char *data, size_t size)
{
	static const char conv[] = "0123456789abcdef";
	char buf[4096];
	size_t used = 0;
	for( size_t i = 0; i < size; i++ )
	{
		if( used + 4 > sizeof(buf) )
		{
			if( !streamdumper_write(ctx, buf, used, "data") )
				return false;
			used = 0;
		}
		unsigned char c = data[i];
		if( !streamdumper_escaped(c) )
			buf[used++] = (char)c;
		else
		{
			buf[used++] = '\\';
			buf[used++] = 'x';
			buf[used++] = conv[c >> 4];
			buf[used++] = conv[c & 0x0f];
		}
	}
	return used == 0 || streamdumper_write(ctx, buf, used, "data");
}

void proc_streamdumper_on_io(struct connection *con, struct processor_data *pd, void *data, int size, enum bistream_direction dir)
{
//	g_warning("%s con %p pd %p data %p size %i dir %i", __PRETTY_FUNCTION__, con, pd, data, size, dir);
	struct streamdumper_ctx *ctx = pd->ctx;

	/* over a limit when the stream began: nothing of it is dumped; at max_size later: nothing more */
	if( ctx->refused || ctx->stopped )
		return;

	const unsigned char *cdata = data;
	size_t writesize = 0;
	for( int i = 0; i < size; i++ )
		writesize += streamdumper_escaped(cdata[i]) ? 4 : 1;

	if( ctx->file == NULL )
	{
		if( !streamdumper_create(con, ctx, dir, writesize) )
			return;

		if( !streamdumper_write(ctx, streamdumper_stream_start, strlen(streamdumper_stream_start), "stream_start") )
			return;

		if( !streamdumper_write(ctx, streamdumper_direction[dir], strlen(streamdumper_direction[dir]), "direction") )
			return;

		if( !streamdumper_write(ctx, streamdumper_new_data, strlen(streamdumper_new_data), "new_data") )
			return;
		ctx->last_was = dir;
	} else if( ctx->dump != NULL )
	{
		/* this chunk must fit below max_size, else the dump ends before it */
		size_t chunk = writesize;
		if( ctx->last_was != dir )
			chunk += strlen(streamdumper_change_stream) + strlen(streamdumper_direction[dir]) +
				strlen(streamdumper_new_data);
		if( !streamcap_reserve(ctx->cfg->cap, ctx->dump, chunk) )
		{
			streamdumper_finish(ctx);
			ctx->stopped = true;
			return;
		}
	}

	if( ctx->last_was != dir )
	{
		if( !streamdumper_write(ctx, streamdumper_change_stream, strlen(streamdumper_change_stream), "change_stream") )
			return;

		if( !streamdumper_write(ctx, streamdumper_direction[dir], strlen(streamdumper_direction[dir]), "direction") )
			return;

		if( !streamdumper_write(ctx, streamdumper_new_data, strlen(streamdumper_new_data), "new_data") )
			return;

		ctx->last_was = dir;
	}

	if( writesize > 0 )
		streamdumper_write_escaped(ctx, cdata, (size_t)size);
}




void proc_streamdumper_on_io_in(struct connection *con, struct processor_data *pd, void *data, int size)
{
	proc_streamdumper_on_io(con, pd, data, size, bistream_in);
}

void proc_streamdumper_on_io_out(struct connection *con, struct processor_data *pd, void *data, int size)
{
	proc_streamdumper_on_io(con, pd, data, size, bistream_out);
}


void *proc_unicode_ctx_new(void *data);
void proc_unicode_ctx_free(void *ctx);
void proc_unicode_on_io_in(struct connection *con, struct processor_data *pd);

/* only the incoming stream is read, the outgoing one is not kept */
struct processor proc_unicode =
{
	.name = "unicode",
	.new = proc_unicode_ctx_new,
	.free = proc_unicode_ctx_free,
	.thread_io_in = proc_unicode_on_io_in,
};

struct proc_unicode_ctx
{
	uint64_t io_in_offset;
};

void *proc_unicode_ctx_new(void *cfg)
{
	struct proc_unicode_ctx *ctx = g_malloc0(sizeof(struct proc_unicode_ctx));
	ctx->io_in_offset = 0;
	return ctx;
}

void proc_unicode_ctx_free(void *ctx)
{
	g_free(ctx);
}

/* hand the new incoming data to the processors behind, then drop it */
void proc_unicode_on_io_in(struct connection *con, struct processor_data *pd)
{
	g_debug("%s con %p pd %p", __PRETTY_FUNCTION__, con, pd);
	struct proc_unicode_ctx *ctx = pd->ctx;
	void *streamdata = NULL;
	int32_t size = bistream_get_stream(pd->bistream, bistream_in, ctx->io_in_offset, -1, &streamdata);
	if( size <= 0 )
		return;
	ctx->io_in_offset += size;
	for( GList *it = g_list_first(pd->filters); it != NULL; it = g_list_next(it) )
	{
		struct processor_data *filter = it->data;
		g_mutex_lock(&filter->queued.mutex);
		bool added = processor_is_done(filter) || processors_closing(con) ||
			bistream_data_add(filter->bistream, bistream_in, streamdata, size);
		g_mutex_unlock(&filter->queued.mutex);
		if( added )
			continue;
		/* a processor that can give up does so, the others go on */
		processor_limit(con, filter, "stream data limit");
		if( !filter->processor->give_up_on_limit )
			break;
	}
	g_free(streamdata);
	bistream_discard_before(pd->bistream, bistream_in, ctx->io_in_offset);
}


void *proc_filter_cfg(gchar *);
bool proc_filter_accept(struct connection *con, void *config);
void *proc_filter_ctx_new(void *data);
void proc_filter_ctx_free(void *ctx);
void proc_filter_on_io_in(struct connection *con, struct processor_data *pd, void *data, int size);
void proc_filter_on_io_out(struct connection *con, struct processor_data *pd, void *data, int size);

struct processor proc_filter =
{
	.name = "filter",
	.cfg = proc_filter_cfg,
	.process = proc_filter_accept,
	.new = proc_filter_ctx_new,
	.free = proc_filter_ctx_free,
	.io_in = proc_filter_on_io_in,
	.io_out = proc_filter_on_io_out,
};

struct proc_filter_config_rule
{
	GList *types;
	GList *protocols;
};

struct proc_filter_config
{
	GList *allow;
	GList *deny;
};

struct proc_filter_ctx
{
	struct proc_filter_config *config;
};

void proc_filter_dump_rules(struct proc_filter_config *cfg)
{
	struct
	{
		char *mode;
		int offset;
	} cfg_iter_help[] =
	{
		{ "allow", offsetof(struct proc_filter_config, allow) },
		{ "deny", offsetof(struct proc_filter_config, deny) },
		{}
	};

	struct
	{
		char *type;
		int offset;
	} rule_iter_help[] =
	{
		{ "protocol", offsetof(struct proc_filter_config_rule, protocols) },
		{ "type", offsetof(struct proc_filter_config_rule, types) },
		{}
	};

	g_debug("Dumping filter rules ...");
	for( int i=0; cfg_iter_help[i].mode != NULL; i++ )
	{
		GList **list = (((void *)cfg) + cfg_iter_help[i].offset);
//		g_warning("mode %s offset %i list %p %p %p",  cfg_iter_help[i].mode, cfg_iter_help[i].offset, cfg, list, cfg->deny);

		if( *list == NULL )
			continue;

		g_debug("%s:",  cfg_iter_help[i].mode);


		for( GList *it = g_list_first((void *)*list); it != NULL; it = g_list_next(it) )
		{
			for( int j=0; rule_iter_help[j].type != NULL; j++ )
			{
				g_debug("- %s  ", rule_iter_help[j].type);

				struct proc_filter_config_rule *rule = it->data;
//				g_warning("################");
				GList **rules = (((void *)rule) + rule_iter_help[j].offset);
				for( GList *jt = g_list_first(*rules); jt != NULL; jt = g_list_next(jt) )
				{
					char *p = jt->data;
//					g_warning("%s %s %s", cfg_iter_help[i].mode, rule_iter_help[j].type, p);
					g_debug("  - %s",  p);
				}
//				g_warning("################");
			}
		}
	}
//	exit(0);
}

void *proc_filter_cfg(gchar *group_name)
{
	struct proc_filter_config *cfg = g_malloc0(sizeof(struct proc_filter_config));

//	char *mode = NULL;
//	char *what = NULL;

	GList *allow_keys = NULL;
	GList *deny_keys = NULL;

	gchar **keys;
	gchar **key;
	gchar **parts;
	gsize len;
	GError *error=NULL;
	keys = g_key_file_get_keys (g_dionaea->config, group_name, &len, &error);
	for(key = keys; *key; key++) {
		parts = g_strsplit(*key, ".", 4);
		if(g_strcmp0(parts[0], "config") != 0) {
			continue;
		}
		if(g_strcmp0(parts[1], "allow") == 0) {
			if(g_list_find_custom(allow_keys, parts[2], (GCompareFunc) g_strcmp0) == NULL) {
				allow_keys = g_list_append(allow_keys, parts[2]);
			}
		} else if(g_strcmp0(parts[1], "deny") == 0) {
			if(g_list_find(deny_keys, parts[2]) == NULL) {
				deny_keys = g_list_append(deny_keys, parts[2]);
			}
		}
	}

	GList *l;
	gchar **values, **value, *k;
	for (l = allow_keys; l != NULL; l = l->next) {
		struct proc_filter_config_rule *rule = g_malloc0(sizeof(struct proc_filter_config_rule));
		cfg->allow = g_list_append(cfg->allow, rule);
		k = g_strjoin(".", "config", "allow", l->data, "protocols", NULL);
		values = g_key_file_get_string_list(g_dionaea->config, group_name, k, &len, &error);
		if(error == NULL) {
			for(value = values; *value; value++) {
				rule->protocols = g_list_append(rule->protocols, *value);
			}
		} else {
			g_debug("%s", error->message);
		}
		g_clear_error(&error);

		k = g_strjoin(".", "config", "allow", l->data, "types", NULL);
		values = g_key_file_get_string_list(g_dionaea->config, group_name, k, &len, &error);
		if(error == NULL) {
			for(value = values; *value; value++) {
				rule->types = g_list_append(rule->types, *value);
			}
		} else {
			g_debug("%s", error->message);
		}
		g_clear_error(&error);
	}

	for (l = deny_keys; l != NULL; l = l->next) {
		struct proc_filter_config_rule *rule = g_malloc0(sizeof(struct proc_filter_config_rule));
		cfg->deny = g_list_append(cfg->deny, rule);
		k = g_strjoin(".", "config", "deny", l->data, "protocols", NULL);
		values = g_key_file_get_string_list(g_dionaea->config, group_name, k, &len, &error);
		if(error == NULL) {
			for(value = values; *value; value++) {
				rule->protocols = g_list_append(rule->protocols, *value);
			}
		} else {
			g_debug("%s", error->message);
		}
		g_clear_error(&error);

		k = g_strjoin(".", "config", "deny", l->data, "types", NULL);
		values = g_key_file_get_string_list(g_dionaea->config, group_name, k, &len, &error);
		if(error == NULL) {
			for(value = values; *value; value++) {
				rule->types = g_list_append(rule->types, *value);
			}
		} else {
			g_debug("%s", error->message);
		}
		g_clear_error(&error);
	}

	proc_filter_dump_rules(cfg);
	return cfg;
}

bool proc_filter_accept_match(struct connection *con, GList *list)
{
	bool match = false;

	for(GList *it = g_list_first(list); it != NULL; it = g_list_next(it) )
	{
		struct proc_filter_config_rule *rule = it->data;
		bool protocol = rule->protocols ? false : true;
		bool type = rule->types ? false : true;
		for( GList *jt = g_list_first(rule->protocols); jt != NULL; jt = g_list_next(jt) )
		{
			char *p = jt->data;
			if( strcmp(p, con->protocol.name) == 0)
			{
				protocol = true;
				break;
			}
		}

		for( GList *jt = g_list_first(rule->types); jt != NULL; jt = g_list_next(jt) )
		{
			char *p = jt->data;
			if( strcmp(p, connection_type_to_string(con->type)) == 0)
			{
				type = true;
				break;
			}
		}

		if( protocol && type )
		{
			match = true;
			break;
		}
	}
	return match;
}


bool proc_filter_accept(struct connection *con, void *config)
{
//	g_debug("%s con %p config %p",  __PRETTY_FUNCTION__, con, config);

	struct proc_filter_config *cfg = config;

	bool allow = false;
	bool deny = false;

	allow = proc_filter_accept_match(con, cfg->allow);
	if( allow == false )
		return false;

	deny = proc_filter_accept_match(con, cfg->deny);

	if( deny == true )
		return false;

	return true;
}

void *proc_filter_ctx_new(void *config)
{
	struct proc_filter_ctx *ctx = g_malloc0(sizeof(struct proc_filter_ctx));
	ctx->config = config;
	return ctx;
}

void proc_filter_ctx_free(void *ctx)
{
	g_free(ctx);
}

void proc_filter_on_io(struct connection *con, struct processor_data *pd, void *data, int size, enum bistream_direction direction)
{
//	g_debug("%s con %p pd %p data %p size %i direction %i", __PRETTY_FUNCTION__, con, pd, data, size, direction);

	GList *it;
	for( it = pd->filters; it != NULL; it = g_list_next(it) )
	{
		struct processor_data *pd = it->data;
		processor_io_single(con, pd, data, size, direction);
	}
}

void proc_filter_on_io_in(struct connection *con, struct processor_data *pd, void *data, int size)
{
//	g_debug("%s con %p pd %p data %p size %i", __PRETTY_FUNCTION__, con, pd, data, size);
	proc_filter_on_io(con,pd,data,size,bistream_in);
}

void proc_filter_on_io_out(struct connection *con, struct processor_data *pd, void *data, int size)
{
//	g_debug("%s con %p pd %p data %p size %i", __PRETTY_FUNCTION__, con, pd, data, size);
	proc_filter_on_io(con,pd,data,size,bistream_out);
}
