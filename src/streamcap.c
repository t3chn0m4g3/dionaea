/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2026 T-Pot contributors
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The limits of the streamdumper, see include/streamcap.h.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <glib.h>

#include "config.h"
#include "streamcap.h"
#include "log.h"

#define D_LOG_DOMAIN "streamcap"

#define MIB (1024.0 * 1024.0)
/* at most 2^40 MiB, so the bytes fit into 64 bits */
#define MAX_MIB 1099511627776.0
/* folders below the base that are counted (base/day/... as with %Y/%m/%d) */
#define STREAMCAP_DEPTH 16
/* a date folder that could not be read is tried again after 1, 2, 4, ... at most this many checks */
#define STREAMCAP_RETRY_MAX 64

struct file_id
{
	dev_t dev;
	ino_t ino;
};

struct streamcap_dump
{
	struct file_id id;
	bool has_id;      /* the file exists, streamcap_opened() */
	guint64 bytes;    /* written so far */
	char *top;        /* its date folder in the base (NULL: in the base itself, or not below it) */
};

/*
 * What is counted for one entry of the base folder (a date folder, with all
 * below it), or for the files directly in the base (name NULL).
 */
struct top_dir
{
	char *name;
	bool has_id;                 /* id: the folder that its last count read */
	struct file_id id;
	gint64 mtime;                /* its mtime (ns) before that count read it, or when it was taken as ours */
	bool retry;                  /* its count failed: counted again after retry_wait more checks */
	guint retry_wait;
	guint retry_backoff;         /* checks until the next try after the next failure */
	guint64 bytes;               /* its files that are no open dump */
	guint64 files;
	guint64 count_bytes;         /* the dumps closed into it while a count runs */
	guint64 count_files;
	guint64 open_dumps;          /* open dumps of this process in it: it is ours, see check_folder() */
	bool own;                    /* this process made it (streamcap_made()), or it is today's: never read at a refresh */
	guint64 touched;             /* cap->gen of the last streamcap_made() / streamcap_opened() for it */
};

struct streamcap
{
	/* set before the thread starts, never changed */
	char *base;
	guint64 max_bytes;
	guint64 max_files;
	gint64 period;
	/* config.path, under the lock (streamcap_path_set()): today's date folder is ours */
	char *path;

	/* a leaf, see include/streamcap.h; the fields below are under it */
	GMutex lock;
	GCond cond;

	/* files that are no open dump: the sum of loose and dirs */
	guint64 closed_bytes;
	guint64 closed_files;
	struct top_dir loose;        /* the files directly in the base */
	GHashTable *dirs;            /* name -> struct top_dir *: the date folders */
	/* the base folder that the last count of it read */
	bool base_known;
	struct file_id base_id;
	/* a count of the base that failed is tried again after base_wait more checks */
	guint base_wait;
	guint base_backoff;
	/*
	 * counts streamcap_made() and streamcap_opened() (top_dir.touched): a check
	 * that read the base without the lock leaves a record alone that one of them
	 * touched after it took what was known (check_folder())
	 */
	guint64 gen;
	/* the open dumps, with the bytes written to them */
	guint64 open_bytes;
	guint64 open_files;
	GHashTable *open;            /* struct file_id * -> struct streamcap_dump * */

	/* while a count runs it skips the open dumps and the dumps closed meanwhile */
	bool counting;
	GHashTable *closed_in_count; /* struct file_id * (owned) */
	bool counted;                /* the first count of the folder ended */
	guint64 counts;              /* checks of the folder that ended */
	guint64 full_counts;         /* counts of the whole folder that ended */
	guint64 dir_counts;          /* counts of one date folder that ended */
	guint64 started;             /* checks that began (check_now()) */
	bool count_requested;
	bool full_requested;
	/*
	 * A refused dump asks the next check to count the date folders that changed
	 * since their count (refresh_requested), at most once per period
	 * (refresh_asked_at). refresh_counted: that check counted a folder; the
	 * eventloop then takes refresh_asked_at as the time of that count
	 * (counted_at), the next count waits STREAMCAP_RECOUNT_INTERVAL. The clock
	 * is read by the eventloop only.
	 */
	bool refresh_requested;
	bool refresh_running;        /* the check that does it runs */
	bool refresh_asked;
	gint64 refresh_asked_at;
	bool refresh_counted;
	bool counted_once;
	gint64 counted_at;
	bool stop;
	gint stopping;               /* atomic: stop, read by the counts between two entries */
	GThread *thread;

	/* the warnings about refused dumps */
	gint64 (*clock)(void);
	bool warned;
	gint64 warned_at;
	guint64 refused;             /* since the start */
	guint64 refused_unlogged;    /* since the last warning */
	/* the warnings about dumps stopped at max_size */
	bool stop_warned;
	gint64 stop_warned_at;
	guint64 stopped;             /* since the start */
	guint64 stopped_unlogged;    /* since the last warning */

	streamcap_count_hook hook;
	void *hook_data;
};

static guint file_id_hash(gconstpointer key)
{
	const struct file_id *id = key;
	guint64 v = (guint64)id->ino * 31 + (guint64)id->dev;
	return (guint)(v ^ (v >> 32));
}

static gboolean file_id_equal(gconstpointer a, gconstpointer b)
{
	const struct file_id *x = a, *y = b;
	return x->dev == y->dev && x->ino == y->ino;
}

static void top_dir_free(gpointer data)
{
	struct top_dir *top = data;
	g_free(top->name);
	g_free(top);
}

static gint64 mtime_ns(const struct stat *st)
{
	return (gint64)st->st_mtim.tv_sec * G_GINT64_CONSTANT(1000000000) + st->st_mtim.tv_nsec;
}

/*
 * The bases of the caps that exist (base -> number of caps): two references of
 * the streamdumper with the same base each count only their own dumps after the
 * first count, a warning says so. Made at the config of dionaea, freed at its
 * end; the lock is a leaf, taken by streamcap_new() and streamcap_free() only.
 */
static GMutex bases_lock;
static GHashTable *bases;

static guint base_add(const char *base)
{
	g_mutex_lock(&bases_lock);
	if( bases == NULL )
		bases = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
	guint others = GPOINTER_TO_UINT(g_hash_table_lookup(bases, base));
	g_hash_table_insert(bases, g_strdup(base), GUINT_TO_POINTER(others + 1));
	g_mutex_unlock(&bases_lock);
	return others;
}

static void base_remove(const char *base)
{
	g_mutex_lock(&bases_lock);
	guint n = bases != NULL ? GPOINTER_TO_UINT(g_hash_table_lookup(bases, base)) : 0;
	if( n > 1 )
		g_hash_table_insert(bases, g_strdup(base), GUINT_TO_POINTER(n - 1));
	else if( n == 1 )
		g_hash_table_remove(bases, base);
	if( bases != NULL && g_hash_table_size(bases) == 0 )
	{
		g_hash_table_destroy(bases);
		bases = NULL;
	}
	g_mutex_unlock(&bases_lock);
}

bool streamcap_parse_mib(const char *value, guint64 *bytes)
{
	*bytes = 0;
	if( value == NULL )
		return true;
	char *v = g_strstrip(g_strdup(value));
	bool ok = true;
	if( *v != '\0' )
	{
		char *end = NULL;
		errno = 0;
		double mib = g_ascii_strtod(v, &end);
		/* a plain decimal number: no hex, nan or inf */
		if( errno != 0 || end == v || *end != '\0' || strpbrk(v, "xXnN") != NULL ||
			!isfinite(mib) || mib < 0 || mib > MAX_MIB )
			ok = false;
		else
		{
			*bytes = (guint64)(mib * MIB);
			/* below one byte is one byte: 0 would be no limit */
			if( mib > 0 && *bytes == 0 )
				*bytes = 1;
		}
	}
	g_free(v);
	return ok;
}

bool streamcap_parse_count(const char *value, guint64 *count)
{
	*count = 0;
	if( value == NULL )
		return true;
	char *v = g_strstrip(g_strdup(value));
	bool ok = true;
	for( const char *c = v; *c != '\0'; c++ )
		if( !g_ascii_isdigit(*c) )
			ok = false;
	if( ok && *v != '\0' )
	{
		errno = 0;
		guint64 n = g_ascii_strtoull(v, NULL, 10);
		if( errno != 0 )
			ok = false;
		else
			*count = n;
	}
	g_free(v);
	return ok;
}

/* a value of the environment: one or more decimal digits, nothing else */
static bool env_digits(const char *value)
{
	if( value == NULL || *value == '\0' )
		return false;
	for( const char *c = value; *c != '\0'; c++ )
		if( *c < '0' || *c > '9' )
			return false;
	return true;
}

bool streamcap_parse_env_mib(const char *value, guint64 *bytes)
{
	*bytes = 0;
	return env_digits(value) && streamcap_parse_mib(value, bytes);
}

bool streamcap_parse_env_count(const char *value, guint64 *count)
{
	*count = 0;
	return env_digits(value) && streamcap_parse_count(value, count);
}

#define ENV_SHOWN_MAX 64

char *streamcap_env_shown(const char *value)
{
	size_t len = strnlen(value, ENV_SHOWN_MAX);
	char *shown = g_strndup(value, len);
	for( size_t i = 0; i < len; i++ )
		if( !g_ascii_isprint(shown[i]) )
			shown[i] = '?';
	return shown;
}

char *streamcap_base(const char *path)
{
	const char *field = strchr(path, '%');
	size_t len = field != NULL ? (size_t)(field - path) : strlen(path);
	/* the folder that holds the first field */
	while( len > 0 && path[len - 1] != '/' )
		len--;
	/* without the slashes at its end, but / stays */
	while( len > 1 && path[len - 1] == '/' )
		len--;
	if( len == 0 )
		return g_strdup(".");
	return g_strndup(path, len);
}

/* the entry of base that holds the folder dir (newly allocated), NULL: base itself, or not below it */
static char *top_name(const char *base, const char *dir)
{
	if( dir == NULL )
		return NULL;
	const char *rel = NULL;
	size_t n = strlen(base);
	if( strcmp(base, ".") == 0 && dir[0] != '/' )
		rel = dir;
	else if( n > 0 && strncmp(dir, base, n) == 0 && (base[n - 1] == '/' || dir[n] == '/' || dir[n] == '\0') )
		rel = dir + n;
	if( rel == NULL )
		return NULL;
	for( ;; )
	{
		while( *rel == '/' )
			rel++;
		size_t len = strcspn(rel, "/");
		/* ./ is the base itself; ../ leaves it */
		if( len == 1 && rel[0] == '.' )
		{
			rel++;
			continue;
		}
		if( len == 0 || (len == 2 && rel[0] == '.' && rel[1] == '.') )
			return NULL;
		return g_strndup(rel, len);
	}
}

/* the entry of base that is the folder dir itself (newly allocated), NULL: dir is deeper, the base, or not below it */
static char *own_top(const char *base, const char *dir)
{
	char *top = top_name(base, dir);
	if( top == NULL )
		return NULL;
	/* with %Y/%m/%d the year may be older than this process: only the entry itself */
	char *path = g_build_filename(base, top, NULL);
	char *made = g_canonicalize_filename(dir, "/");
	char *entry = g_canonicalize_filename(path, "/");
	bool own = g_strcmp0(made, entry) == 0;
	g_free(made);
	g_free(entry);
	g_free(path);
	if( own )
		return top;
	g_free(top);
	return NULL;
}

/*
 * The entry of the base that is the date folder config.path names now (newly
 * allocated), NULL: none (no path, or a nested one). The local time, as the
 * streamdumper names its folders.
 */
static char *today_top(struct streamcap *cap)
{
	g_mutex_lock(&cap->lock);
	char *path = g_strdup(cap->path);
	g_mutex_unlock(&cap->lock);
	if( path == NULL )
		return NULL;
	time_t now = time(NULL);
	struct tm t;
	char dir[4096];
	size_t n = localtime_r(&now, &t) != NULL ? strftime(dir, sizeof(dir), path, &t) : 0;
	g_free(path);
	return n > 0 ? own_top(cap->base, dir) : NULL;
}

/* the record of the date folder name, made if it is new (NULL: the files directly in the base) */
static struct top_dir *top_get(struct streamcap *cap, const char *name)
{
	if( name == NULL )
		return &cap->loose;
	struct top_dir *top = g_hash_table_lookup(cap->dirs, name);
	if( top == NULL )
	{
		top = g_malloc0(sizeof(struct top_dir));
		top->name = g_strdup(name);
		g_hash_table_insert(cap->dirs, top->name, top);
	}
	return top;
}

static void top_reset_count(gpointer key, gpointer value, gpointer data)
{
	(void)key;
	(void)data;
	struct top_dir *top = value;
	top->count_bytes = 0;
	top->count_files = 0;
}

/* a count begins (cap->lock): the dumps closed from now on are skipped by it and counted on their own */
static void count_begin(struct streamcap *cap)
{
	cap->counting = true;
	g_hash_table_remove_all(cap->closed_in_count);
	g_hash_table_foreach(cap->dirs, top_reset_count, NULL);
	top_reset_count(NULL, &cap->loose, NULL);
}

static void count_end(struct streamcap *cap)
{
	cap->counting = false;
	g_hash_table_remove_all(cap->closed_in_count);
	g_hash_table_foreach(cap->dirs, top_reset_count, NULL);
	top_reset_count(NULL, &cap->loose, NULL);
}

static void closed_sum(struct streamcap *cap)
{
	cap->closed_bytes = cap->loose.bytes;
	cap->closed_files = cap->loose.files;
	GHashTableIter it;
	gpointer value;
	g_hash_table_iter_init(&it, cap->dirs);
	while( g_hash_table_iter_next(&it, NULL, &value) )
	{
		struct top_dir *top = value;
		cap->closed_bytes += top->bytes;
		cap->closed_files += top->files;
	}
}

struct count
{
	guint64 bytes;
	guint64 files;
	GHashTable *links;    /* counted files with more than one name */
	int error;            /* errno of a folder that could not be read, ECANCELED at the stop */
};

static bool stopping(struct streamcap *cap)
{
	return g_atomic_int_get(&cap->stopping) != 0;
}

static void count_file(struct streamcap *cap, const char *name, const struct stat *st, struct count *count)
{
	struct file_id id = { .dev = st->st_dev, .ino = st->st_ino };
	if( st->st_nlink > 1 )
	{
		/* only such a file can come again: the set stays small */
		if( g_hash_table_contains(count->links, &id) )
			return;
		g_hash_table_add(count->links, g_memdup2(&id, sizeof(id)));
	}

	g_mutex_lock(&cap->lock);
	/* an open dump and a dump closed while this count runs are known exactly */
	bool known = g_hash_table_contains(cap->open, &id) || g_hash_table_contains(cap->closed_in_count, &id);
	streamcap_count_hook hook = cap->hook;
	void *hook_data = cap->hook_data;
	g_mutex_unlock(&cap->lock);

	if( !known )
	{
		count->bytes += (guint64)st->st_size;
		count->files++;
	}
	if( hook != NULL )
		hook(cap, name, hook_data);
}

/*
 * Count the folder name of parent with all below it; id and mtime: the folder
 * that was read, before it was read. false if it is not there (gone meanwhile,
 * or no folder).
 */
static bool count_dir(struct streamcap *cap, int parent, const char *name, int depth, struct count *count,
					  struct file_id *id, gint64 *mtime)
{
	/* nothing below the base is followed */
	int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if( fd == -1 )
	{
		if( errno != ENOENT && errno != ENOTDIR && errno != ELOOP )
			count->error = errno;
		return false;
	}
	if( id != NULL )
	{
		struct stat st;
		if( fstat(fd, &st) != 0 )
		{
			count->error = errno;
			close(fd);
			return false;
		}
		id->dev = st.st_dev;
		id->ino = st.st_ino;
		*mtime = mtime_ns(&st);
	}
	DIR *dir = fdopendir(fd);
	if( dir == NULL )
	{
		count->error = errno;
		close(fd);
		return false;
	}

	for( ;; )
	{
		/* the stop waits for one entry, not for the folder */
		if( stopping(cap) )
		{
			count->error = ECANCELED;
			break;
		}
		errno = 0;
		struct dirent *entry = readdir(dir);
		if( entry == NULL )
		{
			if( errno != 0 )
				count->error = errno;
			break;
		}
		if( strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 )
			continue;
		struct stat st;
		if( fstatat(dirfd(dir), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 )
			continue;
		if( S_ISDIR(st.st_mode) )
		{
			if( depth < STREAMCAP_DEPTH )
				count_dir(cap, dirfd(dir), entry->d_name, depth + 1, count, NULL, NULL);
		} else if( S_ISREG(st.st_mode) )
			count_file(cap, entry->d_name, &st, count);
		if( count->error == ECANCELED )
			break;
	}
	/* closes fd */
	closedir(dir);
	return true;
}

/* the base folder (a link is followed, it may lead to another disk) */
static int open_base(struct streamcap *cap, struct file_id *id)
{
	int fd = openat(AT_FDCWD, cap->base, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if( fd == -1 )
		return -1;
	struct stat st;
	if( fstat(fd, &st) != 0 )
	{
		int error = errno;
		close(fd);
		errno = error;
		return -1;
	}
	id->dev = st.st_dev;
	id->ino = st.st_ino;
	return fd;
}

struct found
{
	struct file_id id;
	gint64 mtime;
	guint64 bytes;
	guint64 files;
	int error;            /* the folder could not be read: kept as it was, tried again */
	guint wait;           /* in so many checks */
};

/* a date folder that could not be counted (cap->lock): tried again after 1, 2, 4, ... checks */
static void top_retry(struct top_dir *top)
{
	top->has_id = false;
	top->retry = true;
	top->retry_backoff = top->retry_backoff == 0 ? 1 : MIN(top->retry_backoff * 2, STREAMCAP_RETRY_MAX);
	top->retry_wait = top->retry_backoff;
}

static void dir_warning(struct streamcap *cap, const char *name, int error, guint wait)
{
	g_warning("Could not count the bistreams in %s/%s (%s), the other folders are counted; it is counted "
			  "again in %u check(s)", cap->base, name, strerror(error), wait);
}

static void count_warning(struct streamcap *cap, int error, guint wait)
{
	g_mutex_lock(&cap->lock);
	guint64 bytes = cap->closed_bytes + cap->open_bytes;
	guint64 files = cap->closed_files + cap->open_files;
	g_mutex_unlock(&cap->lock);
	g_warning("Could not count the bistreams in %s (%s), the total stays at %" G_GUINT64_FORMAT
			  " bytes in %" G_GUINT64_FORMAT " files; it is counted again in %u check(s)",
			  cap->base, strerror(error), bytes, files, wait);
}

/* a check of the folder ended (cap->lock) */
static void check_end(struct streamcap *cap)
{
	cap->counts++;
	g_cond_broadcast(&cap->cond);
}

/*
 * Count the whole folder (at the start, and when the base was replaced) and
 * take the result: the date folders and the files directly in the base as
 * found, plus the dumps closed into them meanwhile. A date folder that could
 * not be read keeps what was known of it and is counted again on its own,
 * after 1, 2, 4, ... checks (top_retry()); a base that could not be read keeps
 * the old total, and is counted again in full after 1, 2, 4, ... checks.
 */
static void count_all(struct streamcap *cap)
{
	gint64 start = g_get_monotonic_time();
	/* today's folder is ours (a count over midnight: both days) */
	char *today = today_top(cap);
	char *today_end = NULL;
	g_mutex_lock(&cap->lock);
	count_begin(cap);
	g_mutex_unlock(&cap->lock);

	GHashTable *found = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	GHashTable *links = g_hash_table_new_full(file_id_hash, file_id_equal, g_free, NULL);
	struct count loose = { .links = links };
	int error = 0;
	struct file_id base_id = { 0 };
	bool have_base = false;
	int fd = open_base(cap, &base_id);
	if( fd == -1 )
	{
		/* no base yet, or gone: nothing in it */
		if( errno != ENOENT && errno != ENOTDIR )
			error = errno;
	} else
	{
		have_base = true;
		DIR *dir = fdopendir(fd);
		if( dir == NULL )
		{
			error = errno;
			close(fd);
		} else
		{
			for( ;; )
			{
				if( stopping(cap) )
				{
					error = ECANCELED;
					break;
				}
				errno = 0;
				struct dirent *entry = readdir(dir);
				if( entry == NULL )
				{
					if( errno != 0 )
						error = errno;
					break;
				}
				if( strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 )
					continue;
				struct stat st;
				if( fstatat(dirfd(dir), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 )
					continue;
				if( S_ISDIR(st.st_mode) )
				{
					struct count c = { .links = links };
					struct found *f = g_malloc0(sizeof(struct found));
					if( count_dir(cap, dirfd(dir), entry->d_name, 1, &c, &f->id, &f->mtime) && c.error == 0 )
					{
						f->bytes = c.bytes;
						f->files = c.files;
						g_hash_table_replace(found, g_strdup(entry->d_name), f);
					} else if( c.error != 0 && c.error != ECANCELED )
					{
						/* this folder alone: the others are taken, it is tried again */
						f->error = c.error;
						g_hash_table_replace(found, g_strdup(entry->d_name), f);
					} else
						g_free(f);
					if( c.error == ECANCELED )
						error = ECANCELED;
				} else if( S_ISREG(st.st_mode) )
					count_file(cap, entry->d_name, &st, &loose);
				if( error == ECANCELED )
					break;
			}
			closedir(dir);
		}
	}
	g_hash_table_destroy(links);
	if( error == 0 )
		today_end = today_top(cap);

	g_mutex_lock(&cap->lock);
	bool first = !cap->counted && error == 0;
	if( error == 0 )
	{
		/* the dumps closed while the count ran are in count_bytes / count_files */
		GHashTable *dirs = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, top_dir_free);
		GHashTableIter it;
		gpointer key, value;
		g_hash_table_iter_init(&it, found);
		while( g_hash_table_iter_next(&it, &key, &value) )
		{
			struct found *f = value;
			struct top_dir *old = g_hash_table_lookup(cap->dirs, key);
			struct top_dir *top = g_malloc0(sizeof(struct top_dir));
			top->name = g_strdup(key);
			top->open_dumps = old != NULL ? old->open_dumps : 0;
			top->own = (old != NULL && old->own) || g_strcmp0(key, today) == 0 || g_strcmp0(key, today_end) == 0;
			top->touched = old != NULL ? old->touched : 0;
			if( f->error != 0 )
			{
				/* what was known of it stays (with the dumps closed into it meanwhile) */
				top->bytes = old != NULL ? old->bytes : 0;
				top->files = old != NULL ? old->files : 0;
				top->retry_backoff = old != NULL ? old->retry_backoff : 0;
				top_retry(top);
				f->wait = top->retry_wait;
			} else
			{
				top->has_id = true;
				top->id = f->id;
				top->mtime = f->mtime;
				top->bytes = f->bytes + (old != NULL ? old->count_bytes : 0);
				top->files = f->files + (old != NULL ? old->count_files : 0);
			}
			g_hash_table_insert(dirs, top->name, top);
		}
		/*
		 * a folder the count did not see, made by the dumps of this process
		 * meanwhile: what was closed into it, and its open dumps
		 */
		g_hash_table_iter_init(&it, cap->dirs);
		while( g_hash_table_iter_next(&it, &key, &value) )
		{
			struct top_dir *old = value;
			if( g_hash_table_contains(dirs, key) ||
				(old->count_bytes == 0 && old->count_files == 0 && old->open_dumps == 0) )
				continue;
			struct top_dir *top = g_malloc0(sizeof(struct top_dir));
			top->name = g_strdup(key);
			top->bytes = old->count_bytes;
			top->files = old->count_files;
			top->open_dumps = old->open_dumps;
			top->own = old->own;
			top->touched = old->touched;
			g_hash_table_insert(dirs, top->name, top);
		}
		g_hash_table_destroy(cap->dirs);
		cap->dirs = dirs;
		cap->loose.bytes = loose.bytes + cap->loose.count_bytes;
		cap->loose.files = loose.files + cap->loose.count_files;
		closed_sum(cap);
		cap->base_known = have_base;
		cap->base_id = base_id;
		cap->base_backoff = 0;
		cap->base_wait = 0;
		cap->full_counts++;
	} else
	{
		cap->base_known = false;
		if( error != ECANCELED )
		{
			/* the base could not be read: counted again after 1, 2, 4, ... checks */
			cap->base_backoff = cap->base_backoff == 0 ? 1 : MIN(cap->base_backoff * 2, STREAMCAP_RETRY_MAX);
			cap->base_wait = cap->base_backoff;
		}
	}
	guint base_wait = cap->base_wait;
	cap->refresh_running = false;
	count_end(cap);
	/* a count that failed ended as well: the total stays, the next check counts again */
	if( error != ECANCELED )
		cap->counted = true;
	guint64 bytes = cap->closed_bytes + cap->open_bytes;
	guint64 files = cap->closed_files + cap->open_files;
	check_end(cap);
	g_mutex_unlock(&cap->lock);

	if( error != 0 && error != ECANCELED )
		count_warning(cap, error, base_wait);
	if( error == 0 )
	{
		GHashTableIter it;
		gpointer key, value;
		g_hash_table_iter_init(&it, found);
		while( g_hash_table_iter_next(&it, &key, &value) )
		{
			struct found *f = value;
			if( f->error != 0 )
				dir_warning(cap, key, f->error, f->wait);
		}
	}
	g_hash_table_destroy(found);
	g_free(today);
	g_free(today_end);
	if( first )
		g_info("streamdumper: the bistreams in %s hold %" G_GUINT64_FORMAT " bytes in %" G_GUINT64_FORMAT
			   " files (counted in %.1f s)", cap->base, bytes, files,
			   (double)(g_get_monotonic_time() - start) / G_TIME_SPAN_SECOND);
}

/*
 * Count the date folder name of the base (base_fd) and take the result: what
 * the count found plus the dumps closed into it meanwhile. Used for a folder
 * that is new or was replaced; the other folders are not read.
 */
static int count_top(struct streamcap *cap, int base_fd, const char *name)
{
	g_mutex_lock(&cap->lock);
	count_begin(cap);
	g_mutex_unlock(&cap->lock);

	GHashTable *links = g_hash_table_new_full(file_id_hash, file_id_equal, g_free, NULL);
	struct count c = { .links = links };
	struct file_id id = { 0 };
	gint64 mtime = 0;
	bool there = count_dir(cap, base_fd, name, 1, &c, &id, &mtime);
	g_hash_table_destroy(links);

	guint wait = 0;
	g_mutex_lock(&cap->lock);
	if( c.error == 0 )
	{
		struct top_dir *top = top_get(cap, name);
		top->has_id = there;
		top->id = id;
		top->mtime = mtime;
		top->retry = false;
		top->retry_backoff = 0;
		top->retry_wait = 0;
		top->bytes = c.bytes + top->count_bytes;
		top->files = c.files + top->count_files;
		closed_sum(cap);
		cap->dir_counts++;
	} else if( c.error != ECANCELED )
	{
		/* what was known of it stays */
		struct top_dir *top = top_get(cap, name);
		top_retry(top);
		wait = top->retry_wait;
	}
	count_end(cap);
	g_mutex_unlock(&cap->lock);
	if( c.error != 0 && c.error != ECANCELED )
		dir_warning(cap, name, c.error, wait);
	return c.error;
}

struct seen
{
	char *name;
	bool has_id;
	struct file_id id;
	gint64 mtime;
	guint64 bytes;
	guint64 files;
};

static void seen_free(gpointer data)
{
	struct seen *s = data;
	g_free(s->name);
	g_free(s);
}

/*
 * A check of the folder, every period. The first one, and the one after a
 * replaced or unreadable base, counts the whole folder. Else only the base is
 * read (its entries, the date folders): a date folder that is gone takes what
 * was counted for it before the check out of the total (the dumps closed into
 * it later stay counted: the total is more than the folder holds, dionaea writes
 * fewer dumps, never more); a date folder that is new or was
 * replaced is counted. The dumps in the date folders that stay are not read
 * again: they are known, a file removed from such a folder from outside stays
 * in the total until a refused dump asks for a refresh: then a date folder
 * whose mtime changed since its count is counted again (refresh_ask()).
 */
static void check_folder(struct streamcap *cap)
{
	g_mutex_lock(&cap->lock);
	bool requested = cap->full_requested;
	bool full = !cap->base_known || requested;
	cap->full_requested = false;
	bool refresh = cap->refresh_requested;
	cap->refresh_requested = false;
	cap->refresh_running = refresh;
	bool waits = full && !requested && cap->base_wait > 1;
	if( waits )
	{
		/* the base could not be read the last time: it waits (1: counted at this check) */
		cap->base_wait--;
		cap->refresh_running = false;
		check_end(cap);
	}
	struct file_id known = cap->base_id;
	g_mutex_unlock(&cap->lock);
	if( waits )
		return;
	if( full )
	{
		count_all(cap);
		return;
	}

	struct file_id base_id;
	int fd = open_base(cap, &base_id);
	if( fd == -1 || base_id.dev != known.dev || base_id.ino != known.ino )
	{
		/* the base was replaced (T-Pot's clean.sh: rm -rf, mkdir) or is gone */
		if( fd != -1 )
			close(fd);
		count_all(cap);
		return;
	}
	DIR *dir = fdopendir(fd);
	if( dir == NULL )
	{
		close(fd);
		count_all(cap);
		return;
	}

	/* today's folder is ours: never read at a refresh */
	char *today = today_top(cap);
	/* what is counted for the date folders before the base is read */
	GPtrArray *before = g_ptr_array_new_with_free_func(seen_free);
	g_mutex_lock(&cap->lock);
	guint64 gen = cap->gen;
	GHashTableIter it;
	gpointer value;
	g_hash_table_iter_init(&it, cap->dirs);
	while( g_hash_table_iter_next(&it, NULL, &value) )
	{
		struct top_dir *top = value;
		struct seen *s = g_malloc0(sizeof(struct seen));
		s->name = g_strdup(top->name);
		s->has_id = top->has_id;
		s->id = top->id;
		s->bytes = top->bytes;
		s->files = top->files;
		g_ptr_array_add(before, s);
	}
	g_mutex_unlock(&cap->lock);

	/* the entries of the base: name -> struct seen (has_id: a folder) */
	GHashTable *listed = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, seen_free);
	int error = 0;
	for( ;; )
	{
		if( stopping(cap) )
		{
			error = ECANCELED;
			break;
		}
		errno = 0;
		struct dirent *entry = readdir(dir);
		if( entry == NULL )
		{
			if( errno != 0 )
				error = errno;
			break;
		}
		if( strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 )
			continue;
		struct stat st;
		if( fstatat(dirfd(dir), entry->d_name, &st, AT_SYMLINK_NOFOLLOW) != 0 )
			continue;
		struct seen *s = g_malloc0(sizeof(struct seen));
		s->name = g_strdup(entry->d_name);
		if( S_ISDIR(st.st_mode) )
		{
			s->has_id = true;
			s->id.dev = st.st_dev;
			s->id.ino = st.st_ino;
			s->mtime = mtime_ns(&st);
		}
		g_hash_table_replace(listed, s->name, s);
	}

	bool refreshed = false;
	if( error == 0 )
	{
		/* the date folders that are gone */
		g_mutex_lock(&cap->lock);
		for( guint i = 0; i < before->len; i++ )
		{
			struct seen *s = g_ptr_array_index(before, i);
			if( g_hash_table_contains(listed, s->name) )
				continue;
			struct top_dir *top = g_hash_table_lookup(cap->dirs, s->name);
			if( top == NULL )
				continue;
			top->bytes -= MIN(top->bytes, s->bytes);
			top->files -= MIN(top->files, s->files);
			top->has_id = false;
			top->retry = false;
			/*
			 * Made again or given a dump by this process after the snapshot
			 * (between the listing and this lock): the folder of the snapshot
			 * is gone, the record is the new folder, ours, its id taken at the
			 * next check. Else it is ours again when streamcap_made() says so.
			 */
			if( top->touched > gen )
				continue;
			top->own = false;
			if( top->bytes == 0 && top->files == 0 && top->open_dumps == 0 )
				g_hash_table_remove(cap->dirs, s->name);
		}
		closed_sum(cap);
		/*
		 * The date folders that are new or were replaced from outside are
		 * counted, and the ones whose count failed once their wait is over. A
		 * folder that the dumps of this process made (they name it in
		 * streamcap_opened(), before the folder is first seen here) holds
		 * dumps that are known exactly: it is taken as it is, not read. At a
		 * refresh, a folder whose mtime changed since its count is counted.
		 */
		GPtrArray *recount = g_ptr_array_new_with_free_func(g_free);
		GHashTableIter li;
		g_hash_table_iter_init(&li, listed);
		while( g_hash_table_iter_next(&li, NULL, &value) )
		{
			struct seen *s = value;
			if( !s->has_id )
				continue;
			struct top_dir *top = g_hash_table_lookup(cap->dirs, s->name);
			/* a known folder of today's name holds the dumps of dionaea (a run before this one too) */
			if( top != NULL && today != NULL && strcmp(s->name, today) == 0 )
				top->own = true;
			if( top != NULL && top->retry )
			{
				if( top->retry_wait > 1 )
					top->retry_wait--;
				else
					g_ptr_array_add(recount, g_strdup(s->name));
			} else if( top != NULL && !top->has_id )
			{
				top->has_id = true;
				top->id = s->id;
				top->mtime = s->mtime;
			} else if( top == NULL || top->id.dev != s->id.dev || top->id.ino != s->id.ino )
				g_ptr_array_add(recount, g_strdup(s->name));
			else if( refresh && !top->own && top->mtime != s->mtime )
			{
				g_ptr_array_add(recount, g_strdup(s->name));
				refreshed = true;
			}
		}
		g_mutex_unlock(&cap->lock);

		/* a folder that can not be read is logged and tried again later (count_top), the others go on */
		for( guint i = 0; i < recount->len && error == 0; i++ )
			if( count_top(cap, dirfd(dir), g_ptr_array_index(recount, i)) == ECANCELED )
				error = ECANCELED;
		g_ptr_array_free(recount, TRUE);
	}
	closedir(dir);
	g_hash_table_destroy(listed);
	g_ptr_array_free(before, TRUE);
	g_free(today);

	g_mutex_lock(&cap->lock);
	if( refreshed )
		cap->refresh_counted = true;
	cap->refresh_running = false;
	check_end(cap);
	g_mutex_unlock(&cap->lock);
	if( error != 0 && error != ECANCELED )
		count_warning(cap, error, 1);
}

static gpointer count_thread(gpointer data)
{
	struct streamcap *cap = data;
	g_mutex_lock(&cap->lock);
	/* the first check counts the whole folder, at once */
	bool wait = false;
	while( !cap->stop )
	{
		gint64 deadline = g_get_monotonic_time() + cap->period;
		while( wait && !cap->stop && !cap->count_requested )
			if( !g_cond_wait_until(&cap->cond, &cap->lock, deadline) )
				break;
		wait = true;
		if( cap->stop )
			break;
		cap->count_requested = false;
		cap->started++;
		g_mutex_unlock(&cap->lock);
		check_folder(cap);
		g_mutex_lock(&cap->lock);
		g_cond_broadcast(&cap->cond);
	}
	g_mutex_unlock(&cap->lock);
	return NULL;
}

struct streamcap *streamcap_new(const char *base, guint64 max_bytes, guint64 max_files, gint64 period)
{
	if( max_bytes == 0 && max_files == 0 )
		return NULL;
	struct streamcap *cap = g_malloc0(sizeof(struct streamcap));
	cap->base = g_strdup(base);
	cap->max_bytes = max_bytes;
	cap->max_files = max_files;
	cap->period = period;
	cap->clock = g_get_monotonic_time;
	g_mutex_init(&cap->lock);
	g_cond_init(&cap->cond);
	cap->open = g_hash_table_new(file_id_hash, file_id_equal);
	cap->closed_in_count = g_hash_table_new_full(file_id_hash, file_id_equal, g_free, NULL);
	cap->dirs = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, top_dir_free);
	guint others = base_add(cap->base);
	if( others > 0 )
		g_warning("streamdumper: the bistreams in %s are counted by %u other reference(s) of the streamdumper "
				  "as well: after the first count each limit sees only the dumps of its own reference, so each "
				  "total misses the dumps of the others and the limits can be exceeded; reference the streamdumper once", cap->base, others);
	/* the first count runs in the thread: dionaea listens at once */
	cap->thread = g_thread_new("streamcap", count_thread, cap);
	return cap;
}

void streamcap_stop(struct streamcap *cap)
{
	if( cap == NULL )
		return;
	g_mutex_lock(&cap->lock);
	GThread *thread = cap->thread;
	cap->thread = NULL;
	cap->stop = true;
	g_atomic_int_set(&cap->stopping, 1);
	g_cond_broadcast(&cap->cond);
	g_mutex_unlock(&cap->lock);
	/* outside the lock: a count that runs takes it for every file, and ends after the entry it reads */
	if( thread != NULL )
		g_thread_join(thread);
}

void streamcap_free(struct streamcap *cap)
{
	if( cap == NULL )
		return;
	streamcap_stop(cap);
	g_hash_table_destroy(cap->open);
	g_hash_table_destroy(cap->closed_in_count);
	g_hash_table_destroy(cap->dirs);
	g_cond_clear(&cap->cond);
	g_mutex_clear(&cap->lock);
	base_remove(cap->base);
	g_free(cap->base);
	g_free(cap->path);
	g_free(cap);
}

static char *limit_string(guint64 limit, bool mib)
{
	if( limit == 0 )
		return g_strdup("unlimited");
	if( mib )
		return g_strdup_printf("%.6g MiB", (double)limit / MIB);
	return g_strdup_printf("%" G_GUINT64_FORMAT, limit);
}

static char *amount_string(guint64 used, guint64 limit, const char *unit)
{
	if( limit == 0 )
		return g_strdup_printf("%" G_GUINT64_FORMAT " %s", used, unit);
	return g_strdup_printf("%" G_GUINT64_FORMAT " of %" G_GUINT64_FORMAT " %s", used, limit, unit);
}

/*
 * A dump was refused (cap->lock, eventloop, now from cap->clock): the next
 * check counts the date folders whose mtime changed since their count (dumps
 * removed from outside), asked at most once per period, and done at most once
 * per STREAMCAP_RECOUNT_INTERVAL. A folder that is really full does not change
 * and is not read; the check reads the base, as every period.
 */
static void refresh_ask(struct streamcap *cap, gint64 now)
{
	if( cap->refresh_counted )
	{
		/* the check that was asked for at refresh_asked_at counted a folder */
		cap->refresh_counted = false;
		cap->counted_once = true;
		cap->counted_at = cap->refresh_asked_at;
	}
	if( cap->thread == NULL || cap->refresh_requested || cap->refresh_running )
		return;
	if( cap->refresh_asked && now - cap->refresh_asked_at < cap->period )
		return;
	if( cap->counted_once && now - cap->counted_at < STREAMCAP_RECOUNT_INTERVAL )
		return;
	cap->refresh_requested = true;
	cap->refresh_asked = true;
	cap->refresh_asked_at = now;
	cap->count_requested = true;
	g_cond_broadcast(&cap->cond);
}

struct streamcap_dump *streamcap_open(struct streamcap *cap, size_t first_write)
{
	struct streamcap_dump *dump = NULL;
	bool warn = false;
	guint64 unlogged = 0;

	g_mutex_lock(&cap->lock);
	guint64 bytes = cap->closed_bytes + cap->open_bytes;
	guint64 files = cap->closed_files + cap->open_files;
	bool fits = (cap->max_files == 0 || files < cap->max_files) &&
		(cap->max_bytes == 0 || (bytes <= cap->max_bytes && first_write <= cap->max_bytes - bytes));
	if( fits )
	{
		/* the first write counts at once, with the end of the dump in it */
		dump = g_malloc0(sizeof(struct streamcap_dump));
		dump->bytes = first_write;
		cap->open_files++;
		cap->open_bytes += first_write;
	} else
	{
		cap->refused++;
		cap->refused_unlogged++;
		gint64 now = cap->clock();
		refresh_ask(cap, now);
		if( !cap->warned || now - cap->warned_at >= cap->period )
		{
			warn = true;
			cap->warned = true;
			cap->warned_at = now;
			unlogged = cap->refused_unlogged;
			cap->refused_unlogged = 0;
		}
	}
	g_mutex_unlock(&cap->lock);

	if( warn )
	{
		char *b = amount_string(bytes, cap->max_bytes, "bytes");
		char *f = amount_string(files, cap->max_files, "files");
		char *ms = limit_string(cap->max_bytes, true);
		char *mf = limit_string(cap->max_files, false);
		g_warning("Not dumping the streams of %" G_GUINT64_FORMAT " new connection(s): %s holds %s and %s "
				  "(max_size %s, max_files %s), the connections go on",
				  unlogged, cap->base, b, f, ms, mf);
		g_free(b);
		g_free(f);
		g_free(ms);
		g_free(mf);
	}
	return dump;
}

void streamcap_opened(struct streamcap *cap, struct streamcap_dump *dump, int fd, const char *dir)
{
	/* no filesystem request but the fstat of the file: the name tells the date folder */
	char *top = top_name(cap->base, dir);
	struct stat st;
	bool has_id = fstat(fd, &st) == 0;
	g_mutex_lock(&cap->lock);
	dump->top = top;
	/* the folder holds a dump of this process from now on */
	if( top != NULL )
	{
		struct top_dir *record = top_get(cap, top);
		record->open_dumps++;
		record->touched = ++cap->gen;
	}
	if( has_id )
	{
		dump->id.dev = st.st_dev;
		dump->id.ino = st.st_ino;
		dump->has_id = true;
		g_hash_table_insert(cap->open, &dump->id, dump);
	}
	g_mutex_unlock(&cap->lock);
}

void streamcap_made(struct streamcap *cap, const char *dir)
{
	/* only the entry of the base itself: with %Y/%m/%d the year may be older than this process */
	char *top = own_top(cap->base, dir);
	if( top == NULL )
		return;
	g_mutex_lock(&cap->lock);
	struct top_dir *record = top_get(cap, top);
	record->own = true;
	record->touched = ++cap->gen;
	g_mutex_unlock(&cap->lock);
	g_free(top);
}

void streamcap_path_set(struct streamcap *cap, const char *path)
{
	g_mutex_lock(&cap->lock);
	g_free(cap->path);
	cap->path = g_strdup(path);
	g_mutex_unlock(&cap->lock);
}

bool streamcap_reserve(struct streamcap *cap, struct streamcap_dump *dump, size_t size)
{
	bool warn = false;
	guint64 unlogged = 0;

	g_mutex_lock(&cap->lock);
	guint64 bytes = cap->closed_bytes + cap->open_bytes;
	guint64 files = cap->closed_files + cap->open_files;
	bool fits = cap->max_bytes == 0 || (bytes <= cap->max_bytes && size <= cap->max_bytes - bytes);
	if( fits )
	{
		dump->bytes += size;
		cap->open_bytes += size;
	} else
	{
		cap->stopped++;
		cap->stopped_unlogged++;
		gint64 now = cap->clock();
		refresh_ask(cap, now);
		if( !cap->stop_warned || now - cap->stop_warned_at >= cap->period )
		{
			warn = true;
			cap->stop_warned = true;
			cap->stop_warned_at = now;
			unlogged = cap->stopped_unlogged;
			cap->stopped_unlogged = 0;
		}
	}
	g_mutex_unlock(&cap->lock);

	if( warn )
	{
		char *b = amount_string(bytes, cap->max_bytes, "bytes");
		char *f = amount_string(files, cap->max_files, "files");
		char *ms = limit_string(cap->max_bytes, true);
		char *mf = limit_string(cap->max_files, false);
		g_warning("Stopped dumping the streams of %" G_GUINT64_FORMAT " connection(s) at the limit: %s holds %s and %s "
				  "(max_size %s, max_files %s), the dumps are closed, the connections go on",
				  unlogged, cap->base, b, f, ms, mf);
		g_free(b);
		g_free(f);
		g_free(ms);
		g_free(mf);
	}
	return fits;
}

void streamcap_close(struct streamcap *cap, struct streamcap_dump *dump, bool kept)
{
	g_mutex_lock(&cap->lock);
	cap->open_files--;
	cap->open_bytes -= dump->bytes;
	if( dump->has_id )
		g_hash_table_remove(cap->open, &dump->id);
	if( dump->top != NULL )
	{
		/* the record stays while the folder has an open dump (count_all, check_folder) */
		struct top_dir *top = top_get(cap, dump->top);
		if( top->open_dumps > 0 )
			top->open_dumps--;
	}
	if( kept )
	{
		struct top_dir *top = top_get(cap, dump->top);
		top->files++;
		top->bytes += dump->bytes;
		cap->closed_files++;
		cap->closed_bytes += dump->bytes;
		if( cap->counting && dump->has_id )
		{
			/* the count that runs skips it, it is counted here */
			g_hash_table_add(cap->closed_in_count, g_memdup2(&dump->id, sizeof(dump->id)));
			top->count_files++;
			top->count_bytes += dump->bytes;
		}
	}
	g_mutex_unlock(&cap->lock);
	g_free(dump->top);
	g_free(dump);
}

void streamcap_usage_get(struct streamcap *cap, struct streamcap_usage *usage)
{
	g_mutex_lock(&cap->lock);
	usage->bytes = cap->closed_bytes + cap->open_bytes;
	usage->files = cap->closed_files + cap->open_files;
	usage->open_files = cap->open_files;
	usage->max_bytes = cap->max_bytes;
	usage->max_files = cap->max_files;
	usage->refused = cap->refused;
	usage->stopped = cap->stopped;
	usage->counts = cap->counts;
	usage->full_counts = cap->full_counts;
	usage->dir_counts = cap->dir_counts;
	usage->counted = cap->counted;
	usage->counting_thread = cap->thread != NULL;
	g_mutex_unlock(&cap->lock);
}

/* request a check (full: a count of the whole folder) and wait for it */
static void check_now(struct streamcap *cap, bool full)
{
	g_mutex_lock(&cap->lock);
	/*
	 * the next check that begins (it takes the request) has the number
	 * started + 1; the checks end in order. A check that runs now may have
	 * read the folder before the call (counts + 2 with a flag of its own came
	 * short when that check had ended but the flag was not cleared yet: the
	 * wait took a period).
	 */
	guint64 until = cap->started + 1;
	if( full )
		cap->full_requested = true;
	cap->count_requested = true;
	g_cond_broadcast(&cap->cond);
	while( cap->counts < until && !cap->stop )
		g_cond_wait(&cap->cond, &cap->lock);
	g_mutex_unlock(&cap->lock);
}

void streamcap_recount(struct streamcap *cap)
{
	check_now(cap, true);
}

void streamcap_check(struct streamcap *cap)
{
	check_now(cap, false);
}

void streamcap_count_hook_set(struct streamcap *cap, streamcap_count_hook hook, void *data)
{
	g_mutex_lock(&cap->lock);
	cap->hook = hook;
	cap->hook_data = data;
	g_mutex_unlock(&cap->lock);
}

void streamcap_clock_set(struct streamcap *cap, gint64 (*clock)(void))
{
	g_mutex_lock(&cap->lock);
	cap->clock = clock;
	g_mutex_unlock(&cap->lock);
}
