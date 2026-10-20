/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2026 T-Pot contributors
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_STREAMCAP_H
#define HAVE_STREAMCAP_H

#include <stdbool.h>
#include <stddef.h>
#include <glib.h>

/*
 * The limits of the streamdumper (config.max_size in MiB, config.max_files):
 * the size and the number of the regular files below the base folder of
 * config.path (the folder before the first strftime field, all date folders
 * included).
 *
 * The total is a running count: the files that are no open dump (the count of
 * the folder plus the dumps closed since) and the open dumps with the bytes
 * counted for them (before they are written, and the end of the dump with the
 * first write, so the total never waits for stdio).
 *
 * A thread of its own counts the folder once, at the start: dionaea listens at
 * once, and until that count ended a new dump is admitted from the dumps this
 * process made (for that time the dumps of an earlier run are not in the total,
 * more than the limits can be written). The eventloop never waits
 * for a count, and never reads the folder.
 *
 * After that, every period (60 s), the thread reads only the base folder: its
 * entries, the date folders, and their (dev, ino). The dumps in a date folder
 * that stays are known and not read again: a walk of 188,000 dumps on a cold
 * Docker Desktop bind mount took minutes, and every file request of the
 * eventloop waited behind it. The whole folder is counted again only when the
 * base was replaced (another dev or ino, or gone: T-Pot's clean.sh does rm -rf
 * and mkdir); a date folder that is gone takes what was counted for it out of
 * the total; a date folder that is new or was replaced from outside is
 * counted on its own. A date folder that the dumps of this process made is
 * not read: its dumps are known (streamcap_opened() names the folder). A count
 * skips the open dumps and the dumps closed while it runs, both are known
 * exactly, and it ends after the entry it reads when the thread is stopped.
 *
 * The records are kept per entry of the base: with nested date folders
 * (%Y/%m/%d) that is the first level (the year), which is counted, compared
 * and taken out as a whole; its mtime changes with its own entries only, so
 * a day or dumps removed below a month are not seen until the year goes or a
 * restart. T-Pot's %Y-%m-%d has one level.
 *
 * Dumps removed from outside in a date folder that stays (find -mtime +7
 * -delete) are not seen by the running total. A refused dump (open or reserve)
 * asks the thread for a refresh, at most once per period: the next check
 * compares the mtime of every date folder it lists (one fstatat each, as in
 * every check) with the one taken before its count, and counts again only the
 * folders that changed, at most once per STREAMCAP_RECOUNT_INTERVAL (10 min).
 * The refused dump stays refused, a later one is admitted from the new total.
 * A folder that is really full does not change and is not read again. A date
 * folder that this process made (its mkdir, streamcap_made()) is never read at
 * a refresh: it changes with the own dumps, and on a Docker Desktop bind mount
 * it can hold 200,000 of them just when the cap is reached. Its total is exact
 * for the own dumps; a dump removed from it from outside stays counted until
 * the folder goes (the next day's folder is a new one) or a restart. That errs
 * high: fewer dumps, the disk is protected. The same holds for today's folder
 * (the one config.path names now, streamcap_path_set(), when it is an entry of
 * the base itself), also when a run before a restart of dionaea alone made it
 * (autoheal, the restart policy; T-Pot's clean.sh does not run then): only
 * dionaea writes into the bistreams. It is counted by the first count (with
 * the dumps of that run) and then never read at a refresh; once it is no
 * longer today's it stays so until it goes. A folder that is gone at a check
 * and made again by the dumps of this process while the check reads the base
 * (streamcap_made(), streamcap_opened() count a generation; the check leaves a
 * record alone that was touched after it took the snapshot) stays ours.
 *
 * The total never counts less than the folder holds, so dionaea never writes more
 * than the limits; it can count more (a dump removed from outside), then it writes
 * fewer dumps until it notices. One exception: until the first count ended it
 * holds only the dumps of this run. Else a file removed from outside
 * in a date folder that stays is counted until that folder or the base goes, a
 * refused dump has the folder counted again (not a folder this process made,
 * see above), or a restart (also a
 * removal in the same tick of the filesystem clock as the stat before a count
 * is not seen until the next change); a dump that is created while a count
 * runs may be seen by it as well, with the bytes it had then (0 as a rule),
 * until the next count of that folder. Files put into the base or a known date
 * folder from outside are not seen until the next count of it (dionaea is the
 * one that writes there). Files directly in the base are counted again only
 * with the whole folder.
 *
 * A date folder that can not be read (EACCES, EIO) keeps what was known of it
 * and the others are taken; only that folder is counted again, after 1, 2, 4,
 * ... at most 64 checks, with a warning at every failure. A base that can not
 * be read keeps the total and is counted again in full, backed off the same.
 * A folder whose very first count fails (the first count, or a new folder)
 * has nothing known of it: it holds 0 bytes and files in the total until a
 * try succeeds, so the total misses its dumps for that time (more than the
 * limits can be written).
 *
 * A new dump is admitted when it fits: fewer files than max_files, and the
 * bytes of its first write (with the end of the dump) fit below max_size.
 * Every later chunk of an open dump must fit as well (streamcap_reserve());
 * one that does not stops the dump: it is closed in the format of a dump, as
 * at the end of its connection, and gets nothing more, the connection goes
 * on. So the total stays at or below max_size, open dumps included.
 *
 * One cap per reference of the streamdumper in the processor tree
 * (processors_tree_create() makes a config per reference): reference the
 * streamdumper once. With several references with the same base, each cap
 * counts the folder once and then sees only the dumps of its own reference:
 * each total misses the dumps of the others, together they write more than the
 * limits. streamcap_new()
 * warns when a cap with the same base exists (the same string of the base).
 *
 * Locking: cap->lock is a leaf. The eventloop (open, opened, reserve, close)
 * and the counting thread take it for a few assignments: once at the start of
 * every check and three more times when the check lists the base (once more
 * for a warning), twice per count of the whole folder or of one date folder,
 * and once per file a count finds.
 * Nothing is logged, read or written and no other lock is taken while it is
 * held. The warnings are logged after it was released. It is never taken by a
 * job of the threadpool, so it stands apart from the lock order of
 * include/processor.h. The list of the bases (streamcap_new(), streamcap_free())
 * has a leaf lock of its own, never held with cap->lock.
 */

struct streamcap;
struct streamcap_dump;

struct streamcap_usage
{
	guint64 bytes;       /* total, see above */
	guint64 files;
	guint64 open_files;  /* open dumps (in files) */
	guint64 max_bytes;   /* 0: no limit */
	guint64 max_files;   /* 0: no limit */
	guint64 refused;     /* dumps not made since the start */
	guint64 stopped;     /* dumps stopped at max_size since the start */
	guint64 counts;      /* checks of the folder that ended (every period, see above) */
	guint64 full_counts; /* counts of the whole folder that ended */
	guint64 dir_counts;  /* counts of one date folder (new or replaced) that ended */
	bool counted;        /* the first count of the folder ended */
	bool counting_thread; /* the counting thread runs (until streamcap_stop()) */
};

#define STREAMCAP_PERIOD (60 * G_TIME_SPAN_SECOND)
/* at most one count of changed date folders per interval, at a refused dump (see above) */
#define STREAMCAP_RECOUNT_INTERVAL (10 * 60 * G_TIME_SPAN_SECOND)

/*
 * config.max_size in MiB (a number >= 0, fractions allowed) to bytes, and
 * config.max_files (a whole number >= 0). NULL, "" and 0 are no limit. false
 * for anything else; the caller warns and takes no limit.
 */
bool streamcap_parse_mib(const char *value, guint64 *bytes);
bool streamcap_parse_count(const char *value, guint64 *count);

/*
 * The values of DIONAEA_STREAMDUMPER_MAX_SIZE (MiB) and
 * DIONAEA_STREAMDUMPER_MAX_FILES, which replace config.max_size and
 * config.max_files: decimal digits only (no sign, space, fraction or suffix),
 * in the range of the config option, 0 is no limit. false for anything else
 * (also ""; the caller takes an empty variable as unset).
 */
bool streamcap_parse_env_mib(const char *value, guint64 *bytes);
bool streamcap_parse_env_count(const char *value, guint64 *count);
/*
 * a rejected value for a warning (newly allocated): its first 64 bytes, each
 * one that is no printable ASCII character as '?'
 */
char *streamcap_env_shown(const char *value);

/* the base folder of a config.path with strftime fields (newly allocated) */
char *streamcap_base(const char *path);

/*
 * Start the counting thread, which counts base at once; period in
 * microseconds (STREAMCAP_PERIOD) between two checks of the folder and
 * between two warnings about refused dumps. NULL if both limits are 0.
 */
struct streamcap *streamcap_new(const char *base, guint64 max_bytes, guint64 max_files, gint64 period);
/*
 * end the counting thread and wait for it (at the end of dionaea, before its
 * logs close): a count that runs ends after the entry it reads
 */
void streamcap_stop(struct streamcap *cap);
void streamcap_free(struct streamcap *cap);

/*
 * A new dump whose first write is first_write bytes (the end of the dump
 * included): NULL if it does not fit (logged once per period with the totals),
 * else its slot with first_write counted, which is given back with
 * streamcap_close(). Eventloop only.
 */
struct streamcap_dump *streamcap_open(struct streamcap *cap, size_t first_write);
/* the file of the dump was created as fd in the folder dir (the strftime of config.path) */
void streamcap_opened(struct streamcap *cap, struct streamcap_dump *dump, int fd, const char *dir);
/*
 * the folder dir (the strftime of config.path) was made by this process for a
 * dump (eventloop, after its mkdir): when it is an entry of the base, it is
 * never read at a refresh (see above)
 */
void streamcap_made(struct streamcap *cap, const char *dir);
/*
 * config.path of the dumps (before the first dump): the date folder it names
 * now is ours, see above. Without it only the folders of streamcap_made() are.
 */
void streamcap_path_set(struct streamcap *cap, const char *path);
/*
 * size more bytes for the open dump, before they are written: true and counted
 * if they fit below max_size (always without max_size), else false: the caller
 * closes the dump and writes nothing more to it (logged once per period).
 */
bool streamcap_reserve(struct streamcap *cap, struct streamcap_dump *dump, size_t size);
/* the dump is closed; kept: its file stays in the folder (false: it was never created) */
void streamcap_close(struct streamcap *cap, struct streamcap_dump *dump, bool kept);

void streamcap_usage_get(struct streamcap *cap, struct streamcap_usage *usage);

/* tests: count the whole folder again now and wait for the count to end (returns at streamcap_stop()) */
void streamcap_recount(struct streamcap *cap);
/* tests: check the folder now, as every period, and wait for the check to end (returns at streamcap_stop()) */
void streamcap_check(struct streamcap *cap);
/* tests: called by the counting thread for every file it counted or skipped */
typedef void (*streamcap_count_hook)(struct streamcap *cap, const char *name, void *data);
void streamcap_count_hook_set(struct streamcap *cap, streamcap_count_hook hook, void *data);
/* tests: the clock of the warnings (microseconds, default g_get_monotonic_time) */
void streamcap_clock_set(struct streamcap *cap, gint64 (*clock)(void));

#endif
