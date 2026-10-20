/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef HAVE_BISTEAM_H
#define HAVE_BISTEAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <glib.h>

/*
 * Limits of the stream data the threaded processors (emu, unicode, xmatch)
 * keep, documented internal constants. A request that would cross one of
 * them is refused as a whole, before anything is allocated or copied; the
 * processor layer then stops that processor for the connection (the emu,
 * processor_give_up()) or closes the connection (processors_overload(), for
 * a processor that needs the whole history).
 *
 * The bytes are the allocated capacity of the chunks: a new chunk is
 * allocated to its payload, the last one grows by doubling (up to
 * BISTREAM_CHUNK_BYTES, the exact size where the doubling would cross a
 * limit), a partly discarded one shrinks to what it keeps. The chunk limits
 * bound the bookkeeping of many small packets (one chunk holds at most
 * BISTREAM_CHUNK_BYTES of one direction).
 */
#define BISTREAM_MAX_BYTES (1024U * 1024U)            /* per processor instance */
#define BISTREAM_GLOBAL_BYTES (32U * 1024U * 1024U)   /* per process */
#define BISTREAM_MAX_CHUNKS 1024U                     /* per processor instance */
#define BISTREAM_GLOBAL_CHUNKS 32768U                 /* per process */
#define BISTREAM_CHUNK_BYTES 16384U                   /* payload of one chunk */

enum bistream_direction
{
	bistream_in,
	bistream_out
};

struct stream_chunk
{
	guint8 *data;             /* capacity bytes, len of them used */
	size_t len;
	size_t capacity;          /* counted in the budget */
	uint64_t bistream_offset; /* absolute offset in both directions */
	uint64_t stream_offset;   /* absolute offset in its direction */
	enum bistream_direction direction;
	GList *sequence_link;     /* its link in bistream.sequence */
};

/*
 * Locking: bistream.mutex protects all fields of the bistream and its chunks.
 * The process wide budget has its own mutex, taken inside bistream.mutex
 * (never the other way round) and held only to check and book a reservation.
 * No pointer into the chunks leaves a locked call: readers get a copy.
 */
struct bistream
{
	GMutex mutex;
	GQueue sequence;          /* chunks of both directions in arrival order */
	uint64_t end;             /* absolute end of both directions */
	size_t bytes;             /* capacity of the chunks, counted in the budget */
	size_t chunks;

	struct stream
	{
		GQueue chunks;        /* chunks of this direction, ascending offsets */
		uint64_t end;         /* absolute end of this direction */
	} streams[2];
};

struct bistream_stats
{
	size_t bytes;             /* stored in all bistreams of the process */
	size_t chunks;
	size_t peak_bytes;        /* largest values since the start */
	size_t peak_chunks;
	size_t refused_instance;  /* requests refused by a limit of one instance */
	size_t refused_global;    /* requests refused by the process wide limits */
};

struct bistream *bistream_new(void);
void bistream_free(struct bistream *bs);
/* drop all data, the absolute offsets stay */
void bistream_clear(struct bistream *bs);

/* true: all size bytes were stored; false: nothing was stored (limit, bad arguments) */
bool bistream_data_add(struct bistream *bs, enum bistream_direction dir, const void *data, uint32_t size);

/*
 * Copy [start, end) of one direction (absolute offsets, end -1: everything
 * stored) into a new buffer (g_free, NUL terminated) and return its size.
 * -1 and *data = NULL if the range is empty or not stored (any part of it
 * discarded or beyond the end).
 */
int32_t bistream_get_stream(struct bistream *bs, enum bistream_direction dir, uint64_t start, int64_t end, void **data);

/* absolute end of one direction, the offset of the next byte to arrive */
uint64_t bistream_end(struct bistream *bs, enum bistream_direction dir);
/* free the data of one direction before an absolute offset */
void bistream_discard_before(struct bistream *bs, enum bistream_direction dir, uint64_t offset);

void bistream_stats_get(struct bistream_stats *stats);

uint32_t sizeof_stream_chunks(GList *stream_chunks);
void bistream_debug(struct bistream *bs);
void print_stream_chunk(struct stream_chunk *sc);
void print_stream_chunk2(struct stream_chunk *sc);

#endif
