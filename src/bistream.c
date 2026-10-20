/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: 2009 Paul Baecher & Markus Koetter
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include "log.h"

#define D_LOG_DOMAIN "bistream"

#include "bistream.h"

/*
 * The process wide budget. Taken inside bistream.mutex, never the other way
 * round; a reservation is checked and booked in one critical section, so the
 * limits hold for any number of threads.
 */
static GMutex budget_mutex;
static struct bistream_stats budget;

/* count: a refusal is counted (false for a try that has a smaller fallback) */
static bool budget_reserve(size_t bytes, size_t chunks, bool count)
{
	bool accepted;
	g_mutex_lock(&budget_mutex);
	accepted = bytes <= BISTREAM_GLOBAL_BYTES - budget.bytes &&
		chunks <= BISTREAM_GLOBAL_CHUNKS - budget.chunks;
	if( !accepted && count )
		budget.refused_global++;
	if( accepted )
	{
		budget.bytes += bytes;
		budget.chunks += chunks;
		budget.peak_bytes = MAX(budget.peak_bytes, budget.bytes);
		budget.peak_chunks = MAX(budget.peak_chunks, budget.chunks);
	}
	g_mutex_unlock(&budget_mutex);
	return accepted;
}

static void budget_refused_instance(void)
{
	g_mutex_lock(&budget_mutex);
	budget.refused_instance++;
	g_mutex_unlock(&budget_mutex);
}

static void budget_release(size_t bytes, size_t chunks)
{
	g_mutex_lock(&budget_mutex);
	g_assert(budget.bytes >= bytes && budget.chunks >= chunks);
	budget.bytes -= bytes;
	budget.chunks -= chunks;
	g_mutex_unlock(&budget_mutex);
}

void bistream_stats_get(struct bistream_stats *stats)
{
	g_mutex_lock(&budget_mutex);
	*stats = budget;
	g_mutex_unlock(&budget_mutex);
}

struct bistream *bistream_new(void)
{
	struct bistream *bs = g_malloc0(sizeof(struct bistream));
	g_mutex_init(&bs->mutex);
	g_queue_init(&bs->sequence);
	g_queue_init(&bs->streams[bistream_in].chunks);
	g_queue_init(&bs->streams[bistream_out].chunks);
	return bs;
}

/* bs->mutex held; sc is the first chunk of its direction */
static void chunk_free(struct bistream *bs, struct stream_chunk *sc)
{
	struct stream_chunk *head = g_queue_pop_head(&bs->streams[sc->direction].chunks);
	g_assert(head == sc);
	g_queue_delete_link(&bs->sequence, sc->sequence_link);
	bs->bytes -= sc->capacity;
	bs->chunks--;
	budget_release(sc->capacity, 1);
	g_free(sc->data);
	g_free(sc);
}

void bistream_clear(struct bistream *bs)
{
	g_mutex_lock(&bs->mutex);
	struct stream_chunk *sc;
	while( (sc = g_queue_peek_head(&bs->sequence)) != NULL )
		chunk_free(bs, sc);
	g_mutex_unlock(&bs->mutex);
}

void bistream_free(struct bistream *bs)
{
	bistream_clear(bs);
	g_mutex_clear(&bs->mutex);
	g_free(bs);
}

bool bistream_data_add(struct bistream *bs, enum bistream_direction dir, const void *data, uint32_t size)
{
	g_debug("%s bs %p dir %i data %p size %u", __PRETTY_FUNCTION__, bs, dir, data, size);
	if( dir != bistream_in && dir != bistream_out )
		return false;
	if( size == 0 )
		return true;
	if( data == NULL )
		return false;

	g_mutex_lock(&bs->mutex);

	/* the bytes the last chunk can still take, if it is of this direction */
	struct stream_chunk *last = g_queue_peek_tail(&bs->sequence);
	size_t room = 0;
	if( last != NULL && last->direction == dir )
		room = BISTREAM_CHUNK_BYTES - last->len;
	size_t chunks = 0;
	if( size > room )
		chunks = (size - room + BISTREAM_CHUNK_BYTES - 1) / BISTREAM_CHUNK_BYTES;

	/*
	 * The last chunk grows by doubling up to BISTREAM_CHUNK_BYTES, so small
	 * packets do not reallocate it for every byte; new chunks get the size of
	 * their payload. The budget counts what is allocated (the capacity). If
	 * the doubling does not fit into a limit, the exact size is tried.
	 */
	size_t first = MIN((size_t)size, room);
	size_t grown = 0, exact = 0;
	if( first > 0 && last->len + first > last->capacity )
	{
		exact = last->len + first;
		grown = MIN((size_t)BISTREAM_CHUNK_BYTES, MAX(exact, 2 * last->capacity));
	}
	size_t rest = size - first;   /* into new chunks, allocated exactly */
	size_t capacity = grown;
	size_t extra = (grown > 0 ? grown - last->capacity : 0) + rest;
	size_t extra_exact = (exact > 0 ? exact - last->capacity : 0) + rest;

	/* check every limit before anything is allocated */
	bool fits = chunks <= BISTREAM_MAX_CHUNKS - bs->chunks &&
		size <= (uint64_t)INT64_MAX - bs->end &&
		size <= (uint64_t)INT64_MAX - bs->streams[dir].end;
	if( fits && extra > BISTREAM_MAX_BYTES - bs->bytes )
	{
		capacity = exact;
		extra = extra_exact;
	}
	if( !fits || extra > BISTREAM_MAX_BYTES - bs->bytes )
	{
		budget_refused_instance();
		g_mutex_unlock(&bs->mutex);
		return false;
	}
	if( !budget_reserve(extra, chunks, extra == extra_exact) )
	{
		if( extra == extra_exact || !budget_reserve(extra_exact, chunks, true) )
		{
			g_mutex_unlock(&bs->mutex);
			return false;
		}
		capacity = exact;
		extra = extra_exact;
	}
	bs->bytes += extra;
	bs->chunks += chunks;

	if( capacity > 0 )
	{
		last->data = g_realloc(last->data, capacity);
		last->capacity = capacity;
	}

	const guint8 *input = data;
	while( size > 0 )
	{
		if( room == 0 )
		{
			last = g_malloc0(sizeof(struct stream_chunk));
			last->direction = dir;
			last->stream_offset = bs->streams[dir].end;
			last->bistream_offset = bs->end;
			last->capacity = MIN((size_t)size, (size_t)BISTREAM_CHUNK_BYTES);
			last->data = g_malloc(last->capacity);
			g_queue_push_tail(&bs->sequence, last);
			last->sequence_link = bs->sequence.tail;
			g_queue_push_tail(&bs->streams[dir].chunks, last);
			room = BISTREAM_CHUNK_BYTES;
		}
		size_t take = MIN(size, room);
		g_assert(last->len + take <= last->capacity);
		memcpy(last->data + last->len, input, take);
		last->len += take;
		bs->end += take;
		bs->streams[dir].end += take;
		input += take;
		size -= take;
		room -= take;
	}

	g_mutex_unlock(&bs->mutex);
	return true;
}

uint64_t bistream_end(struct bistream *bs, enum bistream_direction dir)
{
	g_mutex_lock(&bs->mutex);
	uint64_t end = bs->streams[dir].end;
	g_mutex_unlock(&bs->mutex);
	return end;
}

void bistream_discard_before(struct bistream *bs, enum bistream_direction dir, uint64_t offset)
{
	if( dir != bistream_in && dir != bistream_out )
		return;

	g_mutex_lock(&bs->mutex);
	struct stream_chunk *sc;
	while( (sc = g_queue_peek_head(&bs->streams[dir].chunks)) != NULL &&
		   sc->stream_offset < offset )
	{
		uint64_t drop = offset - sc->stream_offset;
		if( drop >= sc->len )
		{
			chunk_free(bs, sc);
			continue;
		}
		/* keep the tail of the chunk, give the memory of the head back */
		size_t keep = sc->len - drop;
		size_t freed = sc->capacity - keep;
		memmove(sc->data, sc->data + drop, keep);
		sc->data = g_realloc(sc->data, keep);
		sc->len = keep;
		sc->capacity = keep;
		sc->stream_offset += drop;
		sc->bistream_offset += drop;
		bs->bytes -= freed;
		budget_release(freed, 0);
		break;
	}
	g_mutex_unlock(&bs->mutex);
}

int32_t bistream_get_stream(struct bistream *bs, enum bistream_direction dir, uint64_t start, int64_t end, void **data)
{
	g_debug("%s bs %p dir %i start %" G_GUINT64_FORMAT " end %" G_GINT64_FORMAT, __PRETTY_FUNCTION__, bs, dir, start, end);
	if( data == NULL )
		return -1;
	*data = NULL;
	if( (dir != bistream_in && dir != bistream_out) || end < -1 )
		return -1;

	g_mutex_lock(&bs->mutex);
	struct stream *stream = &bs->streams[dir];
	struct stream_chunk *first = g_queue_peek_head(&stream->chunks);
	uint64_t finish = end == -1 ? stream->end : (uint64_t)end;
	/* everything asked for has to be stored: not discarded, not beyond the end */
	if( first == NULL || start < first->stream_offset || start >= finish ||
		finish > stream->end || finish - start > INT32_MAX )
	{
		g_mutex_unlock(&bs->mutex);
		return -1;
	}

	size_t size = finish - start;
	guint8 *copy = g_malloc(size + 1);
	size_t copied = 0;
	for( GList *it = stream->chunks.head; it != NULL && copied < size; it = it->next )
	{
		struct stream_chunk *sc = it->data;
		uint64_t from = MAX(start, sc->stream_offset);
		uint64_t until = MIN(finish, sc->stream_offset + sc->len);
		if( from >= until )
			continue;
		memcpy(copy + copied, sc->data + (from - sc->stream_offset), until - from);
		copied += until - from;
	}
	g_mutex_unlock(&bs->mutex);

	/* the chunks of a direction are contiguous, a gap would be a bug */
	g_assert(copied == size);
	copy[size] = '\0';
	*data = copy;
	return (int32_t)size;
}

uint32_t sizeof_stream_chunks(GList *stream_chunks)
{
	uint32_t size = 0;
	for( GList *it = g_list_first(stream_chunks); it != NULL; it = g_list_next(it) )
		size += ((struct stream_chunk *)it->data)->len;
	return size;
}

void print_stream_chunk2(struct stream_chunk *sc)
{
	uint64_t stream_offset = sc->stream_offset;
	uint64_t bistream_offset = sc->bistream_offset;
	char buf[256];
	for( size_t c=0; c<sc->len; c+=16 )
	{
		int off = snprintf(buf, sizeof(buf), "0x%04" G_GINT64_MODIFIER "x | ", bistream_offset + c);
		if( sc->direction == bistream_out )
			off += snprintf(buf+off, sizeof(buf)-off, "%49s", " ");

		for( size_t i=0; i<16; i++ )
		{
			if( i+c < sc->len )
				off += snprintf(buf+off, sizeof(buf)-off, "%02x ", sc->data[c+i]);
			else
				off += snprintf(buf+off, sizeof(buf)-off, "   ");
		}

		if( sc->direction == bistream_in )
			off += snprintf(buf+off, sizeof(buf)-off, "%49s", " ");

		off += snprintf(buf+off, sizeof(buf)-off, "  | ");

		for( size_t i=0; i<16; i++ )
		{
			if( i+c < sc->len )
				off += snprintf(buf+off, sizeof(buf)-off, "%c", isprint(sc->data[c+i]) ? sc->data[c+i] : '.');
			else
				off += snprintf(buf+off, sizeof(buf)-off, " ");
		}
		snprintf(buf+off, sizeof(buf)-off, " | 0x%04" G_GINT64_MODIFIER "x ", stream_offset + c);
		g_debug("%s", buf);
	}
}

void print_stream_chunk(struct stream_chunk *sc)
{
	uint64_t stream_offset = sc->stream_offset;
	uint64_t bistream_offset = sc->bistream_offset;

	for( size_t c=0; c<sc->len; c+=16 )
	{
		printf("0x%04" G_GINT64_MODIFIER "x | ", bistream_offset + c);
		if( sc->direction == bistream_out )
			printf("%49s", " ");

		for( size_t i=0; i<16; i++ )
		{
			if( i+c < sc->len )
				printf("%02x ", sc->data[c+i]);
			else
				printf("   ");
		}

		if( sc->direction == bistream_in )
			printf("%49s", " ");

		printf("  | ");
		for( size_t i=0; i<16; i++ )
		{
			if( i+c < sc->len )
				printf("%c", isprint(sc->data[c+i]) ? sc->data[c+i] : '.');
			else
				printf(" ");
		}
		printf(" | 0x%04" G_GINT64_MODIFIER "x ", stream_offset + c);
		printf("\n");
	}
}

void bistream_debug(struct bistream *bs)
{
	g_mutex_lock(&bs->mutex);
	for( GList *it = bs->sequence.head; it != NULL; it = it->next )
		print_stream_chunk2(it->data);
	g_mutex_unlock(&bs->mutex);
}
