/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * libFuzzer target of src/bistream.c: the input is a sequence of operations
 * (add data to a direction, copy a range, discard before an offset, clear)
 * on two bistreams. A model of the stored bytes of every direction says what
 * each copy must return; after every operation the chunks are checked
 * against the limits and the bookkeeping (sizes, offsets, budget).
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "bistream.h"
#include "fuzz_input.h"

#define STREAMS 2

/* what one direction holds: the stored bytes end at end, contiguous */
struct model_dir
{
	GByteArray *stored;
	uint64_t end;
};

struct model
{
	struct bistream *bs;
	struct model_dir dirs[2];
};

static uint64_t model_base(const struct model_dir *m)
{
	return m->end - m->stored->len;
}

static void check_chunks(const struct model *m)
{
	struct bistream *bs = m->bs;
	size_t bytes = 0, chunks = 0;
	uint64_t last_bistream_offset = 0;
	for( GList *it = bs->sequence.head; it != NULL; it = it->next )
	{
		struct stream_chunk *sc = it->data;
		g_assert_true(sc->direction == bistream_in || sc->direction == bistream_out);
		g_assert_cmpuint(sc->len, >, 0);
		g_assert_cmpuint(sc->len, <=, sc->capacity);
		g_assert_cmpuint(sc->capacity, <=, BISTREAM_CHUNK_BYTES);
		g_assert_true(sc->sequence_link == it);
		if( chunks > 0 )
			g_assert_cmpuint(sc->bistream_offset, >, last_bistream_offset);
		last_bistream_offset = sc->bistream_offset;
		g_assert_cmpuint(sc->bistream_offset + sc->len, <=, bs->end);
		bytes += sc->capacity;
		chunks++;
	}
	g_assert_cmpuint(bytes, ==, bs->bytes);
	g_assert_cmpuint(chunks, ==, bs->chunks);
	g_assert_cmpuint(bs->bytes, <=, BISTREAM_MAX_BYTES);
	g_assert_cmpuint(bs->chunks, <=, BISTREAM_MAX_CHUNKS);

	for( int dir = 0; dir < 2; dir++ )
	{
		const struct model_dir *md = &m->dirs[dir];
		g_assert_cmpuint(bs->streams[dir].end, ==, md->end);
		g_assert_cmpuint(bistream_end(bs, dir), ==, md->end);
		/* the chunks of a direction are contiguous up to its end */
		uint64_t next = model_base(md);
		size_t len = 0;
		for( GList *it = bs->streams[dir].chunks.head; it != NULL; it = it->next )
		{
			struct stream_chunk *sc = it->data;
			g_assert_cmpint(sc->direction, ==, dir);
			g_assert_cmpuint(sc->stream_offset, ==, next);
			g_assert_cmpmem(sc->data, sc->len, md->stored->data + len, sc->len);
			next += sc->len;
			len += sc->len;
		}
		g_assert_cmpuint(len, ==, md->stored->len);
		g_assert_cmpuint(next, ==, md->end);
	}
}

static void check_budget(const struct model *models)
{
	struct bistream_stats stats;
	bistream_stats_get(&stats);
	size_t bytes = 0, chunks = 0;
	for( int i = 0; i < STREAMS; i++ )
	{
		bytes += models[i].bs->bytes;
		chunks += models[i].bs->chunks;
	}
	g_assert_cmpuint(stats.bytes, ==, bytes);
	g_assert_cmpuint(stats.chunks, ==, chunks);
	g_assert_cmpuint(stats.peak_bytes, >=, stats.bytes);
	g_assert_cmpuint(stats.peak_chunks, >=, stats.chunks);
}

static size_t stored_total(const struct model *m)
{
	return m->dirs[0].stored->len + m->dirs[1].stored->len;
}

static void op_add(struct model *m, struct fuzz_input *in)
{
	int dir = fuzz_u8(in) & 1;
	/* small sizes mostly, up to over the limit of an instance */
	uint32_t size = fuzz_u16(in);
	uint8_t scale = fuzz_u8(in) % 6;
	size = (size << scale) % (BISTREAM_MAX_BYTES + BISTREAM_CHUNK_BYTES + 2);
	guint8 *data = g_malloc(size > 0 ? size : 1);
	size_t taken = fuzz_bytes(in, data, size);
	for( size_t i = taken; i < size; i++ )
		data[i] = (guint8)(i * 31 + m->dirs[dir].end);

	size_t chunks_before = m->bs->chunks;
	bool added = bistream_data_add(m->bs, dir, size > 0 ? data : NULL, size);
	if( size == 0 )
		g_assert_true(added);
	/* the capacity of a chunk is below twice its bytes: far from the limits nothing is refused */
	if( 2 * (stored_total(m) + size) <= BISTREAM_MAX_BYTES &&
		chunks_before + size / BISTREAM_CHUNK_BYTES + 2 <= BISTREAM_MAX_CHUNKS )
		g_assert_true(added);
	if( added )
	{
		g_byte_array_append(m->dirs[dir].stored, data, size);
		m->dirs[dir].end += size;
	}
	g_free(data);
}

static void op_get(struct model *m, struct fuzz_input *in)
{
	int dir = fuzz_u8(in) & 1;
	const struct model_dir *md = &m->dirs[dir];
	uint8_t how = fuzz_u8(in);
	/* offsets around the stored range, and arbitrary ones */
	uint64_t start;
	int64_t end;
	switch( how & 3 )
	{
	case 0: start = model_base(md) + (fuzz_u16(in) % (md->stored->len + 2)); break;
	case 1: start = model_base(md) - (fuzz_u8(in) % 3); break;
	case 2: start = fuzz_u64(in); break;
	default: start = 0; break;
	}
	switch( (how >> 2) & 3 )
	{
	case 0: end = -1; break;
	case 1: end = (int64_t)(start + fuzz_u16(in)); break;
	case 2: end = (int64_t)fuzz_u64(in); break;
	default: end = (int64_t)md->end + (int64_t)(fuzz_u8(in) % 3) - 1; break;
	}

	void *copy = (void *)1;
	int32_t size = bistream_get_stream(m->bs, dir, start, end, &copy);

	/* the rule of bistream.h */
	uint64_t finish = end == -1 ? md->end : (uint64_t)end;
	bool stored = md->stored->len > 0 && end >= -1 && start >= model_base(md) && start < finish &&
		finish <= md->end && finish - start <= INT32_MAX;
	if( !stored )
	{
		g_assert_cmpint(size, ==, -1);
		g_assert_null(copy);
		return;
	}
	g_assert_cmpint(size, ==, (int64_t)(finish - start));
	g_assert_nonnull(copy);
	g_assert_cmpmem(copy, size, md->stored->data + (start - model_base(md)), size);
	g_assert_cmpint(((char *)copy)[size], ==, 0);
	g_free(copy);
}

static void op_discard(struct model *m, struct fuzz_input *in)
{
	int dir = fuzz_u8(in) & 1;
	struct model_dir *md = &m->dirs[dir];
	uint8_t how = fuzz_u8(in);
	uint64_t offset;
	switch( how & 3 )
	{
	case 0: offset = model_base(md) + (fuzz_u16(in) % (md->stored->len + 2)); break;
	case 1: offset = md->end; break;
	case 2: offset = fuzz_u64(in); break;
	default: offset = UINT64_MAX; break;
	}
	bistream_discard_before(m->bs, dir, offset);
	if( offset > model_base(md) )
	{
		uint64_t drop = MIN(offset - model_base(md), (uint64_t)md->stored->len);
		g_byte_array_remove_range(md->stored, 0, (guint)drop);
	}
}

static void op_clear(struct model *m)
{
	bistream_clear(m->bs);
	for( int dir = 0; dir < 2; dir++ )
		g_byte_array_set_size(m->dirs[dir].stored, 0);
	g_assert_cmpuint(m->bs->bytes, ==, 0);
	g_assert_cmpuint(m->bs->chunks, ==, 0);
}

static void op_arguments(struct model *m, struct fuzz_input *in)
{
	/* directions and arguments the API refuses without a change */
	int dir = 2 + (fuzz_u8(in) & 0x7f);
	guint8 byte = 0;
	g_assert_false(bistream_data_add(m->bs, dir, &byte, 1));
	g_assert_false(bistream_data_add(m->bs, bistream_in, NULL, 1));
	void *copy = (void *)1;
	g_assert_cmpint(bistream_get_stream(m->bs, dir, 0, -1, &copy), ==, -1);
	g_assert_null(copy);
	g_assert_cmpint(bistream_get_stream(m->bs, bistream_in, 0, -2, &copy), ==, -1);
	g_assert_cmpint(bistream_get_stream(m->bs, bistream_in, 0, -1, NULL), ==, -1);
	bistream_discard_before(m->bs, dir, UINT64_MAX);
}

static void quiet(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data)
{
	(void)domain;
	(void)message;
	(void)data;
	if( level & (G_LOG_LEVEL_ERROR | G_LOG_LEVEL_CRITICAL) )
		abort();
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	g_log_set_default_handler(quiet, NULL);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_input in = { data, size };
	struct model models[STREAMS];
	for( int i = 0; i < STREAMS; i++ )
	{
		models[i].bs = bistream_new();
		for( int dir = 0; dir < 2; dir++ )
		{
			models[i].dirs[dir].stored = g_byte_array_new();
			models[i].dirs[dir].end = 0;
		}
	}

	for( int ops = 0; ops < 256 && fuzz_left(&in) > 0; ops++ )
	{
		uint8_t op = fuzz_u8(&in);
		struct model *m = &models[op >> 7];
		switch( op % 8 )
		{
		case 0: case 1: case 2: op_add(m, &in); break;
		case 3: case 4: op_get(m, &in); break;
		case 5: op_discard(m, &in); break;
		case 6: op_clear(m); break;
		default: op_arguments(m, &in); break;
		}
		check_chunks(m);
		check_budget(models);
	}

	for( int i = 0; i < STREAMS; i++ )
	{
		bistream_free(models[i].bs);
		for( int dir = 0; dir < 2; dir++ )
			g_byte_array_free(models[i].dirs[dir].stored, TRUE);
	}
	struct bistream_stats stats;
	bistream_stats_get(&stats);
	g_assert_cmpuint(stats.bytes, ==, 0);
	g_assert_cmpuint(stats.chunks, ==, 0);
	return 0;
}
