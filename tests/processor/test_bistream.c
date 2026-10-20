/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * Limits, offsets and locking of the stream data of the threaded processors
 * (src/bistream.c).
 */
#include <glib.h>
#include <malloc.h>
#include <string.h>

#include "bistream.h"

static void assert_budget(size_t bytes, size_t chunks)
{
	struct bistream_stats stats;
	bistream_stats_get(&stats);
	g_assert_cmpuint(stats.bytes, ==, bytes);
	g_assert_cmpuint(stats.chunks, ==, chunks);
}

static void assert_booked_chunks(struct bistream *bs)
{
	/* the budget counts the capacity of the chunks, which is what is allocated */
	size_t bytes = 0;
	for (GList *it = bs->sequence.head; it != NULL; it = it->next) {
		struct stream_chunk *sc = it->data;
		g_assert_cmpuint(sc->len, >, 0);
		g_assert_cmpuint(sc->len, <=, sc->capacity);
		g_assert_cmpuint(sc->capacity, <=, BISTREAM_CHUNK_BYTES);
		g_assert_cmpuint(malloc_usable_size(sc->data), >=, sc->capacity);
		g_assert_cmpuint(malloc_usable_size(sc->data), <, sc->capacity + 64);
		bytes += sc->capacity;
	}
	g_assert_cmpuint(bytes, ==, bs->bytes);
	g_assert_cmpuint(g_queue_get_length(&bs->sequence), ==, bs->chunks);
}

static guint8 *pattern(size_t size)
{
	guint8 *data = g_malloc(size);
	for (size_t i = 0; i < size; i++)
		data[i] = (guint8)(i % 251);
	return data;
}

/* per instance: under, at and over the byte limit, in both directions */
static void instance_bytes(void)
{
	guint8 *input = pattern(BISTREAM_MAX_BYTES + 1);
	struct bistream_stats before, after;
	bistream_stats_get(&before);
	struct bistream *bs = bistream_new();
	g_assert_true(bistream_data_add(bs, bistream_in, input, BISTREAM_MAX_BYTES - 2));
	g_assert_true(bistream_data_add(bs, bistream_out, input, 1));      /* under */
	g_assert_true(bistream_data_add(bs, bistream_in, input + BISTREAM_MAX_BYTES - 2, 1)); /* at */
	g_assert_cmpuint(bs->bytes, ==, BISTREAM_MAX_BYTES);
	g_assert_false(bistream_data_add(bs, bistream_out, input, 1));     /* over */
	g_assert_false(bistream_data_add(bs, bistream_in, input, 1));
	g_assert_cmpuint(bs->bytes, ==, BISTREAM_MAX_BYTES);
	g_assert_cmpuint(bistream_end(bs, bistream_in), ==, BISTREAM_MAX_BYTES - 1);
	g_assert_cmpuint(bistream_end(bs, bistream_out), ==, 1);
	assert_budget(BISTREAM_MAX_BYTES, bs->chunks);
	assert_booked_chunks(bs);
	/* counted as refused by the instance, not by the process */
	bistream_stats_get(&after);
	g_assert_cmpuint(after.refused_instance, ==, before.refused_instance + 2);
	g_assert_cmpuint(after.refused_global, ==, before.refused_global);

	/* the refused bytes were not appended, the stored ones are intact */
	void *copy = NULL;
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, 0, -1, &copy), ==, BISTREAM_MAX_BYTES - 1);
	g_assert_cmpmem(copy, BISTREAM_MAX_BYTES - 1, input, BISTREAM_MAX_BYTES - 1);
	g_assert_cmpint(((char *)copy)[BISTREAM_MAX_BYTES - 1], ==, 0);
	g_free(copy);
	g_assert_cmpint(bistream_get_stream(bs, bistream_out, 0, -1, &copy), ==, 1);
	g_assert_cmpint(((guint8 *)copy)[0], ==, 0);
	g_free(copy);

	/* freed space can be used again */
	bistream_discard_before(bs, bistream_in, 10);
	g_assert_cmpuint(bs->bytes, ==, BISTREAM_MAX_BYTES - 10);
	g_assert_true(bistream_data_add(bs, bistream_in, input, 10));
	g_assert_false(bistream_data_add(bs, bistream_in, input, 1));
	bistream_free(bs);

	/* one request over the limit stores nothing, one at the limit everything */
	bs = bistream_new();
	g_assert_false(bistream_data_add(bs, bistream_in, input, BISTREAM_MAX_BYTES + 1));
	g_assert_cmpuint(bs->bytes, ==, 0);
	g_assert_cmpuint(bs->chunks, ==, 0);
	g_assert_cmpuint(bistream_end(bs, bistream_in), ==, 0);
	g_assert_true(bistream_data_add(bs, bistream_in, input, BISTREAM_MAX_BYTES));
	g_assert_cmpuint(bs->chunks, ==, BISTREAM_MAX_BYTES / BISTREAM_CHUNK_BYTES);
	assert_booked_chunks(bs);
	bistream_free(bs);
	g_free(input);
	assert_budget(0, 0);
}

/* per instance: under, at and over the chunk limit with one byte chunks */
static void instance_chunks(void)
{
	struct bistream *bs = bistream_new();
	guint8 byte = 'x';
	for (unsigned i = 0; i < BISTREAM_MAX_CHUNKS - 1; i++)
		g_assert_true(bistream_data_add(bs, i % 2, &byte, 1));     /* alternating: one chunk each */
	g_assert_cmpuint(bs->chunks, ==, BISTREAM_MAX_CHUNKS - 1);
	g_assert_true(bistream_data_add(bs, bistream_out, &byte, 1));  /* at */
	g_assert_cmpuint(bs->chunks, ==, BISTREAM_MAX_CHUNKS);
	g_assert_false(bistream_data_add(bs, bistream_in, &byte, 1));  /* over: needs a chunk */
	g_assert_true(bistream_data_add(bs, bistream_out, &byte, 1));  /* fits into the last chunk */
	g_assert_cmpuint(bs->chunks, ==, BISTREAM_MAX_CHUNKS);
	g_assert_cmpuint(bs->bytes, ==, BISTREAM_MAX_CHUNKS + 1);
	assert_booked_chunks(bs);
	assert_budget(BISTREAM_MAX_CHUNKS + 1, BISTREAM_MAX_CHUNKS);

	/* bistream offsets follow the arrival order of both directions */
	struct stream_chunk *last = bs->sequence.tail->data;
	g_assert_cmpuint(last->bistream_offset, ==, BISTREAM_MAX_CHUNKS - 1);
	g_assert_cmpuint(last->stream_offset, ==, BISTREAM_MAX_CHUNKS / 2 - 1);
	g_assert_cmpuint(last->len, ==, 2);
	bistream_free(bs);

	/* one direction: one byte packets share a chunk until it is full */
	bs = bistream_new();
	for (unsigned i = 0; i < BISTREAM_CHUNK_BYTES; i++)
		g_assert_true(bistream_data_add(bs, bistream_in, &byte, 1));
	g_assert_cmpuint(bs->chunks, ==, 1);
	g_assert_true(bistream_data_add(bs, bistream_in, &byte, 1));
	g_assert_cmpuint(bs->chunks, ==, 2);
	assert_booked_chunks(bs);
	bistream_free(bs);
	assert_budget(0, 0);
}

/*
 * one byte packets: the last chunk grows by doubling, not by one byte, and
 * takes the exact size where the doubling would cross a limit
 */
static void growth(void)
{
	struct bistream *bs = bistream_new();
	guint8 byte = 'g';
	unsigned reallocs = 0;
	size_t capacity = 0;
	for (unsigned i = 1; i <= BISTREAM_CHUNK_BYTES; i++) {
		g_assert_true(bistream_data_add(bs, bistream_in, &byte, 1));
		struct stream_chunk *sc = bs->sequence.tail->data;
		if (sc->capacity != capacity)
			reallocs++;
		capacity = sc->capacity;
		g_assert_cmpuint(sc->capacity, >=, i);
		g_assert_cmpuint(sc->capacity, <=, 2 * i);
		assert_booked_chunks(bs);
		assert_budget(bs->bytes, bs->chunks);
	}
	/* 1, 2, 4, ... 16384 */
	g_assert_cmpuint(reallocs, ==, 15);
	g_assert_cmpuint(bs->bytes, ==, BISTREAM_CHUNK_BYTES);
	bistream_free(bs);

	/* a discard shrinks the chunk to what it keeps */
	bs = bistream_new();
	for (unsigned i = 0; i < 1000; i++)
		g_assert_true(bistream_data_add(bs, bistream_in, &byte, 1));
	g_assert_cmpuint(bs->bytes, ==, 1024);
	bistream_discard_before(bs, bistream_in, 300);
	g_assert_cmpuint(bs->bytes, ==, 700);
	assert_booked_chunks(bs);
	assert_budget(700, 1);
	bistream_free(bs);

	/* near the limit of the instance the doubling falls back to the exact size */
	guint8 *input = pattern(BISTREAM_MAX_BYTES);
	bs = bistream_new();
	g_assert_true(bistream_data_add(bs, bistream_in, input, BISTREAM_MAX_BYTES - 20));
	g_assert_true(bistream_data_add(bs, bistream_out, input, 15));
	/* doubling to 30 would need 15 of the 5 left */
	for (unsigned i = 0; i < 5; i++)
		g_assert_true(bistream_data_add(bs, bistream_out, &byte, 1));
	g_assert_cmpuint(((struct stream_chunk *)bs->sequence.tail->data)->capacity, ==, 20);
	g_assert_cmpuint(bs->bytes, ==, BISTREAM_MAX_BYTES);
	g_assert_false(bistream_data_add(bs, bistream_out, &byte, 1));
	assert_booked_chunks(bs);
	bistream_free(bs);

	/* the same at the limit of the process: the doubling is not counted as refused */
	enum { N = BISTREAM_GLOBAL_BYTES / BISTREAM_MAX_BYTES };
	struct bistream *full[N - 1];
	for (unsigned i = 0; i < N - 1; i++) {
		full[i] = bistream_new();
		g_assert_true(bistream_data_add(full[i], bistream_in, input, BISTREAM_MAX_BYTES));
	}
	bs = bistream_new();
	g_assert_true(bistream_data_add(bs, bistream_in, input, BISTREAM_MAX_BYTES - 1000));
	struct bistream *other = bistream_new();
	g_assert_true(bistream_data_add(other, bistream_out, input, 995));
	struct bistream_stats before, after;
	bistream_stats_get(&before);
	for (unsigned i = 0; i < 5; i++)
		g_assert_true(bistream_data_add(other, bistream_out, &byte, 1));
	g_assert_false(bistream_data_add(other, bistream_out, &byte, 1));
	bistream_stats_get(&after);
	g_assert_cmpuint(after.bytes, ==, BISTREAM_GLOBAL_BYTES);
	g_assert_cmpuint(after.refused_global, ==, before.refused_global + 1);
	g_assert_cmpuint(other->bytes, ==, 1000);
	assert_booked_chunks(other);
	bistream_free(other);
	bistream_free(bs);
	for (unsigned i = 0; i < N - 1; i++)
		bistream_free(full[i]);
	g_free(input);
	assert_budget(0, 0);
}

/* the process wide limits, released by clear and free */
static void global_bytes(void)
{
	enum { N = BISTREAM_GLOBAL_BYTES / BISTREAM_MAX_BYTES };
	guint8 *input = pattern(BISTREAM_MAX_BYTES);
	struct bistream *streams[N + 1];
	for (unsigned i = 0; i <= N; i++)
		streams[i] = bistream_new();
	for (unsigned i = 0; i < N - 1; i++)
		g_assert_true(bistream_data_add(streams[i], bistream_in, input, BISTREAM_MAX_BYTES));
	g_assert_true(bistream_data_add(streams[N - 1], bistream_in, input, BISTREAM_MAX_BYTES - 1));
	g_assert_true(bistream_data_add(streams[N], bistream_out, input, 1));    /* at */
	assert_budget(BISTREAM_GLOBAL_BYTES, (N - 1) * 64 + 64 + 1);
	struct bistream_stats before;
	bistream_stats_get(&before);
	g_assert_false(bistream_data_add(streams[N], bistream_out, input, 1));   /* over */
	g_assert_false(bistream_data_add(streams[N - 1], bistream_in, input, 1));
	g_assert_cmpuint(streams[N]->bytes, ==, 1);
	bistream_clear(streams[0]);
	g_assert_cmpuint(streams[0]->bytes, ==, 0);
	g_assert_true(bistream_data_add(streams[N], bistream_out, input, BISTREAM_MAX_BYTES - 1));
	g_assert_true(bistream_data_add(streams[0], bistream_in, input, 1));     /* at again */
	g_assert_false(bistream_data_add(streams[0], bistream_in, input, 1));    /* over */
	assert_budget(BISTREAM_GLOBAL_BYTES, (N - 1) * 64 + 64 + 1);

	struct bistream_stats stats;
	bistream_stats_get(&stats);
	g_assert_cmpuint(stats.peak_bytes, ==, BISTREAM_GLOBAL_BYTES);
	/* counted as refused by the process, not by an instance */
	g_assert_cmpuint(stats.refused_global, ==, before.refused_global + 3);
	g_assert_cmpuint(stats.refused_instance, ==, before.refused_instance);
	for (unsigned i = 0; i <= N; i++)
		bistream_free(streams[i]);
	g_free(input);
	assert_budget(0, 0);
}

static void global_chunks(void)
{
	enum { N = BISTREAM_GLOBAL_CHUNKS / BISTREAM_MAX_CHUNKS };
	struct bistream *streams[N + 1];
	guint8 byte = 'x';
	for (unsigned j = 0; j <= N; j++)
		streams[j] = bistream_new();
	for (unsigned j = 0; j < N; j++)
		for (unsigned i = 0; i < BISTREAM_MAX_CHUNKS - (j == N - 1); i++)
			g_assert_true(bistream_data_add(streams[j], i % 2, &byte, 1));
	assert_budget(BISTREAM_GLOBAL_CHUNKS - 1, BISTREAM_GLOBAL_CHUNKS - 1);
	g_assert_true(bistream_data_add(streams[N], bistream_in, &byte, 1));   /* at */
	g_assert_false(bistream_data_add(streams[N], bistream_out, &byte, 1)); /* over */
	g_assert_true(bistream_data_add(streams[N], bistream_in, &byte, 1));   /* no new chunk */
	assert_budget(BISTREAM_GLOBAL_CHUNKS + 1, BISTREAM_GLOBAL_CHUNKS);

	struct bistream_stats stats;
	bistream_stats_get(&stats);
	g_assert_cmpuint(stats.peak_chunks, ==, BISTREAM_GLOBAL_CHUNKS);
	bistream_clear(streams[0]);
	g_assert_true(bistream_data_add(streams[N], bistream_out, &byte, 1));
	for (unsigned j = 0; j <= N; j++)
		bistream_free(streams[j]);
	assert_budget(0, 0);
}

static void arguments(void)
{
	struct bistream *bs = bistream_new();
	guint8 byte = 'x';
	void *copy = (void *)1;
	g_assert_true(bistream_data_add(bs, bistream_in, NULL, 0));
	g_assert_false(bistream_data_add(bs, bistream_in, NULL, 1));
	g_assert_false(bistream_data_add(bs, (enum bistream_direction)2, &byte, 1));
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, 0, -1, &copy), ==, -1);
	g_assert_null(copy);
	g_assert_true(bistream_data_add(bs, bistream_in, "abcdef", 6));
	copy = (void *)1;
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, 0, -2, &copy), ==, -1);
	g_assert_null(copy);
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, 0, 7, &copy), ==, -1);  /* beyond the end */
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, 3, 3, &copy), ==, -1);  /* empty */
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, 4, 3, &copy), ==, -1);
	g_assert_cmpint(bistream_get_stream(bs, bistream_out, 0, -1, &copy), ==, -1);
	g_assert_cmpint(bistream_get_stream(bs, (enum bistream_direction)2, 0, -1, &copy), ==, -1);
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, 0, -1, NULL), ==, -1);
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, 2, 5, &copy), ==, 3);
	g_assert_cmpmem(copy, 3, "cde", 3);
	g_free(copy);
	bistream_free(bs);
	assert_budget(0, 0);
}

/* discarding frees chunks and memory, one direction at a time */
static void discard(void)
{
	guint8 *input = pattern(3 * BISTREAM_CHUNK_BYTES);
	struct bistream *bs = bistream_new();
	g_assert_true(bistream_data_add(bs, bistream_in, input, 3 * BISTREAM_CHUNK_BYTES));
	g_assert_true(bistream_data_add(bs, bistream_out, input, 100));
	g_assert_true(bistream_data_add(bs, bistream_in, input, 10));
	g_assert_cmpuint(bs->chunks, ==, 5);

	bistream_discard_before(bs, bistream_in, BISTREAM_CHUNK_BYTES + 300);
	g_assert_cmpuint(bs->chunks, ==, 4);
	g_assert_cmpuint(bs->bytes, ==, 2 * BISTREAM_CHUNK_BYTES - 300 + 100 + 10);
	assert_booked_chunks(bs);
	assert_budget(bs->bytes, bs->chunks);
	void *copy = (void *)1;
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, BISTREAM_CHUNK_BYTES + 299, -1, &copy), ==, -1);
	g_assert_null(copy);
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, BISTREAM_CHUNK_BYTES + 300, 2 * BISTREAM_CHUNK_BYTES + 1, &copy), ==, BISTREAM_CHUNK_BYTES - 299);
	g_assert_cmpmem(copy, BISTREAM_CHUNK_BYTES - 299, input + BISTREAM_CHUNK_BYTES + 300, BISTREAM_CHUNK_BYTES - 299);
	g_free(copy);
	/* the other direction is untouched */
	g_assert_cmpint(bistream_get_stream(bs, bistream_out, 0, -1, &copy), ==, 100);
	g_free(copy);

	/* discarding again before the same offset changes nothing, beyond the end everything */
	size_t bytes = bs->bytes;
	bistream_discard_before(bs, bistream_in, BISTREAM_CHUNK_BYTES + 300);
	g_assert_cmpuint(bs->bytes, ==, bytes);
	bistream_discard_before(bs, bistream_in, UINT64_MAX);
	g_assert_cmpuint(bs->bytes, ==, 100);
	g_assert_cmpuint(bs->chunks, ==, 1);
	g_assert_cmpuint(g_queue_get_length(&bs->streams[bistream_in].chunks), ==, 0);
	g_assert_cmpuint(bistream_end(bs, bistream_in), ==, 3 * BISTREAM_CHUNK_BYTES + 10);
	/* the offsets go on after everything was discarded */
	g_assert_true(bistream_data_add(bs, bistream_in, "xyz", 3));
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, 3 * BISTREAM_CHUNK_BYTES + 10, -1, &copy), ==, 3);
	g_assert_cmpmem(copy, 3, "xyz", 3);
	g_free(copy);
	bistream_discard_before(bs, bistream_out, 100);
	bistream_discard_before(bs, bistream_in, UINT64_MAX);
	g_assert_cmpuint(bs->chunks, ==, 0);
	g_assert_null(bs->sequence.head);
	assert_budget(0, 0);
	bistream_free(bs);
	g_free(input);
}

/* offsets beyond 4 GiB, through the public functions only */
static void large_offsets(void)
{
	const size_t step = BISTREAM_MAX_BYTES - 300;
	guint8 *input = pattern(step + 251);
	struct bistream *bs = bistream_new();
	uint64_t end = 0;
	while (end < (UINT64_C(1) << 32) + 3 * step) {
		/* byte at absolute offset o is o % 251 */
		g_assert_true(bistream_data_add(bs, bistream_in, input + end % 251, step));
		end += step;
		bistream_discard_before(bs, bistream_in, end - 300);
		g_assert_cmpuint(bs->bytes, ==, 300);
	}
	g_assert_cmpuint(bistream_end(bs, bistream_in), ==, end);
	void *copy;
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, end - 300, -1, &copy), ==, 300);
	for (unsigned i = 0; i < 300; i++)
		g_assert_cmpuint(((guint8 *)copy)[i], ==, (end - 300 + i) % 251);
	g_free(copy);
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, end - 301, -1, &copy), ==, -1);
	struct stream_chunk *sc = bs->sequence.head->data;
	g_assert_cmpuint(sc->stream_offset, ==, end - 300);
	g_assert_cmpuint(sc->bistream_offset, ==, end - 300);
	bistream_free(bs);
	g_free(input);

	/* the 64 bit offsets do not wrap */
	bs = bistream_new();
	bs->end = bs->streams[bistream_in].end = INT64_MAX - 1;
	g_assert_true(bistream_data_add(bs, bistream_in, "a", 1));
	g_assert_false(bistream_data_add(bs, bistream_in, "a", 1));
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, INT64_MAX - 1, -1, &copy), ==, 1);
	g_free(copy);
	g_assert_cmpint(bistream_get_stream(bs, bistream_in, INT64_MAX - 1, INT64_MAX, &copy), ==, 1);
	g_free(copy);
	bistream_free(bs);
	assert_budget(0, 0);
}

static gpointer producer(gpointer data)
{
	struct bistream *bs = data;
	guint8 input[127];
	memset(input, 'z', sizeof(input));
	for (unsigned i = 0; i < 20000; i++) {
		uint64_t end = bistream_end(bs, i % 2);
		bistream_discard_before(bs, i % 2, end > 300 ? end - 300 : 0);
		g_assert_true(bistream_data_add(bs, i % 2, input, sizeof(input)));
	}
	return NULL;
}

static gpointer reader(gpointer data)
{
	struct bistream *bs = data;
	for (unsigned i = 0; i < 20000; i++) {
		uint64_t end = bistream_end(bs, bistream_in);
		void *copy;
		int n = bistream_get_stream(bs, bistream_in, end > 100 ? end - 100 : 0, end, &copy);
		if (n > 0) {
			for (int j = 0; j < n; j++)
				g_assert_cmpint(((char *)copy)[j], ==, 'z');
			g_free(copy);
		} else
			g_assert_null(copy);
	}
	return NULL;
}

/* many bistreams book the process wide budget at the same time */
static gpointer booker(gpointer data)
{
	guint8 input[4096];
	memset(input, 'b', sizeof(input));
	struct bistream *bs = bistream_new();
	for (unsigned i = 0; i < 5000; i++) {
		if (!bistream_data_add(bs, i % 2, input, sizeof(input)))
			bistream_clear(bs);
		struct bistream_stats stats;
		bistream_stats_get(&stats);
		g_assert_cmpuint(stats.bytes, <=, BISTREAM_GLOBAL_BYTES);
		g_assert_cmpuint(stats.chunks, <=, BISTREAM_GLOBAL_CHUNKS);
	}
	bistream_free(bs);
	(void)data;
	return NULL;
}

static void concurrent(void)
{
	struct bistream *bs = bistream_new();
	GThread *a = g_thread_new("producer", producer, bs);
	GThread *b = g_thread_new("reader", reader, bs);
	g_thread_join(a);
	g_thread_join(b);
	bistream_free(bs);

	GThread *threads[8];
	for (unsigned i = 0; i < G_N_ELEMENTS(threads); i++)
		threads[i] = g_thread_new("booker", booker, NULL);
	for (unsigned i = 0; i < G_N_ELEMENTS(threads); i++)
		g_thread_join(threads[i]);
	assert_budget(0, 0);
}

static void quiet(const gchar *domain, GLogLevelFlags level, const gchar *message, gpointer data)
{
	if( level & (G_LOG_LEVEL_DEBUG | G_LOG_LEVEL_INFO) )
		return;
	g_log_default_handler(domain, level, message, data);
}

int main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	g_log_set_default_handler(quiet, NULL);
	g_test_add_func("/bistream/instance-bytes", instance_bytes);
	g_test_add_func("/bistream/instance-chunks", instance_chunks);
	g_test_add_func("/bistream/growth", growth);
	g_test_add_func("/bistream/global-bytes", global_bytes);
	g_test_add_func("/bistream/global-chunks", global_chunks);
	g_test_add_func("/bistream/arguments", arguments);
	g_test_add_func("/bistream/discard", discard);
	g_test_add_func("/bistream/large-offsets", large_offsets);
	g_test_add_func("/bistream/concurrent", concurrent);
	return g_test_run();
}
