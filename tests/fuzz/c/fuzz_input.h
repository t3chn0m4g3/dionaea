/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * Reading the operations of a fuzz target from its input: every read takes
 * the next bytes, past the end it reads zeros.
 */
#ifndef DIONAEA_FUZZ_INPUT_H
#define DIONAEA_FUZZ_INPUT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

struct fuzz_input
{
	const uint8_t *data;
	size_t size;
};

static inline size_t fuzz_left(const struct fuzz_input *in)
{
	return in->size;
}

/* up to size bytes into out, returns how many there were */
static inline size_t fuzz_bytes(struct fuzz_input *in, void *out, size_t size)
{
	size_t take = size < in->size ? size : in->size;
	if( take > 0 )
		memcpy(out, in->data, take);
	in->data += take;
	in->size -= take;
	return take;
}

/* the next size bytes in place (fewer at the end) */
static inline const uint8_t *fuzz_span(struct fuzz_input *in, size_t size, size_t *got)
{
	const uint8_t *span = in->data;
	*got = size < in->size ? size : in->size;
	in->data += *got;
	in->size -= *got;
	return span;
}

static inline uint8_t fuzz_u8(struct fuzz_input *in)
{
	uint8_t v = 0;
	fuzz_bytes(in, &v, 1);
	return v;
}

static inline uint16_t fuzz_u16(struct fuzz_input *in)
{
	uint16_t low = fuzz_u8(in);
	return (uint16_t)(low | (fuzz_u8(in) << 8));
}

static inline uint32_t fuzz_u32(struct fuzz_input *in)
{
	uint32_t low = fuzz_u16(in);
	return low | ((uint32_t)fuzz_u16(in) << 16);
}

static inline uint64_t fuzz_u64(struct fuzz_input *in)
{
	uint64_t low = fuzz_u32(in);
	return low | ((uint64_t)fuzz_u32(in) << 32);
}

#endif
