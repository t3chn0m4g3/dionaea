/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 */

/*
 * Unit test of the bundled libemu: the shellcode detection dionaea's emu
 * module runs on every stream (emu_shellcode_test, see modules/emu/detect.c).
 *
 *  - known samples with a GetPC sequence are found at the right offset
 *    (the first byte the emulation starts from, exact values)
 *  - data without GetPC is not reported
 *  - an empty buffer, every 1-byte buffer and random buffers are handled
 *  - one emu can test several buffers in a row, and is freed afterwards
 *
 * A crash (signal) fails the test through its exit status; it is meant to be
 * run with -fsanitize=address,undefined as well.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <emu/emu.h>
#include <emu/emu_shellcode.h>

static int failures;

#define CHECK(cond, ...) \
	do { \
		if (!(cond)) { \
			failures++; \
			printf("FAIL %s:%d: ", __FILE__, __LINE__); \
			printf(__VA_ARGS__); \
			printf("\n"); \
		} \
	} while (0)

struct sample
{
	const char *name;
	const uint8_t *data;
	uint16_t size;
	/* expected result of emu_shellcode_test(): the offset where the
	 * emulation starts, i.e. the first byte from which the code runs into
	 * the GetPC sequence and on for more than 100 steps (not the offset of
	 * the GetPC instruction itself) */
	int32_t offset;
};

/* testsuite/instrtree.c of libemu: call/pop GetPC (e8 ff ff ff ff c0 5e) and
 * an XOR decoder loop behind it. */
static const uint8_t sc_callpop_xor[] = {
	0x33, 0xc9, 0x83, 0xe9, 0xb0, 0xe8, 0xff, 0xff, 0xff, 0xff, 0xc0, 0x5e,
	0x81, 0x76, 0x0e, 0x47, 0x13, 0x2b, 0xc0, 0x83, 0xee, 0xfc, 0xe2, 0xf4,
	0xbb, 0x79, 0xc0, 0x8d, 0xaf, 0xea, 0xd4, 0x3f
};

/* Commented-out sample of testsuite/instrtree.c: jmp short / call / pop GetPC
 * with a small decoder behind it. */
static const uint8_t sc_jmpcall[] = {
	0xfc, 0xbb, 0xbf, 0x05, 0xeb, 0xd0, 0xeb, 0x0c, 0x5e, 0x56, 0x31, 0x1e,
	0xad, 0x01, 0xc3, 0x85, 0xc0, 0x75, 0xf7, 0xc3, 0xe8, 0xef, 0xff, 0xff,
	0xff, 0x43, 0x6f, 0x00, 0x97, 0x53
};

/* fldz; fnstenv [esp-12]; pop ebx (the FPU GetPC variant), then a loop of 128
 * iterations: libemu only reports code that runs for more than 100 steps. */
static const uint8_t sc_fnstenv[] = {
	0xd9, 0xee, 0xd9, 0x74, 0x24, 0xf4, 0x5b, 0x31, 0xc9, 0xb1, 0x80, 0x83,
	0xeb, 0xfc, 0xe2, 0xfb, 0x90, 0x90, 0x90, 0x90
};

static const struct sample samples[] = {
	/* xor ecx,ecx; sub ecx,-0x50 run into the call at byte 5: start 0 */
	{ "instrtree call/pop + xor decoder", sc_callpop_xor, sizeof(sc_callpop_xor), 0 },
	/* cld; mov ebx,..; jmp short to the call: start 0 */
	{ "instrtree jmp/call/pop", sc_jmpcall, sizeof(sc_jmpcall), 0 },
	/* fldz is the first instruction of the GetPC: start 0 */
	{ "fldz/fnstenv/pop", sc_fnstenv, sizeof(sc_fnstenv), 0 },
};

static int32_t run_test(const uint8_t *data, uint16_t size)
{
	struct emu *e = emu_new();
	CHECK(e != NULL, "emu_new returned NULL");
	if (e == NULL)
		return -1;
	int32_t ret = emu_shellcode_test(e, (uint8_t *)data, size);
	emu_free(e);
	return ret;
}

static uint32_t rng_state = 0x1badc0de;

static uint32_t rng(void)
{
	/* xorshift32: the same "random" buffers on every run and platform */
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

int main(void)
{
	size_t i;

	setvbuf(stdout, NULL, _IONBF, 0);

	/* known samples */
	for (i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
		int32_t ret = run_test(samples[i].data, samples[i].size);
		printf("sample '%s' (%u bytes): emu_shellcode_test = %d\n",
			samples[i].name, samples[i].size, ret);
		CHECK(ret == samples[i].offset, "'%s': offset %d, expected %d",
			samples[i].name, ret, samples[i].offset);
	}

	/* the same sample after a prefix of junk, as it comes in a stream */
	{
		uint8_t buf[512];
		memset(buf, 0x41, sizeof(buf));
		memcpy(buf + 100, sc_callpop_xor, sizeof(sc_callpop_xor));
		int32_t ret = run_test(buf, 100 + sizeof(sc_callpop_xor));
		printf("sample behind 100 bytes of inc-ecx junk: emu_shellcode_test = %d\n", ret);
		/* 0x41 (inc ecx) is executable and runs into the sample, so the
		 * emulation starts at the first byte of the junk */
		CHECK(ret == 0, "sample behind inc-ecx junk: offset %d, expected 0", ret);
	}

	/* the same sample behind 100 bytes of ret: a ret cannot run into it,
	 * so the start is the first byte of the sample */
	{
		uint8_t buf[512];
		memset(buf, 0xc3, sizeof(buf));
		memcpy(buf + 100, sc_callpop_xor, sizeof(sc_callpop_xor));
		int32_t ret = run_test(buf, 100 + sizeof(sc_callpop_xor));
		printf("sample behind 100 bytes of ret: emu_shellcode_test = %d\n", ret);
		CHECK(ret == 100, "sample behind ret junk: offset %d, expected 100", ret);
	}

	/* data without any GetPC sequence */
	{
		uint8_t nops[64];
		memset(nops, 0x90, sizeof(nops));
		CHECK(run_test(nops, sizeof(nops)) < 0, "nop sled reported as shellcode");
		const char *text = "GET / HTTP/1.1\r\nHost: example.org\r\nUser-Agent: test\r\n\r\n";
		CHECK(run_test((const uint8_t *)text, strlen(text)) < 0, "HTTP request reported as shellcode");
	}

	/* empty buffer */
	{
		uint8_t one = 0;
		int32_t ret = run_test(&one, 0);
		CHECK(ret < 0, "empty buffer reported as shellcode (%d)", ret);
	}

	/* every 1-byte buffer */
	for (i = 0; i < 256; i++) {
		uint8_t b = (uint8_t)i;
		(void)run_test(&b, 1);
	}
	printf("all 256 one-byte buffers done\n");

	/* every 2- and 3-byte buffer made of the first bytes of the samples */
	for (i = 1; i <= 8; i++) {
		(void)run_test(sc_callpop_xor, i);
		(void)run_test(sc_jmpcall, i);
		(void)run_test(sc_fnstenv, i);
	}

	/* random buffers, sizes 1..2048 */
	for (i = 0; i < 300; i++) {
		uint8_t buf[2048];
		uint16_t size = 1 + (rng() % sizeof(buf));
		uint16_t j;
		for (j = 0; j < size; j++)
			buf[j] = (uint8_t)rng();
		(void)run_test(buf, size);
	}
	printf("300 random buffers done\n");

	/* random buffers with a GetPC sequence inserted at random places, so the
	 * emulator, the tracking and the graph code run on garbage */
	for (i = 0; i < 100; i++) {
		uint8_t buf[512];
		uint16_t size = sizeof(sc_callpop_xor) + (rng() % (sizeof(buf) - sizeof(sc_callpop_xor)));
		uint16_t at = rng() % (size - sizeof(sc_callpop_xor) + 1);
		uint16_t j;
		for (j = 0; j < size; j++)
			buf[j] = (uint8_t)rng();
		memcpy(buf + at, sc_callpop_xor, sizeof(sc_callpop_xor));
		(void)run_test(buf, size);
	}
	printf("100 random buffers with GetPC done\n");

	/* one emu for several tests in a row (tracking reset, buffer/libemu commit b8b08f0) */
	{
		struct emu *e = emu_new();
		int round;
		int32_t first = -3;
		for (round = 0; round < 5; round++) {
			int32_t ret = emu_shellcode_test(e, (uint8_t *)sc_callpop_xor, sizeof(sc_callpop_xor));
			if (round == 0)
				first = ret;
			CHECK(ret == 0, "round %d: offset %d, expected 0", round, ret);
			CHECK(ret == first, "round %d: result %d differs from the first (%d)", round, ret, first);
			uint8_t b = (uint8_t)round;
			(void)emu_shellcode_test(e, &b, 1);
		}
		emu_free(e);
	}

	if (failures) {
		printf("%d check(s) failed\n", failures);
		return 1;
	}
	printf("libemu: all checks passed\n");
	return 0;
}
