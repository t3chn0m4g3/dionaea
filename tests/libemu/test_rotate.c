/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 */

/*
 * ROL, ROR, RCL and RCR of the bundled libemu (src/functions/rol.c, ror.c,
 * rcl.c, rcr.c), as instruction bytes through emu_cpu_parse and
 * emu_cpu_step: by 1 (D0, D1), by CL (D2, D3) and by an immediate (C0, C1),
 * 8, 16 (66 prefix) and 32 bits, on AL, AX and EAX (and on a byte, word
 * and dword in memory for some counts), every count from 0 to 31 and a few
 * above, with CF clear and set and the other flags clear and
 * set before. Each case checks EAX in full against the rotation of x86: the
 * count is masked to 5 bits; ROL and ROR rotate by it modulo the width, RCL
 * and RCR rotate the width and CF by it modulo the width plus one. The rest
 * of EAX stays.
 *
 * The flags as the Intel SDM (vol. 2, RCL/RCR/ROL/ROR) describes them, with
 * the masked count c:
 *  - c = 0: no flag changes;
 *  - CF: ROL the low bit of the result, ROR its high bit (c != 0); RCL and
 *    RCR the last bit rotated out (unchanged when c modulo the width plus
 *    one is 0);
 *  - OF for c = 1: ROL and RCL the high bit of the result XOR CF after, ROR
 *    the two high bits of the result XORed, RCR the high bit of the operand
 *    XOR CF before. For c > 1 OF is undefined and not checked;
 *  - SF, ZF, AF and PF never change.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <emu/emu.h>
#include <emu/emu_cpu.h>
#include <emu/emu_cpu_data.h>
#include <emu/emu_memory.h>

#define CODE 0x1000
#define DATA 0x2000

enum op { ROL = 0, ROR = 1, RCL = 2, RCR = 3 };
static const char *const OPS[] = { "rol", "ror", "rcl", "rcr" };
enum form { BY_ONE, BY_CL, BY_IMM };
static const char *const FORMS[] = { "1", "cl", "imm" };

static const uint32_t values[] = { 0x80000001, 0x12345678, 0xfedcba98, 0x00000000, 0xffffffff, 0x5a5a5aa5,
                                   0x40000040, 0x00008080 };
/* counts above 31: masked to 5 bits */
static const unsigned high_counts[] = { 32, 33, 40, 63, 255 };
/* the flags besides CF, clear or all set before */
#define OTHER_FLAGS (1u << f_pf | 1u << f_af | 1u << f_zf | 1u << f_sf | 1u << f_of)

static int failures;
static int checks;

static uint32_t mask(int bits)
{
	return bits == 32 ? 0xffffffffu : (1u << bits) - 1;
}

/* the rotation of x86 on the low bits of x */
static uint32_t reference(enum op op, int bits, uint32_t x, int cf, unsigned count)
{
	uint64_t v = x & mask(bits);
	unsigned n = count & 0x1f;
	switch( op )
	{
	case ROL:
		n %= bits;
		v = (v << n | v >> (bits - n)) & mask(bits);
		break;
	case ROR:
		n %= bits;
		v = (v >> n | v << (bits - n)) & mask(bits);
		break;
	case RCL:
	case RCR:
		{
			/* the width and CF as one value of bits + 1 */
			unsigned width = bits + 1;
			n %= width;
			uint64_t w = v | (uint64_t)cf << bits;
			uint64_t all = (1ull << width) - 1;
			if( op == RCL )
				w = (w << n | w >> (width - n)) & all;
			else
				w = (w >> n | w << (width - n)) & all;
			v = w & mask(bits);
		}
		break;
	}
	return (x & ~mask(bits)) | (uint32_t)v;
}

/* the flags after the rotation of x86; *of_defined tells whether OF is defined */
static uint32_t reference_flags(enum op op, int bits, uint32_t x, uint32_t flags, unsigned count, bool *of_defined)
{
	unsigned c = count & 0x1f;
	uint32_t result = reference(op, bits, x, flags & 1, count) & mask(bits);
	uint32_t src = x & mask(bits);
	unsigned msb = (unsigned)(result >> (bits - 1)) & 1;
	int cf = flags & 1;
	*of_defined = c == 1;
	if( c == 0 )
		return flags;
	switch( op )
	{
	case ROL:
		cf = result & 1;
		break;
	case ROR:
		cf = msb;
		break;
	case RCL:
	case RCR:
		{
			unsigned n = c % (bits + 1);
			if( n != 0 )
				cf = op == RCL ? (int)((src >> (bits - n)) & 1) : (int)((src >> (n - 1)) & 1);
		}
		break;
	}
	uint32_t out = (flags & ~1u) | (uint32_t)cf;
	if( c == 1 )
	{
		unsigned of = 0;
		switch( op )
		{
		case ROL:
		case RCL:
			of = msb ^ (unsigned)cf;
			break;
		case ROR:
			of = msb ^ ((unsigned)(result >> (bits - 2)) & 1);
			break;
		case RCR:
			of = ((unsigned)(src >> (bits - 1)) & 1) ^ (unsigned)(flags & 1);
			break;
		}
		out = (out & ~(1u << f_of)) | of << f_of;
	}
	return out;
}

/* on EAX, or with in_memory on the dword at DATA ([EBX]) */
static void run_on(enum op op, enum form form, int bits, uint32_t x, uint32_t flags, unsigned count, bool in_memory)
{
	int cf = flags & 1;
	uint8_t code[8];
	int len = 0;
	if( bits == 16 )
		code[len++] = 0x66;
	uint8_t base = form == BY_ONE ? 0xd0 : form == BY_CL ? 0xd2 : 0xc0;
	code[len++] = base + (bits == 8 ? 0 : 1);
	if( in_memory )
		code[len++] = 0x03 | (uint8_t)(op << 3);  /* mod 0, r/m [EBX] */
	else
		code[len++] = 0xc0 | (uint8_t)(op << 3);  /* mod 3, r/m EAX */
	if( form == BY_IMM )
		code[len++] = (uint8_t)count;
	if( form == BY_ONE )
		count = 1;

	struct emu *e = emu_new();
	if( e == NULL )
	{
		fprintf(stderr, "emu_new failed\n");
		exit(1);
	}
	struct emu_cpu *cpu = emu_cpu_get(e);
	emu_cpu_reg32_set(cpu, eax, in_memory ? 0x11111111u : x);
	emu_cpu_reg32_set(cpu, ebx, DATA);
	emu_memory_write_dword(emu_memory_get(e), DATA, in_memory ? x : 0x22222222u);
	emu_cpu_reg32_set(cpu, ecx, 0xcccccc00u | (count & 0xff));
	emu_cpu_eflags_set(cpu, flags);
	emu_memory_write_block(emu_memory_get(e), CODE, code, len);
	emu_cpu_eip_set(cpu, CODE);
	checks++;
	if( emu_cpu_parse(cpu) != 0 || emu_cpu_step(cpu) != 0 )
	{
		printf("FAIL %s %d bits by %s %u: the CPU stopped: %s\n", OPS[op], bits, FORMS[form], count, emu_strerror(e));
		failures++;
	} else
	{
		uint32_t got = emu_cpu_reg32_get(cpu, eax);
		uint32_t mem = 0;
		emu_memory_read_dword(emu_memory_get(e), DATA, &mem);
		if( in_memory )
		{
			if( got != 0x11111111u )
			{
				printf("FAIL %s %d bits on memory: EAX 0x%08x changed\n", OPS[op], bits, got);
				failures++;
			}
			got = mem;
		} else if( mem != 0x22222222u )
		{
			printf("FAIL %s %d bits on EAX: memory 0x%08x changed\n", OPS[op], bits, mem);
			failures++;
		}
		uint32_t want = reference(op, bits, x, cf, count);
		bool of_defined;
		uint32_t want_flags = reference_flags(op, bits, x, flags, count, &of_defined);
		uint32_t checked = 1u << f_cf | OTHER_FLAGS;
		if( !of_defined )
			checked &= ~(1u << f_of);
		uint32_t got_flags = emu_cpu_eflags_get(cpu);
		if( got != want )
		{
			printf("FAIL %s %d bits by %s %u of 0x%08x%s, CF %d before: 0x%08x, want 0x%08x\n",
			       OPS[op], bits, FORMS[form], count, x, in_memory ? " in memory" : "", cf, got, want);
			failures++;
		} else if( (got_flags & checked) != (want_flags & checked) )
		{
			printf("FAIL %s %d bits by %s %u of 0x%08x%s, flags 0x%03x before: flags 0x%03x, want 0x%03x (mask 0x%03x)\n",
			       OPS[op], bits, FORMS[form], count, x, in_memory ? " in memory" : "", flags,
			       got_flags & checked, want_flags & checked, checked);
			failures++;
		}
	}
	emu_free(e);
}

static void run(enum op op, enum form form, int bits, uint32_t x, uint32_t flags, unsigned count)
{
	run_on(op, form, bits, x, flags, count, false);
}

int main(void)
{
	static const int widths[] = { 8, 16, 32 };
	for( int op = ROL; op <= RCR; op++ )
		for( size_t w = 0; w < sizeof(widths) / sizeof(widths[0]); w++ )
			for( size_t v = 0; v < sizeof(values) / sizeof(values[0]); v++ )
				for( int cf = 0; cf <= 1; cf++ )
					for( int others = 0; others <= 1; others++ )
					{
						uint32_t flags = (uint32_t)cf | (others ? OTHER_FLAGS : 0);
						run(op, BY_ONE, widths[w], values[v], flags, 1);
						for( unsigned count = 0; count < 32; count++ )
						{
							run(op, BY_CL, widths[w], values[v], flags, count);
							run(op, BY_IMM, widths[w], values[v], flags, count);
						}
						for( size_t h = 0; h < sizeof(high_counts) / sizeof(high_counts[0]); h++ )
						{
							run(op, BY_CL, widths[w], values[v], flags, high_counts[h]);
							run(op, BY_IMM, widths[w], values[v], flags, high_counts[h]);
						}
						static const unsigned memory_counts[] = { 0, 1, 5, 9, 17, 31 };
						run_on(op, BY_ONE, widths[w], values[v], flags, 1, true);
						for( size_t m = 0; m < sizeof(memory_counts) / sizeof(memory_counts[0]); m++ )
						{
							run_on(op, BY_CL, widths[w], values[v], flags, memory_counts[m], true);
							run_on(op, BY_IMM, widths[w], values[v], flags, memory_counts[m], true);
						}
					}

	if( failures )
	{
		printf("%d of %d checks failed\n", failures, checks);
		return 1;
	}
	printf("all %d ROL, ROR, RCL and RCR checks passed\n", checks);
	return 0;
}
