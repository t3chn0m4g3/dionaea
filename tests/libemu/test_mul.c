/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 */

/*
 * MUL and IMUL of the bundled libemu (src/functions/mul.c, imul.c).
 *
 * The forms the CPU dispatches (F6 /4, F6 /5, F7 /4, F7 /5 and 6B, with
 * the 66 prefix for 16 bits) run as instruction bytes through emu_cpu_parse
 * and emu_cpu_step. 0F AF and 69 have no entry in the instruction table
 * (emu_cpu_itables.h); their functions are called with a decoded
 * instruction. Every case checks EAX and EDX in full and CF and OF, once
 * with both flags clear before and once with both set:
 *
 *  - the product is computed at the width of the destination (EDX:EAX,
 *    DX:AX, AX), unsigned for MUL and signed for IMUL;
 *  - MUL sets CF and OF when the upper half of the product is not 0;
 *  - IMUL sets CF and OF when the product does not fit the destination size:
 *    the full product is not the sign extension of its lower half.
 *
 * Meant to run under -fsanitize=undefined as well: neither file computes a
 * product that overflows its C type.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <emu/emu.h>
#include <emu/emu_cpu.h>
#include <emu/emu_cpu_data.h>
#include <emu/emu_cpu_instruction.h>
#include <emu/emu_memory.h>

/* in imul.c, without a prototype in emu_cpu_functions.h (no table entry) */
int32_t instr_imul_69(struct emu_cpu *c, struct emu_cpu_instruction *i);
int32_t instr_imul_0f_af(struct emu_cpu *c, struct emu_cpu_instruction *i);

#define CODE 0x1000
#define DATA 0x2000

/* EAX, ECX and EDX before; EBX holds DATA for the memory forms */
struct regs { uint32_t eax, ecx, edx; };

struct bytes_case {
	const char *name;
	uint8_t code[8];
	int len;
	struct regs in;
	uint32_t mem; /* the dword at DATA */
	uint32_t eax, edx;
	int cf;
};

/* the 16-bit forms keep the upper halves: 0xaaaa.... in EAX, 0xcccc.... in EDX */
static const struct bytes_case bytes_cases[] = {
	/* F7 /4, MUL r/m32: EDX:EAX <- EAX * r/m32 */
	{ "mul ecx: 0x10000 * 0x10000", { 0xf7, 0xe1 }, 2, { 0x10000, 0x10000, 0x5a5a5a5a }, 0,
	  0x00000000, 0x00000001, 1 },
	{ "mul ecx: 0xffffffff * 0xffffffff", { 0xf7, 0xe1 }, 2, { 0xffffffff, 0xffffffff, 0x5a5a5a5a }, 0,
	  0x00000001, 0xfffffffe, 1 },
	{ "mul ecx: 3 * 4", { 0xf7, 0xe1 }, 2, { 3, 4, 0x5a5a5a5a }, 0,
	  12, 0, 0 },
	{ "mul dword [ebx]: 0x80000000 * 2", { 0xf7, 0x23 }, 2, { 0x80000000, 0, 0x5a5a5a5a }, 2,
	  0x00000000, 0x00000001, 1 },
	{ "mul dword [ebx]: 0x10000 * 0xffff", { 0xf7, 0x23 }, 2, { 0x10000, 0, 0x5a5a5a5a }, 0xffff,
	  0xffff0000, 0x00000000, 0 },

	/* F7 /5, IMUL r/m32: EDX:EAX <- EAX * r/m32 */
	{ "imul ecx: -1 * 1", { 0xf7, 0xe9 }, 2, { 0xffffffff, 1, 0x5a5a5a5a }, 0,
	  0xffffffff, 0xffffffff, 0 },
	{ "imul ecx: 0x7fffffff * 2", { 0xf7, 0xe9 }, 2, { 0x7fffffff, 2, 0x5a5a5a5a }, 0,
	  0xfffffffe, 0x00000000, 1 },
	{ "imul ecx: -2 * 3", { 0xf7, 0xe9 }, 2, { 0xfffffffe, 3, 0x5a5a5a5a }, 0,
	  0xfffffffa, 0xffffffff, 0 },
	{ "imul ecx: -0x80000000 * -0x80000000", { 0xf7, 0xe9 }, 2, { 0x80000000, 0x80000000, 0x5a5a5a5a }, 0,
	  0x00000000, 0x40000000, 1 },
	{ "imul ecx: 0x7fffffff * 1", { 0xf7, 0xe9 }, 2, { 0x7fffffff, 1, 0x5a5a5a5a }, 0,
	  0x7fffffff, 0x00000000, 0 },
	{ "imul dword [ebx]: -0x10000 * 0x10000", { 0xf7, 0x2b }, 2, { 0xffff0000, 0, 0x5a5a5a5a }, 0x10000,
	  0x00000000, 0xffffffff, 1 },

	/* 66 F7 /4, MUL r/m16: DX:AX <- AX * r/m16 */
	{ "mul cx: 0xffff * 0xffff", { 0x66, 0xf7, 0xe1 }, 3, { 0xaaaaffff, 0xbbbbffff, 0xcccc0000 }, 0,
	  0xaaaa0001, 0xccccfffe, 1 },
	{ "mul cx: 0x100 * 0x100", { 0x66, 0xf7, 0xe1 }, 3, { 0xaaaa0100, 0xbbbb0100, 0xcccc1234 }, 0,
	  0xaaaa0000, 0xcccc0001, 1 },
	{ "mul cx: 3 * 4", { 0x66, 0xf7, 0xe1 }, 3, { 0xaaaa0003, 0xbbbb0004, 0xcccc1234 }, 0,
	  0xaaaa000c, 0xcccc0000, 0 },
	{ "mul word [ebx]: 0x8000 * 2", { 0x66, 0xf7, 0x23 }, 3, { 0xaaaa8000, 0, 0xcccc1234 }, 2,
	  0xaaaa0000, 0xcccc0001, 1 },

	/* 66 F7 /5, IMUL r/m16: DX:AX <- AX * r/m16 */
	{ "imul cx: -1 * 1", { 0x66, 0xf7, 0xe9 }, 3, { 0xaaaaffff, 0xbbbb0001, 0xcccc1234 }, 0,
	  0xaaaaffff, 0xccccffff, 0 },
	{ "imul cx: -0x8000 * -0x8000", { 0x66, 0xf7, 0xe9 }, 3, { 0xaaaa8000, 0xbbbb8000, 0xcccc1234 }, 0,
	  0xaaaa0000, 0xcccc4000, 1 },
	{ "imul cx: 0x4000 * 2", { 0x66, 0xf7, 0xe9 }, 3, { 0xaaaa4000, 0xbbbb0002, 0xcccc1234 }, 0,
	  0xaaaa8000, 0xcccc0000, 1 },
	{ "imul cx: 0x3fff * 2", { 0x66, 0xf7, 0xe9 }, 3, { 0xaaaa3fff, 0xbbbb0002, 0xcccc1234 }, 0,
	  0xaaaa7ffe, 0xcccc0000, 0 },

	/* F6 /4, MUL r/m8: AX <- AL * r/m8 */
	{ "mul cl: 0xff * 0xff", { 0xf6, 0xe1 }, 2, { 0xaaaabbff, 0xbbbbbbff, 0x5a5a5a5a }, 0,
	  0xaaaafe01, 0x5a5a5a5a, 1 },
	{ "mul cl: 0x80 * 2", { 0xf6, 0xe1 }, 2, { 0xaaaabb80, 0xbbbbbb02, 0x5a5a5a5a }, 0,
	  0xaaaa0100, 0x5a5a5a5a, 1 },
	{ "mul cl: 3 * 4", { 0xf6, 0xe1 }, 2, { 0xaaaabb03, 0xbbbbbb04, 0x5a5a5a5a }, 0,
	  0xaaaa000c, 0x5a5a5a5a, 0 },

	/* F6 /5, IMUL r/m8: AX <- AL * r/m8 */
	{ "imul cl: -1 * 1", { 0xf6, 0xe9 }, 2, { 0xaaaabbff, 0xbbbbbb01, 0x5a5a5a5a }, 0,
	  0xaaaaffff, 0x5a5a5a5a, 0 },
	{ "imul cl: 0x40 * 2", { 0xf6, 0xe9 }, 2, { 0xaaaabb40, 0xbbbbbb02, 0x5a5a5a5a }, 0,
	  0xaaaa0080, 0x5a5a5a5a, 1 },
	{ "imul cl: -0x80 * -0x80", { 0xf6, 0xe9 }, 2, { 0xaaaabb80, 0xbbbbbb80, 0x5a5a5a5a }, 0,
	  0xaaaa4000, 0x5a5a5a5a, 1 },
	{ "imul cl: -0x40 * 2", { 0xf6, 0xe9 }, 2, { 0xaaaabbc0, 0xbbbbbb02, 0x5a5a5a5a }, 0,
	  0xaaaaff80, 0x5a5a5a5a, 0 },
	{ "imul byte [ebx]: 0x7f * 0x7f", { 0xf6, 0x2b }, 2, { 0xaaaabb7f, 0, 0x5a5a5a5a }, 0x7f,
	  0xaaaa3f01, 0x5a5a5a5a, 1 },

	/* 6B /r ib, IMUL r32, r/m32, imm8 */
	{ "imul eax, ecx, 0x10: 0x12345", { 0x6b, 0xc1, 0x10 }, 3, { 0x5a5a5a5a, 0x12345, 0x5a5a5a5a }, 0,
	  0x00123450, 0x5a5a5a5a, 0 },
	{ "imul eax, ecx, 0x10: 0x10000000", { 0x6b, 0xc1, 0x10 }, 3, { 0x5a5a5a5a, 0x10000000, 0x5a5a5a5a }, 0,
	  0x00000000, 0x5a5a5a5a, 1 },
	{ "imul eax, ecx, 0x10: 0x08000000", { 0x6b, 0xc1, 0x10 }, 3, { 0x5a5a5a5a, 0x08000000, 0x5a5a5a5a }, 0,
	  0x80000000, 0x5a5a5a5a, 1 },
	{ "imul eax, ecx, 0x10: 0x07ffffff", { 0x6b, 0xc1, 0x10 }, 3, { 0x5a5a5a5a, 0x07ffffff, 0x5a5a5a5a }, 0,
	  0x7ffffff0, 0x5a5a5a5a, 0 },
	{ "imul eax, ecx, -1: 0x7fffffff", { 0x6b, 0xc1, 0xff }, 3, { 0x5a5a5a5a, 0x7fffffff, 0x5a5a5a5a }, 0,
	  0x80000001, 0x5a5a5a5a, 0 },
	{ "imul eax, ecx, -1: -0x80000000", { 0x6b, 0xc1, 0xff }, 3, { 0x5a5a5a5a, 0x80000000, 0x5a5a5a5a }, 0,
	  0x80000000, 0x5a5a5a5a, 1 },
	{ "imul eax, [ebx], 0x10: 0x10000000", { 0x6b, 0x03, 0x10 }, 3, { 0x5a5a5a5a, 0, 0x5a5a5a5a }, 0x10000000,
	  0x00000000, 0x5a5a5a5a, 1 },
	{ "imul eax, [ebx], 0x10: -3", { 0x6b, 0x03, 0x10 }, 3, { 0x5a5a5a5a, 0, 0x5a5a5a5a }, 0xfffffffd,
	  0xffffffd0, 0x5a5a5a5a, 0 },

	/* 66 6B /r ib, IMUL r16, r/m16, imm8 */
	{ "imul ax, cx, 0x10: 0x1000", { 0x66, 0x6b, 0xc1, 0x10 }, 4, { 0xaaaa1234, 0xbbbb1000, 0x5a5a5a5a }, 0,
	  0xaaaa0000, 0x5a5a5a5a, 1 },
	{ "imul ax, cx, 0x10: 0x100", { 0x66, 0x6b, 0xc1, 0x10 }, 4, { 0xaaaa1234, 0xbbbb0100, 0x5a5a5a5a }, 0,
	  0xaaaa1000, 0x5a5a5a5a, 0 },
	{ "imul ax, cx, -1: -1", { 0x66, 0x6b, 0xc1, 0xff }, 4, { 0xaaaa1234, 0xbbbbffff, 0x5a5a5a5a }, 0,
	  0xaaaa0001, 0x5a5a5a5a, 0 },
	{ "imul ax, cx, -1: -0x8000", { 0x66, 0x6b, 0xc1, 0xff }, 4, { 0xaaaa1234, 0xbbbb8000, 0x5a5a5a5a }, 0,
	  0xaaaa8000, 0x5a5a5a5a, 1 },
	{ "imul ax, [ebx], 0x10: 0x800", { 0x66, 0x6b, 0x03, 0x10 }, 4, { 0xaaaa1234, 0, 0x5a5a5a5a }, 0x800,
	  0xaaaa8000, 0x5a5a5a5a, 1 },
};

/* 0F AF (r <- r * r/m) and 69 (r <- r/m * imm): EAX/AX is the destination,
 * ECX/CX or the operand at DATA the source */
struct call_case {
	const char *name;
	int32_t (*fn)(struct emu_cpu *, struct emu_cpu_instruction *);
	int opsize16;
	int memory;
	uint32_t imm;
	struct regs in;
	uint32_t mem;
	uint32_t eax;
	int cf;
};

static const struct call_case call_cases[] = {
	{ "imul eax, ecx (0f af): 0x12345 * 0x10", instr_imul_0f_af, 0, 0, 0,
	  { 0x12345, 0x10, 0x5a5a5a5a }, 0, 0x00123450, 0 },
	{ "imul eax, ecx (0f af): 0x10000 * 0x10000", instr_imul_0f_af, 0, 0, 0,
	  { 0x10000, 0x10000, 0x5a5a5a5a }, 0, 0x00000000, 1 },
	{ "imul eax, ecx (0f af): 0x10000 * 2", instr_imul_0f_af, 0, 0, 0,
	  { 0x10000, 2, 0x5a5a5a5a }, 0, 0x00020000, 0 },
	{ "imul eax, ecx (0f af): -1 * -1", instr_imul_0f_af, 0, 0, 0,
	  { 0xffffffff, 0xffffffff, 0x5a5a5a5a }, 0, 0x00000001, 0 },
	{ "imul eax, [ebx] (0f af): 0x40000000 * 2", instr_imul_0f_af, 0, 1, 0,
	  { 0x40000000, 0, 0x5a5a5a5a }, 2, 0x80000000, 1 },
	{ "imul ax, cx (66 0f af): 0x100 * 0x100", instr_imul_0f_af, 1, 0, 0,
	  { 0xaaaa0100, 0xbbbb0100, 0x5a5a5a5a }, 0, 0xaaaa0000, 1 },
	{ "imul ax, cx (66 0f af): 0x100 * 0x10", instr_imul_0f_af, 1, 0, 0,
	  { 0xaaaa0100, 0xbbbb0010, 0x5a5a5a5a }, 0, 0xaaaa1000, 0 },
	{ "imul ax, [ebx] (66 0f af): -0x100 * 0x80", instr_imul_0f_af, 1, 1, 0,
	  { 0xaaaaff00, 0, 0x5a5a5a5a }, 0x80, 0xaaaa8000, 0 },
	{ "imul eax, ecx, 0x10000 (69): 0x10000", instr_imul_69, 0, 0, 0x10000,
	  { 0x5a5a5a5a, 0x10000, 0x5a5a5a5a }, 0, 0x00000000, 1 },
	{ "imul eax, ecx, -5 (69): 3", instr_imul_69, 0, 0, 0xfffffffb,
	  { 0x5a5a5a5a, 3, 0x5a5a5a5a }, 0, 0xfffffff1, 0 },
	{ "imul eax, [ebx], 0x7fffffff (69): -1", instr_imul_69, 0, 1, 0x7fffffff,
	  { 0x5a5a5a5a, 0, 0x5a5a5a5a }, 0xffffffff, 0x80000001, 0 },
	{ "imul ax, cx, 0x100 (66 69): 0x100", instr_imul_69, 1, 0, 0x100,
	  { 0xaaaa1234, 0xbbbb0100, 0x5a5a5a5a }, 0, 0xaaaa0000, 1 },
	{ "imul ax, cx, -2 (66 69): 0x3fff", instr_imul_69, 1, 0, 0xfffe,
	  { 0xaaaa1234, 0xbbbb3fff, 0x5a5a5a5a }, 0, 0xaaaa8002, 0 },
	{ "imul ax, [ebx], 3 (66 69): 0x3000", instr_imul_69, 1, 1, 3,
	  { 0xaaaa1234, 0, 0x5a5a5a5a }, 0x3000, 0xaaaa9000, 1 },
};

static int failures;

static struct emu *setup(const struct regs *in, uint32_t mem, uint32_t eflags)
{
	struct emu *e = emu_new();
	if( e == NULL )
	{
		fprintf(stderr, "emu_new failed\n");
		exit(1);
	}
	struct emu_cpu *cpu = emu_cpu_get(e);
	emu_memory_write_dword(emu_memory_get(e), DATA, mem);
	emu_cpu_reg32_set(cpu, eax, in->eax);
	emu_cpu_reg32_set(cpu, ecx, in->ecx);
	emu_cpu_reg32_set(cpu, edx, in->edx);
	emu_cpu_reg32_set(cpu, ebx, DATA);
	emu_cpu_eflags_set(cpu, eflags);
	return e;
}

static void check(const char *name, struct emu *e, uint32_t eflags, uint32_t want_eax, uint32_t want_edx, int want_cf)
{
	struct emu_cpu *cpu = emu_cpu_get(e);
	uint32_t r_eax = emu_cpu_reg32_get(cpu, eax);
	uint32_t r_edx = emu_cpu_reg32_get(cpu, edx);
	uint32_t r_ebx = emu_cpu_reg32_get(cpu, ebx);
	int cf = CPU_FLAG_ISSET(cpu, f_cf) ? 1 : 0;
	int of = CPU_FLAG_ISSET(cpu, f_of) ? 1 : 0;
	int ok = r_eax == want_eax && r_edx == want_edx && r_ebx == DATA && cf == want_cf && of == want_cf;
	printf("%s %-44s flags before %s: EDX:EAX %08x:%08x CF %d OF %d",
	       ok ? "ok  " : "FAIL", name, eflags ? "set  " : "clear", r_edx, r_eax, cf, of);
	if( !ok )
	{
		printf(", want %08x:%08x CF %d OF %d", want_edx, want_eax, want_cf, want_cf);
		failures++;
	}
	printf("\n");
}

static const uint32_t flag_states[] = { 0, (1u << f_cf) | (1u << f_of) };

static void run_bytes(const struct bytes_case *t)
{
	for( size_t f = 0; f < sizeof(flag_states) / sizeof(flag_states[0]); f++ )
	{
		struct emu *e = setup(&t->in, t->mem, flag_states[f]);
		struct emu_cpu *cpu = emu_cpu_get(e);
		emu_memory_write_block(emu_memory_get(e), CODE, (void *)t->code, t->len);
		emu_cpu_eip_set(cpu, CODE);
		if( emu_cpu_parse(cpu) != 0 || emu_cpu_step(cpu) != 0 )
		{
			printf("FAIL %-44s: the CPU stopped: %s\n", t->name, emu_strerror(e));
			failures++;
		} else if( emu_cpu_eip_get(cpu) != CODE + (uint32_t)t->len )
		{
			printf("FAIL %-44s: EIP 0x%08x after the instruction\n", t->name, emu_cpu_eip_get(cpu));
			failures++;
		} else
		{
			check(t->name, e, flag_states[f], t->eax, t->edx, t->cf);
		}
		emu_free(e);
	}
}

static void run_call(const struct call_case *t)
{
	for( size_t f = 0; f < sizeof(flag_states) / sizeof(flag_states[0]); f++ )
	{
		struct emu *e = setup(&t->in, t->mem, flag_states[f]);
		struct emu_cpu *cpu = emu_cpu_get(e);
		struct emu_cpu_instruction i;
		memset(&i, 0, sizeof(i));
		uint16_t imm16 = (uint16_t)t->imm;
		uint8_t imm8 = (uint8_t)t->imm;
		i.prefixes = t->opsize16 ? PREFIX_OPSIZE : 0;
		i.modrm.mod = t->memory ? 0 : 3;
		i.modrm.opc = 0; /* eax / ax */
		i.modrm.rm = 1;  /* ecx / cx */
		i.modrm.ea = DATA;
		i.imm = t->imm;
		i.imm16 = &imm16;
		i.imm8 = &imm8;
		if( t->fn(cpu, &i) != 0 )
		{
			printf("FAIL %-44s: the function failed: %s\n", t->name, emu_strerror(e));
			failures++;
		} else
		{
			check(t->name, e, flag_states[f], t->eax, t->in.edx, t->cf);
		}
		emu_free(e);
	}
}

int main(void)
{
	for( size_t n = 0; n < sizeof(bytes_cases) / sizeof(bytes_cases[0]); n++ )
		run_bytes(&bytes_cases[n]);
	for( size_t n = 0; n < sizeof(call_cases) / sizeof(call_cases[0]); n++ )
		run_call(&call_cases[n]);

	if( failures )
	{
		printf("%d checks failed\n", failures);
		return 1;
	}
	printf("all MUL and IMUL checks passed\n");
	return 0;
}
