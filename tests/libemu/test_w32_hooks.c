/**
 * This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 */

/*
 * The hooks of the bundled libemu that copy a buffer of the emulated program
 * (src/environment/win32/*_hooks.c), with a profile as dionaea's profile run
 * makes it (modules/emu/profile.c): msvcrt fwrite, kernel32 WriteFile and
 * _lwrite, ws2_32 send, sendto and recv.
 *
 *  - fwrite and WriteFile copy at most 1 MiB per call. size * count of
 *    fwrite is computed in 64 bits. A longer write writes nothing: fwrite
 *    returns 0, WriteFile returns 0 with 0 bytes written, and the profile
 *    holds an empty byte argument.
 *  - send copies at most 64 KiB; a longer one returns -1 with an empty byte
 *    argument.
 *  - recv gives the emulated program at most 4096 bytes and writes no more
 *    than that into its buffer.
 *  - When the copy can not be allocated (calloc is wrapped with
 *    -Wl,--wrap=calloc), the call returns its error value and the emulated
 *    program goes on at its return address.
 *
 * Every call checks EAX, EIP (the return address) and ESP (cdecl for fwrite,
 * stdcall for the others). One case runs alone when its name is the
 * argument.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <emu/emu.h>
#include <emu/emu_cpu.h>
#include <emu/emu_memory.h>
#include <emu/environment/emu_env.h>
#include <emu/environment/emu_profile.h>
#include <emu/environment/win32/emu_env_w32.h>
#include <emu/environment/win32/emu_env_w32_dll.h>
#include <emu/environment/win32/emu_env_w32_dll_export.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL %s line %d: %s\n", current, __LINE__, #x); exit(1); } } while (0)

#define RET   0x00123456
#define STACK 0x00200000
#define DATA  0x00300000
#define MIB   (1024u * 1024u)

static const char *current = "";

/* ---- calloc of the hooks: when armed, the first one of at least NOMEM_SIZE
 * bytes fails (the copy of a NOMEM_SIZE write; the profile allocates less) ---- */

#define NOMEM_SIZE 0x1000

void *__real_calloc(size_t nmemb, size_t size);

static bool calloc_fail;

void *__wrap_calloc(size_t nmemb, size_t size)
{
	if( calloc_fail && size != 0 && nmemb >= NOMEM_SIZE / size )
	{
		calloc_fail = false;
		return NULL;
	}
	return __real_calloc(nmemb, size);
}

/* ---- an emulation with a profile, msvcrt and ws2_32 loaded ---- */

struct run
{
	struct emu *e;
	struct emu_env *env;
};

static struct run start(void)
{
	struct run r;
	r.e = emu_new();
	CHECK(r.e != NULL);
	r.env = emu_env_new(r.e);
	CHECK(r.env != NULL);
	r.env->profile = emu_profile_new();
	CHECK(emu_env_w32_load_dll(r.env->env.win, "msvcrt.dll") == 0);
	CHECK(emu_env_w32_load_dll(r.env->env.win, "ws2_32.dll") == 0);
	return r;
}

static void stop(struct run *r)
{
	emu_env_free(r->env);
	emu_free(r->e);
}

static uint32_t api(struct emu_env *env, const char *dllname, const char *fnname)
{
	for( int i = 0; env->env.win->loaded_dlls[i]; i++ )
	{
		struct emu_env_w32_dll *dll = env->env.win->loaded_dlls[i];
		if( strcmp(dll->dllname, dllname) != 0 )
			continue;
		for( int j = 0; dll->exportx[j].fnname; j++ )
			if( strcmp(dll->exportx[j].fnname, fnname) == 0 )
				return dll->baseaddr + dll->exportx[j].virtualaddr;
	}
	CHECK(0);
	return 0;
}

/* calls dllname!fnname with the arguments on the stack, returns EAX */
static uint32_t call(struct run *r, const char *dllname, const char *fnname, const uint32_t *args, int nargs,
                     uint32_t esp_after)
{
	struct emu_cpu *cpu = emu_cpu_get(r->e);
	struct emu_memory *mem = emu_memory_get(r->e);
	CHECK(emu_memory_write_dword(mem, STACK, RET) == 0);
	for( int i = 0; i < nargs; i++ )
		CHECK(emu_memory_write_dword(mem, STACK + 4 + 4 * i, args[i]) == 0);
	emu_cpu_reg32_set(cpu, esp, STACK);
	emu_cpu_reg32_set(cpu, eax, 0xdeadbeef);
	emu_cpu_eip_set(cpu, api(r->env, dllname, fnname));
	CHECK(emu_env_w32_eip_check(r->env) != NULL);
	CHECK(emu_cpu_eip_get(cpu) == RET);
	CHECK(emu_cpu_reg32_get(cpu, esp) == esp_after);
	return emu_cpu_reg32_get(cpu, eax);
}

/* the byte argument of the last call in the profile, NULL if it has none */
static struct emu_profile_argument *bytea(struct run *r, const char *fnname)
{
	struct emu_profile_function *f = emu_profile_functions_last(r->env->profile->functions);
	if( emu_profile_functions_istail(f) || strcmp(f->fnname, fnname) != 0 )
		return NULL;
	for( struct emu_profile_argument *a = emu_profile_arguments_first(f->arguments);
	     !emu_profile_arguments_istail(a); a = emu_profile_arguments_next(a) )
	{
		struct emu_profile_argument *b = a->render == render_ptr ? a->value.tptr.ptr : a;
		if( b != NULL && b->render == render_bytea )
			return b;
	}
	return NULL;
}

static size_t profiled_calls(struct run *r)
{
	size_t n = 0;
	for( struct emu_profile_function *f = emu_profile_functions_first(r->env->profile->functions);
	     !emu_profile_functions_istail(f); f = emu_profile_functions_next(f) )
		n++;
	return n;
}

/* DATA holds len bytes i * 7 + 1 */
static void fill(struct run *r, uint32_t len)
{
	unsigned char *buf = malloc(len);
	CHECK(buf != NULL);
	for( uint32_t i = 0; i < len; i++ )
		buf[i] = (unsigned char)(i * 7 + 1);
	CHECK(emu_memory_write_block(emu_memory_get(r->e), DATA, buf, len) == 0);
	free(buf);
}

static bool is_fill(const unsigned char *data, uint32_t len)
{
	for( uint32_t i = 0; i < len; i++ )
		if( data[i] != (unsigned char)(i * 7 + 1) )
			return false;
	return true;
}

static uint32_t dword_at(struct run *r, uint32_t addr)
{
	uint32_t v;
	CHECK(emu_memory_read_dword(emu_memory_get(r->e), addr, &v) == 0);
	return v;
}

/* ---- msvcrt fwrite(buffer, size, count, stream), cdecl ---- */

static void fwrite_case(uint32_t size, uint32_t count, uint32_t want_eax, uint32_t want_bytes)
{
	struct run r = start();
	fill(&r, 4096);
	uint32_t args[] = { DATA, size, count, 0x1234 };
	CHECK(call(&r, "msvcrt", "fwrite", args, 4, STACK + 4) == want_eax);
	struct emu_profile_argument *b = bytea(&r, "fwrite");
	CHECK(b != NULL);
	CHECK(b->value.bytea.size == want_bytes);
	CHECK(is_fill(b->value.bytea.data, want_bytes < 4096 ? want_bytes : 4096));
	stop(&r);
}

static void test_fwrite_small(void)       { fwrite_case(16, 4, 0x40, 0x40); }
static void test_fwrite_one_mib(void)     { fwrite_case(1, MIB, MIB, MIB); }
static void test_fwrite_over_one_mib(void) { fwrite_case(1, MIB + 1, 0, 0); }
static void test_fwrite_256_mib(void)     { fwrite_case(0x01000000, 0x10, 0, 0); }
static void test_fwrite_4_gib(void)       { fwrite_case(0xffffffff, 1, 0, 0); }
static void test_fwrite_wraps_32_bits(void) { fwrite_case(0x10000, 0x10000, 0, 0); }
static void test_fwrite_count_zero(void)  { fwrite_case(0x10, 0, 0, 0); }

static void test_fwrite_no_memory(void)
{
	struct run r = start();
	fill(&r, 4096);
	uint32_t args[] = { DATA, 1, NOMEM_SIZE, 0x1234 };
	calloc_fail = true;
	CHECK(call(&r, "msvcrt", "fwrite", args, 4, STACK + 4) == 0);
	CHECK(!calloc_fail);
	CHECK(profiled_calls(&r) == 0);
	stop(&r);
}

/* ---- kernel32 WriteFile(file, buffer, n, written, overlapped), stdcall ---- */

#define WRITTEN (STACK + 0x100)

static void writefile_case(uint32_t n, uint32_t want_eax, uint32_t want_bytes)
{
	struct run r = start();
	fill(&r, 4096);
	CHECK(emu_memory_write_dword(emu_memory_get(r.e), WRITTEN, 0x5a5a5a5a) == 0);
	uint32_t args[] = { 0x4711, DATA, n, WRITTEN, 0 };
	CHECK(call(&r, "kernel32", "WriteFile", args, 5, STACK + 4 + 5 * 4) == want_eax);
	CHECK(dword_at(&r, WRITTEN) == want_bytes);
	struct emu_profile_argument *b = bytea(&r, "WriteFile");
	CHECK(b != NULL);
	CHECK(b->value.bytea.size == want_bytes);
	CHECK(is_fill(b->value.bytea.data, want_bytes < 4096 ? want_bytes : 4096));
	stop(&r);
}

static void test_writefile_small(void)        { writefile_case(0x40, 1, 0x40); }
static void test_writefile_one_mib(void)      { writefile_case(MIB, 1, MIB); }
static void test_writefile_over_one_mib(void) { writefile_case(MIB + 1, 0, 0); }
static void test_writefile_16_mib(void)       { writefile_case(0x01000000, 0, 0); }
static void test_writefile_4_gib(void)        { writefile_case(0xffffffff, 0, 0); }

static void test_writefile_no_memory(void)
{
	struct run r = start();
	fill(&r, 4096);
	CHECK(emu_memory_write_dword(emu_memory_get(r.e), WRITTEN, 0x5a5a5a5a) == 0);
	uint32_t args[] = { 0x4711, DATA, NOMEM_SIZE, WRITTEN, 0 };
	calloc_fail = true;
	CHECK(call(&r, "kernel32", "WriteFile", args, 5, STACK + 4 + 5 * 4) == 0);
	CHECK(!calloc_fail);
	CHECK(dword_at(&r, WRITTEN) == 0);
	CHECK(profiled_calls(&r) == 0);
	stop(&r);
}

/* ---- kernel32 _lwrite(file, buffer, n), stdcall: below 1 MiB ---- */

static void test_lwrite_small(void)
{
	struct run r = start();
	fill(&r, 4096);
	uint32_t args[] = { 0x4711, DATA, 0x40 };
	CHECK(call(&r, "kernel32", "_lwrite", args, 3, STACK + 4 + 3 * 4) == 0x40);
	struct emu_profile_argument *b = bytea(&r, "_lwrite");
	CHECK(b != NULL && b->value.bytea.size == 0x40 && is_fill(b->value.bytea.data, 0x40));
	stop(&r);
}

static void test_lwrite_4_gib(void)
{
	struct run r = start();
	uint32_t args[] = { 0x4711, DATA, 0xffffffff };
	CHECK(call(&r, "kernel32", "_lwrite", args, 3, STACK + 4 + 3 * 4) == 0xffffffff);
	struct emu_profile_argument *b = bytea(&r, "_lwrite");
	CHECK(b != NULL && b->value.bytea.size == 0);
	stop(&r);
}

static void test_lwrite_no_memory(void)
{
	struct run r = start();
	fill(&r, 4096);
	uint32_t args[] = { 0x4711, DATA, NOMEM_SIZE };
	calloc_fail = true;
	CHECK(call(&r, "kernel32", "_lwrite", args, 3, STACK + 4 + 3 * 4) == 0xffffffff);
	CHECK(!calloc_fail);
	struct emu_profile_argument *b = bytea(&r, "_lwrite");
	CHECK(b != NULL && b->value.bytea.size == 0);
	stop(&r);
}

/* ---- ws2_32 send(s, buffer, n, flags), stdcall: at most 64 KiB ---- */

static void send_case(uint32_t n, uint32_t want_eax, uint32_t want_bytes)
{
	struct run r = start();
	fill(&r, 4096);
	uint32_t args[] = { 0x77, DATA, n, 0 };
	CHECK(call(&r, "ws2_32", "send", args, 4, STACK + 4 + 4 * 4) == want_eax);
	struct emu_profile_argument *b = bytea(&r, "send");
	CHECK(b != NULL);
	CHECK(b->value.bytea.size == want_bytes);
	CHECK(is_fill(b->value.bytea.data, want_bytes < 4096 ? want_bytes : 4096));
	stop(&r);
}

static void test_send_small(void)      { send_case(0x40, 0x40, 0x40); }
static void test_send_64_kib(void)     { send_case(0x10000, 0x10000, 0x10000); }
static void test_send_over_64_kib(void) { send_case(0x10001, 0xffffffff, 0); }
static void test_send_4_gib(void)      { send_case(0xffffffff, 0xffffffff, 0); }

static void test_send_no_memory(void)
{
	struct run r = start();
	fill(&r, 4096);
	uint32_t args[] = { 0x77, DATA, NOMEM_SIZE, 0 };
	calloc_fail = true;
	CHECK(call(&r, "ws2_32", "send", args, 4, STACK + 4 + 4 * 4) == 0xffffffff);
	CHECK(!calloc_fail);
	struct emu_profile_argument *b = bytea(&r, "send");
	CHECK(b != NULL && b->value.bytea.size == 0);
	stop(&r);
}

/* ---- ws2_32 sendto(s, buffer, n, flags, to, tolen), stdcall ---- */

static void test_sendto_small(void)
{
	struct run r = start();
	fill(&r, 4096);
	uint32_t args[] = { 0x77, DATA, 0x40, 0, DATA, 16 };
	CHECK(call(&r, "ws2_32", "sendto", args, 6, STACK + 4 + 6 * 4) == 0x40);
	stop(&r);
}

static void test_sendto_no_memory(void)
{
	struct run r = start();
	fill(&r, 4096);
	uint32_t args[] = { 0x77, DATA, NOMEM_SIZE, 0, DATA, 16 };
	calloc_fail = true;
	CHECK(call(&r, "ws2_32", "sendto", args, 6, STACK + 4 + 6 * 4) == 0xffffffff);
	CHECK(!calloc_fail);
	stop(&r);
}

/* ---- ws2_32 recv(s, buffer, n, flags), stdcall: at most 4096 bytes ---- */

static uint32_t recv_hook(struct emu_env *env, struct emu_env_hook *hook, ...)
{
	(void)env;
	(void)hook;
	va_list vl;
	va_start(vl, hook);
	(void)va_arg(vl, int);                 /* s */
	char *buffer = va_arg(vl, char *);
	int len = va_arg(vl, int);
	va_end(vl);
	memset(buffer, 'R', len);
	return len;
}

static void recv_case(uint32_t n, uint32_t want)
{
	struct run r = start();
	CHECK(emu_env_w32_export_hook(r.env, "recv", recv_hook, NULL) == 0);
	unsigned char before[8192];
	memset(before, 'Z', sizeof(before));
	CHECK(emu_memory_write_block(emu_memory_get(r.e), DATA, before, sizeof(before)) == 0);
	uint32_t args[] = { 0x77, DATA, n, 0 };
	CHECK(call(&r, "ws2_32", "recv", args, 4, STACK + 4 + 4 * 4) == want);
	unsigned char after[8192];
	CHECK(emu_memory_read_block(emu_memory_get(r.e), DATA, after, sizeof(after)) == 0);
	for( uint32_t i = 0; i < sizeof(after); i++ )
		CHECK(after[i] == (i < want ? 'R' : 'Z'));
	stop(&r);
}

static void test_recv_small(void)     { recv_case(100, 100); }
static void test_recv_4096(void)      { recv_case(4096, 4096); }
static void test_recv_64_kib(void)    { recv_case(0x10000, 4096); }

static void test_recv_no_memory(void)
{
	struct run r = start();
	CHECK(emu_env_w32_export_hook(r.env, "recv", recv_hook, NULL) == 0);
	uint32_t args[] = { 0x77, DATA, NOMEM_SIZE, 0 };
	calloc_fail = true;
	CHECK(call(&r, "ws2_32", "recv", args, 4, STACK + 4 + 4 * 4) == 0xffffffff);
	CHECK(!calloc_fail);
	stop(&r);
}

/* ---- */

static const struct
{
	const char *name;
	void (*fn)(void);
} cases[] = {
#define CASE(x) { #x, test_##x }
	CASE(fwrite_small),
	CASE(fwrite_one_mib),
	CASE(fwrite_over_one_mib),
	CASE(fwrite_256_mib),
	CASE(fwrite_4_gib),
	CASE(fwrite_wraps_32_bits),
	CASE(fwrite_count_zero),
	CASE(fwrite_no_memory),
	CASE(writefile_small),
	CASE(writefile_one_mib),
	CASE(writefile_over_one_mib),
	CASE(writefile_16_mib),
	CASE(writefile_4_gib),
	CASE(writefile_no_memory),
	CASE(lwrite_small),
	CASE(lwrite_4_gib),
	CASE(lwrite_no_memory),
	CASE(send_small),
	CASE(send_64_kib),
	CASE(send_over_64_kib),
	CASE(send_4_gib),
	CASE(send_no_memory),
	CASE(sendto_small),
	CASE(sendto_no_memory),
	CASE(recv_small),
	CASE(recv_4096),
	CASE(recv_64_kib),
	CASE(recv_no_memory),
#undef CASE
};

int main(int argc, char **argv)
{
	int ran = 0;
	for( size_t n = 0; n < sizeof(cases) / sizeof(cases[0]); n++ )
	{
		if( argc > 1 && strcmp(argv[1], cases[n].name) != 0 )
			continue;
		current = cases[n].name;
		cases[n].fn();
		printf("ok   %s\n", cases[n].name);
		ran++;
	}
	if( ran == 0 )
	{
		fprintf(stderr, "no case %s\n", argc > 1 ? argv[1] : "");
		return 1;
	}
	return 0;
}
