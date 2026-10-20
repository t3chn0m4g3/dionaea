/* SPDX-FileCopyrightText: 2026 T-Pot contributors
 * SPDX-License-Identifier: CC0-1.0
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <emu/emu.h>
#include <emu/emu_cpu.h>
#include <emu/emu_memory.h>
#include <emu/environment/emu_env.h>
#include <emu/environment/win32/emu_env_w32.h>
#include <emu/environment/win32/emu_env_w32_dll.h>
#include <emu/environment/win32/emu_env_w32_dll_export.h>
#include <emu/environment/win32/emu_env_w32_synthetic.h>

extern struct emu_env_w32_known_dll known_dlls[];
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)
static uint32_t dword(struct emu_memory *m, uint32_t p)
{
    uint32_t value;
    CHECK(emu_memory_read_dword(m, p, &value) == 0);
    return value;
}
static uint16_t word(struct emu_memory *m, uint32_t p)
{
    uint16_t value;
    CHECK(emu_memory_read_word(m, p, &value) == 0);
    return value;
}
static void text(struct emu_memory *m, uint32_t p, char *out)
{
    for (size_t i = 0; i < 256; i++) {
        CHECK(emu_memory_read_byte(m, p+i, (uint8_t *)&out[i]) == 0);
        if (!out[i]) return;
    }
    CHECK(0);
}
static size_t loaded(struct emu_env *env)
{
    size_t n = 0;
    while (env->env.win->loaded_dlls[n]) n++;
    return n;
}
static struct emu_env_w32_dll *find(struct emu_env *env, const char *name)
{
    for (size_t i = 0; i < loaded(env); i++)
        if (!strcmp(env->env.win->loaded_dlls[i]->dllname, name))
            return env->env.win->loaded_dlls[i];
    CHECK(0);
    return NULL;
}
static struct emu_env_w32_dll_export *export(struct emu_env_w32_dll *dll, const char *name)
{
    for (size_t i = 0; dll->exportx[i].fnname; i++)
        if (!strcmp(dll->exportx[i].fnname, name)) return &dll->exportx[i];
    CHECK(0);
    return NULL;
}
static uint32_t call(struct emu_env *env, const char *api, uint32_t a, uint32_t b)
{
    struct emu_cpu *cpu = emu_cpu_get(env->emu);
    struct emu_memory *mem = emu_memory_get(env->emu);
    struct emu_env_w32_dll *kernel = find(env, "kernel32");
    CHECK(emu_memory_write_dword(mem, 0x200000, 0x123456) == 0);
    CHECK(emu_memory_write_dword(mem, 0x200004, a) == 0);
    CHECK(emu_memory_write_dword(mem, 0x200008, b) == 0);
    emu_cpu_reg32_set(cpu, esp, 0x200000);
    emu_cpu_reg32_set(cpu, eax, 0xdeadbeef);
    emu_cpu_eip_set(cpu, kernel->baseaddr + export(kernel, api)->virtualaddr);
    CHECK(emu_env_w32_eip_check(env) != NULL);
    CHECK(emu_cpu_eip_get(cpu) == 0x123456);
    return emu_cpu_reg32_get(cpu, eax);
}
int main(void)
{
    for (int round = 0; round < 3; round++) {
        struct emu *e = emu_new();
        CHECK(e != NULL);
        struct emu_env *env = emu_env_new(e);
        CHECK(env && env->env.win);
        struct emu_memory *mem = emu_memory_get(e);
        for (size_t k = 1; known_dlls[k].dllname; k++) {
            const struct emu_env_w32_known_dll *known = &known_dlls[k];
            CHECK(emu_env_w32_load_dll(env->env.win, (char *)known->dllname) == 0);
            size_t before = loaded(env);
            CHECK(emu_env_w32_load_dll(env->env.win, (char *)known->dllname) == 0);
            CHECK(loaded(env) == before);
            struct emu_env_w32_dll *dll = find(env, known->dllname);
            uint32_t base = dll->baseaddr;
            CHECK(word(mem, base) == 0x5a4d);
            uint32_t pe = base + dword(mem, base + 0x3c);
            CHECK(dword(mem, pe) == 0x4550);
            CHECK(word(mem, pe + 0x18) == 0x10b);
            CHECK(dword(mem, pe + 0x34) == base);
            CHECK(dword(mem, pe + 0x50) == dll->imagesize);
            uint32_t rva = dword(mem, pe + 0x78), bytes = dword(mem, pe + 0x7c);
            CHECK(rva + bytes <= dll->imagesize);
            uint32_t dir = base + rva, eat = base + dword(mem, dir+28);
            uint32_t names = base + dword(mem, dir+32), ords = base + dword(mem, dir+36);
            CHECK(dword(mem, dir+16) == 1);
            uint32_t count = dword(mem, dir+24), actual = 0;
            while (dll->exportx[actual].fnname) actual++;
            CHECK(count == actual);
            char previous[256] = {0};
            for (uint32_t i = 0; i < count; i++) {
                char name[256];
                text(mem, base + dword(mem, names+i*4), name);
                CHECK(!i || strcmp(previous, name) < 0);
                strcpy(previous, name);
                struct emu_env_w32_dll_export *ex = export(dll, name);
                uint16_t index = word(mem, ords+i*2);
                CHECK(index + 1 == ex->ordinal);
                CHECK(index < dword(mem, dir+20));
                CHECK(dword(mem, eat+index*4) == ex->virtualaddr);
                CHECK(ex->virtualaddr < rva); /* never treated as a PE forwarder */
            }
            if (!round) printf("%s: %u sorted exports, API addresses and ordinals verified\n", known->dllname, count);
        }
        CHECK(loaded(env) == 11);
        struct emu_env_w32_dll *kernel = find(env,"kernel32");
        CHECK(emu_memory_write_block(mem, 0x210000, "WinExec", 8) == 0);
        CHECK(call(env,"GetProcAddress",kernel->baseaddr,0x210000) == 0x7c86136d);
        CHECK(call(env,"GetProcAddress",kernel->baseaddr,export(kernel,"WinExec")->ordinal) == 0x7c86136d);
        CHECK(emu_memory_write_block(mem, 0x210000, "NoSuchApi", 10) == 0);
        CHECK(call(env,"GetProcAddress",kernel->baseaddr,0x210000) == 0);
        CHECK(call(env,"GetProcAddress",kernel->baseaddr,0xffff) == 0);
        CHECK(call(env,"GetProcAddress",0xdead0000,1) == 0);
        CHECK(emu_memory_write_block(mem, 0x210000, "URLMON.DLL", 11) == 0);
        CHECK(call(env,"LoadLibraryA",0x210000,0) == find(env,"urlmon")->baseaddr);
        CHECK(call(env,"GetProcAddress",find(env,"ws2_32")->baseaddr,23) == 0x71a13b91);
        CHECK(export(find(env,"shdocvw"),"IEWinMain")->ordinal == 101);
        CHECK(emu_env_w32_load_dll(env->env.win,"not-present.dll") == -1);
        CHECK(emu_env_w32_load_dll(env->env.win,NULL) == -1);
        struct emu_env_w32_known_dll bad = known_dlls[1];
        bad.imagesize = 0x1000;
        CHECK(emu_env_w32_map_synthetic_dll(mem,&bad) == -1);
        bad = known_dlls[1]; bad.baseaddress = 0xfffff000;
        CHECK(emu_env_w32_map_synthetic_dll(mem,&bad) == -1);
        struct emu_env_w32_dll_export invalid[] = {{"invalid",1,NULL,NULL,NULL,0},{0}};
        bad = known_dlls[1]; bad.exports = invalid;
        CHECK(emu_env_w32_map_synthetic_dll(mem,&bad) == -1);
        CHECK(emu_env_w32_map_synthetic_dll(mem,NULL) == -1);
        emu_env_free(env);
        emu_free(e);
    }
    puts("Synthetic DLL load/resolve/free and invalid metadata checks passed");
    return 0;
}
