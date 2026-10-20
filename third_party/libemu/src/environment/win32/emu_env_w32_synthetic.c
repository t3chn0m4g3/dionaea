/* SPDX-FileCopyrightText: 2026 T-Pot contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* Independently constructed PE32 emulation data. No Windows DLL bytes are used.
 * Format: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
 * Only public API names, RVAs and ordinal numbers from libemu's export metadata
 * are used. API calls are intercepted by libemu's existing hooks; this image
 * supplies no implementation of Windows functions.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "emu/emu_memory.h"
#include "emu/environment/win32/emu_env_w32_dll.h"
#include "emu/environment/win32/emu_env_w32_dll_export.h"
#include "emu/environment/win32/emu_env_w32_synthetic.h"

static void le16(uint8_t *p, uint16_t value)
{
    p[0] = value;
    p[1] = value >> 8;
}

static void le32(uint8_t *p, uint32_t value)
{
    le16(p, value);
    le16(p + 2, value >> 16);
}

static uint32_t get32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static int by_name(const void *a, const void *b)
{
    const struct emu_env_w32_dll_export *const *left = a;
    const struct emu_env_w32_dll_export *const *right = b;
    return strcmp((*left)->fnname, (*right)->fnname);
}

int emu_env_w32_map_synthetic_dll(struct emu_memory *memory,
                                 const struct emu_env_w32_known_dll *dll)
{
    if (memory == NULL || dll == NULL || dll->dllname == NULL || dll->exports == NULL ||
        dll->imagesize < 0x1000 || (uint64_t)dll->baseaddress + dll->imagesize > UINT64_C(0x100000000))
        return -1;
    size_t count = 0;
    size_t strings = strnlen(dll->dllname, 64);
    if (strings == 64)
        return -1;
    strings += 5; /* .dll and terminator */
    uint32_t max_rva = 0xfff, max_ordinal = 0;
    for (; dll->exports[count].fnname != NULL; count++) {
        const struct emu_env_w32_dll_export *ex = &dll->exports[count];
        size_t len = strnlen(ex->fnname, 256);
        if (count >= UINT16_MAX || len == 256 || len == 0 || ex->ordinal == 0 ||
            ex->ordinal > UINT16_MAX || ex->virtualaddr == 0 || ex->virtualaddr >= dll->imagesize)
            return -1;
        strings += len + 1;
        if (ex->virtualaddr > max_rva)
            max_rva = ex->virtualaddr;
        if (ex->ordinal > max_ordinal)
            max_ordinal = ex->ordinal;
    }
    if (count == 0)
        return -1;
    uint64_t rva64 = ((uint64_t)max_rva + 0x1000) & ~UINT64_C(0xfff);
    uint64_t length64 = 40 + (uint64_t)max_ordinal * 4 + (uint64_t)count * 6 + strings;
    uint64_t section_size = (length64 + 0xfff) & ~UINT64_C(0xfff);
    if (rva64 + section_size > dll->imagesize)
        return -1;
    uint32_t rva = rva64, length = length64;
    uint8_t *data = calloc(1, length);
    const struct emu_env_w32_dll_export **names = malloc(count * sizeof(*names));
    if (data == NULL || names == NULL) {
        free(data);
        free(names);
        return -1;
    }
    for (size_t i = 0; i < count; i++)
        names[i] = &dll->exports[i];
    qsort(names, count, sizeof(*names), by_name);
    uint32_t eat = 40, npt = eat + max_ordinal * 4, ot = npt + count * 4;
    uint32_t cursor = ot + count * 2;
    le32(data + 12, rva + cursor);
    size_t dll_len = strlen(dll->dllname);
    memcpy(data + cursor, dll->dllname, dll_len);
    memcpy(data + cursor + dll_len, ".dll", 5);
    cursor += dll_len + 5;
    le32(data + 16, 1); /* OrdinalBase */
    le32(data + 20, max_ordinal);
    le32(data + 24, count);
    le32(data + 28, rva + eat);
    le32(data + 32, rva + npt);
    le32(data + 36, rva + ot);
    int result = -1;
    for (size_t i = 0; i < count; i++) {
        const struct emu_env_w32_dll_export *ex = names[i];
        uint8_t *slot = data + eat + (ex->ordinal - 1) * 4;
        uint32_t previous = get32(slot);
        if ((i && strcmp(names[i-1]->fnname, ex->fnname) == 0) ||
            (previous && previous != ex->virtualaddr))
            goto out;
        le32(slot, ex->virtualaddr);
        le32(data + npt + i * 4, rva + cursor);
        le16(data + ot + i * 2, ex->ordinal - 1);
        size_t len = strlen(ex->fnname) + 1;
        memcpy(data + cursor, ex->fnname, len);
        cursor += len;
    }
    uint8_t header[0x200] = {0};
    le16(header, 0x5a4d); /* MZ */
    le32(header + 0x3c, 0x80);
    le32(header + 0x80, 0x4550); /* PE signature */
    le16(header + 0x84, 0x14c); /* i386 */
    le16(header + 0x86, 1);
    le16(header + 0x94, 0xe0);
    le16(header + 0x96, 0x2102); /* executable, 32 bit, DLL */
    uint8_t *optional = header + 0x98;
    le16(optional, 0x10b); /* PE32 */
    le32(optional + 8, section_size);
    le32(optional + 28, dll->baseaddress);
    le32(optional + 32, 0x1000); /* section alignment */
    le32(optional + 36, 0x200); /* file alignment */
    le32(optional + 56, dll->imagesize);
    le32(optional + 60, sizeof(header));
    le16(optional + 68, 3); /* console subsystem */
    le32(optional + 92, 16);
    le32(optional + 96, rva);
    le32(optional + 100, length);
    uint8_t *section = header + 0x178;
    memcpy(section, ".edata", 6);
    le32(section + 8, section_size);
    le32(section + 12, rva);
    le32(section + 16, (length + 0x1ff) & ~0x1ff);
    le32(section + 20, sizeof(header));
    le32(section + 36, 0x40000040); /* initialized data, readable */
    if (emu_memory_write_block(memory, dll->baseaddress, header, sizeof(header)) < 0 ||
        emu_memory_write_block(memory, dll->baseaddress + rva, data, length) < 0)
        goto out;
    result = 0;
out:
    free(names);
    free(data);
    return result;
}
