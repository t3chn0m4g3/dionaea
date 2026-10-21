/* This file is part of the dionaea honeypot
 *
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 *
 * libFuzzer target of the scan of the emu processor (modules/emu/detect.c):
 * emu_shellcode_test() of the bundled libemu on any bytes, at most one scan
 * window (EMU_SCAN_MAX, 64 KiB less one byte). libemu runs at most
 * EMU_SHELLCODE_TEST_MAX_STEPS per candidate; -timeout bounds the scan.
 */
#include <stdint.h>
#include <stdlib.h>

#include <emu/emu.h>
#include <emu/emu_shellcode.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if( size > UINT16_MAX )
		return -1;
	/* libemu takes the buffer as writable; a copy keeps the input intact */
	uint8_t *copy = malloc(size > 0 ? size : 1);
	if( copy == NULL )
		return 0;
	for( size_t i = 0; i < size; i++ )
		copy[i] = data[i];
	struct emu *e = emu_new();
	int32_t found = emu_shellcode_test(e, copy, (uint16_t)size);
	emu_free(e);
	free(copy);
	if( found >= (int32_t)size && size >= 2 )
		abort();
	return 0;
}
