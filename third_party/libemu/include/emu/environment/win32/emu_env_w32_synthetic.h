/* SPDX-FileCopyrightText: 2026 T-Pot contributors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef EMU_ENV_W32_SYNTHETIC_H
#define EMU_ENV_W32_SYNTHETIC_H

struct emu_memory;
struct emu_env_w32_known_dll;

int emu_env_w32_map_synthetic_dll(struct emu_memory *memory,
                                 const struct emu_env_w32_known_dll *dll);
#endif
