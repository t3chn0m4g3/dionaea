/*
 * SPDX-FileCopyrightText: none
 *
 * SPDX-License-Identifier: CC0-1.0
 */

/*
 * Replaces the config.h that libemu's configure script generated. The CMake
 * build in CMakeLists.txt is its only user.
 *
 * The sources only ask for DEBUG (extra instruction dump code in emu_cpu.c,
 * which costs CPU for nothing in a honeypot). configure.ac defaults it to on;
 * here it stays off. The HAVE_* values configure also found (stdint.h,
 * strdup, ...) are not used by any file under src/ or include/.
 */

#ifndef LIBEMU_CONFIG_H
#define LIBEMU_CONFIG_H

/* #undef DEBUG */

#endif /* LIBEMU_CONFIG_H */
