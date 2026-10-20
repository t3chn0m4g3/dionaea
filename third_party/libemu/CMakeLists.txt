# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

# CMake build of the bundled libemu (buffer/libemu bf443cb), used instead of
# its autotools build: configure.ac forces clang, overwrites CFLAGS, calls an
# undefined AC_DEFINE_DIR and builds with -Werror. Only the library is built,
# as a static library with -fPIC so it can be linked into the dionaea emu
# module; the Python 2 bindings, tools/sctest and the testsuite programs are
# not part of it.
#
# The sources include "../config.h" (config.h next to this file); the only
# thing the autotools build put there that matters is DEBUG, which stays
# undefined (see config.h).

cmake_minimum_required(VERSION 3.10...3.31 FATAL_ERROR)

if(NOT CMAKE_PROJECT_NAME)
  project(libemu LANGUAGES C)
endif()

set(
  LIBEMU_SRCS
  src/emu.c
  src/emu_log.c
  src/emu_memory.c
  src/emu_cpu_data.c
  src/emu_cpu.c
  src/emu_string.c
  src/emu_getpc.c
  src/emu_graph.c
  src/emu_hashtable.c
  src/emu_list.c
  src/emu_queue.c
  src/emu_stack.c
  src/emu_shellcode.c
  src/emu_source.c
  src/emu_track.c
  src/emu_breakpoint.c
  src/libdasm.c
  src/functions/aaa.c
  src/functions/adc.c
  src/functions/add.c
  src/functions/and.c
  src/functions/call.c
  src/functions/cmp.c
  src/functions/cmps.c
  src/functions/dec.c
  src/functions/div.c
  src/functions/group_1.c
  src/functions/group_2.c
  src/functions/group_3.c
  src/functions/group_4.c
  src/functions/group_5.c
  src/functions/group_10.c
  src/functions/idiv.c
  src/functions/imul.c
  src/functions/inc.c
  src/functions/int.c
  src/functions/jcc.c
  src/functions/jmp.c
  src/functions/lodscc.c
  src/functions/loopcc.c
  src/functions/misc.c
  src/functions/mov.c
  src/functions/movsx.c
  src/functions/movzx.c
  src/functions/mul.c
  src/functions/neg.c
  src/functions/not.c
  src/functions/or.c
  src/functions/pop.c
  src/functions/push.c
  src/functions/rcl.c
  src/functions/rcr.c
  src/functions/repcc.c
  src/functions/ret.c
  src/functions/rol.c
  src/functions/ror.c
  src/functions/sal.c
  src/functions/sar.c
  src/functions/sbb.c
  src/functions/scas.c
  src/functions/shr.c
  src/functions/stoscc.c
  src/functions/sub.c
  src/functions/test.c
  src/functions/xchg.c
  src/functions/xor.c
  src/environment/emu_env.c
  src/environment/emu_profile.c
  src/environment/win32/emu_env_w32.c
  src/environment/win32/emu_env_w32_synthetic.c
  src/environment/win32/emu_env_w32_dll.c
  src/environment/win32/emu_env_w32_dll_export.c
  src/environment/win32/env_w32_dll_export_kernel32_hooks.c
  src/environment/win32/env_w32_dll_export_urlmon_hooks.c
  src/environment/win32/env_w32_dll_export_ws2_32_hooks.c
  src/environment/win32/env_w32_dll_export_msvcrt_hooks.c
  src/environment/win32/env_w32_dll_export_shell32_hooks.c
  src/environment/win32/env_w32_dll_export_shdocvw_hooks.c
  src/environment/linux/emu_env_linux.c
  src/environment/linux/env_linux_syscall_hooks.c
)

add_library(emu STATIC ${LIBEMU_SRCS})

target_include_directories(
  emu
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(emu PRIVATE _GNU_SOURCE)

set_target_properties(
  emu PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  C_STANDARD 99
  C_EXTENSIONS ON
)

# The code is from 2007-2012 and punns types freely, so keep the optimizer
# away from strict aliasing. No -Werror and no warnings at all (-w): the
# warnings of a vendored library are not ours to fix. The emulator is CPU
# bound, so build it optimized even when the rest of dionaea is a Debug build
# (-O2 comes after the flags of the build type and replaces its -O level).
target_compile_options(
  emu
  PRIVATE
    -O2
    -fno-strict-aliasing
    -w
)
