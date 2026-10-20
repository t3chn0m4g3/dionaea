<!--
SPDX-FileCopyrightText: 2026 T-Pot contributors
SPDX-License-Identifier: CC0-1.0
-->

# Bundled libemu provenance

The emulator is derived from buffer/libemu revision bf443cb. Its existing
copyright notices and GPL-2.0-or-later licensing are retained. Local changes
include the CMake build, memory/error fixes and synthetic Windows export models.
The prefix map of `emu_cpu.c` is a constant table shared by the emu workers.

libdasm (src/libdasm.c, libdasm.h, opcode_tables.h) is libdasm 1.4 by jt / nologin.org with small local edits. Its README declares it public domain ('You can do whatever you like with it'). The later BSD-2-Clause licence of libdasm 1.6 does not apply to this copy. The files are combined with GPL-2.0-or-later libemu.

The original eleven files under `src/environment/win32/dlls/` contained Windows
DLL byte excerpts. They are excluded from this source tree. The runtime builds
PE32 headers and export tables in `emu_env_w32_synthetic.c`, using the public
PE format and numeric API metadata. It contains no Windows function bodies or
DOS stub copied from those DLLs. Existing export names, RVAs and hooks come from
libemu's interface tables. Public ordinal numbers are retained where the old
export metadata was complete. For shdocvw, IEWinMain keeps ordinal 101 and the
other names receive deterministic synthetic ordinals.

The models support name and ordinal API resolution for emulation. They are not
Windows DLL replacements and do not reproduce original header or code bytes.
Shellcode that depends on such bytes can behave differently.

Future vendor updates must not bring back the files of
`src/environment/win32/dlls/`.

This describes the technical changes and source provenance. It is not a legal
clearance of the project or its dependencies.
