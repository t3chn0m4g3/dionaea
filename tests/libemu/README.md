<!--
SPDX-FileCopyrightText: none
SPDX-License-Identifier: CC0-1.0
-->

# libemu unit test

`test_libemu.c` tests the bundled libemu (`third_party/libemu`) through the
function the emu module calls on every stream, `emu_shellcode_test()`:

- known shellcode samples (`third_party/libemu/testsuite/instrtree.c` and an
  FPU GetPC variant) are found,
- data without GetPC (nop sled, HTTP request, empty buffer) is not,
- every 1-byte buffer, 300 random buffers and 100 random buffers with a GetPC
  sample inside are handled,
- one `emu` can test several buffers in a row (the tracking reset).

It is built with `-DDIONAEA_BUILD_TESTS=ON` (default OFF, the release build is
unchanged) and run by ctest. The `libemu-test` stage of the `Dockerfile` does
both in the builder image:

    docker build --target libemu-test .

With AddressSanitizer, UndefinedBehaviorSanitizer and LeakSanitizer:

    docker build --target libemu-test \
      --build-arg LIBEMU_TEST_CFLAGS="-fsanitize=address,undefined -fno-sanitize=shift,signed-integer-overflow -fno-omit-frame-pointer" .

`test_synthetic_pe.c` loads all eleven independently generated PE32 models,
checks their sorted export tables, API RVAs and ordinals, and exercises
GetProcAddress, LoadLibrary and repeated load/free cycles. Invalid metadata and
unknown APIs are rejected. No Windows DLL byte images or ASan suppressions are
used.

`test_mul.c` runs MUL and IMUL (F6, F7 and 6B, 8, 16 and 32 bits, register
and memory operands) as instruction bytes through `emu_cpu_parse` and
`emu_cpu_step`, and calls the IMUL forms 0F AF and 69, which the CPU does not
dispatch, with a decoded instruction. Each case checks EAX and EDX in full and
CF and OF, with both flags clear and set before. mul.c and imul.c compute no
product that overflows its C type, so the test also passes with
`-fsanitize=signed-integer-overflow` on them.

`test_rotate.c` runs ROL, ROR, RCL and RCR (D0 to D3, C0 and C1: by 1, by CL
and by an immediate; 8, 16 and 32 bits) on AL, AX and EAX and on memory, with
every count from 0 to 31 and some above, CF clear and set and the other flags
clear and set before. It checks the result in full against the rotation of
x86 and the flags as the Intel SDM gives them: none for a masked count of 0, CF
otherwise, OF for a masked count of 1, SF, ZF, AF and PF never (OF of a larger
count is undefined and not checked). The rotations shift in 64 bits by less
than 64; the test build turns the shift checks off for all of libemu, see below.

`test_w32_hooks.c` calls the hooks that copy a buffer of the emulated program
with a profile, as dionaea's profile run does: fwrite, WriteFile and _lwrite (at
most 1 MiB per call), send and sendto (at most 64 KiB) and recv
(at most 4096 bytes and no more than the hook returned, without output). It checks EAX, EIP, ESP, the bytes written and the byte
argument of the profile; with `-Wl,--wrap=calloc` it makes the copy fail. The
byte arguments of one profile hold at most 8 MiB in all: 12 fwrite calls of
1 MiB record 8 of 1 MiB and 4 of 0 bytes and return 1 MiB each.
`./test_w32_hooks <case>` runs one case.

- UBSan runs without `shift` and `signed-integer-overflow`: the emulated x86
  instructions are written with C shifts and signed arithmetic (about 100
  reports in a run), which is the emulator's job and works on GCC and clang.
