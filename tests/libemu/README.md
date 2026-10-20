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

- UBSan runs without `shift` and `signed-integer-overflow`: the emulated x86
  instructions are written with C shifts and signed arithmetic (about 100
  reports in a run), which is the emulator's job and works on GCC and clang.
