# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

# Unit test of the bundled libemu, built with -DDIONAEA_BUILD_TESTS=ON and run
# with ctest (see the libemu-test stage of the Dockerfile).
#
# With -DCMAKE_C_FLAGS="-fsanitize=address,undefined" the test runs under
# AddressSanitizer without DLL-array suppressions.

add_executable(test_libemu test_libemu.c)
target_link_libraries(test_libemu PRIVATE emu)
target_compile_definitions(test_libemu PRIVATE _GNU_SOURCE)

add_test(NAME libemu COMMAND test_libemu)
set_tests_properties(
  libemu PROPERTIES
  ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1;UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1"
)

add_executable(test_synthetic_pe test_synthetic_pe.c)
target_link_libraries(test_synthetic_pe PRIVATE emu)
target_compile_definitions(test_synthetic_pe PRIVATE _GNU_SOURCE)
add_test(NAME synthetic_pe COMMAND test_synthetic_pe)
set_tests_properties(synthetic_pe PROPERTIES
  ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1;UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")

add_executable(test_mul test_mul.c)
target_link_libraries(test_mul PRIVATE emu)
target_compile_definitions(test_mul PRIVATE _GNU_SOURCE)
add_test(NAME mul COMMAND test_mul)
set_tests_properties(mul PROPERTIES
  ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1;UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")

# calloc is wrapped to make the copy of a hook fail
add_executable(test_w32_hooks test_w32_hooks.c)
target_link_libraries(test_w32_hooks PRIVATE emu)
target_link_options(test_w32_hooks PRIVATE -Wl,--wrap=calloc)
target_compile_definitions(test_w32_hooks PRIVATE _GNU_SOURCE)
add_test(NAME w32_hooks COMMAND test_w32_hooks)
set_tests_properties(w32_hooks PROPERTIES
  ENVIRONMENT "ASAN_OPTIONS=detect_leaks=1;UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1")
