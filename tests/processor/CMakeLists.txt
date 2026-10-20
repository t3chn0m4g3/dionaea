# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

# Unit tests of the stream processing (bistream, processor jobs, threadpool
# admission, emu detection windows), built with -DDIONAEA_BUILD_TESTS=ON and
# run with ctest (see the processor-test stage of the Dockerfile).
#
# -DCMAKE_C_FLAGS="-fsanitize=address,undefined" or "-fsanitize=thread" run
# them under the sanitizers; with ThreadSanitizer glib_tsan.h makes the GLib
# mutexes and conditions of the code under test visible to it.

set(PROCESSOR_TEST_ENV
  "ASAN_OPTIONS=detect_leaks=1"
  "UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1"
  "TSAN_OPTIONS=halt_on_error=1:second_deadlock_stack=1"
)

set(PROCESSOR_TEST_INCLUDES ../../include ${CMAKE_BINARY_DIR} ${GLIB2_INCLUDE_DIRS})

if(CMAKE_C_FLAGS MATCHES "-fsanitize=thread")
  set(PROCESSOR_TEST_SUPPORT glib_tsan.c)
  add_compile_options(-include ${CMAKE_CURRENT_SOURCE_DIR}/glib_tsan.h)
else()
  set(PROCESSOR_TEST_SUPPORT "")
endif()

add_executable(test_bistream test_bistream.c ../../src/bistream.c ${PROCESSOR_TEST_SUPPORT})
target_include_directories(test_bistream PRIVATE ${PROCESSOR_TEST_INCLUDES})
target_link_libraries(test_bistream PRIVATE ${GLIB2_LIBRARIES})
add_test(NAME bistream COMMAND test_bistream)

add_executable(test_processor test_processor.c stubs.c stubs_tempfile.c ../../src/processor.c
               ../../src/streamcap.c ../../src/threads.c ../../src/bistream.c
               ../../src/refcount.c ${PROCESSOR_TEST_SUPPORT})
target_include_directories(test_processor PRIVATE ${PROCESSOR_TEST_INCLUDES})
# g_thread_pool_push is wrapped to inject enqueue failures
target_link_options(test_processor PRIVATE -Wl,--wrap=g_thread_pool_push)
target_link_libraries(test_processor PRIVATE ${GLIB2_LIBRARIES} EV::EV)
add_test(NAME processor COMMAND test_processor)

# the streamdumper and its limits with the temp files of util.c; close and fclose are wrapped
# to catch a second close of a descriptor, fstatat and readdir to count the reads of the
# counting thread and to slow them down
add_executable(test_streamdumper test_streamdumper.c stubs.c ../../src/processor.c
               ../../src/streamcap.c ../../src/util.c ../../src/threads.c ../../src/bistream.c
               ../../src/refcount.c ${PROCESSOR_TEST_SUPPORT})
target_include_directories(test_streamdumper PRIVATE ${PROCESSOR_TEST_INCLUDES})
target_link_options(test_streamdumper PRIVATE -Wl,--wrap=close -Wl,--wrap=fclose
                    -Wl,--wrap=fstatat -Wl,--wrap=readdir)
target_link_libraries(test_streamdumper PRIVATE ${GLIB2_LIBRARIES} EV::EV)
add_test(NAME streamdumper COMMAND test_streamdumper)

# connection_listen() of the core: the sources of dionaea without dionaea.c (the test has
# g_dionaea); listen, close, accept and the bind of the privileged child are wrapped
set(DIONAEA_CORE_SOURCES
  ../../src/bistream.c ../../src/connection.c ../../src/connection_dtls.c ../../src/connection_tcp.c
  ../../src/connection_tls.c ../../src/connection_udp.c ../../src/dns.c ../../src/incident.c
  ../../src/log.c ../../src/modules.c ../../src/node_info.c ../../src/pchild.c ../../src/processor.c
  ../../src/refcount.c ../../src/signals.c ../../src/streamcap.c ../../src/ssl.c ../../src/threads.c
  ../../src/util.c ../../src/download_log.c ../../src/log_text.c)
add_executable(test_connection_listen test_connection_listen.c ${DIONAEA_CORE_SOURCES} ${PROCESSOR_TEST_SUPPORT})
# no local of connection.c hides another (the errno of a failed listen() was named as the GError)
set_source_files_properties(../../src/connection.c PROPERTIES COMPILE_OPTIONS "-Werror=shadow")
target_include_directories(test_connection_listen PRIVATE ${PROCESSOR_TEST_INCLUDES} ../..
                           ${GMODULE2_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})
# the core uses the OpenSSL 1.x API (DH, RSA) and GLib's g_pattern_match
target_compile_options(test_connection_listen PRIVATE -Wno-deprecated-declarations)
target_link_options(test_connection_listen PRIVATE -Wl,--wrap=listen -Wl,--wrap=close -Wl,--wrap=accept
                    -Wl,--wrap=pchild_sent_bind)
target_link_libraries(test_connection_listen PRIVATE ${GLIB2_LIBRARIES} ${GMODULE2_LIBRARIES}
                      ${OPENSSL_LIBRARIES} EV::EV UDNS::UDNS)
add_test(NAME connection_listen COMMAND test_connection_listen)

# the buffering of the log files (src/log.c)
add_executable(test_log test_log.c ../../src/log.c ${PROCESSOR_TEST_SUPPORT})
target_include_directories(test_log PRIVATE ${PROCESSOR_TEST_INCLUDES})
target_link_libraries(test_log PRIVATE ${GLIB2_LIBRARIES} EV::EV)
add_test(NAME log COMMAND test_log)

# the log lines of downloads that do not complete (src/download_log.c)
add_executable(test_download_log test_download_log.c ../../src/download_log.c ../../src/log_text.c ${PROCESSOR_TEST_SUPPORT})
target_include_directories(test_download_log PRIVATE ${PROCESSOR_TEST_INCLUDES})
target_link_libraries(test_download_log PRIVATE ${GLIB2_LIBRARIES} EV::EV)
add_test(NAME download_log COMMAND test_download_log)

set(PROCESSOR_TESTS bistream processor streamdumper connection_listen log download_log)

if(WITH_MODULE_EMU AND DIONAEA_BUNDLED_LIBEMU)
  if(CMAKE_C_FLAGS MATCHES "-fsanitize=[^ ]*undefined")
    # the known shifts and signed overflows of libemu (see the libemu-test
    # stage of the Dockerfile); the code under test is checked in full
    target_compile_options(emu PRIVATE -fno-sanitize=shift,signed-integer-overflow)
  endif()
  add_executable(test_detect test_detect.c stubs.c stubs_tempfile.c ../../modules/emu/detect.c
                 ../../modules/emu/trim.c ../../src/processor.c ../../src/streamcap.c ../../src/threads.c ../../src/bistream.c
                 ../../src/refcount.c ${PROCESSOR_TEST_SUPPORT})
  target_include_directories(test_detect PRIVATE ${PROCESSOR_TEST_INCLUDES} ../../modules/emu)
  # emu_shellcode_test is wrapped to record the scanned windows, malloc_trim to count the trims,
  # g_thread_try_new to make the thread of the trailing trim fail
  target_link_options(test_detect PRIVATE -Wl,--wrap=emu_shellcode_test -Wl,--wrap=malloc_trim
                      -Wl,--wrap=g_thread_try_new)
  target_link_libraries(test_detect PRIVATE emu ${GLIB2_LIBRARIES} EV::EV)
  add_test(NAME detect COMMAND test_detect)
  list(APPEND PROCESSOR_TESTS detect)

  # the file hooks of the emulation without a temp file, and with the real temp files of util.c
  # and emulate_ctx_free of emulate.c (stubs for the rest of dionaea); tempdownload_new is wrapped
  # to make it fail
  add_executable(test_emu_hooks test_emu_hooks.c ../../modules/emu/hooks.c ../../modules/emu/emulate.c
                 ../../src/util.c ${PROCESSOR_TEST_SUPPORT})
  target_include_directories(test_emu_hooks PRIVATE ${PROCESSOR_TEST_INCLUDES} ../../modules/emu)
  target_link_options(test_emu_hooks PRIVATE -Wl,--wrap=tempdownload_new)
  target_link_libraries(test_emu_hooks PRIVATE emu ${GLIB2_LIBRARIES} EV::EV)
  add_test(NAME emu_hooks COMMAND test_emu_hooks)
  list(APPEND PROCESSOR_TESTS emu_hooks)
endif()

if(WITH_MODULE_CURL AND CURL_FOUND)
  # the download and upload sessions of the curl module without a temp file
  add_executable(test_curl_session test_curl_session.c ../../src/log_text.c ${PROCESSOR_TEST_SUPPORT})
  target_include_directories(test_curl_session PRIVATE ${PROCESSOR_TEST_INCLUDES} ../../src ${CURL_INCLUDE_DIRS})
  # the module uses the form API of curl
  target_compile_options(test_curl_session PRIVATE -Wno-deprecated-declarations)
  target_link_libraries(test_curl_session PRIVATE ${CURL_LIBRARIES} ${GLIB2_LIBRARIES} EV::EV)
  add_test(NAME curl_session COMMAND test_curl_session)
  list(APPEND PROCESSOR_TESTS curl_session)
endif()

set_tests_properties(${PROCESSOR_TESTS} PROPERTIES ENVIRONMENT "${PROCESSOR_TEST_ENV}" TIMEOUT 600)
