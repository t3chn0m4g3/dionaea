#!/bin/sh
# This file is part of the dionaea honeypot
#
# SPDX-FileCopyrightText: none
#
# SPDX-License-Identifier: CC0-1.0

# Build the C fuzz targets with clang, libFuzzer, ASan and UBSan (see ../README.md):
#   build.sh [SOURCE] [OUT]
# SOURCE is the checkout (default /src), OUT the folder of the build (default /out).
# COVERAGE=1 builds them for llvm-cov instead (source based coverage, no sanitizers),
# to replay a corpus with -runs=0.
set -eu

SRC=${1:-/src}
OUT=${2:-/out}
CC=${CC:-clang}
SANITIZE="-fsanitize=address,undefined -fno-sanitize-recover=undefined"
CFLAGS="-g -O1 -fno-omit-frame-pointer $SANITIZE"
if [ "${COVERAGE:-0}" = 1 ]; then
	CFLAGS="-g -O0 -fprofile-instr-generate -fcoverage-mapping"
fi
HERE="$SRC/tests/fuzz/c"

mkdir -p "$OUT/include"
# what the sources take from the config.h of CMake
cat > "$OUT/include/config.h" <<CONFIG
#ifndef CONFIG_H
#define CONFIG_H
#define DIONAEA_VERSION "fuzz"
#define PREFIX "/opt/dionaea"
#define LOCALSTATEDIR "/opt/dionaea/var"
#define LOCALESTATEDIR "/opt/dionaea/var"
#define DIONAEA_CONFDIR "/opt/dionaea/etc/dionaea"
#define DIONAEA_MODDIR "/opt/dionaea/lib/dionaea"
#define DIONAEA_PYTHON_SITELIBDIR ""
#define DIONAEA_RUNDIR "/opt/dionaea/var/run"
#define PYTHON_PATH "/usr/bin/python3"
#define HAVE_LINUX_SOCKIOS_H 1
#endif
CONFIG

GLIB="$(pkg-config --cflags glib-2.0)"
GLIB_LIBS="$(pkg-config --libs glib-2.0)"
INCLUDES="-I$OUT/include -I$SRC/include -I$SRC -I$HERE $GLIB"

# the bundled libemu, instrumented, without the shift and signed-integer-overflow checks of UBSan
# (as in the libemu-test stage of the Dockerfile); configured once (a second configure of the
# standalone libemu skips its project())
[ -f "$OUT/libemu/CMakeCache.txt" ] || cmake -S "$SRC/third_party/libemu" -B "$OUT/libemu" -DCMAKE_C_COMPILER="$CC" -DCMAKE_BUILD_TYPE=Debug \
	-DCMAKE_C_FLAGS="$CFLAGS -fsanitize=fuzzer-no-link -fno-sanitize=shift,signed-integer-overflow" >/dev/null
cmake --build "$OUT/libemu" -j "$(nproc)" >/dev/null
LIBEMU_INCLUDES="-I$SRC/third_party/libemu/include"
LIBEMU="$(find "$OUT/libemu" -name 'libemu.a' | head -1)"

target() {
	name=$1
	shift
	echo "building $name"
	$CC $CFLAGS -fsanitize=fuzzer "$@" -o "$OUT/$name"
}

target fuzz_bistream $INCLUDES "$HERE/fuzz_bistream.c" "$SRC/src/bistream.c" $GLIB_LIBS

target fuzz_processor $INCLUDES -I"$SRC/tests/processor" "$HERE/fuzz_processor.c" \
	"$SRC/tests/processor/stubs.c" "$SRC/src/processor.c" "$SRC/src/streamcap.c" "$SRC/src/util.c" \
	"$SRC/src/threads.c" "$SRC/src/bistream.c" "$SRC/src/refcount.c" $GLIB_LIBS -lev

target fuzz_profile $INCLUDES $LIBEMU_INCLUDES -I"$SRC/modules/emu" "$HERE/fuzz_profile.c" \
	"$SRC/modules/emu/profile.c" "$LIBEMU" $GLIB_LIBS -lev

target fuzz_shellcode $LIBEMU_INCLUDES "$HERE/fuzz_shellcode.c" "$LIBEMU"
