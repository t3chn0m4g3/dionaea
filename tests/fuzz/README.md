<!--
SPDX-FileCopyrightText: none
SPDX-License-Identifier: CC0-1.0
-->

# Fuzz targets

The parsers that read the bytes of a client, as fuzz targets: C with libFuzzer,
AddressSanitizer and UndefinedBehaviorSanitizer, Python with atheris. They are
not part of the image or of the normal build; `tests/fuzz/Dockerfile` has the
environments of both.

A failing input is an input that makes a target fail: a sanitizer report, a check of
the target, an error that escapes the function the caller hands the bytes to
(for a service: `handle_io_in`, whose errors the binding logs with their
traceback before it closes the connection), a run longer than `-timeout` or
memory above `-rss_limit_mb`. An error the caller catches on purpose is none (the `ValueError` of the multipart parser
above `max_num_fields`, the `MalformedMessage` of MongoDB). Every failing input gets a
regression test under `tests/processor`, `tests/libemu` or
`tests/functional/unit`, which fails without its fix.

## Targets

| Target | Code | What the target checks |
|---|---|---|
| `c/fuzz_bistream.c` | `src/bistream.c` | operations of the input on two bistreams against a model of the stored bytes: every copy, the chunks, the limits, the budget of the process |
| `c/fuzz_processor.c` | `src/processor.c`, `src/streamcap.c` | the processors of T-Pot's `dionaea.cfg` for four connections, reads up to 6 MiB: a threaded reader behind `unicode` gets every byte, every dump is the literal of its stream, the folder keeps `max_size` / `max_files` |
| `c/fuzz_profile.c` | `modules/emu/profile.c`, `emu_profile_argument_add_bytea` | profiles of the shapes the libemu hooks record: the JSON is valid UTF-8 and JSON, every string decodes to what the profile holds |
| `c/fuzz_shellcode.c` | `third_party/libemu`, `emu_shellcode_test` | the scan of one window (at most 64 KiB) |
| `python/fuzz_smb.py` | `smb/smb.py`, `smb2.py`, `ntlm.py`, `rpcservices.py`, `smb/include` | a client stream in reads through `smbd.handle_io_in`: SMB1 and SMB2, NTLMSSP, DCERPC; the buffer below one message, the limits of a connection, print jobs within `max_upload_size` |
| `python/fuzz_mqtt.py` | `mqtt/mqtt.py`, `mqtt/include/packets.py` | the framing of `handle_io_in`, the packet classes, `publish_fields`, `subscribe_fields`, `suback` |
| `python/fuzz_mongo.py` | `mongo/mongo.py` with the bson of the image | the framing and `_parse` of OP_QUERY and OP_COMMAND |
| `python/fuzz_http_multipart.py` | `http.py`, `iter_uploaded_files` | a body and the body repeated to 256 KiB, the files are slices of the body |
| `python/fuzz_emu_scripts.py` | `emu_scripts/handler.py` | a file and the file repeated to 256 KiB: no error |

`python/standins.py` stands in for the C binding (`dionaea.core`) as
`binding.pyx` behaves where the services can tell: `send` takes `str` or
`bytes`, an incident takes an `int` that fits a C `long` and a `str` that is
valid UTF-8, and the log handler of `dionaea/log.py` formats every record at
DEBUG without catching an error.

## C targets

    docker build --target c -t dionaea-fuzz-c tests/fuzz
    mkdir -p build-fuzz
    docker run --rm -v "$PWD":/src:ro -v "$PWD/build-fuzz":/out dionaea-fuzz-c /src/tests/fuzz/c/build.sh
    docker run --rm -v "$PWD":/src:ro -v "$PWD/build-fuzz":/out dionaea-fuzz-c \
      /src/tests/fuzz/c/run.sh bistream 1800 /out

`build.sh` builds the bundled libemu with the flags of the targets (without the
`shift` and `signed-integer-overflow` checks of UBSan, as the libemu-test stage
of the `Dockerfile`) and the four targets. `run.sh TARGET SECONDS OUT` runs one
target with one fuzzing process (`-fork=1`, a failing input does not end the run),
`-rss_limit_mb=2048 -timeout=5`; the corpus grows in `OUT/corpus/TARGET`,
failing inputs go to `OUT/artifacts/TARGET`. Reproduce and minimize a failing input with:

    docker run --rm -v "$PWD":/src:ro -v "$PWD/build-fuzz":/out dionaea-fuzz-c \
      /out/fuzz_processor /out/artifacts/processor/<artifact>
    docker run --rm -v "$PWD":/src:ro -v "$PWD/build-fuzz":/out dionaea-fuzz-c \
      /out/fuzz_processor -minimize_crash=1 -runs=20000 /out/artifacts/processor/<artifact>

## Python targets

atheris 3.0.0 runs on Python 3.6 to 3.12, not on the 3.14 of the image, so the
Python targets run on Python 3.12 (`python:3.12-slim-trixie`) with the bson of
the image (pymongo 4.16.0). The sources under test run unchanged on 3.12.

    docker build --target python -t dionaea-fuzz-py tests/fuzz
    docker run --rm -v "$PWD":/src:ro -v "$PWD/build-fuzz":/out dionaea-fuzz-py \
      /src/tests/fuzz/python/run.sh smb 1800 /out

`run.sh TARGET SECONDS OUT` runs `fuzz_TARGET.py` with its dictionary
(`TARGET.dict`), `-rss_limit_mb=2048 -timeout=5 -max_len=65536`. With
`FUZZ_FAILURES` (run.sh sets `OUT/failures/TARGET`) an error is written once per
place (the input and its traceback) and the run goes on; without it the error is
raised, which is how a failing input is reproduced:

    docker run --rm -v "$PWD":/src:ro -v "$PWD/build-fuzz":/out dionaea-fuzz-py \
      python3 /src/tests/fuzz/python/fuzz_mqtt.py /out/failures/mqtt/<artifact>.input

`replay.py TARGET FILE_OR_FOLDER...` runs inputs once through a target without
atheris, also on the Python 3.14 of the image (a failing input of the 3.12 run
is checked there before it counts):

    python3 tests/fuzz/python/replay.py mqtt build-fuzz/failures/mqtt/<artifact>.input

The input of `smb`, `mqtt` and `mongo` is a byte n (modulo 9), n cut points of
3 bytes and the stream: the reads end at the cut points, and what
`handle_io_in` does not take comes again in front of the next read, as the
binding does.

## Coverage

C: `COVERAGE=1 build.sh` builds the targets for llvm-cov (no sanitizers); a
corpus replays with `-runs=0`:

    docker run --rm -e COVERAGE=1 -v "$PWD":/src:ro -v "$PWD/build-cov":/out dionaea-fuzz-c /src/tests/fuzz/c/build.sh
    docker run --rm -v "$PWD":/src:ro -v "$PWD/build-cov":/out -v "$PWD/build-fuzz":/fuzz dionaea-fuzz-c sh -c \
      'LLVM_PROFILE_FILE=/tmp/p.profraw /out/fuzz_bistream -runs=0 /fuzz/corpus/bistream;
       llvm-profdata merge -sparse /tmp/p.profraw -o /tmp/p.profdata;
       llvm-cov report /out/fuzz_bistream -instr-profile=/tmp/p.profdata /src/src/bistream.c'

Python: coverage.py over `replay.py`:

    python3 -m coverage run --include='modules/python/dionaea/*' tests/fuzz/python/replay.py smb build-fuzz/corpus/smb
    python3 -m coverage report

## Seeds

`corpus/TARGET/` holds the seeds, a few hundred bytes each, from the fixtures
and test packets of the tests; `corpus/make_seeds.py` writes them. Three SMB
seeds are sessions of impacket 0.12.0 against the SMB stand-in (see
`make_seeds.py`). A run copies the seeds into its own corpus outside the
repository.
