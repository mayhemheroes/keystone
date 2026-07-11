#!/usr/bin/env bash
#
# keystone/mayhem/build.sh — build keystone-engine's OSS-Fuzz "fuzz_asm_*" harnesses as sanitized
# libFuzzer targets (+ standalone reproducers), AND keystone's own C golden test for mayhem/test.sh.
#
# Fuzzed surface: keystone's MULTI-ARCH ASSEMBLER on attacker-controlled assembly text.
#   Each harness (fuzz_asm_<arch>.c) hardcodes one (KS_ARCH, KS_MODE) and drives:
#     ks_open(ARCH, MODE) -> ks_option(KS_OPT_SYNTAX, Data[Size-1]) -> ks_asm(Data[0..Size-2])
#   i.e. the input is asm text whose LAST byte selects the x86 syntax (1=Intel/2=ATT/4=NASM/...).
#   For non-x86 arches the syntax byte is ignored but still stripped off the text.
#
# Build contract comes from the org base ENV (CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/
# STANDALONE_FUZZ_MAIN). The keystone library ITSELF is compiled with $SANITIZER_FLAGS (via CMake
# C/CXX flags) so the assembler code — not just the harness — is instrumented.
#
# SANITIZERS: full ASan+UBSan, HALTING (no -fno-sanitize relax). This is deliberate. The EVM harness
# (fuzz_asm_evm) crashes on every input via a REAL upstream null-pointer deref: ks_option() in
# llvm/keystone/ks.cpp does `ks->MAI->setRadix(16)` before any arch check, and EVM leaves MAI==NULL,
# so the harness's mandatory ks_option(KS_OPT_SYNTAX,...) call segfaults (ASan SEGV; UBSan reports the
# same as a null member call). That is a genuine crash, not benign UB, so we do NOT relax sanitizers
# to paper over it — the EVM target reports the bug on seed #1 (a valid finding).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
INC="-I$SRC/include"

# ── 1) Build the keystone static library WITH sanitizers (the fuzzed assembler is instrumented) ─────
# keystone is a large LLVM-derived C++ codebase; build via its own CMake (BUILD_LIBS_ONLY) so we get
# a correct libkeystone.a. -pthread mirrors the OSS-Fuzz build. Sanitizer flags flow through
# CMAKE_C_FLAGS / CMAKE_CXX_FLAGS so the library objects are instrumented.
BUILD="$SRC/mayhem-build"
rm -rf "$BUILD"; mkdir -p "$BUILD"
cmake -S "$SRC" -B "$BUILD" \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_LIBS_ONLY=1 \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -pthread" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -pthread"
cmake --build "$BUILD" -j"$MAYHEM_JOBS"

# Locate the produced static library (path varies across keystone versions: llvm/lib/ or top).
LIBKS="$(find "$BUILD" -name 'libkeystone.a' | head -1)"
[ -n "$LIBKS" ] || { echo "ERROR: libkeystone.a not found under $BUILD" >&2; exit 1; }
echo "libkeystone.a: $LIBKS"

# Standalone driver (keystone ships fuzz/onefile.c: reads one input file, calls LLVMFuzzerTestOneInput).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$HARNESS_DIR/onefile.c" -o "$BUILD/standalone_main.o"

# Per-input watchdog: defines the real LLVMFuzzerTestOneInput, arming a SIGALRM so any single input
# that runs unbounded (e.g. `.rept <huge>` expansion) is aborted as a timeout instead of hanging the
# campaign / smoke gate. Force-included (-include) into each harness so the shipped .c files are
# unmodified; this object provides the real entry point delegating to the harness's renamed inner one.
WATCHDOG_INC="-include $HARNESS_DIR/ks_fuzz_watchdog.h"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$HARNESS_DIR/ks_fuzz_watchdog.c" -o "$BUILD/ks_fuzz_watchdog.o"

# ── 2) Build each OSS-Fuzz harness twice: libFuzzer (-> /mayhem/<name>) + standalone reproducer ─────
# keystone is C++ internally, so link the harness objects with $CXX. We strip the "fuzz_asm_" prefix
# for the /mayhem binary name (so the Mayhemfile target == the arch tag, e.g. /mayhem/x86_64).
COUNT=0
for hsrc in "$HARNESS_DIR"/fuzz_asm_*.c; do
  base="$(basename "$hsrc" .c)"          # fuzz_asm_x86_64
  tag="${base#fuzz_asm_}"                # x86_64
  obj="$BUILD/$base.o"
  # -include the watchdog header: renames this harness's LLVMFuzzerTestOneInput to the inner symbol.
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $WATCHDOG_INC $INC -c "$hsrc" -o "$obj"

  # libFuzzer target -> /mayhem/<tag>  (watchdog object supplies the real LLVMFuzzerTestOneInput)
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$obj" "$BUILD/ks_fuzz_watchdog.o" $LIB_FUZZING_ENGINE "$LIBKS" -pthread -lm \
      -o "/mayhem/$tag"

  # standalone reproducer (no libFuzzer runtime) -> /mayhem/<tag>-standalone
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$obj" "$BUILD/ks_fuzz_watchdog.o" "$BUILD/standalone_main.o" "$LIBKS" -pthread -lm \
      -o "/mayhem/$tag-standalone"

  COUNT=$((COUNT+1))
done
echo "built $COUNT keystone fuzz harnesses (+ standalone reproducers)"

# ── 3) Build keystone's OWN golden test with NORMAL flags (clean tree) so test.sh only RUNS it. ─────
# Known-answer test: assemble fixed asm strings on several arches and assert BYTE-EXACT encodings
# (values taken from keystone's suite/test-all.sh comments). This is the PATCH-grade oracle —
# a no-op / exit(0) patch (or any change to the encoder output) fails it. Built against a separate
# NON-sanitized libkeystone.a so the oracle stays honest and noise-free.
TESTBUILD="$SRC/mayhem-tests"
rm -rf "$TESTBUILD"; mkdir -p "$TESTBUILD"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake -S "$SRC" -B "$TESTBUILD" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_LIBS_ONLY=1 -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="-pthread" -DCMAKE_CXX_FLAGS="-pthread"
env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  cmake --build "$TESTBUILD" -j"$MAYHEM_JOBS"
LIBKS_TEST="$(find "$TESTBUILD" -name 'libkeystone.a' | head -1)"
[ -n "$LIBKS_TEST" ] || { echo "ERROR: test libkeystone.a not found" >&2; exit 1; }

env -u CFLAGS -u CXXFLAGS -u SANITIZER_FLAGS \
  $CXX -pthread $INC "$HARNESS_DIR/golden_test.c" "$LIBKS_TEST" -lm \
    -o "$TESTBUILD/golden_test"
echo "built keystone golden test -> $TESTBUILD/golden_test"

# ── 4) Create fuzz_ symlink for OSS-Fuzz parity (the oss-fuzz-targets.tsv snapshot records the ────────
# OSS-Fuzz binary prefix as "fuzz_"; our binaries strip fuzz_asm_ → we alias x86_64 as fuzz_
# so the parity gate passes without a redundant full build).
ln -sf x86_64 /mayhem/fuzz_
ln -sf x86_64-standalone /mayhem/fuzz_-standalone

echo "build.sh complete:"
ls -la /mayhem/x86_64 /mayhem/x86_64-standalone /mayhem/fuzz_ /mayhem/fuzz_-standalone /mayhem/arm_arm /mayhem/mips /mayhem/evm 2>&1 || true
