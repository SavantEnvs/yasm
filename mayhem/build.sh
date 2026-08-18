#!/usr/bin/env bash
#
# mayhem/build.sh -- build yasm's two fuzz harnesses (fuzz_nasm, fuzz_gas)
# over libyasm's assembler pipeline, AND yasm's own upstream golden-output
# regression suite (via its autotools `make check`) for mayhem/test.sh.
#
# BUILD SYSTEM: yasm ships BOTH autotools (configure.ac/Makefile.am) and
# CMake (CMakeLists.txt). This uses AUTOTOOLS for BOTH the fuzz build and
# the oracle build -- see "C notes for the next worker" in the integration
# report for why: CMake here has ZERO test wiring (no CMakeLists.txt under
# any tests/ directory), while autotools' `make check` runs yasm's own
# ~40 out_test.sh-driven golden-output regression scripts (assemble a fixed
# .asm, hex-dump the object, `diff -w` against a committed .hex/.errwarn
# golden) essentially for free -- exactly the genuine, bash-level,
# sabotage-resistant known-answer oracle SPEC 6.3 wants. Reusing the SAME
# build system for the sanitized fuzz library keeps the whole build
# single-toolchain.
#
# yasm has NO committed `configure` (only configure.ac/Makefile.am/m4/*.m4),
# so it needs one autoreconf bootstrap; it also code-generates its own x86
# instruction tables (gen_x86_insn.py, needs python3) and lexers/perfect
# hashes (re2c/genperf/genmacro/genmodule -- all built as host tools from
# source, no network). All of that is LOCAL computation over files already
# in the checkout -- no network at any point here (air-gapped re-run, SPEC
# 6.5). Re-running this script on an already-built tree is safe: autoreconf
# regenerates the same output deterministically, and `make`/`configure` are
# both naturally incremental (SPEC 6.2 item 9).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) -- must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# Always ensure the LIBRARY gets SanitizerCoverage instrumentation, regardless of the base image's
# default or an empty override (SPEC/netnew-worker-prompt.md §6): without -fsanitize=fuzzer-no-link
# the fuzzed library carries no coverage and Mayhem would report 0 edges even though the harness TU
# itself is instrumented via $LIB_FUZZING_ENGINE at the final link.
case "$SANITIZER_FLAGS" in
  *fuzzer-no-link*) ;;
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link" ;;
esac
# Relax exactly FOUR UBSan sub-checks that are unconditional false positives in yasm's own code,
# confirmed by hand (see mayhem/*/known-findings/ for the genuine bugs found once these are
# relaxed -- without this, the very first byte fed to either harness crashes every single run and
# the target is unfuzzable, a 0-productivity "always crashes" target that still builds+fuzz-smokes):
#   - shift-base:        libyasm/bitvect.c's BitVector_Mask() does `~0L << mask` -- the embedded
#                         BitVector library's universal (and here harmless) idiom for an N-bit mask.
#                         Fires on EVERY yasm invocation (confirmed via the plain, unsanitized-except
#                         -fsanitize=undefined CLI too, not just this harness).
#   - array-bounds:       libyasm/expr.c's `yasm_expr` uses the pre-C99 "struct hack" -- `terms[2]`
#                         is a fixed-size placeholder the code intentionally over-allocates for
#                         expressions with more than two terms (documented in libyasm/expr.h's own
#                         comment). UBSan's static array-bounds check cannot see the real allocation
#                         size and flags every >2-term expression (e.g. `a + b + c`) as OOB.
#   - nonnull-attribute:  the re2c-generated NASM/GAS token scanners' buffer-refill routine
#                         (fill() in modules/parsers/{nasm,gas}/*-token.re) calls
#                         `memcpy(buf, s->tok, n)` where `s->tok` is NULL with n==0 on the very
#                         first fill of a fresh scanner -- a zero-length memcpy from NULL is
#                         harmless in practice but UB per the strict standard/glibc's nonnull
#                         attribute; fires on every GAS-parser invocation before a single fuzzer
#                         byte is even consumed.
#   - function:           libyasm/hamt.c's generic HAMT (hash-array-mapped-trie) symbol table
#                         stores callbacks like symtab_parser_finalize_checksym (libyasm/symrec.c)
#                         through a generic `int (*)(void *, void *)` function-pointer type -- a
#                         completely standard, ABI-safe (all pointer types, same calling
#                         convention) C idiom for a generic container, but the -fsanitize=function
#                         check flags every indirect call through it as a type mismatch. Fires on
#                         ANY input that reaches yasm_symtab_parser_finalize() -- i.e. essentially
#                         any successfully-parsed input (confirmed with a 1-BYTE input, "\n",
#                         which is enough for the GAS parser to finish and finalize the symtab) --
#                         so left enabled, the target "crashes" on its first successful parse.
# ASan and every OTHER UBSan check (null, bounds on other types, signed-integer-overflow, etc.) stay
# HALTING -- this only relaxes the four confirmed-benign, unconditionally-firing checks above, the
# same "hoextdown" pattern documented in the port-repo skill's field notes.
case "$SANITIZER_FLAGS" in
  *fno-sanitize=shift-base*) ;;
  *) SANITIZER_FLAGS="$SANITIZER_FLAGS -fno-sanitize=shift-base,array-bounds,nonnull-attribute,function" ;;
esac
# DWARF <= 3 (SPEC §6.2 item 10): clang-19's plain -g emits DWARF-5; be explicit.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${COVERAGE_FLAGS=}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE STANDALONE_FUZZ_MAIN COVERAGE_FLAGS MAYHEM_JOBS
: "${SRC:=/mayhem}"
cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
FUZZ_BUILD="$SRC/mayhem-build-fuzz"     # sanitized static libyasm.a for the harnesses
ORACLE_BUILD="$SRC/mayhem-build-oracle" # NORMAL-flags build: the yasm CLI + its own test suite

# ── 0) Bootstrap autotools ONCE against the checked-out source tree ────────────────────────────
# yasm ships configure.ac/Makefile.am/m4/*.m4 but no committed `configure` -- generate it (and
# config.h.in, aclocal.m4, config/{compile,install-sh,missing,depcomp,test-driver}) locally, no
# network. Safe to re-run: autoreconf is deterministic given the same inputs. Both build dirs below
# are separate out-of-tree (VPATH) builds against this ONE generated $SRC/configure, so they never
# collide on object files (each `configure` invocation below creates its own build directory).
if [ ! -x "$SRC/configure" ]; then
  autoreconf -fi   # run with cwd == $SRC (set above) -- a directory ARG is not what autoreconf
                   # expects (it takes optional TEMPLATE-FILE args, not a source dir) and silently
                   # produces an incomplete bootstrap (confirmed: configure gets generated but
                   # autoheader's config.h.in does not, and config.status then fails).
fi

# ── 1) FUZZ build: libyasm.a compiled WITH sanitizers + SanCov + DWARF-3 ───────────────────────
mkdir -p "$FUZZ_BUILD"
( cd "$FUZZ_BUILD" && "$SRC/configure" \
    --disable-nls --enable-python --disable-python-bindings \
    CC="$CC" PYTHON=python3 \
    CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS" \
  && make -j"$MAYHEM_JOBS" libyasm.a )
[ -f "$FUZZ_BUILD/libyasm.a" ] || { echo "FATAL: $FUZZ_BUILD/libyasm.a not produced" >&2; exit 1; }

# Standalone driver object, built once, linked into every harness's -standalone binary. It's a C
# file (not C++ -- yasm has no C++ code at all, so no extern "C" mangling concerns here).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$FUZZ_BUILD" -I"$SRC" \
    -c -x c "$STANDALONE_FUZZ_MAIN" -o "$FUZZ_BUILD/standalone_main.o"

# Shared harness driver (see mayhem/harnesses/fuzz_common.c for the full design rationale: why we
# drive libyasm's module API directly instead of yasm's own main()/do_assemble(), why input is
# staged under /dev/shm, and the sigsetjmp guard around yasm_fatal()'s exit()).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$FUZZ_BUILD" -I"$SRC" \
    -c "$HARNESS_DIR/fuzz_common.c" -o "$FUZZ_BUILD/fuzz_common.o"

for h in fuzz_nasm fuzz_gas; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -I"$FUZZ_BUILD" -I"$SRC" \
      -c "$HARNESS_DIR/$h.c" -o "$FUZZ_BUILD/$h.o"

  # libFuzzer binary -> /mayhem/<h> (the Mayhem target).
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE \
      "$FUZZ_BUILD/$h.o" "$FUZZ_BUILD/fuzz_common.o" "$FUZZ_BUILD/libyasm.a" \
      -o "/mayhem/$h"

  # Standalone (non-fuzzer) reproducer -> /mayhem/<h>-standalone (artifact, not a Mayhem target).
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS \
      "$FUZZ_BUILD/$h.o" "$FUZZ_BUILD/fuzz_common.o" "$FUZZ_BUILD/standalone_main.o" \
      "$FUZZ_BUILD/libyasm.a" -o "/mayhem/$h-standalone"

  echo "built $h (+ standalone)"
done

# Copy the per-target dictionaries into /mayhem (referenced by the Mayhemfiles' -dict= arg).
cp "$SRC/mayhem/fuzz_nasm/fuzz_nasm.dict" /mayhem/fuzz_nasm.dict
cp "$SRC/mayhem/fuzz_gas/fuzz_gas.dict" /mayhem/fuzz_gas.dict

# ── 2) ORACLE build: yasm CLI + its OWN upstream test suite, NORMAL flags (no sanitizer, no ─────
#    DWARF-3 override) -- a separate, clean, independent build so mayhem/test.sh stays an honest
#    functional oracle (SPEC 6.2 item 10 / 6.3). `make check`'s TESTS run yasm's own out_test.sh
#    golden-output regression scripts (bash `diff -w` of hex-dumped object files / stderr against
#    committed .hex/.errwarn goldens) plus a handful of internal-library unit tests -- built here,
#    only RUN by mayhem/test.sh.
mkdir -p "$ORACLE_BUILD"
( cd "$ORACLE_BUILD" && "$SRC/configure" \
    --disable-nls --enable-python --disable-python-bindings \
    CC="$CC" PYTHON=python3 \
    CFLAGS="-g -O2 $COVERAGE_FLAGS" \
  && make -j"$MAYHEM_JOBS" all )
# Deliberately a SEPARATE, sequential `make` invocation (not `make all test_hd ...` together):
# `all` recurses into "." a second time via automake's po/-triggered SUBDIRS mechanism
# (Makefile's own `all-recursive` target spawns a nested `make` PROCESS for the same directory),
# which independently rebuilds libyasm.a. Requesting `test_hd`/the unit-test binaries as EXTRA
# goals on that SAME command line makes the top-level make ALSO try to relink libyasm.a itself, in
# parallel with the nested recursive invocation doing the same -- two independent `ar`/`ranlib`
# processes racing on one output file. Confirmed reproducing this exact race on a re-run (`ar:
# unable to copy file 'libyasm.a'` / spurious `undefined reference` link failures for the unit
# tests) -- splitting into two sequential `make` calls makes the second one start only once
# libyasm.a is already fully built and up to date, so there is nothing left to race.
( cd "$ORACLE_BUILD" && make -j"$MAYHEM_JOBS" test_hd bitvect_test floatnum_test leb128_test \
         splitpath_test combpath_test uncstring_test )

for bin in yasm test_hd; do
  [ -x "$ORACLE_BUILD/$bin" ] || { echo "FATAL: $ORACLE_BUILD/$bin was not built" >&2; exit 1; }
  # Must be dynamically linked so verify-repo's LD_PRELOAD sabotage shim can neuter it -- a
  # statically-linked binary would survive sabotage and make mayhem/test.sh reward-hackable.
  if ! file "$ORACLE_BUILD/$bin" | grep -q 'dynamically linked'; then
    echo "FATAL: $ORACLE_BUILD/$bin is not dynamically linked -- the sabotage check could not" >&2
    echo "       neuter it, which would make mayhem/test.sh a reward-hackable oracle." >&2
    file "$ORACLE_BUILD/$bin" >&2
    exit 1
  fi
done

echo "build.sh complete:"
ls -la /mayhem/fuzz_nasm /mayhem/fuzz_gas /mayhem/fuzz_nasm-standalone /mayhem/fuzz_gas-standalone \
       /mayhem/fuzz_nasm.dict /mayhem/fuzz_gas.dict \
       "$ORACLE_BUILD/yasm" "$ORACLE_BUILD/test_hd" 2>&1 || true
