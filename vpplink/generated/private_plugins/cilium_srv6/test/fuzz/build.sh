#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cilium Authors
#
# Build and run the cilium_srv6 parser fuzz targets (Issue #67).
#
# The build takes no VPP tree, no CMake and no vlib: the four parser headers
# are compiled against the minimal wire-format stubs in stub/. That is not a
# convenience, it is the architectural check the issue asks for — if a parser
# helper starts depending on vlib, this build stops working, and the blocking
# PR job reports it.
#
# Commands
#
#   ./build.sh build            build the four replay binaries (ASan+UBSan)
#   ./build.sh build-fuzzer     build the four libFuzzer binaries
#   ./build.sh check            build + regression corpus + seed corpus +
#                               generators (level 0). This is the blocking
#                               PR gate.
#   ./build.sh check-full       the same with the nightly generator level
#   ./build.sh fuzz SECONDS     short coverage-guided run of every target
#   ./build.sh fuzz-one T SEC   long coverage-guided run of one target
#   ./build.sh mutants          negative control: rebuild each target against
#                               a mutated copy of its parser and require the
#                               sanitizer to fire
#   ./build.sh clean
#
# Environment
#
#   CC        compiler, default clang
#   OUT       build directory, default ./build
#   JOBS      parallel targets for `check`, default 4

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(cd "$HERE/../.." && pwd)"   # .../vpp/plugins/cilium_srv6
PLUGINS_DIR="$(cd "$PLUGIN_DIR/.." && pwd)" # .../vpp/plugins

CC="${CC:-clang}"
OUT="${OUT:-$HERE/build}"
JOBS="${JOBS:-4}"

TARGETS=(
  fuzz_guard_parser
  fuzz_end_cilium_parser
  fuzz_headend_classify
  fuzz_pmtud_parser
)

# The parser header each target owns. Used by the mutant negative control.
# Written as a function rather than an associative array so that the script
# also runs under the bash 3.2 that ships with macOS.
target_header () {
  case "$1" in
    fuzz_guard_parser)      echo cilium_srv6_gparse.h ;;
    fuzz_end_cilium_parser) echo cilium_srv6_parse.h ;;
    fuzz_headend_classify)  echo cilium_srv6_hparse.h ;;
    fuzz_pmtud_parser)      echo cilium_srv6_pmtud_parse.h ;;
    *) echo "build.sh: no parser header known for target $1" >&2; exit 2 ;;
  esac
}

# -fno-sanitize-recover: a UBSan report must fail the run, not print and
# continue. Without it an integer overflow in a parser would be a line of CI
# log rather than a red job.
CFLAGS_COMMON=(
  -std=gnu11
  -g -O1
  -fno-omit-frame-pointer
  -fsanitize=address,undefined
  -fno-sanitize-recover=all
  -Wall -Wextra -Werror
  -Wno-unused-parameter
  -I "$HERE/stub"
  -I "$PLUGINS_DIR"
)

info () { printf '\033[1m==> %s\033[0m\n' "$*"; }
fail () { printf '\033[1;31m==> %s\033[0m\n' "$*" >&2; exit 1; }

build_replay () {
  local t="$1" extra_inc="${2:-}" out="${3:-$OUT/$t}"
  local -a inc=()

  [ -n "$extra_inc" ] && inc=(-I "$extra_inc")

  # The ${a[@]+...} guard keeps `set -u` happy on the bash 3.2 that ships
  # with macOS, where expanding an empty array is an unbound variable.
  "$CC" ${inc[@]+"${inc[@]}"} "${CFLAGS_COMMON[@]}" \
    -o "$out" \
    "$HERE/harness/$t.c" \
    "$HERE/harness/fuzz_main.c" \
    "$HERE/harness/fuzz_stats.c" \
    "$HERE/generators/gen_${t#fuzz_}.c"
}

build_libfuzzer () {
  local t="$1"

  "$CC" "${CFLAGS_COMMON[@]}" -fsanitize=fuzzer \
    -o "$OUT/${t}_libfuzzer" \
    "$HERE/harness/$t.c" \
    "$HERE/harness/fuzz_libfuzzer.c" \
    "$HERE/harness/fuzz_stats.c"
}

cmd_build () {
  mkdir -p "$OUT"
  for t in "${TARGETS[@]}"; do
    info "building $t (replay, ASan+UBSan)"
    build_replay "$t"
  done
}

cmd_build_fuzzer () {
  mkdir -p "$OUT"
  for t in "${TARGETS[@]}"; do
    info "building $t (libFuzzer)"
    build_libfuzzer "$t"
  done
}

# Replay the committed corpus and the generated matrix for one target.
run_check () {
  local t="$1" level="$2"
  local -a args=(--require-outcomes)

  [ -d "$HERE/corpus/regression/$t" ] && args+=("$HERE/corpus/regression/$t")
  [ -d "$HERE/corpus/seed/$t" ] && args+=("$HERE/corpus/seed/$t")
  if [ "$level" = full ]; then
    args+=(--generate-full)
  else
    args+=(--generate)
  fi

  "$OUT/$t" "${args[@]}"
}

cmd_check () {
  local level="${1:-pr}"
  local -a pids=() names=()
  local rc=0 i

  cmd_build

  for t in "${TARGETS[@]}"; do
    info "checking $t (corpus + generators, level=$level)"
    run_check "$t" "$level" > "$OUT/$t.log" 2>&1 &
    pids+=($!) names+=("$t")
    if [ "${#pids[@]}" -ge "$JOBS" ]; then
      for i in "${!pids[@]}"; do
        wait "${pids[$i]}" || rc=1
      done
      pids=() names=()
    fi
  done
  for i in "${!pids[@]}"; do
    wait "${pids[$i]}" || rc=1
  done

  for t in "${TARGETS[@]}"; do
    cat "$OUT/$t.log"
  done

  [ "$rc" -eq 0 ] || fail "one or more targets failed"
  info "all targets pass"
}

cmd_fuzz () {
  local secs="${1:-60}" t

  cmd_build_fuzzer
  mkdir -p "$OUT/corpus"
  for t in "${TARGETS[@]}"; do
    info "libFuzzer $t for ${secs}s"
    mkdir -p "$OUT/corpus/$t"
    "$OUT/${t}_libfuzzer" \
      "$OUT/corpus/$t" \
      "$HERE/corpus/seed/$t" \
      "$HERE/corpus/regression/$t" \
      -max_total_time="$secs" \
      -max_len=2048 \
      -print_final_stats=1 \
      -artifact_prefix="$OUT/crash-$t-"
  done
}

cmd_fuzz_one () {
  local t="${1:?target}" secs="${2:-1800}"

  mkdir -p "$OUT" "$OUT/corpus/$t"
  build_libfuzzer "$t"
  info "libFuzzer $t for ${secs}s"
  "$OUT/${t}_libfuzzer" \
    "$OUT/corpus/$t" \
    "$HERE/corpus/seed/$t" \
    "$HERE/corpus/regression/$t" \
    -max_total_time="$secs" \
    -max_len=2048 \
    -print_final_stats=1 \
    -artifact_prefix="$OUT/crash-$t-"
}

#
# Negative control.
#
# The point is to answer "would this harness notice?" without ever editing a
# production file. mutants/mutate.sh writes a mutated *copy* of the parser
# header into a scratch include directory that is placed ahead of the real
# plugin directory on the include path; the harness, the corpus and the
# generators are unchanged. A mutant that does not make the run fail means
# the harness has stopped checking something.
#
cmd_mutants () {
  local rc=0 t mutant desc dir hdr b f why

  mkdir -p "$OUT"
  while IFS=$'\t' read -r t mutant desc; do
    case "$t" in ''|\#*) continue;; esac

    hdr="$(target_header "$t")"
    dir="$OUT/mutant/$t/$mutant"
    rm -rf "$dir"; mkdir -p "$dir/cilium_srv6"

    info "mutant $t/$mutant: $desc"
    "$HERE/mutants/mutate.sh" "$mutant" "$PLUGIN_DIR/$hdr" "$dir/cilium_srv6/$hdr"

    # The other parser headers must still resolve; only the mutated one is
    # shadowed, so symlink the rest of the plugin directory.
    for f in "$PLUGIN_DIR"/*.h; do
      b="$(basename "$f")"
      [ "$b" = "$hdr" ] && continue
      ln -sf "$f" "$dir/cilium_srv6/$b"
    done

    build_replay "$t" "$dir" "$dir/$t"

    # Only the generators are used: they reach every branch by construction,
    # so the control does not depend on the committed corpus.
    # Run through a nested shell so that the "Abort trap"/"Aborted" notice a
    # sanitizer abort produces lands in the log next to the report instead of
    # in this script's output, where it reads like a failure of the gate.
    # The trailing `exit` suppresses bash's implicit exec of a lone simple
    # command, so the nested shell — not this one — is the process that
    # reports the abort, and the notice lands in the log.
    if bash -c '"$0" --generate --quiet; exit $?' "$dir/$t" > "$dir/run.log" 2>&1; then
      printf '\033[1;31m    NOT DETECTED\033[0m\n' >&2
      rc=1
    else
      why="$(grep -m1 -E 'ERROR: (AddressSanitizer|libFuzzer)|runtime error|post-condition failed' \
             "$dir/run.log" || true)"
      if [ -z "$why" ]; then
        printf '\033[1;31m    binary failed, but not with a sanitizer or post-condition report\033[0m\n' >&2
        tail -5 "$dir/run.log" >&2
        rc=1
      else
        printf '    detected: %s\n' "$why"
      fi
    fi
  done < "$HERE/mutants/mutants.tsv"

  [ "$rc" -eq 0 ] || fail "negative control failed: a mutant went undetected"
  info "negative control passed: every mutant is detected"
}

cmd_clean () { rm -rf "$OUT"; }

case "${1:-check}" in
  build)        cmd_build ;;
  build-fuzzer) cmd_build_fuzzer ;;
  check)        cmd_check pr ;;
  check-full)   cmd_check full ;;
  fuzz)         shift; cmd_fuzz "$@" ;;
  fuzz-one)     shift; cmd_fuzz_one "$@" ;;
  mutants)      cmd_mutants ;;
  clean)        cmd_clean ;;
  *)            fail "unknown command: $1" ;;
esac
