#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cilium Authors
#
# Build and run the host-side check of the SR domain node address set rules
# (D-90, errata #34 item 205).
#
# srdomain_rules_test compiles cilium_srv6_srdomain_rules.h on its own - no VPP
# tree, no CMake, no vlib - against the byte-level stubs of ../fuzz/stub, and
# checks the staged transaction that replaces the SR domain set as a whole: a
# staged replacement is never visible to the hot path predicate, a commit
# swaps the complete set in one step, an abort or a refused commit leaves the
# previous set fully in force, and a replacement larger than the capacity is
# refused rather than truncated.
#
# Reusing the fuzz stubs is deliberate, for the same reason ../localep,
# ../hotpath, ../wire and ../classify-scope do it: the rules are a pure
# function of the two buffers. If they start needing plugin state this build
# stops working, and that break is the signal.
#
# Commands
#
#   ./build.sh check   build and run (ASan+UBSan). The default.
#   ./build.sh build   build only
#   ./build.sh clean
#
# Environment
#
#   CC   compiler, default clang
#   OUT  build directory, default ./build

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLUGIN_DIR="$(cd "$HERE/../.." && pwd)"     # .../vpp/plugins/cilium_srv6
PLUGINS_DIR="$(cd "$PLUGIN_DIR/.." && pwd)" # .../vpp/plugins
STUB_DIR="$(cd "$HERE/../fuzz/stub" && pwd)"

CC="${CC:-clang}"
OUT="${OUT:-$HERE/build}"

CFLAGS=(
  -std=gnu11
  -g -O1
  -fno-omit-frame-pointer
  -fsanitize=address,undefined
  -fno-sanitize-recover=all
  -Wall -Wextra -Werror
  -I "$STUB_DIR"
  -I "$PLUGINS_DIR"
)

info () { printf '\033[1m==> %s\033[0m\n' "$*"; }
fail () { printf '\033[1;31m==> %s\033[0m\n' "$*" >&2; exit 1; }

cmd_build () {
  mkdir -p "$OUT"
  info "building srdomain_rules_test (ASan+UBSan)"
  "$CC" "${CFLAGS[@]}" -o "$OUT/srdomain_rules_test" "$HERE/srdomain_rules_test.c"
}

cmd_check () {
  cmd_build
  info "running srdomain_rules_test against the D-90 / item 205 atomic set replacement rules"
  "$OUT/srdomain_rules_test" || fail "srdomain_rules_test failed"
  info "the worker-visible SR domain set is always a complete committed set"
}

cmd_clean () { rm -rf "$OUT"; }

case "${1:-check}" in
  build) cmd_build ;;
  check) cmd_check ;;
  clean) cmd_clean ;;
  *)     fail "unknown command: $1" ;;
esac
