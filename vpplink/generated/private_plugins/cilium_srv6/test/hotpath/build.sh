#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cilium Authors
#
# Build and run the D-85 hot-path fence check (Issue #21, errata #34 item 176).
#
# It compiles cilium_srv6_revision.h on its own — no VPP tree, no CMake, no
# vlib — against the byte-level stubs of ../fuzz/stub, and checks the fence and
# the per-key match predicate that every forwarding judgement in the plugin
# (ProgramCache hit, fragment bypass, conntrack reply bypass, D-51 lease) and
# the CLI that displays those judgements go through.
#
# Reusing the fuzz stubs is deliberate, for the same reason ../wire does it:
# the fence is a pure function of (quoted revision, published revision, current
# incarnation). If it starts needing plugin state this build stops working, and
# that break is the signal.
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
  info "building fence_test (ASan+UBSan)"
  "$CC" "${CFLAGS[@]}" -o "$OUT/fence_test" "$HERE/fence_test.c"
}

cmd_check () {
  cmd_build
  info "running fence_test against the 00 §2.23 rules"
  "$OUT/fence_test" || fail "fence_test failed"
  info "the D-85 fence holds on every forwarding predicate"
}

cmd_clean () { rm -rf "$OUT"; }

case "${1:-check}" in
  build) cmd_build ;;
  check) cmd_check ;;
  clean) cmd_clean ;;
  *)     fail "unknown command: $1" ;;
esac
