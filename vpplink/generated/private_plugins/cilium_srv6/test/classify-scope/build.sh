#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cilium Authors
#
# Build and run the classify-scope check (Issue #21 Stage 0 run 16,
# errata #34 item 191).
#
# It compiles cilium_srv6_classify_scope.h on its own — no VPP tree, no CMake,
# no vlib — against the byte-level stubs of ../fuzz/stub, and checks which
# interfaces must carry cilium-srv6-classify: the predicate that decides
# whether a Pod-facing interface is on the 02 §1 headend path at all, or
# whether its packets leave the ip6-unicast arc for the plain IPv6 FIB with no
# policy evaluation.
#
# Reusing the fuzz stubs is deliberate, for the same reason ../hotpath and
# ../wire do it: the predicate is a pure function of the D-73 classification
# and of whether the interface has a LocalEndpointTable entry. If it starts
# needing plugin state this build stops working, and that break is the signal.
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
  info "building classify_scope_test (ASan+UBSan)"
  "$CC" "${CFLAGS[@]}" -o "$OUT/classify_scope_test" "$HERE/classify_scope_test.c"
}

cmd_check () {
  cmd_build
  info "running classify_scope_test against the 02 §1 / §3 headend path rules"
  "$OUT/classify_scope_test" || fail "classify_scope_test failed"
  info "every Pod-facing interface is on the headend path; nothing else is"
}

cmd_clean () { rm -rf "$OUT"; }

case "${1:-check}" in
  build) cmd_build ;;
  check) cmd_check ;;
  clean) cmd_clean ;;
  *)     fail "unknown command: $1" ;;
esac
