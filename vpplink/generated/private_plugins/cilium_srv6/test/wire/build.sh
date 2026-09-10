#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cilium Authors
#
# Build and run the IF-3 wire format check (errata #34 item 148 / D-76).
#
# It compiles cilium_srv6_punt_wire.h on its own — no VPP tree, no CMake, no
# vlib — against the byte-level stubs of ../fuzz/stub, and checks the frames
# it produces against the golden hex of
# design/detail/02-headend-dataplane.md §5.6.7, which is the same byte
# sequence pkg/srv6ec/compiler/wire_test.go pins on the agent side.
#
# Reusing the fuzz stubs is deliberate: the serializer has the same
# architectural requirement as the four parser headers (a pure function of
# bytes, no VPP state), so if it starts needing vlib this build stops working
# and that break is the signal.
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

# -fno-sanitize-recover: a UBSan report must fail the run, not print and
# continue, exactly as in the fuzz build.
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
  info "building wire_test (ASan+UBSan)"
  "$CC" "${CFLAGS[@]}" -o "$OUT/wire_test" "$HERE/wire_test.c"
}

cmd_check () {
  cmd_build
  info "running wire_test against the 02 §5.6.7 golden frames"
  "$OUT/wire_test" || fail "wire_test failed"
  info "wire format matches the golden frames"
}

cmd_clean () { rm -rf "$OUT"; }

case "${1:-check}" in
  build) cmd_build ;;
  check) cmd_check ;;
  clean) cmd_clean ;;
  *)     fail "unknown command: $1" ;;
esac
