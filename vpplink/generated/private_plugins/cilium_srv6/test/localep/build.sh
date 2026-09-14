#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cilium Authors
#
# Build and run the two host-side checks of what srv6_local_ep_add_del does.
#
# localep_rules_test — the attachment identity check (Issue #21 Stage 0 run 17
# OP-17-1, errata #34 item 200). It compiles cilium_srv6_localep_rules.h on its
# own — no VPP tree, no CMake, no vlib — against the byte-level stubs of
# ../fuzz/stub, and checks the rule srv6_local_ep_add_del applies to the CNI
# attachment identity: an ADD is accepted only when the D-68 binding table
# binds that attachment to that interface lifetime, and a DELETE that names an
# attachment removes only that attachment's entry.
#
# policyrev_slot_test — the POLICY revision key ownership rules (Issue #21
# Stage 0 run 21 OP-21-2, errata #34 item 222). Same stubs, compiling
# cilium_srv6_policyrev_rules.h, and checking what a LocalEndpointTable entry's
# install, re-install and delete do to the PolicyLeaseTable slot of its
# identity relative to the publication that owns the key. It lives here rather
# than in a directory of its own because the sequence it replays is the local
# endpoint install path: the run-21 loss began with an entry that created the
# slot before the seed publish arrived.
#
# Reusing the fuzz stubs is deliberate, for the same reason ../hotpath,
# ../wire and ../classify-scope do it: both decisions are pure functions — of
# the wire fields and what the binding table holds, and of whether a slot
# exists and holds the publication's reference. If either starts needing plugin
# state this build stops working, and that break is the signal.
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
  info "building localep_rules_test (ASan+UBSan)"
  "$CC" "${CFLAGS[@]}" -o "$OUT/localep_rules_test" "$HERE/localep_rules_test.c"
  info "building policyrev_slot_test (ASan+UBSan)"
  "$CC" "${CFLAGS[@]}" -o "$OUT/policyrev_slot_test" "$HERE/policyrev_slot_test.c"
}

cmd_check () {
  cmd_build
  info "running localep_rules_test against the D-68 / item 200 acceptance rules"
  "$OUT/localep_rules_test" || fail "localep_rules_test failed"
  info "an endpoint is installed on the interface its own attachment is bound to, or on none"
  info "running policyrev_slot_test against the D-83 / item 222 ownership rules"
  "$OUT/policyrev_slot_test" || fail "policyrev_slot_test failed"
  info "a published POLICY key outlives every entry that happens to name it"
}

cmd_clean () { rm -rf "$OUT"; }

case "${1:-check}" in
  build) cmd_build ;;
  check) cmd_check ;;
  clean) cmd_clean ;;
  *)     fail "unknown command: $1" ;;
esac
