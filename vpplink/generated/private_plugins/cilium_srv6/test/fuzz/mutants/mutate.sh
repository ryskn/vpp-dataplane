#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Cilium Authors
#
# Write a mutated copy of a production parser header.
#
#   mutate.sh <mutant-name> <source-header> <destination-header>
#
# The source is never modified. The destination is placed on an include path
# ahead of the plugin directory, so the harness compiles against the mutant
# while every production file stays exactly as committed. This is what the
# Issue #67 decision asks for:
#
#   "production parser に bug を入れるのではなく、test-only mutant に harness
#    を当てて ASan failure が出ることを確認する"
#
# Each mutation is a literal text substitution whose anchor must appear
# exactly once. If a refactor moves or rewrites the anchor, this script fails
# loudly rather than silently producing an unmutated copy that would make the
# negative control pass for the wrong reason.

set -euo pipefail

name="${1:?mutant name}"
src="${2:?source header}"
dst="${3:?destination header}"

case "$name" in
  # The clamp of the parse bound to the readable area is removed, so the
  # bound becomes the attacker-declared payload length. Every parser derives
  # bound = min(avail, 40 + payload_length); after this mutation a declared
  # length longer than the first buffer turns into a read past it. Detected
  # by ASan, because the harness places each packet in an exact-size block.
  bound_from_declared)
    pat='  bound = avail;'
    rep='  bound = 0xffffffffu;'
    ;;
  bound_from_declared_decl)
    pat='  u32 bound = avail;'
    rep='  u32 bound = 0xffffffffu;'
    ;;

  # D-54: an inspection failure on an offset-zero M=1 fragment is reported as
  # an ordinary malformed packet again, collapsing the counter split and the
  # evasion signal with it. Detected by the guard target's P3/P4/P7.
  guard_fragment_failure_class)
    pat='  return (fs == CILIUM_SRV6_GFRAG_FIRST) ? CILIUM_SRV6_GUARD_DROP_UNINSPECTABLE_FRAGMENT :'
    rep='  return (0) ? CILIUM_SRV6_GUARD_DROP_UNINSPECTABLE_FRAGMENT :'
    ;;

  # D-28: an SRH that still has segments to visit is decapsulated here rather
  # than forwarded, which would skip the remaining path processing. Detected
  # by the destination target's P5.
  parse_accept_segments_left)
    pat='  if (srh->segments_left != 0)'
    rep='  if (0)'
    ;;

  # D-43: a non-first fragment is given an L4 discriminator, which it cannot
  # have — it carries payload, not a header chain. A ProgramCache lookup with
  # a fabricated discriminator is a policy decision on invented key material.
  # Detected by the headend target's P5.
  #
  # The anchor is the tab-indented assignment inside the non-first branch, not
  # the visually identical space-indented ones in cilium_srv6_hparse_l4() and
  # in the field initialisation at the top of cilium_srv6_hparse(). Mutating
  # either of those would be overwritten before the function returns and the
  # control would silently pass.
  hparse_nonfirst_discriminator)
    pat=$'\t\tr->l4_discriminator = 0;'
    rep=$'\t\tr->l4_discriminator = 1;'
    ;;

  # D-21 / 02 §9: the guard that makes the MTU subtraction non-negative is
  # removed, so ptb_mtu - overhead wraps and is then truncated into u16.
  # Detected by the PMTUD target's P5.
  pmtud_mtu_underflow)
    pat='  if (overhead >= ptb_mtu)'
    rep='  if (0)'
    ;;

  *)
    echo "mutate.sh: unknown mutant '$name'" >&2
    exit 2
    ;;
esac

n="$(grep -c -F -- "$pat" "$src" || true)"
if [ "$n" != "1" ]; then
  cat >&2 <<EOF
mutate.sh: mutant '$name' expects exactly one occurrence of its anchor in
  $src
but found $n. The parser has changed shape. Update the anchor in
mutants/mutate.sh so that the negative control keeps testing the property it
was written for — do not delete the mutant.

anchor: $pat
EOF
  exit 2
fi

mkdir -p "$(dirname "$dst")"
pat="$pat" rep="$rep" perl -0777 -pe 'BEGIN { $p = $ENV{pat}; $r = $ENV{rep} } s/\Q$p\E/$r/' \
  "$src" > "$dst"

if cmp -s "$src" "$dst"; then
  echo "mutate.sh: mutant '$name' produced an unmodified copy" >&2
  exit 2
fi
