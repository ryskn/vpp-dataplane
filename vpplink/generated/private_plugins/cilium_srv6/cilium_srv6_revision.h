/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — the revision value type and the D-85 fence.
 *
 * design/detail/00-overview.md §2.23 (D-85), §2.23.5 in particular.
 *
 * This header holds the three reserved values of the revision namespace and
 * the *only* comparison the plugin makes on the incarnation half of a
 * revision. It deliberately depends on nothing but <vppinfra/clib.h>: a
 * revision is a number, the fence is a compare, and neither needs vlib, vnet
 * or any plugin global. That is what lets the host-side check in
 * test/hotpath/ exercise the fence directly (Issue #21 / errata #34 item 176),
 * the same way test/wire/ exercises the IF-3 serializer.
 *
 * Every judgement that can let a packet through — the ProgramCache hit in
 * cilium-srv6-program, the fragment bypass in cilium-srv6-classify, the
 * conntrack reply bypass in cilium-srv6-ct, the D-51 lease — and the CLI that
 * displays those judgements go through the two functions below. One predicate,
 * one answer: `show cilium srv6 program-cache` cannot report STALE for an
 * entry the forwarding path would still use.
 */

#ifndef __included_cilium_srv6_revision_h__
#define __included_cilium_srv6_revision_h__

#include <vppinfra/clib.h>

/*
 * Sentinel revision. Slot 0 of the policy and endpoint revision tables is the
 * "key has no slot" slot and holds this value, which no published revision can
 * take, so an entry that depends on an unknown key never matches and punts
 * (fail-closed).
 */
#define CILIUM_SRV6_REV_INVALID ((u64) ~0)

/*
 * D-83 value range, shared by the three revision namespaces (ENDPOINT keyed by
 * destination IPv6, PATH keyed by PathCache index, POLICY keyed by
 * SecurityIdentity):
 *
 *   0                        the key does not exist. A publish of 0 withdraws
 *                            the key; no install may quote it; a slot whose
 *                            revision reads 0 never matches a quotation.
 *   1 .. CILIUM_SRV6_REV_INVALID-1
 *                            a real revision. Same value again = idempotent,
 *                            lower = refused, higher = advance.
 *   CILIUM_SRV6_REV_INVALID  reserved sentinel, always refused on publish.
 *
 * 0 is deliberately not "revision zero": the agent's revision counters start
 * at 1, so making 0 mean absence removes the case in which a freshly created
 * slot compares equal to a quotation that was made before it existed.
 *
 * The one place a quoted 0 is legal is `path_revision` of a DENY ProgramCache
 * entry, which has no path dependency at all (02 §4.3: a DENY must not be
 * invalidated by an unrelated route flap).
 */
#define CILIUM_SRV6_REV_ABSENT ((u64) 0)

/*
 * D-85 (00 §2.23) — agent revision incarnation.
 *
 * A revision is not a bare counter. It is
 *
 *   revision = (agent_revision_incarnation << 32) | local_sequence
 *
 * where the incarnation is a durable monotonic counter of *agent process*
 * generations (srv6_instance_state v2) and the sequence is the per-key
 * process-local counter the agent already had. A restarted agent therefore
 * starts numerically above everything any previous process of that node
 * published, in every namespace at once, so the per-key "lower is refused" rule
 * above accepts it with no resynchronisation and no dump message.
 *
 * The layout alone does not cover a key the new agent process no longer knows
 * about: nothing republishes it, so the plugin keeps the old value and an entry
 * installed by the old process would still compare equal to it. So the plugin
 * also keeps the incarnation it last accepted
 * (`hm->current_revision_incarnation`) and treats *every* quotation of another
 * incarnation as stale. That is what makes "the agent that decided this is
 * gone" a property of the quotation itself, with no table walk.
 *
 * Neither reserved value can be produced by the agent's composition (0 has
 * incarnation 0, which is never claimed; ~0 would need incarnation 0xffffffff,
 * which is reserved), so the two rules do not interfere.
 *
 * The one quoted 0 that is legal — a DENY's `path_revision` — is *not*
 * incarnation-checked, for the same reason it is not key-checked: it states
 * "this entry has no path dependency" and is not a member of the revision
 * namespace at all.
 */
#define CILIUM_SRV6_REV_INCARNATION(rev) ((u32) ((rev) >> 32))

/*
 * The D-85 fence itself: does `revision` belong to the agent process that
 * currently holds the revision authority?
 *
 * Strict — `CILIUM_SRV6_REV_ABSENT` and `CILIUM_SRV6_REV_INVALID` both answer
 * 0, because neither is a quotation of a revision. The one caller that is
 * allowed to quote 0 (a DENY's absent path dependency) establishes that before
 * it asks, and the control-plane callers that want "0 is not a fault" use
 * cilium_srv6_revision_is_stale_incarnation() in cilium_srv6_headend.h.
 *
 * Cost: one shift and one compare against a u32 the caller already holds.
 */
static_always_inline int
cilium_srv6_revision_is_current (u64 revision, u32 current_incarnation)
{
  return CILIUM_SRV6_REV_INCARNATION (revision) == current_incarnation;
}

/*
 * "This quotation is usable": it was made by the current agent process *and*
 * it is still what the key publishes.
 *
 * The two halves are independent facts with different remedies (00 §2.23.8):
 * a per-key mismatch is "the content of this key changed", which the next
 * compile fixes; an incarnation mismatch is "the process that decided this no
 * longer holds the revision authority", which only that process's successor
 * finishing its seed fixes. Both mean the holder may not forward on the
 * decision, which is why one function answers both and every forwarding
 * judgement calls it.
 *
 * `published` is whatever the key's table currently reads, including
 * CILIUM_SRV6_REV_INVALID for a slot that does not exist or was handed to
 * another owner; the equality then fails, as it must.
 */
static_always_inline int
cilium_srv6_revision_matches (u64 quoted, u64 published, u32 current_incarnation)
{
  if (PREDICT_FALSE (!cilium_srv6_revision_is_current (quoted, current_incarnation)))
    return 0;

  return quoted == published;
}

#endif /* __included_cilium_srv6_revision_h__ */
