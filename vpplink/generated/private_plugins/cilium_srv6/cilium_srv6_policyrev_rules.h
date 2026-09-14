/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — POLICY revision key ownership rules
 * (D-30, D-83, D-84, errata #34 item 222).
 *
 * A POLICY revision key is a SecurityIdentity (D-83), and the plugin holds
 * one PolicyLeaseTable slot per key. The slot is reference counted, because
 * more than one thing names it: the LocalEndpointTable entry of a local
 * endpoint with that identity, every ProgramCache entry whose src_identity is
 * that identity, the conntrack pin of a reply peer, and — this is what this
 * header is about — the publication itself.
 *
 * # Why the publication owns a reference
 *
 * 02 §4.3 says a published key exists until it is withdrawn, and the plugin's
 * acceptance rule for srv6_program_add_del is that a quoted key MUST exist:
 * a missing key is refused with INVALID_VALUE_4, reported apart from a stale
 * quotation precisely because no recompile fixes it. The agent's ledger, on
 * the other side, records a key as acknowledged from the publish reply until
 * it withdraws it. The two only agree if the key outlives every entry that
 * happens to name it, which means the publication has to hold a reference of
 * its own.
 *
 * Without it the lifetime of a published key is the lifetime of an arbitrary
 * entry. Issue #21 run 21 is that shape: a LocalEndpointTable entry for
 * identity 46532 was installed before the seed publish, so the entry created
 * the slot; the publish found the slot and wrote the revision into it without
 * taking a reference; the D-72 replay reinstalled that one entry, the entry's
 * reference went to zero, the slot was released with the revision in it, and
 * the reinstall created a fresh slot at revision 0. Every later install for
 * 46532 quoting the published revision was then refused for a missing key,
 * permanently, while the agent's ledger still read acknowledged.
 *
 * # The rule
 *
 * A publication owns exactly one reference to the slot of each identity it
 * publishes with a non-ABSENT revision, from the publish that first carries
 * one until the withdraw that takes it back. Therefore:
 *
 *   - a slot with `published` set has refcount >= 1 at all times, so no entry
 *     unref can release it;
 *   - a publish for an identity that is already published takes no second
 *     reference, so republishing an unchanged identity stays idempotent;
 *   - a withdraw returns the publication's reference, and the slot is then
 *     released with the last entry that still names it — not before, because
 *     releasing it under a reader would hand its index to another identity.
 *
 * Kept out of cilium_srv6_headend.c, and free of vlib and of the pool and
 * hash the slots actually live in, so that it is a pure function of three
 * observations — does the slot exist, does it hold the publication's
 * reference, is this element a withdraw — and can be executed on the host by
 * vpp/plugins/cilium_srv6/test/localep.
 *
 * Design references:
 *   design/detail/00-overview.md D-30, D-83, D-84, §2.1
 *   design/detail/02-headend-dataplane.md §4.3, §4.3.1, §8
 */

#ifndef __included_cilium_srv6_policyrev_rules_h__
#define __included_cilium_srv6_policyrev_rules_h__

#include <vppinfra/types.h>
#include <vppinfra/clib.h>

/*
 * What one element of srv6_policy_revision_publish does to the slot of its
 * identity. The five cases are exhaustive over (slot exists, slot is
 * published, element is a withdraw).
 */
typedef enum
{
  /* No slot yet, and a real revision to publish: create the slot. The
     reference the create takes is the publication's. */
  CILIUM_SRV6_POLICYREV_CREATE = 0,

  /* The slot exists but holds no publication reference — an entry or a
     conntrack pin created it before the publication arrived, or it was
     withdrawn and is coming back — so the reference the create would have
     taken is taken here instead. This is the case item 222 was missing. */
  CILIUM_SRV6_POLICYREV_ADOPT,

  /* The slot exists and is already published: write the new revision and take
     nothing. A publication owns one reference, not one per message. */
  CILIUM_SRV6_POLICYREV_REPUBLISH,

  /* A withdraw of a published identity: clear the revision and the lease, and
     give the publication's reference back. The slot survives while entries
     and pins still name it. */
  CILIUM_SRV6_POLICYREV_WITHDRAW,

  /* A withdraw with no publication reference to return: the identity has no
     slot at all, or it has one that was never published. Nothing to release;
     an existing slot still has its revision and lease cleared. */
  CILIUM_SRV6_POLICYREV_WITHDRAW_NOTHING_HELD,
} cilium_srv6_policyrev_action_t;

/*
 * The decision itself. `revision_is_absent` is "this element's revision is
 * CILIUM_SRV6_REV_ABSENT", i.e. the element is a withdraw; the sentinel and
 * ordering checks are the caller's and are already done by the time this is
 * reached.
 */
static_always_inline cilium_srv6_policyrev_action_t
cilium_srv6_policyrev_publish_action (int slot_exists, int published, int revision_is_absent)
{
  if (revision_is_absent)
    return (slot_exists && published) ? CILIUM_SRV6_POLICYREV_WITHDRAW :
					CILIUM_SRV6_POLICYREV_WITHDRAW_NOTHING_HELD;

  if (!slot_exists)
    return CILIUM_SRV6_POLICYREV_CREATE;

  return published ? CILIUM_SRV6_POLICYREV_REPUBLISH : CILIUM_SRV6_POLICYREV_ADOPT;
}

/*
 * Whether this element needs a slot the pool does not hold yet, which is the
 * only thing the capacity pre-check of the publish handler may count. Taking
 * the publication's reference on a slot that already exists (ADOPT) creates
 * nothing and must not be counted, or a publication of already-referenced
 * identities would be refused with LIMIT_EXCEEDED for capacity it does not
 * use.
 */
static_always_inline int
cilium_srv6_policyrev_publish_allocates (int slot_exists, int revision_is_absent)
{
  return (!slot_exists && !revision_is_absent) ? 1 : 0;
}

/*
 * The invariant the reference rule exists to create: a published slot is
 * never at zero references, so the release path of csh_policy_rev_slot_unref
 * can only ever be reached by a slot the publication has already let go of.
 * Asserted where the slot is released, and executed directly by the host
 * test.
 */
static_always_inline int
cilium_srv6_policyrev_slot_invariant_ok (u32 refcount, int published)
{
  return published ? (refcount >= 1) : 1;
}

#endif /* __included_cilium_srv6_policyrev_rules_h__ */
