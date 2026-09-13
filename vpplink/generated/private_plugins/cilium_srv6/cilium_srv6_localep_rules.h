/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — LocalEndpointTable attachment identity rules
 * (D-68, D-70, D-71, errata #34 item 200).
 *
 * The cross-authority half of srv6_local_ep_add_del, kept free of vlib and of
 * the plugin's own tables so that it is a pure function of three observations:
 *
 *   - the attachment identity the writer put on the wire;
 *   - the interface incarnation the writer put on the wire;
 *   - what the CNI attachment binding table (D-68) holds for that
 *     sw_if_index, if anything.
 *
 * # Why the key is not enough
 *
 * A LocalEndpointTable entry is keyed by (sw_if_index, if_incarnation) and
 * the D-31 check refuses a write whose incarnation is not the live one. Both
 * halves of that key are dataplane counters, and a plugin that restarts
 * restarts both of them: the composite identity of an interface is
 * (PluginInstanceID, sw_if_index, if_incarnation) (errata #34 item 180), so a
 * writer that kept a handle across a restart replays a tuple that is *live*
 * and names whatever interface the new instance put in that slot. The D-31
 * check cannot see the difference, because there is none to see in the key.
 *
 * Issue #21 run 17 is exactly that: after a VPP restart the Pod interface
 * lifecycle service recreated four TUNs in a different order, two attachments
 * swapped sw_if_index slots, and the agent reinstalled both endpoints from the
 * handles it had kept. Both writes carried a live (sw_if_index,
 * if_incarnation) and both were accepted. The packets failed closed at
 * cilium-srv6-classify (DROP_SRC_IP_MISMATCH) rather than being misdelivered,
 * and same-node forwarding stayed at 0% until the agent was restarted.
 *
 * What separates the two cases is an authority the plugin already holds: the
 * binding table says which CNI attachment an interface is behind, and it is
 * rebuilt by the writer of the interfaces themselves, under the current plugin
 * instance. Making the endpoint write name its attachment turns "is this
 * handle live" into "does the writer's attachment and this dataplane's binding
 * describe the same interface" — a consistency check between two authorities,
 * not a second opinion about either. D-72 reconstructs the binding table
 * before any LocalEndpoint is installed, so a legitimate ADD never arrives
 * before its binding.
 *
 * The identity's syntax rules (length bound, character set) are the binding
 * table's, from cilium_srv6_ifbind_rules.h, and are deliberately not restated
 * here: the two messages carry the same identity in the same encoding, and a
 * second copy of the rule is a second chance to disagree with it.
 *
 * Design references:
 *   design/detail/00-overview.md D-31, D-68, D-70, D-71, §2.14.3
 *   design/detail/02-headend-dataplane.md §2, §8
 */

#ifndef __included_cilium_srv6_localep_rules_h__
#define __included_cilium_srv6_localep_rules_h__

#include <vppinfra/types.h>
#include <vppinfra/clib.h>

#include <cilium_srv6/cilium_srv6_ifbind_rules.h>

/*
 * Outcome of the attachment identity check of one add or delete.
 *
 * ACCEPT does not mean the write happens: the caller still applies the checks
 * this file knows nothing about (the interface exists, D-31, the endpoint
 * address). It means only that the writer's attachment and this dataplane's
 * binding agree. Every REJECT_* leaves the LocalEndpointTable untouched.
 */
typedef enum
{
  CILIUM_SRV6_LOCALEP_ACCEPT = 0,

  /* Length or character set of attachment_id, empty included. An ADD must
     name an attachment; there is no unnamed local endpoint. */
  CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID,
  /* No attachment claims this interface: the binding table has no entry for
     sw_if_index. D-68 has no second authority to fall back to. */
  CILIUM_SRV6_LOCALEP_REJECT_NO_BINDING,
  /* The interface is bound, to a different attachment than the writer's. This
     is the run-17 shape. */
  CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT,
  /* The binding is for this attachment but names another interface lifetime.
     Unreachable while the binding table's own invariants hold - a binding is
     removed with the interface it names - so it is a check on those
     invariants rather than on the writer. */
  CILIUM_SRV6_LOCALEP_REJECT_BINDING_INCARNATION,
  /* DELETE: the entry that is installed here was installed for a different
     attachment. The writer's attachment has no entry on this interface, which
     is why the caller answers it as an absence. */
  CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT_ENTRY,
} cilium_srv6_localep_verdict_t;

/* What the binding table holds for one sw_if_index, or `present == 0`. The
   identity is borrowed, not owned: it is only compared. */
typedef struct
{
  u8 present;
  const u8 *attachment_id;
  u32 id_len;
  u32 if_incarnation;
} cilium_srv6_localep_binding_t;

/* What the LocalEndpointTable holds for one sw_if_index, or `present == 0`.
   Same borrowing rule. */
typedef struct
{
  u8 present;
  const u8 *attachment_id;
  u32 id_len;
} cilium_srv6_localep_entry_t;

/*
 * Byte-exact comparison of two attachment identities.
 *
 * Not a string compare: an identity is a byte vector of exactly the length
 * that was published, it is not NUL terminated, and it is never truncated -
 * the whole reason the VPP interface tag was unusable as the binding carrier
 * is that two attachments of one Pod differ only in a ':ethN' suffix that a
 * 63-byte tag cuts off (cilium_srv6_ifbind_rules.h). A comparison that stops
 * at the first NUL, or at a fixed width, reintroduces that collapse.
 *
 * The loop is written out rather than delegated to clib_memcmp so that this
 * header keeps depending on nothing but the integer types, which is what lets
 * test/localep compile it with no VPP tree at all. An identity is at most 255
 * bytes and this runs on the control plane only.
 */
static_always_inline int
cilium_srv6_localep_id_equal (const u8 *a, u32 a_len, const u8 *b, u32 b_len)
{
  u32 i;

  if (a_len != b_len)
    return 0;
  if (a_len == 0)
    return 1;
  if (a == 0 || b == 0)
    return 0;

  for (i = 0; i < a_len; i++)
    if (a[i] != b[i])
      return 0;

  return 1;
}

/*
 * Decide the attachment identity check of one ADD.
 *
 * The order of the checks is the order in which the answers get more
 * specific, so that the retval names the first thing that is wrong:
 *
 *   1. the identity is well-formed (the binding table's own rule);
 *   2. some attachment claims this interface at all;
 *   3. it is this attachment;
 *   4. the binding was published for the interface lifetime being written.
 *
 * 3 is a refusal and not a correction: the plugin does not know which of the
 * two writers is behind, and installing the endpoint on the interface the
 * binding names instead would be the plugin choosing an interface for an
 * endpoint - the thing D-68 exists to keep it from doing. The writer
 * re-resolves the attachment against the binding table and writes again.
 */
static_always_inline cilium_srv6_localep_verdict_t
cilium_srv6_localep_decide_add (const u8 *id, u32 id_len, u32 if_incarnation,
				cilium_srv6_localep_binding_t binding)
{
  if (!cilium_srv6_ifbind_id_valid (id, id_len))
    return CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID;

  if (!binding.present)
    return CILIUM_SRV6_LOCALEP_REJECT_NO_BINDING;

  if (!cilium_srv6_localep_id_equal (id, id_len, binding.attachment_id, binding.id_len))
    return CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT;

  if (binding.if_incarnation != if_incarnation)
    return CILIUM_SRV6_LOCALEP_REJECT_BINDING_INCARNATION;

  return CILIUM_SRV6_LOCALEP_ACCEPT;
}

/*
 * Decide the attachment identity check of one DELETE.
 *
 * It is compared against the identity the *entry* was installed with, not
 * against the binding table. A withdrawal has to work when the binding is
 * already gone - that is the ordinary Pod teardown, and the interface delete
 * callback removes the binding in the same event that frees the index - so
 * consulting the binding here would make a removal depend on the thing whose
 * disappearance motivates it. It is the same reason
 * cilium_srv6_ifbind_decide_del does not consult the interface.
 *
 * An empty identity is the unverified form and is accepted: it is the D-70
 * orphan sweep, which names a lifetime it has just read out of
 * srv6_local_ep_dump under the current plugin instance and has no attachment
 * to quote, because srv6_local_ep_details does not carry one. That is not a
 * hole a stale writer can climb through: the entries a stale writer removes
 * are the ones it *has* an identity for, and quoting the identity it recorded
 * is what this check catches. An empty identity is a request to delete
 * whatever is at a lifetime the caller has just observed, which is what the
 * message meant before item 200 and is still exactly as strong as the D-31
 * fence.
 */
static_always_inline cilium_srv6_localep_verdict_t
cilium_srv6_localep_decide_del (const u8 *id, u32 id_len, cilium_srv6_localep_entry_t entry)
{
  if (id_len == 0)
    return CILIUM_SRV6_LOCALEP_ACCEPT;

  if (!cilium_srv6_ifbind_id_valid (id, id_len))
    return CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID;

  if (!entry.present)
    return CILIUM_SRV6_LOCALEP_ACCEPT; /* the caller answers the absence */

  if (!cilium_srv6_localep_id_equal (id, id_len, entry.attachment_id, entry.id_len))
    return CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT_ENTRY;

  return CILIUM_SRV6_LOCALEP_ACCEPT;
}

#endif /* __included_cilium_srv6_localep_rules_h__ */
