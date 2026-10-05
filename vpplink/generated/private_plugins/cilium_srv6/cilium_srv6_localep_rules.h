/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — LocalEndpointTable attachment identity rules
 * and exact mutation rules (D-68, D-70, D-71, D-88, errata #34 items 200 and
 * 202).
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
 * # Exact mutation (errata #34 item 202, D-88)
 *
 * Item 200 made the plugin check *which interface* a write may name. Item 202
 * makes it check *which entry* a write may change. An ADD no longer overwrites
 * an installed entry: it installs where nothing is installed, succeeds without
 * writing anything where exactly the requested tuple is installed, and is
 * refused where anything else is. A DELETE no longer removes whatever a handle
 * names: it must name the exact instance that is installed, and an empty
 * attachment identity - the handle-only form the D-70 orphan sweep used while
 * srv6_local_ep_details carried no attachment - is refused. The decision is
 * still a pure function, now of the requested tuple, the binding and the
 * installed entry's tuple, so the plugin tables stay out of this file.
 *
 * Design references:
 *   design/detail/00-overview.md D-31, D-68, D-69, D-70, D-71, D-88, §2.14.3
 *   design/detail/02-headend-dataplane.md §2, §8.2
 */

#ifndef __included_cilium_srv6_localep_rules_h__
#define __included_cilium_srv6_localep_rules_h__

#include <vppinfra/types.h>
#include <vppinfra/clib.h>

#include <cilium_srv6/cilium_srv6_ifbind_rules.h>

/*
 * Outcome of one srv6_local_ep_add_del, as far as these rules decide it.
 *
 * ACCEPT does not mean the write happens: the caller still applies the checks
 * this file knows nothing about (the interface exists, D-31, the endpoint
 * address on an ADD). It means only that nothing here refuses it. Every
 * REJECT_* leaves the LocalEndpointTable untouched, and so does
 * ACCEPT_IDEMPOTENT: it is a success that changes nothing.
 */
typedef enum
{
  CILIUM_SRV6_LOCALEP_ACCEPT = 0,
  /* ADD: the entry that is installed is exactly the requested tuple
     (errata #34 item 202, D-88). The caller answers success and writes
     nothing - no field, no policy revision slot reference, no classify
     refresh. */
  CILIUM_SRV6_LOCALEP_ACCEPT_IDEMPOTENT,

  /* Length or character set of attachment_id. An ADD must name an
     attachment; there is no unnamed local endpoint. */
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
  /* ADD: an entry is installed on this interface and it is not the requested
     tuple (D-88). Nothing is replaced: the writer removes the installed entry
     with its own exact DELETE first. */
  CILIUM_SRV6_LOCALEP_REJECT_CONFLICT,
  /* DELETE: attachment_id is empty. There is no wildcard DELETE (D-88). */
  CILIUM_SRV6_LOCALEP_REJECT_ID_EMPTY,
  /* DELETE: the address is the unspecified address. No entry can carry it (an
     ADD refuses it), so a DELETE that names it does not name an installed
     instance; it is the shape of the pre-D-88 handle-only removal, which
     filled every field but the key with zero. */
  CILIUM_SRV6_LOCALEP_REJECT_ADDRESS_UNSPECIFIED,
  /* DELETE: no entry is installed on this interface. */
  CILIUM_SRV6_LOCALEP_REJECT_NO_ENTRY,
  /* DELETE: an entry is installed on this interface and it is not the instance
     the DELETE names - another attachment's, or a successor of this
     attachment's with another identity, Context, address or quota class. The
     named instance is absent, which is why the caller answers it the way it
     answers REJECT_NO_ENTRY. */
  CILIUM_SRV6_LOCALEP_REJECT_OTHER_INSTANCE,
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

/*
 * The semantic tuple of one LocalEndpointTable entry (errata #34 item 202,
 * D-88): every field srv6_local_ep_add_del(ADD) writes into the entry, and the
 * key it writes it under.
 *
 * owner_quota_class is in it for the same reason the others are. It is stored
 * in the entry (cilium_srv6_local_ep_t) and the ProgramCache, fragment cache
 * and punt quotas charge the endpoint by it (D-42), so an ADD that differs only
 * in it is a request to change the entry. Answering such an ADD as an
 * idempotent success would either change the entry - the implicit replace D-88
 * forbids - or tell the writer an entry exists that does not.
 *
 * policy_revision is not in it: it is the revision of the identity's slot, not
 * a field the ADD carries.
 *
 * The identity is borrowed, as everywhere in this file.
 */
typedef struct
{
  const u8 *attachment_id;
  u32 id_len;
  u32 sw_if_index;
  u32 if_incarnation;
  u32 identity;
  u32 local_context_id;
  u32 owner_quota_class;
  u8 ip[16];
} cilium_srv6_localep_tuple_t;

/* What the LocalEndpointTable holds for one sw_if_index, or `present == 0`. An
   installed entry whose attachment identity is missing is present with
   id_len 0: it then equals no request, which is the fail-closed reading of a
   table whose own invariant (item 200: every entry has one) is broken. */
typedef struct
{
  u8 present;
  cilium_srv6_localep_tuple_t tuple;
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

/* Whether a 16-byte address is the unspecified address (::). */
static_always_inline int
cilium_srv6_localep_ip_is_unspecified (const u8 *ip)
{
  u32 i;

  for (i = 0; i < 16; i++)
    if (ip[i] != 0)
      return 0;

  return 1;
}

/*
 * Whether two tuples describe the same entry instance (D-88): every field,
 * exactly. There is no field that is "close enough" - a tuple that differs in
 * any of them is either a different endpoint on this interface or a successor
 * of this one, and both are things an ADD must not overwrite and a DELETE must
 * not remove.
 */
static_always_inline int
cilium_srv6_localep_tuple_equal (const cilium_srv6_localep_tuple_t *a,
				 const cilium_srv6_localep_tuple_t *b)
{
  u32 i;

  if (a->sw_if_index != b->sw_if_index || a->if_incarnation != b->if_incarnation ||
      a->identity != b->identity || a->local_context_id != b->local_context_id ||
      a->owner_quota_class != b->owner_quota_class)
    return 0;

  for (i = 0; i < 16; i++)
    if (a->ip[i] != b->ip[i])
      return 0;

  return cilium_srv6_localep_id_equal (a->attachment_id, a->id_len, b->attachment_id, b->id_len);
}

/*
 * Decide the attachment identity check of one ADD (errata #34 item 200).
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
 *
 * It says nothing about what is installed; cilium_srv6_localep_decide_add_exact
 * below is the whole ADD decision and calls this first.
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
 * Decide one ADD completely (errata #34 items 200 and 202, D-88).
 *
 * An ADD is allowed in exactly three states:
 *
 *   - no entry is installed on the interface: ACCEPT, and the caller installs;
 *   - the installed entry is exactly the requested tuple: ACCEPT_IDEMPOTENT,
 *     and the caller answers success without writing anything;
 *   - the installed entry is anything else: REJECT_CONFLICT, and nothing is
 *     written.
 *
 * The third state used to be an implicit replace - the old entry's fields
 * overwritten in place - and that is exactly what D-88 removes. A replacement
 * of an identity (D-69), of an interface lifetime (D-68) or of an attachment
 * is the writer's old exact DELETE, its ACK, then the new ADD; a plugin that
 * also accepted an overwrite would let a writer that skipped the DELETE, or a
 * stale writer that never knew there was one, move an interface's identity,
 * address and Context to another endpoint's values with nothing invalidated in
 * between.
 *
 * The binding check comes first, so an idempotent success also means the
 * binding table still binds this attachment to this interface lifetime: a
 * replay is not a way to have an entry confirmed whose binding has moved. The
 * replays this answers with success are the retry of an install whose ACK was
 * lost, the agent's restart adoption (errata #34 item 217) and the D-72
 * recovery publication, all of which re-send the tuple that is installed.
 */
static_always_inline cilium_srv6_localep_verdict_t
cilium_srv6_localep_decide_add_exact (const cilium_srv6_localep_tuple_t *req,
				      cilium_srv6_localep_binding_t binding,
				      cilium_srv6_localep_entry_t entry)
{
  cilium_srv6_localep_verdict_t v;

  v = cilium_srv6_localep_decide_add (req->attachment_id, req->id_len, req->if_incarnation,
				      binding);
  if (v != CILIUM_SRV6_LOCALEP_ACCEPT)
    return v;

  if (!entry.present)
    return CILIUM_SRV6_LOCALEP_ACCEPT;

  if (cilium_srv6_localep_tuple_equal (req, &entry.tuple))
    return CILIUM_SRV6_LOCALEP_ACCEPT_IDEMPOTENT;

  return CILIUM_SRV6_LOCALEP_REJECT_CONFLICT;
}

/*
 * Check the shape of one DELETE before anything is looked up (D-88):
 *
 *	LocalEndpoint DELETE MUST identify the exact currently installed
 *	semantic endpoint instance. An empty attachment_id or wildcard delete
 *	MUST be rejected.
 *
 * An empty attachment_id was the unverified form before D-88 - the D-70 orphan
 * sweep's, when srv6_local_ep_details carried no attachment to quote. The dump
 * reports one now, so every caller has the identity of what it removes and
 * there is no caller left for a form that removes whatever a handle names.
 *
 * It is separate from cilium_srv6_localep_decide_del so that the caller can
 * refuse a malformed DELETE before it consults the interface: a wildcard is
 * refused as a wildcard, not answered with an interface error that a caller
 * might read as "already gone".
 */
static_always_inline cilium_srv6_localep_verdict_t
cilium_srv6_localep_check_del_request (const cilium_srv6_localep_tuple_t *req)
{
  if (req->id_len == 0)
    return CILIUM_SRV6_LOCALEP_REJECT_ID_EMPTY;

  if (!cilium_srv6_ifbind_id_valid (req->attachment_id, req->id_len))
    return CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID;

  if (cilium_srv6_localep_ip_is_unspecified (req->ip))
    return CILIUM_SRV6_LOCALEP_REJECT_ADDRESS_UNSPECIFIED;

  return CILIUM_SRV6_LOCALEP_ACCEPT;
}

/*
 * Decide one DELETE (errata #34 items 200 and 202, D-88).
 *
 * The DELETE removes the installed entry only if it is the exact instance the
 * DELETE names: the same attachment, the same interface lifetime, the same
 * address, the same identity, the same Context and the same quota class.
 * Address + attachment + handle is the minimum D-88 sets; identity and Context
 * are in the match because the message carries them, and quota class because
 * the tuple an ADD is compared against carries it and one definition of "the
 * same instance" serves both directions. That closes the one path the minimum
 * leaves: an identity change (D-69) keeps the attachment, the handle and the
 * address, so a DELETE of the old identity's entry that arrived after the new
 * entry was installed would otherwise remove the successor.
 *
 * It is compared against the *entry*, not against the binding table. A
 * withdrawal has to work when the binding is already gone - that is the
 * ordinary Pod teardown, and the interface delete callback removes the binding
 * in the same event that frees the index - so consulting the binding here
 * would make a removal depend on the thing whose disappearance motivates it.
 * It is the same reason cilium_srv6_ifbind_decide_del does not consult the
 * interface.
 */
static_always_inline cilium_srv6_localep_verdict_t
cilium_srv6_localep_decide_del (const cilium_srv6_localep_tuple_t *req,
				cilium_srv6_localep_entry_t entry)
{
  cilium_srv6_localep_verdict_t v;

  v = cilium_srv6_localep_check_del_request (req);
  if (v != CILIUM_SRV6_LOCALEP_ACCEPT)
    return v;

  if (!entry.present)
    return CILIUM_SRV6_LOCALEP_REJECT_NO_ENTRY;

  if (!cilium_srv6_localep_tuple_equal (req, &entry.tuple))
    return CILIUM_SRV6_LOCALEP_REJECT_OTHER_INSTANCE;

  return CILIUM_SRV6_LOCALEP_ACCEPT;
}

#endif /* __included_cilium_srv6_localep_rules_h__ */
