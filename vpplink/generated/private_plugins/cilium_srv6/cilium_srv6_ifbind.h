/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — CNI attachment binding table (D-68).
 *
 * The dataplane-side authoritative registry of "which VPP interface is this
 * Pod attachment behind". It answers exactly one question and invents
 * nothing: the component that creates a Pod's VPP interface publishes the
 * binding over IF-2, and the agent reads it back to resolve a stable CNI
 * attachment identity into the (sw_if_index, if_incarnation) handle every
 * local endpoint install is keyed by (D-31).
 *
 * # Why the table is here and not in the agent
 *
 * sw_if_index is an ephemeral dataplane handle: VPP reuses it as soon as an
 * interface is deleted. An agent-side cache of "attachment A is behind index
 * 10" therefore survives the disappearance of the interface it describes, and
 * the next Pod that gets index 10 inherits A's endpoint programming — a
 * misdelivery, not a stale entry. Keeping the registry next to the interface
 * pool makes the two lifetimes the same one: the interface delete callback
 * below removes the binding in the same event that frees the index, and the
 * agent's copy is a snapshot it must re-derive rather than a state it owns.
 *
 * It also survives an agent restart, which an agent-side registry would not.
 *
 * # What it is not
 *
 * It is not an authority over attachment identity. The plugin never derives,
 * completes or guesses an attachment ID; it stores what the publisher wrote
 * and refuses anything ambiguous. The two directions it keeps exact are
 *
 *   attachment_id                  -> exactly one live (sw_if_index, incarnation)
 *   (sw_if_index, incarnation)     -> at most one attachment_id
 *
 * and the decision rules that maintain them are in
 * cilium_srv6_ifbind_rules.h, free of vlib so that they can be exercised as
 * pure functions.
 *
 * Design references:
 *   design/detail/00-overview.md §2.12, D-31, D-68
 *   design/detail/02-headend-dataplane.md §2, §8
 *   design/detail/04-context-allocator.md §5
 */

#ifndef __included_cilium_srv6_ifbind_h__
#define __included_cilium_srv6_ifbind_h__

#include <vlib/vlib.h>
#include <vppinfra/mhash.h>

#include <cilium_srv6/cilium_srv6_ifbind_rules.h>

/* One row of the binding table. */
typedef struct
{
  /* The CNI attachment identity, as published. It is a vector of exactly
     the bytes that were written: it is not NUL terminated and is never
     truncated. */
  u8 *attachment_id;
  u32 sw_if_index;
  u32 if_incarnation;
} cilium_srv6_if_binding_t;

typedef struct
{
  /* Pool of bindings. */
  cilium_srv6_if_binding_t *bindings;

  /* attachment_id -> pool index. mhash with a vector string key: it copies
     the key into its own heap, so the identity is stored once and no caller
     has to keep its buffer alive. */
  mhash_t by_attachment;

  /* sw_if_index -> pool index, ~0 when the interface has no binding. This
     vector is what makes the reverse direction exact without a second hash:
     an sw_if_index has at most one live incarnation at a time, so one slot
     per index is enough to hold "(index, incarnation) -> at most one
     attachment". */
  u32 *by_sw_if_index;

  u32 n_bindings;
  u8 initialised;
} cilium_srv6_ifbind_main_t;

extern cilium_srv6_ifbind_main_t cilium_srv6_ifbind_main;

/*
 * srv6_if_attachment_add_del (IF-2, 02 §8).
 *
 * Returns 0 on success (insert, idempotent repeat or removal) and a
 * VNET_API_ERROR_* value otherwise. Every rejection leaves the table
 * unchanged.
 */
int cilium_srv6_if_attachment_add_del (const u8 *attachment_id, u32 id_len, u32 sw_if_index,
				       u32 if_incarnation, u8 is_add);

/* The binding of one interface, or NULL. Used by the dump handler and the
   CLI; it is not a hot path lookup. */
const cilium_srv6_if_binding_t *cilium_srv6_ifbind_by_sw_if_index (u32 sw_if_index);

/* Map a rules verdict onto the VNET_API_ERROR_* value the .api documents. */
int cilium_srv6_ifbind_verdict_to_api_error (cilium_srv6_ifbind_verdict_t v);

#endif /* __included_cilium_srv6_ifbind_h__ */
