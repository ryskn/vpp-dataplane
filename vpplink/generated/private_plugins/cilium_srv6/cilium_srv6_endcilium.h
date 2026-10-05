/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — End.Cilium and endpoint delivery (C8-b).
 *
 * This component adds the destination packet processing itself on top of
 * the infrastructure guard (C8-a) and the EndpointContextTable (C8-c):
 *
 *   ip6-lookup                                  (DA matches Block:uN_B:uC::/64)
 *     -> cilium-end-cilium    03 §3: SR domain source check, Context
 *                             resolution, bounded outer/SRH parse, decap,
 *                             bounded inner parse, inner DA equality
 *     -> cilium-ep-deliver    03 §6: D-12 handle re-check, conntrack hook,
 *                             transmit through the entry's forwarding
 *                             object (no inner FIB lookup)
 *
 * Design references:
 *   design/detail/03-destination-dataplane.md §1 (graph), §1.1 (fail-closed
 *     ladder), §3 (cilium-end-cilium), §5 (inner extraction), §6
 *     (cilium-ep-deliver), §7 (IF-2), §8 (drop reasons), §9 (no hot path
 *     allocation)
 *   design/detail/01-packet-format.md §2.3 (Context ID = DA bit 64..95),
 *     §3 (inner packet), §3.1 (bounded parser), §3.2 (destination length
 *     validation)
 *   design/detail/00-overview.md §2 (D-10, D-12, D-19, D-28, D-32, D-35,
 *     D-45), §6 (constants and address plan invariants)
 *   design/detail/06-observability.md §2 (drop reason names), §3 (metrics)
 */

#ifndef __included_cilium_srv6_endcilium_h__
#define __included_cilium_srv6_endcilium_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/buffer.h>
#include <vnet/dpo/dpo.h>
#include <vnet/fib/fib_source.h>
#include <vnet/ip/ip6_packet.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_context.h>

/*
 * 00 §6 address plan. The End.Cilium local SID is Block:uN_B:uC::/64
 * (LB 32 + LN 16 + F 16), and D-46 invariant 1 requires uN_node to come
 * from GIB_RANGE and uC_* from LIB_RANGE, with the two ranges disjoint.
 * Violating that makes a transit node's /48 uN entry and this /64 entry
 * overlap, so the values are validated before the FIB entry is created.
 */
#define CILIUM_SRV6_LOCALSID_PREFIX_LEN 64
#define CILIUM_SRV6_GIB_FIRST		0x0001
#define CILIUM_SRV6_GIB_LAST		0xbfff
#define CILIUM_SRV6_LIB_FIRST		0xc000
#define CILIUM_SRV6_LIB_LAST		0xfffe

/*
 * 03 §3 / D-32: the outer source address must belong to the SR domain node
 * set. The design specifies "node/transit address 集合との prefix/集合比較
 * 1 回" but 03 §7 originally listed no IF-2 message that carries the set, so
 * this plugin defines the srv6_sr_domain_* messages (see the DEVIATION note in
 * cilium_srv6.api).
 *
 * D-90 (errata #34 item 205): the set has a configurable bounded capacity
 * (`sr-domain-capacity` in the `cilium-srv6` startup stanza) and is replaced
 * only as a whole, by the staged transaction of cilium_srv6_srdomain_rules.h.
 * The prefix type, the hot path predicate and every transaction decision live
 * there; this file holds the two buffers and takes the barrier.
 *
 * An empty set matches nothing, which is the fail-closed state before the
 * agent has configured anything.
 */
#include <cilium_srv6/cilium_srv6_srdomain_rules.h>

/* The bounded parser limits of 01 §3.1 / §3.2 live in
 * cilium_srv6_parse.h, together with the parser itself. */

/* Interval at which the 03 §1.1 readiness monitor process runs. */
#define CILIUM_SRV6_ENDCILIUM_TICK_INTERVAL 1.0

/*
 * Buffer metadata handed from cilium-end-cilium to cilium-ep-deliver.
 *
 * 03 §4 (D-12) requires exactly {pool_index, context_id, entry_generation}
 * plus the ACTIVE state to be re-checked in cilium-ep-deliver, so those
 * three values are what travels; nothing else is trusted across the arc.
 *
 * It lives in the vnet opaque scratch area (vnet_buffer_get_opaque), which
 * is the sanctioned per-plugin space. cilium-ep-deliver terminates the
 * packet on an interface transmit, so the ip.* fields it overlaps (already
 * consumed by ip6-lookup) are not needed downstream.
 */
typedef struct
{
  u32 pool_index;
  u32 context_id;
  u32 entry_generation;
} cilium_srv6_deliver_meta_t;

STATIC_ASSERT (sizeof (cilium_srv6_deliver_meta_t) <= VNET_BUFFER_OPAQUE_SIZE,
	       "cilium-ep-deliver metadata does not fit the vnet opaque scratch area");

static_always_inline cilium_srv6_deliver_meta_t *
cilium_srv6_deliver_meta (vlib_buffer_t *b)
{
  return (cilium_srv6_deliver_meta_t *) vnet_buffer_get_opaque (b);
}

/*
 * Conntrack hook (C10, 03 §6 step 2).
 *
 * C10 (node-local conntrack) is out of scope for this component, so the
 * call site is abstracted as a registered function pointer and skipped
 * while nothing is registered. The buffer passed to the hook has already
 * been decapsulated and bounds-checked, so its current data pointer is the
 * inner IPv6 header and the inner 5-tuple can be read from it.
 *
 * What the hook receives is exactly what the forward path is allowed to
 * know (D-45): the Context handle and the delivery interface. It must NOT
 * be given a policy revision — D-19/D-45 require the entry to be created
 * with state UNVERIFIED and `policy_revision` left at its sentinel, so that
 * the first reply is re-authorised on the receiving node's slow path
 * instead of matching a guessed revision.
 */
typedef struct
{
  u32 context_id;
  u32 entry_generation;
  u32 pool_index;
  u32 tx_sw_if_index;
} cilium_srv6_ct_ctx_t;

typedef void (*cilium_srv6_ct_create_fn) (vlib_main_t *vm, u32 thread_index, vlib_buffer_t *b,
					  const cilium_srv6_ct_ctx_t *ctx);

extern cilium_srv6_ct_create_fn cilium_srv6_ct_create_hook;

/* Register (or, with NULL, unregister) the C10 conntrack entry point. */
void cilium_srv6_ct_register (cilium_srv6_ct_create_fn fn);

typedef struct
{
  /* ---- hot path ---- */

  /* SR domain node address set (03 §3 / D-32), the active buffer of D-90.
   * Its pointer and count change only in cilium_srv6_sr_domain_txn_install
   * under the worker barrier, and its slots are never written while it is
   * active, so a worker reads either the previous complete set or the next
   * one. */
  cilium_srv6_sr_domain_set_t sr_domain;

  /*
   * Graph arc from cilium-ep-deliver to the node of each ACTIVE entry's
   * delivery forwarding object, indexed by ACTIVE pool index.
   *
   * 03 §2 fixes the pool entry at one cache line and it is already full, so
   * the resolved arc is kept in this parallel array rather than in the
   * entry. It is allocated once at start up (03 §9: no hot path
   * allocation) and only written under the worker barrier.
   */
  u32 *delivery_next;

  /* ---- control plane ---- */

  fib_source_t fib_source;
  dpo_type_t dpo_type;

  ip6_address_t localsid; /* Block:uN_B:uC:: (01 §2.3) */
  u32 table_id;
  u32 fib_index;
  u16 un_node;
  u16 uc;

  u8 locator_set;	  /* srv6_uc_locator_set has been applied */
  u8 localsid_installed;  /* the /64 FIB entry exists */
  u8 delivery_suspended;  /* 03 §1.1 fail-closed ladder engaged */
  u8 initialised;

  u64 n_delivery_suspends; /* 06 §3 acl_delivery_suspends_total */
  u64 n_localsid_installs;

  /* D-90: the staging buffer and the transaction identities. Control plane
   * only; no worker reads them. */
  cilium_srv6_sr_domain_txn_t sr_domain_txn;

  u32 process_node_index;
} cilium_srv6_endcilium_main_t;

extern cilium_srv6_endcilium_main_t cilium_srv6_endcilium_main;

extern vlib_node_registration_t cilium_srv6_end_cilium_node;
extern vlib_node_registration_t cilium_srv6_ep_deliver_node;

/*
 * 03 §3 / D-32: outer SA ∈ SR_DOMAIN_NODE_SET, read from the active buffer
 * only (D-90). An empty set returns 0, so a node that has not been told its
 * SR domain drops every packet that reaches the local SID as
 * DROP_UNTRUSTED_SOURCE.
 */
static_always_inline int
cilium_srv6_sr_domain_contains (const cilium_srv6_endcilium_main_t *em, const ip6_address_t *a)
{
  return cilium_srv6_sr_domain_set_contains (&em->sr_domain, a);
}

/*
 * Delivery arc for one ACTIVE pool index (03 §6 step 4). ~0 means the entry
 * has no usable forwarding object, which is treated as a recycled handle.
 */
static_always_inline u32
cilium_srv6_delivery_next_get (const cilium_srv6_endcilium_main_t *em, u32 pool_index)
{
  if (PREDICT_FALSE (pool_index >= vec_len (em->delivery_next)))
    return ~0;

  return em->delivery_next[pool_index];
}

/*
 * Resolve the graph arc from cilium-ep-deliver to `dpo`'s node.
 *
 * MUST be called without the worker barrier held from a barrier section
 * this plugin opened: the underlying dpo_stack_from_node() takes the
 * barrier itself when it has to add a new edge.
 *
 * Returns ~0 if the arc could not be resolved.
 */
u32 cilium_srv6_delivery_resolve (const dpo_id_t *dpo);

/* Store / clear the resolved arc for one pool index. Worker barrier held. */
void cilium_srv6_delivery_set (u32 pool_index, u32 next_index);

/* Control plane entry points (cilium_srv6_endcilium.c). */
int cilium_srv6_sr_domain_publish_begin (u64 txn_id);
int cilium_srv6_sr_domain_publish_put (u64 txn_id, const ip6_address_t *prefix, u32 len);
int cilium_srv6_sr_domain_publish_commit (u64 txn_id, u32 n_prefixes);
int cilium_srv6_sr_domain_publish_abort (u64 txn_id);
int cilium_srv6_uc_locator_set (u32 table_id, u16 un_node, u16 uc, u8 is_add);

u8 *format_cilium_srv6_sr_domain (u8 *s, va_list *args);

#endif /* __included_cilium_srv6_endcilium_h__ */
