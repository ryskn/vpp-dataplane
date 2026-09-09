/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — drop reason inventory (C5).
 *
 * design/detail/06-observability.md §1:
 *
 *   "drop は必ず理由別 counter に計上する。理由不明の drop counter を
 *    作らない (分類できない drop は実装バグとして扱う)。"
 *
 * A convention cannot enforce that. This file turns it into a checked
 * property: every error counter of every cilium_srv6 graph node is bound to
 * exactly one 06 §2 reason (or explicitly to "not a drop"), the binding
 * tables are sized by the generated N_ERROR constants, and the plugin
 * refuses to initialise when a counter is left unbound or when a table no
 * longer matches the node it describes.
 *
 * Design references:
 *   design/detail/06-observability.md §1 (no unknown drop), §2 (reason
 *     table), §3 (cilium_srv6_drop_total), §4.2 (`show cilium srv6 errors`)
 *   design/detail/02-headend-dataplane.md §8 (srv6_counters_dump)
 *   design/detail/03-destination-dataplane.md §8 (destination reasons)
 */

#ifndef __included_cilium_srv6_counters_h__
#define __included_cilium_srv6_counters_h__

#include <vlib/vlib.h>

/*
 * The 06 §2 reason space.
 *
 * UNSET is value 0 on purpose. The per-node binding tables are written as
 * designated initialisers indexed by error code, so a counter that nobody
 * bound keeps the zero value; making zero an invalid reason is what turns
 * "somebody added a counter and forgot the reason" into an init-time error
 * instead of a silently unclassified drop.
 *
 * NOT_A_DROP is the explicit "this counter does not count a drop" value. It
 * maps to SRV6_DROP_REASON_API_NONE on the wire.
 *
 * The two ENCAP_ reasons are drops 06 §2 has no name for; see the enum
 * comment in cilium_srv6.api.
 *
 * LINK_LOCAL_CONTROL, UNINSPECTABLE_FRAGMENT and FRAGMENT_NOT_PERMITTED are
 * in 06 §2. They are listed last because the list order is the
 * plugin-internal enum order and appending keeps the existing values
 * unchanged; the wire order is the one in cilium_srv6.api.
 *
 * UNINSPECTABLE_FRAGMENT and FRAGMENT_NOT_PERMITTED are the two D-54 guard
 * drops, and #64 keeps them apart. The first is the fail-closed drop of an
 * offset-zero fragment whose security-relevant header chain the guard could
 * not completely verify: a security-relevant malformed packet, i.e. a
 * possible evasion attempt rather than a confirmed one. The second is the
 * `untrusted-fragment-drop-all` hardening option refusing a fragment by
 * administrative policy: an operational signal, zero while the option is
 * off. It is the same separation as SRC_IP_MISMATCH versus
 * LINK_LOCAL_CONTROL above — a candidate security signal does not share a
 * reason label, and therefore a cilium_srv6_drop_total series, with a
 * consequence of the configuration.
 *
 * FRAGMENT_STALE_REINJECT (#90) is the same kind of separation applied to the
 * headend: the drop is not a property of the packets on the wire but of the
 * control plane's answer arriving too late (or for a record this node no
 * longer holds), so folding it into FRAGMENT_UNRESOLVED would make an agent
 * latency problem look like a fragment-ordering problem.
 */
#define foreach_cilium_srv6_drop_reason                                                            \
  _ (NOT_A_DROP, "NOT_A_DROP", "not a drop")                                                       \
  _ (SID_BLOCK_INJECTION, "DROP_SID_BLOCK_INJECTION", "SID Block injection attempt")               \
  _ (SID_BLOCK_QUARANTINED, "DROP_SID_BLOCK_QUARANTINED", "SID Block from a quarantined "          \
								"interface")                       \
  _ (UNTRUSTED_SOURCE, "DROP_UNTRUSTED_SOURCE", "outer SA outside the SR domain")                  \
  _ (UNKNOWN_SOURCE_EP, "DROP_UNKNOWN_SOURCE_EP", "interface/endpoint inconsistency")              \
  _ (SRC_IP_MISMATCH, "DROP_SRC_IP_MISMATCH", "source address spoof by the Pod")                   \
  _ (POLICY_DENIED, "DROP_POLICY_DENIED", "NetworkPolicy DENY or no match")                        \
  _ (SLOWPATH_OVERFLOW, "DROP_SLOWPATH_OVERFLOW", "punt queue or quota refusal")                   \
  _ (NO_REMOTE_ENDPOINT, "DROP_NO_REMOTE_ENDPOINT", "no BGP route or no usable path")              \
  _ (IDENTITY_UNRESOLVED, "DROP_IDENTITY_UNRESOLVED", "cluster endpoint identity unresolved")      \
  _ (FRAGMENT_UNRESOLVED, "DROP_FRAGMENT_UNRESOLVED", "fragment order or verdict cache")           \
  _ (INNER_MTU_EXCEEDED, "DROP_INNER_MTU_EXCEEDED", "inner packet over the effective MTU")          \
  _ (UNKNOWN_CONTEXT, "DROP_UNKNOWN_CONTEXT", "Context ID not allocated")                          \
  _ (INVALID_CONTEXT, "DROP_INVALID_CONTEXT", "tombstone hit, endpoint deleted")                   \
  _ (CONTEXT_RECYCLED, "DROP_CONTEXT_RECYCLED", "defensive D-12 handle re-check")                  \
  _ (MALFORMED_OUTER, "DROP_MALFORMED_OUTER", "outer or SRH structure invalid")                    \
  _ (MALFORMED_INNER, "DROP_MALFORMED_INNER", "inner packet structure invalid")                    \
  _ (CONTEXT_IP_MISMATCH, "DROP_CONTEXT_IP_MISMATCH", "inner DA is not the Context endpoint")       \
  _ (SRV6_NOT_READY, "DROP_SRV6_NOT_READY", "coverage lost, suspended or unconfigured")            \
  _ (ENCAP_STALE_PATH, "DROP_ENCAP_STALE_PATH", "path handle retired under a packet in flight")    \
  _ (ENCAP_NO_HEADROOM, "DROP_ENCAP_NO_HEADROOM", "no buffer headroom for the outer header")       \
  _ (LINK_LOCAL_CONTROL, "DROP_LINK_LOCAL_CONTROL", "IPv6 link control packet on an L3-only "      \
							"Pod attachment (D-50)")                    \
  _ (UNINSPECTABLE_FRAGMENT, "DROP_UNINSPECTABLE_FRAGMENT",                                        \
     "offset-zero fragment whose header chain is not fully inspectable (D-54)")                    \
  _ (FRAGMENT_NOT_PERMITTED, "DROP_FRAGMENT_NOT_PERMITTED",                                        \
     "fragment refused by untrusted-fragment-drop-all (D-54 hardening option)")                     \
  _ (FRAGMENT_STALE_REINJECT, "DROP_FRAGMENT_STALE_REINJECT",                                      \
     "reinjected first fragment with no live reinjection capability (#90)")

typedef enum
{
  CILIUM_SRV6_DROP_UNSET = 0,
#define _(sym, str, desc) CILIUM_SRV6_DROP_##sym,
  foreach_cilium_srv6_drop_reason
#undef _
    CILIUM_SRV6_DROP_N_REASON,
} cilium_srv6_drop_reason_t;

/* One graph node's counter classification. */
typedef struct
{
  /* Registered graph node name, e.g. "cilium-srv6-guard". */
  const char *node_name;
  /* reasons[error_code] is the reason that counter is bound to. */
  const u8 *reasons;
  /* The node's registered descriptors, so that a record can carry the
     counter name, description and severity from the registration rather
     than from a second hand-written copy. */
  const vlib_error_desc_t *descs;
  /* Length of `reasons`, which must equal the node's registered n_errors. */
  u32 n_errors;
  /* Resolved at init; ~0 while the node has not been found. */
  u32 node_index;
} cilium_srv6_counter_node_t;

/* One read-out record: a counter summed over every worker thread. */
typedef struct
{
  const char *node_name;
  const char *counter_name;
  const char *counter_desc;
  u64 value;
  u8 reason;
  u8 severity;
} cilium_srv6_counter_record_t;

/* Reason name ("DROP_...", or "NOT_A_DROP") and one-line description. */
const char *cilium_srv6_drop_reason_name (u8 reason);
const char *cilium_srv6_drop_reason_desc (u8 reason);

/* `%U` formatter for a reason. */
format_function_t format_cilium_srv6_drop_reason;

/*
 * Walk every classified counter of every cilium_srv6 graph node, newest
 * value first summed across workers. `reason_filter` is a
 * cilium_srv6_drop_reason_t, or ~0 for every counter. The callback must not
 * retain the record: the strings point into the node registration.
 */
typedef void (*cilium_srv6_counter_fn) (const cilium_srv6_counter_record_t *r, void *opaque);

void cilium_srv6_counters_foreach (vlib_main_t *vm, u32 reason_filter, cilium_srv6_counter_fn fn,
				   void *opaque);

/* Total per reason, indexed by cilium_srv6_drop_reason_t. `totals` must have
   CILIUM_SRV6_DROP_N_REASON elements. */
void cilium_srv6_counters_totals (vlib_main_t *vm, u64 *totals);

#endif /* __included_cilium_srv6_counters_h__ */
