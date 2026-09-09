/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — infrastructure guard / ACL (C8-a), dataplane.
 *
 * The match/action table implemented here is design/detail/
 * 03-destination-dataplane.md §1.1:
 *
 *   trust = guard_trust_map[(rx_sw_if_index, rx_if_incarnation)]   (D-31)
 *
 *   if (trust == UNTRUSTED):
 *       if (ip6.dst ∈ SRV6_BLOCK)                → DROP_SID_BLOCK_INJECTION
 *       if (ip6.next_header == 43, Routing)    → DROP_SID_BLOCK_INJECTION
 *       bounded EH walk (01 §3.1, cilium_srv6_gparse.h); SRV6_BLOCK
 *       appearing in the first inner DA also drops, and the D-54 fragment
 *       branch decides what an offset-zero fragment has to show
 *   if (trust == QUARANTINED):
 *       if (ip6.dst ∈ SRV6_BLOCK)                → DROP_SID_BLOCK_QUARANTINED
 *   if (trust == TRUSTED_FABRIC):
 *       pass
 *
 * Note on RFC 8754 §5.1 (SEC-1): what §5.1 actually mandates is ingress
 * filtering of packets whose *outer* destination is inside the SID block —
 * the first comparison above. The inner IPv6 / header-chain inspection this
 * node adds on top is a defence in depth specific to this design, motivated
 * by shared-underlay deployments where a packet a Pod sent outside the SID
 * block can be rewritten or decapsulated on the way and re-enter as a SID
 * Block destined packet (D-32). It is not a restatement of SEC-1.
 *
 * Note on the SRH segment list scan: D-32 states that an untrusted ingress
 * drops Routing Type 4 unconditionally, "1 比較". Because *any* Routing
 * header encountered in the chain is dropped before its segment list can
 * be reached, an explicit segment-list scan would be unreachable code. The
 * segment list check is therefore subsumed by the Routing header drop,
 * which is strictly stronger.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/feature/feature.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_types.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6.api_enum.h>

typedef struct
{
  u32 sw_if_index;
  u32 if_incarnation;
  u8 trust;
  u8 verdict;
  ip6_address_t dst;
} cilium_srv6_guard_trace_t;

typedef enum
{
  CILIUM_SRV6_GUARD_NEXT_DROP,
  CILIUM_SRV6_GUARD_N_NEXT,
} cilium_srv6_guard_next_t;

/* `static inline`: under a CLIB_MARCH_VARIANT build VLIB_REGISTER_NODE
 * collapses to an unused declaration, so a plain `static` function
 * referenced only from the registration would trip -Wunused-function. */
static inline u8 *
format_cilium_srv6_guard_verdict (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_GUARD_PASS:
      return format (s, "pass");
    case CILIUM_SRV6_GUARD_PASS_NON_FIRST_FRAGMENT:
      return format (s, "pass (non-first fragment, not inspectable)");
    case CILIUM_SRV6_GUARD_DROP_BLOCK_DA:
      return format (s, "drop (dst in SRV6_BLOCK)");
    case CILIUM_SRV6_GUARD_DROP_ROUTING_HDR:
      return format (s, "drop (IPv6 Routing header, RFC 8754 SEC-1)");
    case CILIUM_SRV6_GUARD_DROP_INNER_BLOCK_DA:
      return format (s, "drop (inner dst in SRV6_BLOCK)");
    case CILIUM_SRV6_GUARD_DROP_QUARANTINED:
      return format (s, "drop (quarantined interface)");
    case CILIUM_SRV6_GUARD_DROP_MALFORMED:
      return format (s, "drop (bounded parser limit / length mismatch)");
    case CILIUM_SRV6_GUARD_DROP_UNINSPECTABLE_FRAGMENT:
      return format (s, "drop (offset-zero fragment, header chain not fully "
			"inspectable, D-54)");
    case CILIUM_SRV6_GUARD_DROP_FRAGMENT_NOT_PERMITTED:
      return format (s, "drop (fragment on untrusted ingress, "
			"untrusted-fragment-drop-all)");
    default:
      return format (s, "unknown(%u)", v);
    }
}

static inline u8 *
format_cilium_srv6_guard_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cilium_srv6_guard_trace_t *t = va_arg (*args, cilium_srv6_guard_trace_t *);

  s = format (s,
	      "cilium-srv6-guard: rx sw_if_index %u incarnation %u trust %U "
	      "dst %U verdict %U",
	      t->sw_if_index, t->if_incarnation, format_cilium_srv6_trust, (u32) t->trust,
	      format_ip6_address, &t->dst, format_cilium_srv6_guard_verdict, (u32) t->verdict);
  return s;
}

/*
 * One trust map lookup per packet (03 §1 NFR-5 budget). TRUSTED_FABRIC is
 * decided by that single lookup; the bounded header walk
 * (cilium_srv6_gparse.h) only runs on the untrusted side.
 */
static_always_inline cilium_srv6_guard_verdict_t
cilium_srv6_guard_inspect (const cilium_srv6_main_t *cm, u8 trust, const ip6_header_t *ip,
			   u32 avail)
{
  if (PREDICT_TRUE (trust == CILIUM_SRV6_TRUST_TRUSTED_FABRIC))
    return CILIUM_SRV6_GUARD_PASS;

  /* Below this point the outer IPv6 header must be readable. */
  if (PREDICT_FALSE (avail < sizeof (ip6_header_t)))
    return CILIUM_SRV6_GUARD_DROP_MALFORMED;

  if (trust == CILIUM_SRV6_TRUST_QUARANTINED)
    {
      /* M-9: quarantine drops are counted separately from injection
	 attempts, because a fabric interface that lost coverage will drop
	 legitimate packets here. */
      if (cilium_srv6_addr_in_block (cm, &ip->dst_address))
	return CILIUM_SRV6_GUARD_DROP_QUARANTINED;
      return CILIUM_SRV6_GUARD_PASS;
    }

  /* UNTRUSTED */
  if (cilium_srv6_addr_in_block (cm, &ip->dst_address))
    return CILIUM_SRV6_GUARD_DROP_BLOCK_DA;

  if (ip->protocol == IP_PROTOCOL_IPV6_ROUTE)
    return CILIUM_SRV6_GUARD_DROP_ROUTING_HDR;

  return cilium_srv6_guard_scan_untrusted (cm->block_u64, cm->block_mask_u64,
					   cm->untrusted_fragment_drop_all, ip, avail);
}

static_always_inline u32
cilium_srv6_guard_error_of_verdict (cilium_srv6_guard_verdict_t v)
{
  switch (v)
    {
    case CILIUM_SRV6_GUARD_DROP_QUARANTINED:
      return CILIUM_SRV6_GUARD_ERROR_SID_BLOCK_QUARANTINED;
    case CILIUM_SRV6_GUARD_DROP_MALFORMED:
      return CILIUM_SRV6_GUARD_ERROR_MALFORMED_INNER;
    case CILIUM_SRV6_GUARD_DROP_UNINSPECTABLE_FRAGMENT:
      /* D-54: kept apart from malformed_inner. A conformant sender cannot
	 produce an offset-zero fragment with a truncated header chain
	 (RFC 7112), so this counter marks a security-relevant malformed
	 packet — a possible evasion attempt — while malformed_inner also
	 collects ordinary broken packets. */
      return CILIUM_SRV6_GUARD_ERROR_UNINSPECTABLE_FRAGMENT;
    case CILIUM_SRV6_GUARD_DROP_FRAGMENT_NOT_PERMITTED:
      /* D-54 hardening option. Its drops include conformant fragments, so
	 it shares neither the counter nor, since #64, the drop reason with
	 the two above. */
      return CILIUM_SRV6_GUARD_ERROR_FRAGMENT_NOT_PERMITTED;
    default:
      /* DROP_BLOCK_DA / DROP_ROUTING_HDR / DROP_INNER_BLOCK_DA are all
	 injection attempts from an untrusted interface (06 §2). */
      return CILIUM_SRV6_GUARD_ERROR_SID_BLOCK_INJECTION;
    }
}

VLIB_NODE_FN (cilium_srv6_guard_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u8 verdicts[VLIB_FRAME_SIZE], *vd = verdicts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_passed = 0;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      u32 sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      const ip6_header_t *ip = (const ip6_header_t *) vlib_buffer_get_current (b[0]);
      u8 trust = cilium_srv6_trust_get (cm, sw_if_index);
      cilium_srv6_guard_verdict_t v;

      v = cilium_srv6_guard_inspect (cm, trust, ip, (u32) b[0]->current_length);
      vd[0] = (u8) v;

      if (PREDICT_TRUE (v == CILIUM_SRV6_GUARD_PASS ||
			v == CILIUM_SRV6_GUARD_PASS_NON_FIRST_FRAGMENT))
	{
	  vnet_feature_next_u16 (next, b[0]);
	  n_passed++;
	}
      else
	{
	  b[0]->error = node->errors[cilium_srv6_guard_error_of_verdict (v)];
	  next[0] = CILIUM_SRV6_GUARD_NEXT_DROP;
	}

      b += 1;
      next += 1;
      vd += 1;
      n_left -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      u32 i;

      b = bufs;
      vd = verdicts;

      for (i = 0; i < frame->n_vectors; i++, b++, vd++)
	{
	  cilium_srv6_guard_trace_t *t;
	  u32 sw_if_index;

	  if (!(b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    continue;

	  sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->sw_if_index = sw_if_index;
	  t->if_incarnation =
	    (sw_if_index < vec_len (cm->ifs)) ? cm->ifs[sw_if_index].incarnation : ~0;
	  t->trust = cilium_srv6_trust_get (cm, sw_if_index);
	  t->verdict = vd[0];

	  if (b[0]->current_length >= sizeof (ip6_header_t))
	    t->dst = ((const ip6_header_t *) vlib_buffer_get_current (b[0]))->dst_address;
	  else
	    clib_memset (&t->dst, 0, sizeof (t->dst));
	}
    }

  vlib_node_increment_counter (vm, node->node_index, CILIUM_SRV6_GUARD_ERROR_PASSED, n_passed);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cilium_srv6_guard_node) = {
  .name = "cilium-srv6-guard",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_cilium_srv6_guard_trace,
  .format_buffer = format_ip6_header,
  .n_errors = CILIUM_SRV6_GUARD_N_ERROR,
  .error_counters = cilium_srv6_guard_error_counters,
  .n_next_nodes = CILIUM_SRV6_GUARD_N_NEXT,
  .next_nodes = {
    [CILIUM_SRV6_GUARD_NEXT_DROP] = "ip6-drop",
  },
};

/*
 * 03 §1.1 / D-9 / D-24: the guard is a permanent ingress feature. It is
 * enabled on every interface from plugin init (cilium_srv6_guard.c) rather
 * than only on the interfaces the agent classified, so that it works
 * before and without the agent.
 *
 * "ip6-flow-classify" is the head of the built-in ip6-unicast chain
 * (ip6-flow-classify → ip6-inacl → ip6-policer-classify →
 *  ipsec6-input-feature → l2tp-decap → vpath-input-ip6 →
 *  ip6-vxlan-bypass → ip6-lookup), so ordering before it puts the guard
 * transitively before every built-in decap/bypass feature and before
 * ip6-lookup — that is, before anything that could reach the End.Cilium
 * local SID or decapsulate the packet.
 */
VNET_FEATURE_INIT (cilium_srv6_guard_feature, static) = {
  .arc_name = "ip6-unicast",
  .node_name = "cilium-srv6-guard",
  .runs_before = VNET_FEATURES ("ip6-flow-classify"),
};
