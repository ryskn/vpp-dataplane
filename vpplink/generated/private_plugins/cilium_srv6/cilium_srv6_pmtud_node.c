/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — cilium-srv6-ptb (C7, #20), dataplane.
 *
 * design/detail/02-headend-dataplane.md §9, outer direction:
 *
 *   "transit PTB受信: ICMPv6 checksum、quoted outer SA、lengthを検証し、
 *    invoking packet prefixがRecentTx stateに一致することを必須とする。
 *    shift済みDAはPathCache.expected_shift_states/SRHと照合し、RFC 9800 §9.4
 *    相当の処理でService SIDを復元する。曖昧・古い・未送信の引用は無視する。"
 *
 * Where this node sits and why.
 *
 * A transit-originated PTB is addressed to this node's node address (it is
 * the source address of the packet that was too big), so it arrives as
 *
 *   ip6-input -> ip6-lookup -> ip6-local -> ip6-icmp-input -> here
 *
 * That path gives three properties the design asks for and that a feature
 * arc on the ingress interface would not:
 *
 *   1. ip6-local validates the ICMPv6 checksum before dispatching, so 02 §9's
 *      checksum requirement is already met (see the comment in VPP's
 *      icmp6.c: "Checksum is already validated by ip6_local node").
 *   2. ip6-icmp-input rejects an invalid code for the type and a message
 *      shorter than the ICMPv6 header.
 *   3. only packets actually addressed to a local address get here, so a
 *      PTB aimed at some other node is never considered.
 *
 * The ingress interface is still known at this point
 * (vnet_buffer(b)->sw_if_index[VLIB_RX] survives ip6-local), which is what
 * D-36 (a) needs: the design's "trusted fabric ingress のみ" is enforced
 * here, on the receiving interface's trust classification, not by where the
 * node is attached.
 *
 * The node is a tap: whatever the verdict, the packet continues to ip6-punt,
 * which is exactly where an ICMPv6 Packet Too Big went before this plugin
 * registered for the type (icmp6_init leaves every unclaimed type pointing
 * at ip6-punt). Learning from a PTB never changes what VPP does with it.
 *
 * Design references:
 *   design/detail/02-headend-dataplane.md §9
 *   design/detail/01-packet-format.md §2 (CSID container), §7 (PTB format)
 *   design/detail/00-overview.md §2 (D-16, D-21, D-36)
 *   design/detail/06-observability.md §3 (ptb_rejected_total by reason)
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_pmtud.h>
#include <cilium_srv6/cilium_srv6.api_enum.h>

typedef enum
{
  CILIUM_SRV6_PTB_NEXT_PUNT,
  CILIUM_SRV6_PTB_N_NEXT,
} cilium_srv6_ptb_next_t;

typedef struct
{
  u32 rx_sw_if_index;
  u32 shift_state;
  u32 learned_mtu;
  u64 path_id;
  u8 verdict;
} cilium_srv6_ptb_trace_t;

/* `static inline`: see the note in cilium_srv6_guard_node.c. */
static inline u8 *
format_cilium_srv6_ptb_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cilium_srv6_ptb_trace_t *t = va_arg (*args, cilium_srv6_ptb_trace_t *);

  s = format (s,
	      "cilium-srv6-ptb: rx sw_if_index %u, path_id 0x%016llx, "
	      "shift state %u, learned inner mtu %u\n"
	      "  %U",
	      t->rx_sw_if_index, (unsigned long long) t->path_id, t->shift_state, t->learned_mtu,
	      format_cilium_srv6_ptb_verdict, (u32) t->verdict);
  return s;
}

/*
 * One error counter per verdict, so that 06 §3's `ptb_rejected_total` can be
 * broken down by reason without any additional plumbing.
 */
static_always_inline u32
cilium_srv6_ptb_counter_of (cilium_srv6_ptb_verdict_t v)
{
  switch (v)
    {
    case CILIUM_SRV6_PTB_ACCEPTED:
      return CILIUM_SRV6_PTB_ERROR_ACCEPTED;
    case CILIUM_SRV6_PTB_ACCEPTED_UNUSABLE:
      return CILIUM_SRV6_PTB_ERROR_PATH_UNUSABLE;
    case CILIUM_SRV6_PTB_NOT_READY:
      return CILIUM_SRV6_PTB_ERROR_NOT_READY;
    case CILIUM_SRV6_PTB_UNTRUSTED_INGRESS:
      return CILIUM_SRV6_PTB_ERROR_UNTRUSTED_INGRESS;
    case CILIUM_SRV6_PTB_SOURCE_NOT_IN_DOMAIN:
      return CILIUM_SRV6_PTB_ERROR_SOURCE_NOT_IN_DOMAIN;
    case CILIUM_SRV6_PTB_MALFORMED:
      return CILIUM_SRV6_PTB_ERROR_MALFORMED;
    case CILIUM_SRV6_PTB_QUOTE_NOT_OURS:
      return CILIUM_SRV6_PTB_ERROR_QUOTE_NOT_OURS;
    case CILIUM_SRV6_PTB_NO_RECORD:
      return CILIUM_SRV6_PTB_ERROR_NO_RECORD;
    case CILIUM_SRV6_PTB_STALE_RECORD:
      return CILIUM_SRV6_PTB_ERROR_STALE_RECORD;
    case CILIUM_SRV6_PTB_SIZE_MISMATCH:
      return CILIUM_SRV6_PTB_ERROR_SIZE_MISMATCH;
    case CILIUM_SRV6_PTB_STALE_PATH:
      return CILIUM_SRV6_PTB_ERROR_STALE_PATH;
    case CILIUM_SRV6_PTB_DA_MISMATCH:
      return CILIUM_SRV6_PTB_ERROR_DA_MISMATCH;
    case CILIUM_SRV6_PTB_INNER_MISMATCH:
      return CILIUM_SRV6_PTB_ERROR_INNER_MISMATCH;
    default:
      return CILIUM_SRV6_PTB_ERROR_MTU_OUT_OF_RANGE;
    }
}

VLIB_NODE_FN (cilium_srv6_ptb_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  cilium_srv6_ptb_trace_t infos[VLIB_FRAME_SIZE], *in = infos;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 counts[CILIUM_SRV6_PTB_N_VERDICT];
  u32 i;

  clib_memset (counts, 0, sizeof (counts));

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      cilium_srv6_ptb_verdict_t v;
      u32 state = 0, mtu = 0;
      u64 path_id = 0;

      v = cilium_srv6_pmtud_ptb_receive (vm, b[0], &state, &mtu, &path_id);

      in->rx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_RX];
      in->shift_state = state;
      in->learned_mtu = mtu;
      in->path_id = path_id;
      in->verdict = (u8) v;

      if ((u32) v < CILIUM_SRV6_PTB_N_VERDICT)
	counts[v]++;

      /* The node only observes: the packet keeps the disposition it had
	 before the plugin claimed ICMPv6 type 2. */
      next[0] = CILIUM_SRV6_PTB_NEXT_PUNT;

      b += 1;
      next += 1;
      in += 1;
      n_left -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      b = bufs;
      in = infos;

      for (i = 0; i < frame->n_vectors; i++, b++, in++)
	{
	  cilium_srv6_ptb_trace_t *t;

	  if (!(b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    continue;

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  *t = *in;
	}
    }

  for (i = 0; i < CILIUM_SRV6_PTB_N_VERDICT; i++)
    {
      if (counts[i])
	vlib_node_increment_counter (vm, node->node_index,
				     cilium_srv6_ptb_counter_of ((cilium_srv6_ptb_verdict_t) i),
				     counts[i]);
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cilium_srv6_ptb_node) = {
  .name = "cilium-srv6-ptb",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_cilium_srv6_ptb_trace,
  .format_buffer = format_ip6_header,
  .n_errors = CILIUM_SRV6_PTB_N_ERROR,
  .error_counters = cilium_srv6_ptb_error_counters,
  .n_next_nodes = CILIUM_SRV6_PTB_N_NEXT,
  .next_nodes = {
    [CILIUM_SRV6_PTB_NEXT_PUNT] = "ip6-punt",
  },
};
