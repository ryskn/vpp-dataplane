/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — cilium-ep-deliver (C8-b), dataplane.
 *
 * design/detail/03-destination-dataplane.md §6:
 *
 *   1. metadata の {context_id, entry_generation, state} を再検査
 *   2. conntrack: forward entry + reply entry を state=UNVERIFIED で
 *      create/refresh
 *      ★ policy_revision は書かない (sentinel のまま) — D-19/D-45
 *   3. e.pkts/bytes 更新
 *   4. dpo_index (= Pod interface への forwarding object) で TX
 *      (inner dst の FIB lookup は行わない)
 *
 * Step 1 is the D-12 defence against a Context entry being reclaimed while
 * a packet that already captured its handle is in flight; a mismatch is
 * DROP_CONTEXT_RECYCLED (03 §4).
 *
 * Step 2 is C10 and is out of scope for this component, so the call is a
 * registered hook that is skipped while nothing is registered. What the
 * hook can see is deliberately limited to the Context handle, the delivery
 * interface and the (already bounds-checked) inner packet the buffer now
 * starts with: D-45 keeps cluster-global semantic state off the forward
 * path, and D-19/D-45 forbid writing a guessed policy_revision, because the
 * headend reply check of 02 §7.2 would then match it and skip the slow path
 * re-authorisation.
 *
 * Step 4 transmits through the entry's forwarding object. The graph arc to
 * that object's node was resolved when the Context was installed
 * (cilium_srv6_delivery_resolve), so no FIB lookup of the inner destination
 * happens here.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_context.h>
#include <cilium_srv6/cilium_srv6_endcilium.h>
#include <cilium_srv6/cilium_srv6.api_enum.h>

typedef enum
{
  CILIUM_SRV6_EP_DELIVER_NEXT_DROP,
  CILIUM_SRV6_EP_DELIVER_N_NEXT,
} cilium_srv6_ep_deliver_next_t;

typedef struct
{
  u32 context_id;
  u32 pool_index;
  u32 entry_generation;
  u32 tx_sw_if_index;
  u32 next_index;
  u8 recycled;
} cilium_srv6_deliver_trace_t;

/* `static inline`: see the note in cilium_srv6_guard_node.c. */
static inline u8 *
format_cilium_srv6_deliver_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cilium_srv6_deliver_trace_t *t = va_arg (*args, cilium_srv6_deliver_trace_t *);

  if (t->recycled)
    return format (s,
		   "cilium-ep-deliver: ctx 0x%08x pool %u gen %u "
		   "drop (DROP_CONTEXT_RECYCLED)",
		   t->context_id, t->pool_index, t->entry_generation);

  return format (s,
		 "cilium-ep-deliver: ctx 0x%08x pool %u gen %u "
		 "tx sw_if_index %u next %u",
		 t->context_id, t->pool_index, t->entry_generation, t->tx_sw_if_index,
		 t->next_index);
}

VLIB_NODE_FN (cilium_srv6_ep_deliver_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  const cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;
  cilium_srv6_ct_create_fn ct_hook = cilium_srv6_ct_create_hook;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_delivered = 0;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      const cilium_srv6_deliver_meta_t *m = cilium_srv6_deliver_meta (b[0]);
      cilium_srv6_context_entry_t *e;
      u32 next_index;

      /*
       * 03 §4 / §6 step 1. cilium_srv6_context_handle_valid() checks the
       * {pool_index, context_id, entry_generation} triple and the ACTIVE
       * state in one pass, which also catches an entry that moved to
       * SUSPENDED between the two nodes.
       */
      if (PREDICT_FALSE (
	    !cilium_srv6_context_handle_valid (m->pool_index, m->context_id, m->entry_generation)))
	{
	  b[0]->error = node->errors[CILIUM_SRV6_EP_DELIVER_ERROR_CONTEXT_RECYCLED];
	  next[0] = CILIUM_SRV6_EP_DELIVER_NEXT_DROP;
	  goto next_packet;
	}

      next_index = cilium_srv6_delivery_next_get (em, m->pool_index);
      if (PREDICT_FALSE (next_index == (u32) ~0))
	{
	  /* The handle validated but the delivery arc is gone: the entry is
	     being reclaimed. Same fail-closed classification. */
	  b[0]->error = node->errors[CILIUM_SRV6_EP_DELIVER_ERROR_CONTEXT_RECYCLED];
	  next[0] = CILIUM_SRV6_EP_DELIVER_NEXT_DROP;
	  goto next_packet;
	}

      e = cilium_srv6_context_entry_at (m->pool_index);

      /* 03 §6 step 2 (C10). Skipped while no conntrack is registered. */
      if (PREDICT_FALSE (ct_hook != 0))
	{
	  cilium_srv6_ct_ctx_t c;

	  c.context_id = m->context_id;
	  c.entry_generation = m->entry_generation;
	  c.pool_index = m->pool_index;
	  c.tx_sw_if_index = e->tx_sw_if_index;

	  ct_hook (vm, thread_index, b[0], &c);
	}

      /*
       * 03 §6 step 3. The per-entry counters live in the pool entry
       * (03 §2), so several workers delivering to the same endpoint update
       * the same two words without a lock; this can under-count under
       * concurrency but never affects forwarding.
       */
      e->pkts += 1;
      e->bytes += vlib_buffer_length_in_chain (vm, b[0]);

      /* 03 §6 step 4: transmit on the entry's interface. No FIB lookup of
	 the inner destination is performed. */
      vnet_buffer (b[0])->sw_if_index[VLIB_TX] = e->tx_sw_if_index;
      next[0] = (u16) next_index;
      n_delivered++;

    next_packet:
      b += 1;
      next += 1;
      n_left -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      u32 i;

      b = bufs;
      next = nexts;

      for (i = 0; i < frame->n_vectors; i++, b++, next++)
	{
	  const cilium_srv6_deliver_meta_t *m;
	  cilium_srv6_deliver_trace_t *t;

	  if (!(b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    continue;

	  m = cilium_srv6_deliver_meta (b[0]);
	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));

	  t->context_id = m->context_id;
	  t->pool_index = m->pool_index;
	  t->entry_generation = m->entry_generation;
	  t->next_index = next[0];
	  t->recycled = (next[0] == CILIUM_SRV6_EP_DELIVER_NEXT_DROP) ? 1 : 0;
	  t->tx_sw_if_index = vnet_buffer (b[0])->sw_if_index[VLIB_TX];
	}
    }

  vlib_node_increment_counter (vm, node->node_index, CILIUM_SRV6_EP_DELIVER_ERROR_DELIVERED,
			       n_delivered);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cilium_srv6_ep_deliver_node) = {
  .name = "cilium-ep-deliver",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_cilium_srv6_deliver_trace,
  .format_buffer = format_ip6_header,
  .n_errors = CILIUM_SRV6_EP_DELIVER_N_ERROR,
  .error_counters = cilium_srv6_ep_deliver_error_counters,
  .n_next_nodes = CILIUM_SRV6_EP_DELIVER_N_NEXT,
  .next_nodes = {
    [CILIUM_SRV6_EP_DELIVER_NEXT_DROP] = "ip6-drop",
  },
};
