/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — cilium-srv6-punt (C7), dataplane.
 *
 * design/detail/02-headend-dataplane.md §5.1:
 *
 *   VPP: cilium-srv6-punt -> punt socket (packet 全体 + meta{src_identity,
 *        rx_sw_if_index})
 *
 * The admission rules, the one-shot token and the IF-3 metadata layout live
 * in cilium_srv6_punt.c; this node is only the graph end of it. A packet that
 * is accepted is handed to the transport and its buffer is freed here, in the
 * same shape VPP's own punt socket node uses. A packet that is refused —
 * queue full, owner or identity over quota (D-42), or no transport at all —
 * is dropped as DROP_SLOWPATH_OVERFLOW: 02 §5.2 requires the slow path to
 * stay fail-closed, so an overflow never bypasses the miss.
 *
 * Which of the three bounded queues a packet is charged to was decided
 * upstream and travels in the buffer metadata: the compile queue by default,
 * the reply re-authorisation queue for 02 §7.2 branch 2 (D-38), and the
 * fragment queue for a first fragment (D-43).
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6.api_enum.h>

typedef enum
{
  CILIUM_SRV6_PUNT_NEXT_DROP,
  CILIUM_SRV6_PUNT_N_NEXT,
} cilium_srv6_punt_next_t;

typedef struct
{
  u32 src_identity;
  u32 owner_quota_class;
  u8 queue;
  u8 reason;
  u8 punted;
} cilium_srv6_punt_trace_t;

/* `static inline`: see the note in cilium_srv6_guard_node.c. */
static inline u8 *
format_cilium_srv6_punt_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cilium_srv6_punt_trace_t *t = va_arg (*args, cilium_srv6_punt_trace_t *);

  s = format (s, "cilium-srv6-punt: identity %u owner %u queue %U reason %U -> %s",
	      t->src_identity, t->owner_quota_class, format_cilium_srv6_punt_queue, (u32) t->queue,
	      format_cilium_srv6_punt_reason, (u32) t->reason,
	      t->punted ? "agent (IF-3)" : "drop (DROP_SLOWPATH_OVERFLOW)");
  return s;
}

VLIB_NODE_FN (cilium_srv6_punt_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u8 punted[VLIB_FRAME_SIZE], *pt = punted;
  u32 to_free[VLIB_FRAME_SIZE];
  u32 to_drop[VLIB_FRAME_SIZE];
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_free = 0, n_drop = 0, i;

  vlib_get_buffers (vm, from, bufs, n_left);

  /*
   * The trace is taken before the packets are handed over, because an
   * accepted packet's buffer is released as soon as the transport has copied
   * it and a refused one is enqueued to the drop node.
   */
  for (i = 0; i < frame->n_vectors; i++)
    {
      const cilium_srv6_headend_meta_t *meta;
      const cilium_srv6_path_meta_t *pm;
      cilium_srv6_punt_trace_t *t;

      if (!(node->flags & VLIB_NODE_FLAG_TRACE))
	break;

      if (!(bufs[i]->flags & VLIB_BUFFER_IS_TRACED))
	continue;

      meta = cilium_srv6_headend_meta (bufs[i]);
      pm = cilium_srv6_path_meta (bufs[i]);

      t = vlib_add_trace (vm, node, bufs[i], sizeof (*t));
      t->src_identity = meta->src_identity;
      t->owner_quota_class = meta->owner_quota_class;
      t->queue = pm->punt_queue;
      t->reason = pm->punt_reason;
      t->punted = 0;
    }

  while (n_left > 0)
    {
      const cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b[0]);

      pt[0] = cilium_srv6_punt_one (vm, b[0], pm->punt_queue, pm->punt_reason) ? 1 : 0;

      b += 1;
      pt += 1;
      n_left -= 1;
    }

  for (i = 0; i < frame->n_vectors; i++)
    {
      if (punted[i])
	{
	  to_free[n_free++] = from[i];
	  continue;
	}

      /* 02 §5.2: "超過 packet は drop (DROP_SLOWPATH_OVERFLOW)。fail-closed
	 を保つため queue 溢れで bypass しない". */
      bufs[i]->error = node->errors[CILIUM_SRV6_PUNT_ERROR_SLOWPATH_OVERFLOW];
      to_drop[n_drop++] = from[i];
    }

  if (n_free)
    vlib_buffer_free (vm, to_free, n_free);

  if (n_drop)
    vlib_buffer_enqueue_to_single_next (vm, node, to_drop, CILIUM_SRV6_PUNT_NEXT_DROP, n_drop);

  vlib_node_increment_counter (vm, node->node_index, CILIUM_SRV6_PUNT_ERROR_PUNTED, n_free);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cilium_srv6_punt_node) = {
  .name = "cilium-srv6-punt",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_cilium_srv6_punt_trace,
  .format_buffer = format_ip6_header,
  .n_errors = CILIUM_SRV6_PUNT_N_ERROR,
  .error_counters = cilium_srv6_punt_error_counters,
  .n_next_nodes = CILIUM_SRV6_PUNT_N_NEXT,
  .next_nodes = {
    [CILIUM_SRV6_PUNT_NEXT_DROP] = "ip6-drop",
  },
};
