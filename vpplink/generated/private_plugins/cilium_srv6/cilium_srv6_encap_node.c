/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — cilium-srv6-encap (C7), dataplane.
 *
 * design/detail/02-headend-dataplane.md §6:
 *
 *   1. conntrack update (§7): create/refresh the egress flow entry
 *   2. flow entropy hash (01 §4)
 *   3. prepend the outer IPv6 header (DA = path.da_template, Next Header 41,
 *      Flow Label = hash)
 *   4. if srh_len > 0, insert the SRH (Next Header 43)
 *   5. -> ip6-output
 *
 * plus the inner MTU rule of §9, which runs before any of it:
 * "encap 前に inner length > 有効値なら ICMPv6 PTB を source Pod へ返し、
 * packet を drop する (DROP_INNER_MTU_EXCEEDED)". The effective value is
 * min(PathCache.base_mtu, PathMtuTable[path_id].effective_mtu) — the D-21
 * split between the immutable handle and the mutable learned value. Learning
 * that value (PTB validation, RecentTx correlation, decay) belongs to the
 * PMTUD work; generating the PTB itself is reached through
 * cilium_srv6_ptb_send_hook.
 *
 * The outer header carries no upper layer header, so there is no checksum to
 * compute (01 §3). A future encryption layer (01 §6) is inserted between
 * steps 2 and 3.
 *
 * DEVIATION (next node). 02 §1 draws the arc as "-> ip6-output -> NIC". This
 * node hands the packet to ip6-lookup instead, because nothing in the design
 * defines an adjacency for the outer destination — the DA comes from a
 * PathCache template, not from a resolved next hop — and ip6-output requires
 * one (vnet_buffer(b)->ip.adj_index[VLIB_TX]). ip6-lookup resolves the outer
 * DA in the underlay FIB and dispatches to ip6-rewrite -> ip6-output -> NIC,
 * which is the same wire behaviour with one FIB lookup that the design's
 * shorthand leaves implicit. The FIB it looks in is the configured outer
 * table (srv6_headend_config_set), not the Pod interface's.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_types.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_pmtud.h>
#include <cilium_srv6/cilium_srv6.api_enum.h>

typedef enum
{
  CILIUM_SRV6_ENCAP_NEXT_DROP,
  CILIUM_SRV6_ENCAP_NEXT_LOOKUP,
  CILIUM_SRV6_ENCAP_N_NEXT,
} cilium_srv6_encap_next_t;

typedef enum
{
  CILIUM_SRV6_ENCAP_OK = 0,
  CILIUM_SRV6_ENCAP_NOT_READY,
  CILIUM_SRV6_ENCAP_STALE_PATH,
  CILIUM_SRV6_ENCAP_MTU_EXCEEDED,
  CILIUM_SRV6_ENCAP_PATH_UNUSABLE,
  CILIUM_SRV6_ENCAP_NO_HEADROOM,
  CILIUM_SRV6_ENCAP_N_VERDICT,
} cilium_srv6_encap_verdict_t;

typedef struct
{
  u32 path_cache_index;
  u32 path_generation;
  u32 flow_label;
  u32 inner_length;
  u32 effective_mtu;
  u8 verdict;
  u8 srh_len;
  ip6_address_t da;
  /* 06 §6 asks the headend trace to carry the Service SID. It is not the
     same address as `da` whenever the path carries an SRH or a C-SID
     compressed tail: `da` is the first hop the packet is sent to, the
     Service SID is the End.Cilium instance that finally resolves the
     Context (01 §2.3). Tracing only `da` cannot answer "which endpoint was
     this packet actually addressed to". */
  ip6_address_t service_sid;
} cilium_srv6_encap_trace_t;

/* `static inline`: see the note in cilium_srv6_guard_node.c. */
static inline u8 *
format_cilium_srv6_encap_verdict (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_ENCAP_OK:
      return format (s, "encapsulated");
    case CILIUM_SRV6_ENCAP_NOT_READY:
      return format (s, "drop (DROP_SRV6_NOT_READY: headend not configured)");
    case CILIUM_SRV6_ENCAP_STALE_PATH:
      return format (s, "drop (path handle no longer resolves)");
    case CILIUM_SRV6_ENCAP_MTU_EXCEEDED:
      return format (s, "drop (DROP_INNER_MTU_EXCEEDED)");
    case CILIUM_SRV6_ENCAP_PATH_UNUSABLE:
      return format (s, "drop (DROP_INNER_MTU_EXCEEDED: path unusable, "
			"learned MTU leaves less than 1280 bytes)");
    case CILIUM_SRV6_ENCAP_NO_HEADROOM:
      return format (s, "drop (no headroom for the outer header)");
    default:
      return format (s, "unknown(%u)", v);
    }
}

static inline u8 *
format_cilium_srv6_encap_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cilium_srv6_encap_trace_t *t = va_arg (*args, cilium_srv6_encap_trace_t *);

  s = format (s,
	      "cilium-srv6-encap: path %d gen %u da %U srh %u bytes\n"
	      "  service sid %U\n"
	      "  inner %u bytes, effective mtu %u, flow label 0x%05x, "
	      "verdict %U",
	      (t->path_cache_index == (u32) ~0) ? -1 : (int) t->path_cache_index,
	      t->path_generation, format_ip6_address, &t->da, (u32) t->srh_len, format_ip6_address,
	      &t->service_sid, t->inner_length, t->effective_mtu, t->flow_label,
	      format_cilium_srv6_encap_verdict, (u32) t->verdict);
  return s;
}

/*
 * One packet of 02 §6. The buffer is only modified once every check has
 * passed, so a dropped packet stays intact for the trace and for the PTB
 * hook, which quotes the inner packet (01 §7).
 */
static_always_inline cilium_srv6_encap_verdict_t
cilium_srv6_encap_one (vlib_main_t *vm, const cilium_srv6_headend_main_t *hm, u32 thread_index,
		       vlib_buffer_t *b, f64 now, cilium_srv6_encap_trace_t *info)
{
  const cilium_srv6_headend_meta_t *meta = cilium_srv6_headend_meta (b);
  const cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b);
  cilium_srv6_ct_egress_fn ct_hook = cilium_srv6_ct_egress_hook;
  const cilium_srv6_path_t *path;
  const ip6_header_t *inner;
  ip6_header_t *outer;
  ip6_address_t inner_src, inner_dst;
  u32 inner_length, overhead, flow_label;
  u16 effective_mtu;
  u8 inner_tc, fragmented;

  info->path_cache_index = pm->path_cache_index;
  info->path_generation = pm->path_generation;
  info->verdict = CILIUM_SRV6_ENCAP_OK;
  info->srh_len = 0;
  info->flow_label = 0;
  info->effective_mtu = 0;
  info->inner_length = 0;
  clib_memset (&info->da, 0, sizeof (info->da));
  clib_memset (&info->service_sid, 0, sizeof (info->service_sid));

  if (PREDICT_FALSE (b->current_length < sizeof (ip6_header_t)))
    return CILIUM_SRV6_ENCAP_NOT_READY;

  /* 01 §1: without a node address and an underlay FIB there is no outer
     header to build. Fail closed rather than emitting a header with an
     unspecified source. */
  if (PREDICT_FALSE (!hm->configured))
    return CILIUM_SRV6_ENCAP_NOT_READY;

  /*
   * D-12: the handle is re-resolved here rather than carried as a pointer,
   * so a path retired between the decision and the encapsulation cannot be
   * dereferenced.
   */
  path = cilium_srv6_path_get (hm, pm->path_cache_index, pm->path_generation);
  if (PREDICT_FALSE (path == NULL))
    return CILIUM_SRV6_ENCAP_STALE_PATH;

  inner = (const ip6_header_t *) vlib_buffer_get_current (b);
  inner_src = inner->src_address;
  inner_dst = inner->dst_address;
  inner_tc = (u8) ((clib_net_to_host_u32 (inner->ip_version_traffic_class_and_flow_label) >> 20) &
		   0xff);

  inner_length = (u32) vlib_buffer_length_in_chain (vm, b);
  effective_mtu = cilium_srv6_path_effective_mtu (hm, path);

  info->srh_len = path->srh_len;
  info->da = path->da_template;
  info->service_sid = path->service_sid;
  info->inner_length = inner_length;
  info->effective_mtu = effective_mtu;

  /*
   * 02 §9. The check runs before the conntrack update so that a packet that
   * is going to be dropped does not create flow state; the PTB tells the Pod
   * to resend a smaller packet, which will then create the entry.
   *
   * An effective MTU of 0 is the "path unusable" state of 02 §9: a validated
   * PTB proved that this path cannot carry even a 1280 byte inner packet.
   * There is no legal MTU to advertise below the IPv6 minimum, so the packet
   * fails closed without a PTB and the reconciler is expected to move the
   * flow to an alternative or direct path.
   */
  if (PREDICT_FALSE (effective_mtu == 0))
    return CILIUM_SRV6_ENCAP_PATH_UNUSABLE;

  if (PREDICT_FALSE (inner_length > (u32) effective_mtu))
    {
      cilium_srv6_ptb_send_fn ptb = cilium_srv6_ptb_send_hook;

      if (ptb != 0)
	ptb (vm, b, effective_mtu);

      return CILIUM_SRV6_ENCAP_MTU_EXCEEDED;
    }

  overhead = (u32) sizeof (ip6_header_t) + (u32) path->srh_len;

  /* vlib_buffer_advance() backwards is only legal inside the pre-data area.
     current_data is signed, so the comparison has to be as well. */
  if (PREDICT_FALSE (b->current_data < (i16) overhead))
    return CILIUM_SRV6_ENCAP_NO_HEADROOM;

  /* 02 §6 step 1 (C10). Skipped while no conntrack is registered; the buffer
     still starts at the inner IPv6 header here, so the hook can read the
     inner 5-tuple from it. */
  if (PREDICT_FALSE (ct_hook != 0))
    {
      cilium_srv6_ct_query_t q;

      q.src_identity = meta->src_identity;
      q.local_context_id = meta->local_context_id;
      q.owner_quota_class = meta->owner_quota_class;
      q.policy_revision = cilium_srv6_policy_revision (hm, meta->policy_rev_slot);
      q.endpoint_revision = hm->endpoint_revision;
      q.path_revision = hm->path_revision;
      q.now = now;

      ct_hook (vm, thread_index, b, &q);
    }

  /*
   * 02 §6 step 2 / 01 §4. A fragmented datagram hashes (src, dst, id, next
   * header) so that every fragment carries the same label and transit ECMP
   * keeps them on one path.
   */
  fragmented =
    (meta->flags & (CILIUM_SRV6_META_F_FRAG_FIRST | CILIUM_SRV6_META_F_FRAG_NON_FIRST)) ? 1 : 0;

  /* The fragment hash uses the Fragment header's Next Header, which is what
     every fragment of the datagram carries, rather than the upper layer
     protocol the first fragment additionally exposes. */
  flow_label = cilium_srv6_flow_label (hm, &inner_src, &inner_dst,
				       fragmented ? pm->frag_next_header : meta->proto, pm->sport,
				       pm->dport, meta->frag_id, fragmented);
  info->flow_label = flow_label;

  /* 02 §6 steps 3 and 4. */
  vlib_buffer_advance (b, -(word) overhead);
  outer = (ip6_header_t *) vlib_buffer_get_current (b);

  outer->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (
    (0x6 << 28) | ((u32) (hm->copy_dscp ? (inner_tc & 0xfc) : 0) << 20) | flow_label);
  outer->payload_length = clib_host_to_net_u16 ((u16) (inner_length + path->srh_len));
  outer->protocol = path->srh_len ? IP_PROTOCOL_IPV6_ROUTE : IP_PROTOCOL_IPV6;
  outer->hop_limit = hm->hop_limit;
  outer->src_address = hm->node_address;
  outer->dst_address = path->da_template;

  if (PREDICT_FALSE (path->srh_len != 0))
    clib_memcpy_fast ((u8 *) (outer + 1), path->srh_template, path->srh_len);

  /* ip6-lookup takes the FIB from sw_if_index[VLIB_TX] when it is not ~0, so
     the outer destination is resolved in the underlay table rather than in
     the Pod interface's. */
  vnet_buffer (b)->sw_if_index[VLIB_TX] = hm->outer_fib_index;

  /*
   * 02 §9 / D-21: record what a transit node could quote back, so that an
   * ICMPv6 PTB for this packet can be correlated to this path.
   *
   * Only packets larger than the IPv6 minimum link MTU are recorded: RFC 8200
   * requires every link to carry 1280 bytes, so no conforming router can
   * report a Packet Too Big for a smaller one, and 02 §9 refuses a reported
   * MTU below 1280 in any case. That keeps the common small-packet path out
   * of the RecentTx table entirely.
   */
  if (PREDICT_FALSE (inner_length + overhead > CILIUM_SRV6_PMTUD_RECORD_MIN_SIZE))
    {
      cilium_srv6_pmtud_tx_t tx;

      tx.path_id = path->path_id;
      tx.mtu_index = path->mtu_index;
      tx.path_index = pm->path_cache_index;
      tx.path_generation = pm->path_generation;
      tx.flow_label = flow_label;
      tx.outer_size = inner_length + overhead;
      tx.owner_quota_class = meta->owner_quota_class;
      tx.overhead = (u16) overhead;
      tx.next_header = outer->protocol;
      tx.pad = 0;
      tx.inner_src = inner_src;
      tx.inner_dst = inner_dst;

      cilium_srv6_pmtud_record_tx (vm, &tx);
    }

  return CILIUM_SRV6_ENCAP_OK;
}

static_always_inline u32
cilium_srv6_encap_error_of_verdict (cilium_srv6_encap_verdict_t v)
{
  switch (v)
    {
    case CILIUM_SRV6_ENCAP_MTU_EXCEEDED:
    case CILIUM_SRV6_ENCAP_PATH_UNUSABLE:
      /* Both are the 06 §2 DROP_INNER_MTU_EXCEEDED reason: the inner packet
	 does not fit. The packet trace distinguishes the two. */
      return CILIUM_SRV6_ENCAP_ERROR_INNER_MTU_EXCEEDED;
    case CILIUM_SRV6_ENCAP_STALE_PATH:
      return CILIUM_SRV6_ENCAP_ERROR_STALE_PATH;
    case CILIUM_SRV6_ENCAP_NO_HEADROOM:
      return CILIUM_SRV6_ENCAP_ERROR_NO_HEADROOM;
    default:
      return CILIUM_SRV6_ENCAP_ERROR_SRV6_NOT_READY;
    }
}

VLIB_NODE_FN (cilium_srv6_encap_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  cilium_srv6_encap_trace_t infos[VLIB_FRAME_SIZE], *in = infos;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_encapsulated = 0;
  f64 now = vlib_time_now (vm);

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      const cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b[0]);
      cilium_srv6_encap_verdict_t v;

      v = cilium_srv6_encap_one (vm, hm, thread_index, b[0], now, in);
      in->verdict = (u8) v;

      if (PREDICT_TRUE (v == CILIUM_SRV6_ENCAP_OK))
	{
	  cilium_srv6_program_t *e = cilium_srv6_program_at (hm, pm->program_index);

	  /* 02 §4.1 per-entry byte counter. A reply that bypassed the
	     ProgramCache (D-47) or a fragment forwarded from the
	     FragmentVerdictCache has no entry to charge. */
	  if (e != NULL && e->in_use)
	    e->bytes += in->inner_length;

	  next[0] = CILIUM_SRV6_ENCAP_NEXT_LOOKUP;
	  n_encapsulated++;
	}
      else
	{
	  b[0]->error = node->errors[cilium_srv6_encap_error_of_verdict (v)];
	  next[0] = CILIUM_SRV6_ENCAP_NEXT_DROP;
	}

      b += 1;
      next += 1;
      in += 1;
      n_left -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      u32 i;

      b = bufs;
      in = infos;

      for (i = 0; i < frame->n_vectors; i++, b++, in++)
	{
	  cilium_srv6_encap_trace_t *t;

	  if (!(b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    continue;

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  *t = *in;
	}
    }

  vlib_node_increment_counter (vm, node->node_index, CILIUM_SRV6_ENCAP_ERROR_ENCAPSULATED,
			       n_encapsulated);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cilium_srv6_encap_node) = {
  .name = "cilium-srv6-encap",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_cilium_srv6_encap_trace,
  .format_buffer = format_ip6_header,
  .n_errors = CILIUM_SRV6_ENCAP_N_ERROR,
  .error_counters = cilium_srv6_encap_error_counters,
  .n_next_nodes = CILIUM_SRV6_ENCAP_N_NEXT,
  .next_nodes = {
    [CILIUM_SRV6_ENCAP_NEXT_DROP] = "ip6-drop",
    [CILIUM_SRV6_ENCAP_NEXT_LOOKUP] = "ip6-lookup",
  },
};
