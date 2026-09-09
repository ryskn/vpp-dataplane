/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — cilium-end-cilium (C8-b), dataplane.
 *
 * design/detail/03-destination-dataplane.md §3, in order:
 *
 *   if (outer.src ∉ SR_DOMAIN_NODE_SET) → drop (DROP_UNTRUSTED_SOURCE)
 *   ctx = be32(DA.bits[64..95])
 *   idx = ActiveContextTable.lookup(ctx)
 *   if (miss && TombstoneTable.lookup(ctx)) → drop (DROP_INVALID_CONTEXT)
 *   if (miss)                               → drop (DROP_UNKNOWN_CONTEXT)
 *   e = pool[idx]
 *   if (e.state != ACTIVE)                  → drop (DROP_SRV6_NOT_READY)
 *   validate outer.payload_length <= buffer_chain_length
 *   if (outer.next_header == 43):
 *       validate routing_type=4, hdr_ext_len, last_entry,
 *                segments_left == 0, segment/TLV bounds, srh.next_header=41
 *   if (outer.next_header != 41 && != 43)   → drop (DROP_MALFORMED_OUTER)
 *   decap
 *   inner checks                            → drop (DROP_MALFORMED_INNER)
 *   if (inner.dst != e.endpoint_ip)         → drop (DROP_CONTEXT_IP_MISMATCH)
 *   → cilium-ep-deliver
 *
 * The Context resolution deliberately runs before the header parse so that
 * invalid traffic is dropped without paying for the parse and the decap
 * (03 §3: "ここまでで無効 traffic は落ちる").
 *
 * Bounded parser rules (01 §3.1 / §3.2). Nothing outside
 * [current_data, current_data + bound) is dereferenced, where
 *
 *   bound = min(first buffer's readable length, 40 + outer payload length)
 *
 * so every field access is preceded by an explicit bound comparison and a
 * declared length that runs past the readable area is a length
 * inconsistency, not a read.
 *
 * Note on PERM_INV (04 §1 / 03 §3): the Context ID taken from the
 * destination address is used as the table key unchanged. 04 §1 defines the
 * wire value as `(epoch << 24) | PERM(node_key, counter)` and states that
 * the permutation is applied once at allocation time and "hot path には
 * 現れない"; srv6_context_add installs that same wire value as the key
 * (03 §2). Applying PERM_INV here, as the pseudo-code of 03 §3 line 196
 * says, would produce `(epoch << 24) | counter`, which is not a key of the
 * ActiveContextTable and would make every packet DROP_UNKNOWN_CONTEXT.
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_types.h>
#include <vnet/ip/format.h>
#include <vnet/srv6/sr_packet.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_context.h>
#include <cilium_srv6/cilium_srv6_parse.h>
#include <cilium_srv6/cilium_srv6_endcilium.h>
#include <cilium_srv6/cilium_srv6.api_enum.h>

typedef enum
{
  CILIUM_SRV6_END_CILIUM_NEXT_DROP,
  CILIUM_SRV6_END_CILIUM_NEXT_DELIVER,
  CILIUM_SRV6_END_CILIUM_N_NEXT,
} cilium_srv6_end_cilium_next_t;

/* Verdicts, kept for the packet trace of 06 §6 ("destination: 抽出 ctx、
 * pool state、inner DA 検証結果"). */
typedef enum
{
  CILIUM_SRV6_EC_OK = 0,
  CILIUM_SRV6_EC_UNTRUSTED_SOURCE,
  CILIUM_SRV6_EC_UNKNOWN_CONTEXT,
  CILIUM_SRV6_EC_INVALID_CONTEXT,
  CILIUM_SRV6_EC_CONTEXT_RECYCLED,
  CILIUM_SRV6_EC_SRV6_NOT_READY,
  CILIUM_SRV6_EC_MALFORMED_OUTER,
  CILIUM_SRV6_EC_MALFORMED_INNER,
  CILIUM_SRV6_EC_CONTEXT_IP_MISMATCH,
  CILIUM_SRV6_EC_N_VERDICT,
} cilium_srv6_ec_verdict_t;

typedef struct
{
  u32 context_id;
  u32 pool_index;
  u32 entry_generation;
  u32 decap_len; /* outer IPv6 (+ SRH) bytes removed */
  u8 entry_state;
  u8 has_srh;
} cilium_srv6_ec_result_t;

typedef struct
{
  u32 context_id;
  u32 pool_index;
  u32 entry_generation;
  u32 decap_len;
  u8 verdict;
  u8 entry_state;
  u8 has_srh;
  ip6_address_t outer_src;
  ip6_address_t inner_dst;
  ip6_address_t endpoint_ip;
} cilium_srv6_ec_trace_t;

/* `static inline`: under a CLIB_MARCH_VARIANT build VLIB_REGISTER_NODE
 * collapses to an unused declaration, so a plain `static` function
 * referenced only from the registration would trip -Wunused-function. */
static inline u8 *
format_cilium_srv6_ec_verdict (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_EC_OK:
      return format (s, "deliver");
    case CILIUM_SRV6_EC_UNTRUSTED_SOURCE:
      return format (s, "drop (DROP_UNTRUSTED_SOURCE: outer SA not in the SR domain node set)");
    case CILIUM_SRV6_EC_UNKNOWN_CONTEXT:
      return format (s, "drop (DROP_UNKNOWN_CONTEXT)");
    case CILIUM_SRV6_EC_INVALID_CONTEXT:
      return format (s, "drop (DROP_INVALID_CONTEXT: tombstone hit)");
    case CILIUM_SRV6_EC_CONTEXT_RECYCLED:
      return format (s, "drop (DROP_CONTEXT_RECYCLED)");
    case CILIUM_SRV6_EC_SRV6_NOT_READY:
      return format (s, "drop (DROP_SRV6_NOT_READY: entry is not ACTIVE)");
    case CILIUM_SRV6_EC_MALFORMED_OUTER:
      return format (s, "drop (DROP_MALFORMED_OUTER)");
    case CILIUM_SRV6_EC_MALFORMED_INNER:
      return format (s, "drop (DROP_MALFORMED_INNER)");
    case CILIUM_SRV6_EC_CONTEXT_IP_MISMATCH:
      return format (s, "drop (DROP_CONTEXT_IP_MISMATCH)");
    default:
      return format (s, "unknown(%u)", v);
    }
}

static inline u8 *
format_cilium_srv6_ec_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cilium_srv6_ec_trace_t *t = va_arg (*args, cilium_srv6_ec_trace_t *);

  s = format (s,
	      "cilium-end-cilium: outer src %U ctx 0x%08x srh %s "
	      "pool %d gen %u state %U decap %u\n"
	      "  inner dst %U expected %U verdict %U",
	      format_ip6_address, &t->outer_src, t->context_id, t->has_srh ? "yes" : "no",
	      (t->pool_index == (u32) ~0) ? -1 : (int) t->pool_index, t->entry_generation,
	      format_cilium_srv6_context_state, (u32) t->entry_state, t->decap_len,
	      format_ip6_address, &t->inner_dst, format_ip6_address, &t->endpoint_ip,
	      format_cilium_srv6_ec_verdict, (u32) t->verdict);
  return s;
}

/*
 * One packet of 03 §3.
 *
 * Order matters: the Context is resolved before the headers are parsed so
 * that invalid traffic is dropped without paying for the parse and the
 * decapsulation (03 §3: "ここまでで無効 traffic は落ちる", probing
 * resistance).
 *
 * Performs no allocation and does not modify the buffer: the decap length
 * is returned so that the caller advances the buffer only once the packet
 * has been fully accepted, which also keeps a dropped packet intact for the
 * trace.
 */
static_always_inline cilium_srv6_ec_verdict_t
cilium_srv6_end_cilium_one (vlib_main_t *vm, const cilium_srv6_endcilium_main_t *em,
			    vlib_buffer_t *b, cilium_srv6_ec_result_t *r)
{
  const u8 *p0 = (const u8 *) vlib_buffer_get_current (b);
  const ip6_header_t *ip = (const ip6_header_t *) p0;
  const cilium_srv6_context_entry_t *e;
  u32 pool_index = ~0;
  u32 ctx;

  r->context_id = 0;
  r->pool_index = ~0;
  r->entry_generation = 0;
  r->decap_len = 0;
  r->entry_state = CILIUM_SRV6_CONTEXT_INVALID;
  r->has_srh = 0;

  /* Nothing is read from the outer header until it is known to be there. */
  if (PREDICT_FALSE (b->current_length < sizeof (ip6_header_t)))
    return CILIUM_SRV6_EC_MALFORMED_OUTER;

  /*
   * D-32, second defence layer: on a shared underlay a trusted fabric
   * interface can carry an untrusted host, so per-interface trust alone is
   * not enough. One bounded set comparison.
   */
  if (PREDICT_FALSE (!cilium_srv6_sr_domain_contains (em, &ip->src_address)))
    return CILIUM_SRV6_EC_UNTRUSTED_SOURCE;

  /*
   * 01 §2.3 / D-10: Context ID = DA bit 64..95, network byte order. The
   * value is used as the ActiveContextTable key unchanged; see the PERM_INV
   * note at the top of this file.
   */
  ctx = clib_net_to_host_u32 (ip->dst_address.as_u32[2]);
  r->context_id = ctx;

  switch (cilium_srv6_context_resolve (ctx, &pool_index))
    {
    case CILIUM_SRV6_CTX_FOUND:
      break;
    case CILIUM_SRV6_CTX_INVALIDATED:
      return CILIUM_SRV6_EC_INVALID_CONTEXT;
    default:
      return CILIUM_SRV6_EC_UNKNOWN_CONTEXT;
    }

  e = cilium_srv6_context_entry_at (pool_index);
  if (PREDICT_FALSE (e == NULL || e->context_id != ctx))
    return CILIUM_SRV6_EC_CONTEXT_RECYCLED;

  r->pool_index = pool_index;
  r->entry_generation = e->entry_generation;
  r->entry_state = e->state;

  /* SUSPENDED delivery (03 §1.1 fail-closed ladder) and any entry inside
     its grace period drop here rather than being delivered. */
  if (PREDICT_FALSE (e->state != CILIUM_SRV6_CONTEXT_ACTIVE))
    return CILIUM_SRV6_EC_SRV6_NOT_READY;

  /* Bounded header parse and inner destination equality (01 §3.1 / §3.2,
     03 §5). Every dereference inside is bound checked first. */
  switch (cilium_srv6_parse_outer (p0, b->current_length, vlib_buffer_length_in_chain (vm, b),
				   &e->endpoint_ip, &r->decap_len, &r->has_srh))
    {
    case CILIUM_SRV6_PARSE_OK:
      return CILIUM_SRV6_EC_OK;
    case CILIUM_SRV6_PARSE_MALFORMED_INNER:
      return CILIUM_SRV6_EC_MALFORMED_INNER;
    case CILIUM_SRV6_PARSE_IP_MISMATCH:
      return CILIUM_SRV6_EC_CONTEXT_IP_MISMATCH;
    default:
      return CILIUM_SRV6_EC_MALFORMED_OUTER;
    }
}

static_always_inline u32
cilium_srv6_ec_error_of_verdict (cilium_srv6_ec_verdict_t v)
{
  switch (v)
    {
    case CILIUM_SRV6_EC_UNTRUSTED_SOURCE:
      return CILIUM_SRV6_END_CILIUM_ERROR_UNTRUSTED_SOURCE;
    case CILIUM_SRV6_EC_UNKNOWN_CONTEXT:
      return CILIUM_SRV6_END_CILIUM_ERROR_UNKNOWN_CONTEXT;
    case CILIUM_SRV6_EC_INVALID_CONTEXT:
      return CILIUM_SRV6_END_CILIUM_ERROR_INVALID_CONTEXT;
    case CILIUM_SRV6_EC_CONTEXT_RECYCLED:
      return CILIUM_SRV6_END_CILIUM_ERROR_CONTEXT_RECYCLED;
    case CILIUM_SRV6_EC_SRV6_NOT_READY:
      return CILIUM_SRV6_END_CILIUM_ERROR_SRV6_NOT_READY;
    case CILIUM_SRV6_EC_MALFORMED_INNER:
      return CILIUM_SRV6_END_CILIUM_ERROR_MALFORMED_INNER;
    case CILIUM_SRV6_EC_CONTEXT_IP_MISMATCH:
      return CILIUM_SRV6_END_CILIUM_ERROR_CONTEXT_IP_MISMATCH;
    default:
      return CILIUM_SRV6_END_CILIUM_ERROR_MALFORMED_OUTER;
    }
}

VLIB_NODE_FN (cilium_srv6_end_cilium_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  const cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  cilium_srv6_ec_result_t results[VLIB_FRAME_SIZE], *r = results;
  u8 verdicts[VLIB_FRAME_SIZE], *vd = verdicts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_decapsulated = 0;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      cilium_srv6_ec_verdict_t v = cilium_srv6_end_cilium_one (vm, em, b[0], r);

      vd[0] = (u8) v;

      if (PREDICT_TRUE (v == CILIUM_SRV6_EC_OK))
	{
	  cilium_srv6_deliver_meta_t *m = cilium_srv6_deliver_meta (b[0]);

	  /* decap: remove the outer IPv6 header and, if present, the SRH. */
	  vlib_buffer_advance (b[0], (word) r->decap_len);

	  /* 03 §4 (D-12): only the versioned handle crosses the arc. */
	  m->pool_index = r->pool_index;
	  m->context_id = r->context_id;
	  m->entry_generation = r->entry_generation;

	  next[0] = CILIUM_SRV6_END_CILIUM_NEXT_DELIVER;
	  n_decapsulated++;
	}
      else
	{
	  b[0]->error = node->errors[cilium_srv6_ec_error_of_verdict (v)];
	  next[0] = CILIUM_SRV6_END_CILIUM_NEXT_DROP;
	}

      b += 1;
      next += 1;
      r += 1;
      vd += 1;
      n_left -= 1;
    }

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      u32 i;

      b = bufs;
      r = results;
      vd = verdicts;

      for (i = 0; i < frame->n_vectors; i++, b++, r++, vd++)
	{
	  const cilium_srv6_context_entry_t *e;
	  cilium_srv6_ec_trace_t *t;
	  const u8 *p0;

	  if (!(b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    continue;

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  clib_memset (t, 0, sizeof (*t));

	  t->context_id = r->context_id;
	  t->pool_index = r->pool_index;
	  t->entry_generation = r->entry_generation;
	  t->decap_len = r->decap_len;
	  t->entry_state = r->entry_state;
	  t->has_srh = r->has_srh;
	  t->verdict = vd[0];

	  /* A delivered packet has already been advanced past the outer
	     header, so the trace reads the inner header at offset 0 and the
	     outer source is no longer in the buffer. */
	  p0 = (const u8 *) vlib_buffer_get_current (b[0]);

	  if (vd[0] == CILIUM_SRV6_EC_OK)
	    {
	      if (b[0]->current_length >= sizeof (ip6_header_t))
		t->inner_dst = ((const ip6_header_t *) p0)->dst_address;
	    }
	  else if (b[0]->current_length >= sizeof (ip6_header_t))
	    {
	      /* A dropped packet is never advanced, so the outer header is
		 still at offset 0 and no inner destination was accepted. */
	      t->outer_src = ((const ip6_header_t *) p0)->src_address;
	    }

	  e = (r->pool_index == (u32) ~0) ? NULL : cilium_srv6_context_entry_at (r->pool_index);
	  if (e != NULL)
	    t->endpoint_ip = e->endpoint_ip;
	}
    }

  vlib_node_increment_counter (vm, node->node_index, CILIUM_SRV6_END_CILIUM_ERROR_DECAPSULATED,
			       n_decapsulated);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cilium_srv6_end_cilium_node) = {
  .name = "cilium-end-cilium",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_cilium_srv6_ec_trace,
  .format_buffer = format_ip6_header,
  .n_errors = CILIUM_SRV6_END_CILIUM_N_ERROR,
  .error_counters = cilium_srv6_end_cilium_error_counters,
  .n_next_nodes = CILIUM_SRV6_END_CILIUM_N_NEXT,
  .next_nodes = {
    [CILIUM_SRV6_END_CILIUM_NEXT_DROP] = "ip6-drop",
    [CILIUM_SRV6_END_CILIUM_NEXT_DELIVER] = "cilium-ep-deliver",
  },
};
