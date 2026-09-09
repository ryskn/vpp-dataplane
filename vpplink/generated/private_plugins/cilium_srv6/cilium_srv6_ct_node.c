/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — cilium-srv6-ct (C7), dataplane.
 *
 * design/detail/02-headend-dataplane.md §7.2 and D-47. The node exists
 * because a reply packet (Pod B -> Pod A, ephemeral port) has no ALLOW entry
 * in the ProgramCache — policy is evaluated in one direction only — so
 * without this stage every reply would miss, punt and be denied, and TCP
 * would never establish.
 *
 * The three branches of D-47:
 *
 *   1. reply hit, every allow condition met      -> cilium-srv6-encap
 *      (the five-step judgement of 02 §7.2 / D-51: state ==
 *      VERIFIED_ESTABLISHED with the endpoint context/identity still
 *      matching the LocalEndpointTable and a consistent protocol state, then
 *      verified_revision == the current revision of remote_identity, then a
 *      PolicyLeaseTable lease granted for that revision, then an unexpired
 *      deadline (D-49))
 *   2. reply hit failing any of those            -> cilium-srv6-punt on the
 *      dedicated re-authorisation queue (D-38)
 *   3. miss or forward direction                 -> cilium-srv6-program
 *
 * C10 (the node-local conntrack table itself) is a separate component, so the
 * lookup is a registered hook and the node classifies every packet as branch
 * 3 while nothing is registered. That is the correct fail-safe default: with
 * no conntrack, every packet is authorised by the ProgramCache exactly as
 * TC-702 requires of a one-way packet, and no packet can bypass policy.
 *
 * DESIGN GAP, reported and closed by C10 rather than invented here. Branch 1
 * bypasses the ProgramCache, so something has to supply the path the reply is
 * encapsulated on, but the conntrack entry of 02 §7.1 has no path handle
 * field. This node takes the handle from the hook's result and fails closed —
 * a REPLY_ALLOW whose handle does not resolve is turned into a
 * re-authorisation punt rather than being forwarded on a guessed path. The
 * conntrack table fills the handle in during the §7.2 branch-2 promotion: the
 * agent resolves it as part of the re-authorisation (it already resolves one
 * in 02 §5.1 step 5) and writes it with srv6_ct_verify, where the deviation
 * from 02 §7.1 / §8 is documented.
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
  CILIUM_SRV6_CT_NEXT_DROP,
  CILIUM_SRV6_CT_NEXT_PROGRAM,
  CILIUM_SRV6_CT_NEXT_ENCAP,
  CILIUM_SRV6_CT_NEXT_PUNT,
  CILIUM_SRV6_CT_N_NEXT,
} cilium_srv6_ct_next_t;

typedef struct
{
  u32 src_identity;
  u32 local_context_id;
  u32 path_cache_index;
  u8 verdict;
  u8 hooked;
} cilium_srv6_ct_trace_t;

/* `static inline`: see the note in cilium_srv6_guard_node.c. */
static inline u8 *
format_cilium_srv6_ct_verdict (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_CT_MISS:
      return format (s, "miss/forward -> cilium-srv6-program");
    case CILIUM_SRV6_CT_REPLY_ALLOW:
      return format (s, "reply hit, ProgramCache bypassed");
    case CILIUM_SRV6_CT_REPLY_REAUTH:
      return format (s, "reply hit, re-authorisation punt");
    default:
      return format (s, "unknown(%u)", v);
    }
}

static inline u8 *
format_cilium_srv6_ct_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cilium_srv6_ct_trace_t *t = va_arg (*args, cilium_srv6_ct_trace_t *);

  s = format (s,
	      "cilium-srv6-ct: identity %u context %u conntrack %s path %d "
	      "verdict %U",
	      t->src_identity, t->local_context_id, t->hooked ? "registered" : "absent (C10)",
	      (t->path_cache_index == (u32) ~0) ? -1 : (int) t->path_cache_index,
	      format_cilium_srv6_ct_verdict, (u32) t->verdict);
  return s;
}

VLIB_NODE_FN (cilium_srv6_ct_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  cilium_srv6_ct_lookup_fn ct_hook = cilium_srv6_ct_lookup_hook;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u8 verdicts[VLIB_FRAME_SIZE], *vd = verdicts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_forward = 0, n_reply = 0, n_reauth = 0;
  f64 now = vlib_time_now (vm);

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      cilium_srv6_headend_meta_t *meta = cilium_srv6_headend_meta (b[0]);
      cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b[0]);
      cilium_srv6_ct_lookup_verdict_t v = CILIUM_SRV6_CT_MISS;

      if (PREDICT_FALSE (ct_hook != 0))
	{
	  cilium_srv6_ct_query_t q;
	  cilium_srv6_ct_result_t res;

	  /*
	   * Everything 02 §7.2 lets the conntrack stage compare against: the
	   * live identity and endpoint incarnation from the LocalEndpointTable
	   * (via the classify metadata), the currently published dependency
	   * revisions, and the time for the D-49 / D-51 lease condition, which
	   * the hook resolves from the PolicyLeaseTable slot of the entry's
	   * remote identity.
	   */
	  q.src_identity = meta->src_identity;
	  q.local_context_id = meta->local_context_id;
	  q.owner_quota_class = meta->owner_quota_class;
	  q.policy_revision = cilium_srv6_policy_revision (hm, meta->policy_rev_slot);
	  q.endpoint_revision = hm->endpoint_revision;
	  q.path_revision = hm->path_revision;
	  q.now = now;

	  res.path_cache_index = ~0;
	  res.path_generation = 0;

	  v = ct_hook (vm, thread_index, b[0], &q, &res);

	  if (v == CILIUM_SRV6_CT_REPLY_ALLOW)
	    {
	      /* Fail closed if the bypass cannot name a resolvable path. */
	      if (PREDICT_FALSE (cilium_srv6_path_get (hm, res.path_cache_index,
						       res.path_generation) == NULL))
		{
		  v = CILIUM_SRV6_CT_REPLY_REAUTH;
		}
	      else
		{
		  pm->path_cache_index = res.path_cache_index;
		  pm->path_generation = res.path_generation;
		  pm->program_index = ~0;
		}
	    }
	}

      vd[0] = (u8) v;

      switch (v)
	{
	case CILIUM_SRV6_CT_REPLY_ALLOW:
	  meta->flags |= CILIUM_SRV6_META_F_CT_REPLY;
	  next[0] = CILIUM_SRV6_CT_NEXT_ENCAP;
	  n_reply++;
	  break;

	case CILIUM_SRV6_CT_REPLY_REAUTH:
	  /* D-38: the re-authorisation punt has its own bounded queue so that
	     a flood of 5-tuples cannot saturate the compile path. */
	  pm->punt_reason = CILIUM_SRV6_PUNT_REASON_REPLY_REAUTH;
	  pm->punt_queue = CILIUM_SRV6_PUNT_Q_REAUTH;
	  next[0] = CILIUM_SRV6_CT_NEXT_PUNT;
	  n_reauth++;
	  break;

	default:
	  next[0] = CILIUM_SRV6_CT_NEXT_PROGRAM;
	  n_forward++;
	  break;
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
	  const cilium_srv6_headend_meta_t *meta;
	  const cilium_srv6_path_meta_t *pm;
	  cilium_srv6_ct_trace_t *t;

	  if (!(b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    continue;

	  meta = cilium_srv6_headend_meta (b[0]);
	  pm = cilium_srv6_path_meta (b[0]);

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  t->src_identity = meta->src_identity;
	  t->local_context_id = meta->local_context_id;
	  t->path_cache_index = pm->path_cache_index;
	  t->verdict = vd[0];
	  t->hooked = (ct_hook != 0);
	}
    }

  vlib_node_increment_counter (vm, node->node_index, CILIUM_SRV6_CT_ERROR_FORWARD, n_forward);
  vlib_node_increment_counter (vm, node->node_index, CILIUM_SRV6_CT_ERROR_REPLY_BYPASS, n_reply);
  vlib_node_increment_counter (vm, node->node_index, CILIUM_SRV6_CT_ERROR_REPLY_REAUTH, n_reauth);

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cilium_srv6_ct_node) = {
  .name = "cilium-srv6-ct",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_cilium_srv6_ct_trace,
  .format_buffer = format_ip6_header,
  .n_errors = CILIUM_SRV6_CT_N_ERROR,
  .error_counters = cilium_srv6_ct_error_counters,
  .n_next_nodes = CILIUM_SRV6_CT_N_NEXT,
  .next_nodes = {
    [CILIUM_SRV6_CT_NEXT_DROP] = "ip6-drop",
    [CILIUM_SRV6_CT_NEXT_PROGRAM] = "cilium-srv6-program",
    [CILIUM_SRV6_CT_NEXT_ENCAP] = "cilium-srv6-encap",
    [CILIUM_SRV6_CT_NEXT_PUNT] = "cilium-srv6-punt",
  },
};
