/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — cilium-srv6-local-deliver (C7-b), dataplane.
 *
 * The LOCAL_DELIVER forwarding action of D-80 (00 §2.20, 02 §4.3.1,
 * errata #34 item 149).
 *
 * D-80 answers "what happens when the destination Pod is on this node" with
 * *same semantic compiler, different forwarding action*. Everything before
 * this node is identical to a remote destination: the infrastructure ACL, the
 * classification that resolves the source identity from the receiving
 * interface (02 §3), the conntrack stage (02 §7) and the ProgramCache lookup
 * with its three per-key dependency revisions and its D-51 lease check
 * (02 §4.2). Only what an ALLOW then does with the packet differs, and this
 * node is that difference:
 *
 *   0. re-resolve the ProgramCache entry and re-check the decision it carries —
 *      its three dependency revisions, including the D-85 agent incarnation
 *      fence, and its D-51 lease — because an index is not a decision and the
 *      entry can be replaced or staled between the two nodes;
 *   1. re-resolve the target interface lifetime and re-check that it still
 *      carries this destination (D-31 / D-68 / D-69);
 *   2. the headend egress conntrack step of 02 §6 step 1, i.e. the same hook
 *      cilium-srv6-encap runs;
 *   3. transmit on the target interface.
 *
 * There is no encapsulation, no SRH and no loopback through a local SID:
 * 00 §2.20 rules self-encapsulation out, because sending same-node traffic
 * out to this node's own Service SID would add SRH construction and a second
 * lookup to a path that needs neither, and would present local reachability
 * as if it were a BGP/SR-Policy-derived path.
 *
 * # Step 1 is not a formality
 *
 * The program stores an interface *lifetime* — (sw_if_index, if_incarnation)
 * — plus the destination endpoint's Security Identity, and all three are
 * compared against the live LocalEndpointTable here rather than trusted from
 * the entry. An sw_if_index is reused the instant an interface is deleted
 * (D-31), so an entry that survived a Pod delete would otherwise transmit one
 * Pod's traffic into whatever Pod inherited the number, which is a
 * misdelivery and not a stale forwarding decision. The identity comparison is
 * D-69's "a change of Security Identity is a semantic endpoint update and MUST
 * invalidate identity-dependent programming": the ENDPOINT revision publish
 * that stales the entry is the mechanism, and this check is what closes the
 * window before it lands.
 *
 * A mismatch punts. It never delivers, and it never drops silently: the
 * agent recompiles the key, finds the current LocalEndpoint state and either
 * installs an entry for the new lifetime or answers with a DENY.
 *
 * # Step 2 is the headend's conntrack step, not the delivery-side one
 *
 * 02 §6 step 1 creates or refreshes the *forward* entry of every packet this
 * node has authorised, and that is what runs here, through the same
 * cilium_srv6_ct_egress_hook cilium-srv6-encap calls.
 *
 * The destination-side step of 03 §6 — forward and reply entries created
 * UNVERIFIED with `verified_revision` left at the sentinel — deliberately does
 * *not* run. Its rule exists because a packet arriving from the SR domain
 * carries neither the source identity nor the revision the sending headend
 * authorised under, so the receiving node cannot store a true revision and
 * D-19/D-45 forbid it from guessing one. On a same-node path that premise does
 * not hold: this node classified the packet, evaluated the policy and holds the
 * revision it decided under.
 *
 * The consequence is that the reply direction of a same-node flow is not
 * covered by the 02 §7.2 reply bypass. 02 §7 defines that bypass in terms of a
 * path handle (branch 1 encapsulates, and srv6_ct_verify carries
 * path_cache_index/path_generation), and a local peer has no path handle at
 * all, so a local reply cannot be promoted to VERIFIED_ESTABLISHED by the
 * design as written. A reply is therefore compiled as a flow of its own and
 * evaluated by NetworkPolicy in its own right — correct and fail-closed, but
 * stricter than the remote case for a policy that only authorises one
 * direction. This is a gap in 02 §7, is reported as such, and is not closed by
 * inventing a local variant of the conntrack bypass here.
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
  CILIUM_SRV6_LOCAL_DELIVER_NEXT_DROP,
  CILIUM_SRV6_LOCAL_DELIVER_NEXT_PUNT,
  /* The interface transmit path. interface-output dispatches on
     vnet_buffer(b)->sw_if_index[VLIB_TX] and performs no FIB lookup of the
     inner destination, which is the property 03 §6 step 4 states for the
     Context's forwarding object. Using it rather than a per-interface
     interface_tx DPO keeps this node free of a second lifetime-keyed table:
     the interface lifetime is already validated above, and an arc table would
     have to be invalidated on exactly the same events. */
  CILIUM_SRV6_LOCAL_DELIVER_NEXT_TX,
  CILIUM_SRV6_LOCAL_DELIVER_N_NEXT,
} cilium_srv6_local_deliver_next_t;

typedef enum
{
  CILIUM_SRV6_LOCAL_DELIVER_OK = 0,
  /* The entry is gone, is no longer a LOCAL_DELIVER, or its target lifetime /
     identity / address is not the live one: punt and let the agent recompile. */
  CILIUM_SRV6_LOCAL_DELIVER_STALE_TARGET,
  /* Defensive: the header disappeared between cilium-srv6-program and here. */
  CILIUM_SRV6_LOCAL_DELIVER_MALFORMED,
  CILIUM_SRV6_LOCAL_DELIVER_N_VERDICT,
} cilium_srv6_local_deliver_verdict_t;

typedef struct
{
  u32 program_index;
  u32 target_sw_if_index;
  u32 target_if_incarnation;
  u32 target_identity;
  u32 live_if_incarnation;
  u32 live_identity;
  ip6_address_t dst;
  u8 verdict;
} cilium_srv6_local_deliver_trace_t;

/* `static inline`: see the note in cilium_srv6_guard_node.c. */
static inline u8 *
format_cilium_srv6_local_deliver_verdict (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_LOCAL_DELIVER_OK:
      return format (s, "delivered");
    case CILIUM_SRV6_LOCAL_DELIVER_STALE_TARGET:
      return format (s, "stale local target -> punt");
    case CILIUM_SRV6_LOCAL_DELIVER_MALFORMED:
      return format (s, "drop (DROP_MALFORMED_INNER)");
    default:
      return format (s, "unknown(%u)", v);
    }
}

static inline u8 *
format_cilium_srv6_local_deliver_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cilium_srv6_local_deliver_trace_t *t = va_arg (*args, cilium_srv6_local_deliver_trace_t *);

  s = format (s,
	      "cilium-srv6-local-deliver: entry %d dst %U\n"
	      "  target sw_if_index %u incarnation %u identity %u\n"
	      "  live incarnation %u identity %u\n"
	      "  verdict %U",
	      (t->program_index == (u32) ~0) ? -1 : (int) t->program_index, format_ip6_address,
	      &t->dst, t->target_sw_if_index, t->target_if_incarnation, t->target_identity,
	      t->live_if_incarnation, t->live_identity, format_cilium_srv6_local_deliver_verdict,
	      (u32) t->verdict);
  return s;
}

/*
 * One packet. Every dereference is preceded by a bounds or lifetime check, and
 * the buffer is only modified once every check has passed.
 */
static_always_inline cilium_srv6_local_deliver_verdict_t
cilium_srv6_local_deliver_one (vlib_main_t *vm, const cilium_srv6_headend_main_t *hm,
			       const cilium_srv6_main_t *gm, u32 thread_index, vlib_buffer_t *b,
			       const ip6_header_t *ip, f64 now)
{
  const cilium_srv6_headend_meta_t *meta = cilium_srv6_headend_meta (b);
  const cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b);
  cilium_srv6_ct_egress_fn ct_hook = cilium_srv6_ct_egress_hook;
  const cilium_srv6_program_t *e;
  const cilium_srv6_local_ep_t *ep;

  /*
   * The entry is re-resolved rather than carried as a pointer, the same way
   * cilium-srv6-encap re-resolves the path handle (D-12): the ProgramCache
   * entry can be evicted or replaced between the two nodes, and a pointer
   * captured in cilium-srv6-program would then be to a reused pool slot.
   */
  e = (pm->program_index == (u32) ~0) ? NULL : cilium_srv6_program_at (hm, pm->program_index);
  if (PREDICT_FALSE (e == NULL || !e->in_use || e->verdict != CILIUM_SRV6_VERDICT_ALLOW ||
		     e->action != CILIUM_SRV6_ACTION_LOCAL_DELIVER))
    return CILIUM_SRV6_LOCAL_DELIVER_STALE_TARGET;

  /*
   * The re-resolution above admits an entry that is *an* ALLOW LOCAL_DELIVER,
   * not necessarily the one cilium-srv6-program judged: the pool slot can have
   * been replaced between the two nodes, and a revision publish that arrives in
   * that window (a control-plane call runs under the worker barrier, which this
   * node's frame is either side of) can stale the very entry the previous node
   * accepted. Delivery is a forwarding decision, so it re-checks the decision's
   * dependencies with exactly the predicate the ProgramCache hit used, rather
   * than trusting an index across a node boundary — the same reason
   * cilium-srv6-encap re-resolves the path handle instead of carrying a pointer
   * (D-12). D-85 makes this concrete: a delivery must never run on an entry
   * quoting an agent incarnation that is no longer the authority, whatever the
   * forwarding action (00 §2.23.5, errata #34 item 176).
   *
   * Cost: the three indexed loads of 02 §4.2, no hash lookup.
   */
  if (PREDICT_FALSE (!cilium_srv6_revisions_match (hm, e->policy_rev_slot, e->policy_revision,
						   e->endpoint_rev_slot, e->endpoint_revision,
						   e->path_cache_index, e->path_revision)))
    return CILIUM_SRV6_LOCAL_DELIVER_STALE_TARGET;

  /* D-51: and the lease that vouches for that revision must still be usable.
     `now` is this node's, so an entry whose lease expired between the two nodes
     is punted here rather than delivered. */
  if (PREDICT_FALSE (!cilium_srv6_policy_lease_valid (hm, e->policy_rev_slot, e->src_identity,
						      e->policy_revision, now)))
    return CILIUM_SRV6_LOCAL_DELIVER_STALE_TARGET;

  /*
   * D-31 / D-68: the lookup itself refuses an sw_if_index whose stored
   * incarnation is not the live one, and the comparison below additionally
   * refuses an entry compiled for a lifetime that has since been replaced by
   * another endpoint on the same index. Delivering to a reused index is a
   * misdelivery, so this is a punt and never a "close enough" transmit.
   */
  ep = cilium_srv6_local_ep_lookup (hm, gm, e->target_sw_if_index);
  if (PREDICT_FALSE (ep == NULL))
    return CILIUM_SRV6_LOCAL_DELIVER_STALE_TARGET;

  if (PREDICT_FALSE (ep->if_incarnation != e->target_if_incarnation ||
		     ep->identity != e->target_identity ||
		     !ip6_address_is_equal (&ep->ip, &ip->dst_address)))
    return CILIUM_SRV6_LOCAL_DELIVER_STALE_TARGET;

  /*
   * 02 §6 step 1 (C10), the same hook and the same query cilium-srv6-encap
   * builds: the entry created here is the *forward* entry of this flow,
   * carrying the source endpoint's incarnation and the revision the
   * ProgramCache authorised the packet under. Skipped while no conntrack is
   * registered. The buffer still starts at the IPv6 header, so the hook reads
   * the 5-tuple from it exactly as it does on the encapsulation path.
   */
  if (PREDICT_FALSE (ct_hook != 0))
    {
      cilium_srv6_ct_query_t q;

      q.src_identity = meta->src_identity;
      q.local_context_id = meta->local_context_id;
      q.owner_quota_class = meta->owner_quota_class;
      q.policy_revision = cilium_srv6_policy_revision (hm, meta->policy_rev_slot);
      q.now = now;

      ct_hook (vm, thread_index, b, &q);
    }

  /*
   * Transmit on the endpoint's interface. No FIB lookup of the destination is
   * performed: the interface is the one the LocalEndpointTable binds to this
   * destination, which is the same authority 03 §6 step 4 delivers on.
   */
  vnet_buffer (b)->sw_if_index[VLIB_TX] = e->target_sw_if_index;

  return CILIUM_SRV6_LOCAL_DELIVER_OK;
}

VLIB_NODE_FN (cilium_srv6_local_deliver_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_main_t *gm = &cilium_srv6_main;
  u32 thread_index = vm->thread_index;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u8 verdicts[VLIB_FRAME_SIZE], *vd = verdicts;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_verdict[CILIUM_SRV6_LOCAL_DELIVER_N_VERDICT] = { 0 };
  f64 now = vlib_time_now (vm);
  u32 i;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b[0]);
      const ip6_header_t *ip = (const ip6_header_t *) vlib_buffer_get_current (b[0]);
      cilium_srv6_local_deliver_verdict_t v;

      if (PREDICT_FALSE (b[0]->current_length < sizeof (ip6_header_t)))
	v = CILIUM_SRV6_LOCAL_DELIVER_MALFORMED;
      else
	v = cilium_srv6_local_deliver_one (vm, hm, gm, thread_index, b[0], ip, now);

      vd[0] = (u8) v;

      switch (v)
	{
	case CILIUM_SRV6_LOCAL_DELIVER_OK:
	  next[0] = CILIUM_SRV6_LOCAL_DELIVER_NEXT_TX;
	  break;

	case CILIUM_SRV6_LOCAL_DELIVER_MALFORMED:
	  b[0]->error = node->errors[CILIUM_SRV6_LOCAL_DELIVER_ERROR_MALFORMED_INNER];
	  next[0] = CILIUM_SRV6_LOCAL_DELIVER_NEXT_DROP;
	  break;

	default:
	  /*
	   * The IF-3 cause stays STALE_REVISION: by the time the agent answers
	   * this punt the entry really is stale, because a LocalEndpoint
	   * lifecycle change advances the destination's own ENDPOINT revision
	   * key (D-80 / D-83). A cause of its own would be an IF-3 wire enum
	   * change for a value nothing branches on; the node counter below is
	   * what distinguishes it locally.
	   */
	  pm->punt_reason = CILIUM_SRV6_PUNT_REASON_STALE_REVISION;
	  pm->punt_queue = CILIUM_SRV6_PUNT_Q_COMPILE;
	  next[0] = CILIUM_SRV6_LOCAL_DELIVER_NEXT_PUNT;
	  break;
	}

      n_verdict[v]++;

      b += 1;
      next += 1;
      vd += 1;
      n_left -= 1;
    }

  /* MALFORMED puts a reason into b->error, which the drop node counts; the
     other two are counted here, following the convention of the guard and
     program nodes. */
  if (n_verdict[CILIUM_SRV6_LOCAL_DELIVER_OK])
    vlib_node_increment_counter (vm, node->node_index, CILIUM_SRV6_LOCAL_DELIVER_ERROR_DELIVERED,
				 n_verdict[CILIUM_SRV6_LOCAL_DELIVER_OK]);
  if (n_verdict[CILIUM_SRV6_LOCAL_DELIVER_STALE_TARGET])
    vlib_node_increment_counter (vm, node->node_index,
				 CILIUM_SRV6_LOCAL_DELIVER_ERROR_PUNT_STALE_TARGET,
				 n_verdict[CILIUM_SRV6_LOCAL_DELIVER_STALE_TARGET]);

  /* The trace record is rebuilt here rather than carried per packet: a
     per-packet array of it would be 8 KB of stack for a value only a traced
     packet reads, and everything in it is either in the buffer metadata or
     re-resolvable from the entry the same way the processing loop resolved it.
     A value that changed since then is itself worth seeing in a trace. */
  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      b = bufs;
      vd = verdicts;

      for (i = 0; i < frame->n_vectors; i++, b++, vd++)
	{
	  const cilium_srv6_path_meta_t *pm;
	  const cilium_srv6_program_t *e;
	  const cilium_srv6_local_ep_t *ep;
	  cilium_srv6_local_deliver_trace_t *t;

	  if (!(b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    continue;

	  pm = cilium_srv6_path_meta (b[0]);

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  clib_memset (t, 0, sizeof (*t));

	  t->verdict = vd[0];
	  t->program_index = pm->program_index;

	  if (b[0]->current_length >= sizeof (ip6_header_t))
	    t->dst = ((const ip6_header_t *) vlib_buffer_get_current (b[0]))->dst_address;

	  e =
	    (pm->program_index == (u32) ~0) ? NULL : cilium_srv6_program_at (hm, pm->program_index);
	  if (e == NULL)
	    continue;

	  t->target_sw_if_index = e->target_sw_if_index;
	  t->target_if_incarnation = e->target_if_incarnation;
	  t->target_identity = e->target_identity;

	  ep = cilium_srv6_local_ep_lookup (hm, gm, e->target_sw_if_index);
	  if (ep != NULL)
	    {
	      t->live_if_incarnation = ep->if_incarnation;
	      t->live_identity = ep->identity;
	    }
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cilium_srv6_local_deliver_node) = {
  .name = "cilium-srv6-local-deliver",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_cilium_srv6_local_deliver_trace,
  .format_buffer = format_ip6_header,
  .n_errors = CILIUM_SRV6_LOCAL_DELIVER_N_ERROR,
  .error_counters = cilium_srv6_local_deliver_error_counters,
  .n_next_nodes = CILIUM_SRV6_LOCAL_DELIVER_N_NEXT,
  .next_nodes = {
    [CILIUM_SRV6_LOCAL_DELIVER_NEXT_DROP] = "ip6-drop",
    [CILIUM_SRV6_LOCAL_DELIVER_NEXT_PUNT] = "cilium-srv6-punt",
    [CILIUM_SRV6_LOCAL_DELIVER_NEXT_TX] = "interface-output",
  },
};
