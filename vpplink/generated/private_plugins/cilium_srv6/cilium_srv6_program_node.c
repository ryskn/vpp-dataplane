/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — cilium-srv6-program (C7), dataplane.
 *
 * design/detail/02-headend-dataplane.md §4.2, verbatim:
 *
 *   e = ProgramCache.lookup(key)
 *   if (!e)                                 -> punt (§5)
 *   if (!dependency_revisions_match(e))      -> punt (§5, stale)
 *   lease = PolicyLeaseTable[e.key.src_identity]
 *   if (e.verdict == ALLOW &&
 *       (lease.lease_revision != e.policy_revision ||
 *        now >= lease.valid_until))          -> punt (§5, lease invalid)
 *   if (e.verdict == DENY)                   -> drop (DROP_POLICY_DENIED)
 *   meta.path = PathCache.get(e.path_cache_index, e.path_generation)
 *   if (!meta.path)                          -> punt (§5, stale handle)
 *   -> encap
 *
 * The key is the 24 byte tuple of §4.1 — (src_identity, dst, proto,
 * l4_discriminator) — with the discriminator generalised per D-41, so an
 * ICMPv6 type/code policy is not collapsed into one all-ALLOW or all-DENY
 * entry.
 *
 * Dependency-scoped invalidation (D-17 / D-30): the entry carries the three
 * revisions it was compiled against, and only those three are compared. The
 * policy revision is per src identity, so an unrelated NetworkPolicy change
 * cannot stale this entry — which is what stops a namespace-scoped user from
 * driving the whole cluster into the bounded punt queue.
 *
 * This node is also where a first fragment's verdict is recorded, because
 * that is the point at which the verdict and the path handle both exist
 * (01 §3.1 / D-20).
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
  CILIUM_SRV6_PROGRAM_NEXT_DROP,
  CILIUM_SRV6_PROGRAM_NEXT_ENCAP,
  CILIUM_SRV6_PROGRAM_NEXT_PUNT,
  CILIUM_SRV6_PROGRAM_N_NEXT,
} cilium_srv6_program_next_t;

typedef enum
{
  CILIUM_SRV6_PROGRAM_ALLOW = 0,
  CILIUM_SRV6_PROGRAM_DENY,
  CILIUM_SRV6_PROGRAM_PUNT_MISS,
  CILIUM_SRV6_PROGRAM_PUNT_STALE,
  CILIUM_SRV6_PROGRAM_PUNT_LEASE,
  CILIUM_SRV6_PROGRAM_PUNT_PATH,
  /* defensive: the header disappeared between classify and here */
  CILIUM_SRV6_PROGRAM_MALFORMED,
  CILIUM_SRV6_PROGRAM_N_VERDICT,
} cilium_srv6_program_verdict_t;

/* Verdicts that put a reason into b->error; the drop node counts those, so
 * they must not also be counted explicitly (the convention the guard and
 * cilium-end-cilium nodes already follow). */
#define CILIUM_SRV6_PROGRAM_VERDICT_IS_DROP(v)                                                     \
  ((v) == CILIUM_SRV6_PROGRAM_DENY || (v) == CILIUM_SRV6_PROGRAM_MALFORMED)

typedef struct
{
  u32 src_identity;
  u32 l4_discriminator;
  u32 program_index;
  u32 path_cache_index;
  u32 path_generation;
  /* 06 §6 asks the headend trace to carry the *dependency revisions*. All
     three of D-17 / D-30 are traced next to the values the node currently
     publishes: with only the policy pair a trace of a PUNT_STALE cannot say
     which of the three dependencies moved, which is what the TC-602 graph
     order check and stale-entry investigations read. */
  u64 policy_revision;
  u64 current_policy_revision;
  u64 endpoint_revision;
  u64 current_endpoint_revision;
  u64 path_revision;
  u64 current_path_revision;
  /* Seconds left on the PolicyLeaseTable lease of this entry's dependency
     pair (D-49 / D-51); 0 when there is no valid lease for it. */
  f64 lease_remaining;
  u8 verdict;
  u8 proto;
  u8 frag_first;
  ip6_address_t dst;
} cilium_srv6_program_trace_t;

/* `static inline`: see the note in cilium_srv6_guard_node.c. */
static inline u8 *
format_cilium_srv6_program_verdict (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_PROGRAM_ALLOW:
      return format (s, "hit(ALLOW)");
    case CILIUM_SRV6_PROGRAM_DENY:
      return format (s, "hit(DENY) -> drop (DROP_POLICY_DENIED)");
    case CILIUM_SRV6_PROGRAM_PUNT_MISS:
      return format (s, "miss -> punt");
    case CILIUM_SRV6_PROGRAM_PUNT_STALE:
      return format (s, "dependency revision mismatch -> punt");
    case CILIUM_SRV6_PROGRAM_PUNT_LEASE:
      return format (s, "no valid policy lease -> punt");
    case CILIUM_SRV6_PROGRAM_PUNT_PATH:
      return format (s, "stale path handle -> punt");
    case CILIUM_SRV6_PROGRAM_MALFORMED:
      return format (s, "drop (DROP_MALFORMED_INNER)");
    default:
      return format (s, "unknown(%u)", v);
    }
}

static inline u8 *
format_cilium_srv6_program_trace (u8 *s, va_list *args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  cilium_srv6_program_trace_t *t = va_arg (*args, cilium_srv6_program_trace_t *);

  s = format (s,
	      "cilium-srv6-program: identity %u dst %U proto %u l4-disc %u%s\n"
	      "  entry %d path %d gen %u lease %.3fs\n"
	      "  dependency revisions (entry/current): policy %llu/%llu "
	      "endpoint %llu/%llu path %llu/%llu\n"
	      "  verdict %U",
	      t->src_identity, format_ip6_address, &t->dst, (u32) t->proto, t->l4_discriminator,
	      t->frag_first ? " (first fragment)" : "",
	      (t->program_index == (u32) ~0) ? -1 : (int) t->program_index,
	      (t->path_cache_index == (u32) ~0) ? -1 : (int) t->path_cache_index,
	      t->path_generation, t->lease_remaining, t->policy_revision,
	      t->current_policy_revision, t->endpoint_revision, t->current_endpoint_revision,
	      t->path_revision, t->current_path_revision, format_cilium_srv6_program_verdict,
	      (u32) t->verdict);
  return s;
}

/*
 * One packet of 02 §4.2. No allocation, and every dereference is preceded by
 * a bounds or generation check.
 */
static_always_inline cilium_srv6_program_verdict_t
cilium_srv6_program_one (const cilium_srv6_headend_main_t *hm, vlib_buffer_t *b,
			 const ip6_header_t *ip, f64 now, u32 *program_index)
{
  const cilium_srv6_headend_meta_t *meta = cilium_srv6_headend_meta (b);
  cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b);
  cilium_srv6_program_t *e;
  u64 key[3];
  u32 index;

  *program_index = ~0;

  cilium_srv6_program_key (key, meta->src_identity, &ip->dst_address, meta->proto,
			   meta->l4_discriminator);

  if (PREDICT_FALSE (!cilium_srv6_program_lookup (hm, key, &index)))
    return CILIUM_SRV6_PROGRAM_PUNT_MISS;

  e = cilium_srv6_program_at (hm, index);
  if (PREDICT_FALSE (e == NULL || !e->in_use))
    return CILIUM_SRV6_PROGRAM_PUNT_MISS;

  *program_index = index;

  /*
   * D-17 / D-30: only the three revisions this entry depends on are
   * compared, and the policy one is the slot of *this* src identity.
   */
  if (PREDICT_FALSE (!cilium_srv6_revisions_match (hm, e->policy_rev_slot, e->policy_revision,
						   e->endpoint_rev_slot, e->endpoint_revision,
						   e->path_cache_index, e->path_revision)))
    return CILIUM_SRV6_PROGRAM_PUNT_STALE;

  /*
   * 02 §4.2 / D-49 / D-51: the revision comparison above established policy
   * semantic freshness; this establishes policy watcher liveness. The lease
   * is not a field of the entry — it lives in the PolicyLeaseTable slot of
   * this entry's dependency identity, and is granted for the very revision
   * the entry stores, so one indexed read answers both remaining questions
   * (00 §2.1).
   *
   * A headend whose policy watcher is unhealthy stops pushing and stops
   * installing, so the deadline passes and every flow of that identity falls
   * back to the slow path, which is the fail-closed behaviour U-3 asks for.
   * DENY is fail-safe and consults no lease, so it is checked after this.
   */
  if (PREDICT_FALSE (e->verdict == CILIUM_SRV6_VERDICT_ALLOW &&
		     !cilium_srv6_policy_lease_valid (hm, e->policy_rev_slot, e->src_identity,
						      e->policy_revision, now)))
    return CILIUM_SRV6_PROGRAM_PUNT_LEASE;

  if (PREDICT_FALSE (e->verdict != CILIUM_SRV6_VERDICT_ALLOW))
    return CILIUM_SRV6_PROGRAM_DENY;

  /* D-12: the handle must still resolve to the generation it was compiled
     with, otherwise the path was retired underneath this packet. */
  if (PREDICT_FALSE (cilium_srv6_path_get (hm, e->path_cache_index, e->path_generation) == NULL))
    return CILIUM_SRV6_PROGRAM_PUNT_PATH;

  pm->path_cache_index = e->path_cache_index;
  pm->path_generation = e->path_generation;
  pm->program_index = index;

  /*
   * Per-entry statistics and the eviction input (02 §4.1, §5.3). Several
   * workers may update the same entry; that can under-count but never
   * affects forwarding.
   */
  e->packets += 1;
  e->last_used = now;

  return CILIUM_SRV6_PROGRAM_ALLOW;
}

static_always_inline u32
cilium_srv6_program_error_of_verdict (cilium_srv6_program_verdict_t v)
{
  switch (v)
    {
    case CILIUM_SRV6_PROGRAM_ALLOW:
      return CILIUM_SRV6_PROGRAM_ERROR_ALLOWED;
    case CILIUM_SRV6_PROGRAM_DENY:
      return CILIUM_SRV6_PROGRAM_ERROR_POLICY_DENIED;
    case CILIUM_SRV6_PROGRAM_PUNT_STALE:
      return CILIUM_SRV6_PROGRAM_ERROR_PUNT_STALE;
    case CILIUM_SRV6_PROGRAM_PUNT_LEASE:
      return CILIUM_SRV6_PROGRAM_ERROR_PUNT_LEASE_EXPIRED;
    case CILIUM_SRV6_PROGRAM_PUNT_PATH:
      return CILIUM_SRV6_PROGRAM_ERROR_PUNT_STALE_PATH;
    case CILIUM_SRV6_PROGRAM_MALFORMED:
      return CILIUM_SRV6_PROGRAM_ERROR_MALFORMED_INNER;
    default:
      return CILIUM_SRV6_PROGRAM_ERROR_PUNT_MISS;
    }
}

static_always_inline u8
cilium_srv6_punt_reason_of_verdict (cilium_srv6_program_verdict_t v)
{
  switch (v)
    {
    case CILIUM_SRV6_PROGRAM_PUNT_STALE:
      return CILIUM_SRV6_PUNT_REASON_STALE_REVISION;
    case CILIUM_SRV6_PROGRAM_PUNT_LEASE:
      return CILIUM_SRV6_PUNT_REASON_LEASE_EXPIRED;
    case CILIUM_SRV6_PROGRAM_PUNT_PATH:
      return CILIUM_SRV6_PUNT_REASON_STALE_PATH;
    default:
      return CILIUM_SRV6_PUNT_REASON_MISS;
    }
}

VLIB_NODE_FN (cilium_srv6_program_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b = bufs;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  u8 verdicts[VLIB_FRAME_SIZE], *vd = verdicts;
  u32 indices[VLIB_FRAME_SIZE], *pi = indices;
  u32 *from = vlib_frame_vector_args (frame);
  u32 n_left = frame->n_vectors;
  u32 n_verdict[CILIUM_SRV6_PROGRAM_N_VERDICT] = { 0 };
  f64 now = vlib_time_now (vm);
  u32 i;

  vlib_get_buffers (vm, from, bufs, n_left);

  while (n_left > 0)
    {
      cilium_srv6_headend_meta_t *meta = cilium_srv6_headend_meta (b[0]);
      cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b[0]);
      const ip6_header_t *ip = (const ip6_header_t *) vlib_buffer_get_current (b[0]);
      cilium_srv6_program_verdict_t v;

      if (PREDICT_FALSE (b[0]->current_length < sizeof (ip6_header_t)))
	{
	  /* cilium-srv6-classify already validated this; a packet that lost
	     its header between the two nodes is malformed. */
	  b[0]->error = node->errors[CILIUM_SRV6_PROGRAM_ERROR_MALFORMED_INNER];
	  next[0] = CILIUM_SRV6_PROGRAM_NEXT_DROP;
	  vd[0] = CILIUM_SRV6_PROGRAM_MALFORMED;
	  pi[0] = ~0;
	  goto next_packet;
	}

      v = cilium_srv6_program_one (hm, b[0], ip, now, pi);
      vd[0] = (u8) v;

      /*
       * 01 §3.1 / D-20: a first fragment's verdict is recorded here, bound to
       * the identity, endpoint incarnation, three revisions, lease and path
       * handle of the entry that produced it, so that the later fragments of
       * the same datagram are forwarded on exactly that decision and nothing
       * broader.
       */
      if (PREDICT_FALSE ((meta->flags & CILIUM_SRV6_META_F_FRAG_FIRST) != 0 &&
			 (v == CILIUM_SRV6_PROGRAM_ALLOW || v == CILIUM_SRV6_PROGRAM_DENY)))
	{
	  const cilium_srv6_program_t *e = cilium_srv6_program_at (hm, pi[0]);

	  cilium_srv6_frag_record (vm, &ip->src_address, &ip->dst_address, meta->frag_id,
				   pm->frag_next_header, meta, e,
				   (v == CILIUM_SRV6_PROGRAM_ALLOW) ? CILIUM_SRV6_VERDICT_ALLOW :
								      CILIUM_SRV6_VERDICT_DENY,
				   pm->path_cache_index, pm->path_generation);
	}

      switch (v)
	{
	case CILIUM_SRV6_PROGRAM_ALLOW:
	  next[0] = CILIUM_SRV6_PROGRAM_NEXT_ENCAP;
	  break;

	case CILIUM_SRV6_PROGRAM_DENY:
	  b[0]->error = node->errors[CILIUM_SRV6_PROGRAM_ERROR_POLICY_DENIED];
	  next[0] = CILIUM_SRV6_PROGRAM_NEXT_DROP;
	  break;

	default:
	  /* 02 §5.2 / D-43: a fragment-derived punt uses the dedicated
	     fragment queue so that fragment traffic cannot saturate the
	     compile queue. */
	  pm->punt_reason = cilium_srv6_punt_reason_of_verdict (v);
	  pm->punt_queue = (meta->flags & CILIUM_SRV6_META_F_FRAG_FIRST) ?
			     CILIUM_SRV6_PUNT_Q_FRAGMENT :
			     CILIUM_SRV6_PUNT_Q_COMPILE;
	  next[0] = CILIUM_SRV6_PROGRAM_NEXT_PUNT;
	  break;
	}

      n_verdict[v]++;

    next_packet:
      b += 1;
      next += 1;
      vd += 1;
      pi += 1;
      n_left -= 1;
    }

  for (i = 0; i < CILIUM_SRV6_PROGRAM_N_VERDICT; i++)
    if (n_verdict[i] && !CILIUM_SRV6_PROGRAM_VERDICT_IS_DROP (i))
      vlib_node_increment_counter (
	vm, node->node_index,
	cilium_srv6_program_error_of_verdict ((cilium_srv6_program_verdict_t) i), n_verdict[i]);

  if (PREDICT_FALSE (node->flags & VLIB_NODE_FLAG_TRACE))
    {
      b = bufs;
      vd = verdicts;
      pi = indices;

      for (i = 0; i < frame->n_vectors; i++, b++, vd++, pi++)
	{
	  const cilium_srv6_headend_meta_t *meta;
	  const cilium_srv6_program_t *e;
	  cilium_srv6_program_trace_t *t;

	  if (!(b[0]->flags & VLIB_BUFFER_IS_TRACED))
	    continue;

	  meta = cilium_srv6_headend_meta (b[0]);

	  t = vlib_add_trace (vm, node, b[0], sizeof (*t));
	  clib_memset (t, 0, sizeof (*t));

	  t->src_identity = meta->src_identity;
	  t->l4_discriminator = meta->l4_discriminator;
	  t->proto = meta->proto;
	  t->frag_first = (meta->flags & CILIUM_SRV6_META_F_FRAG_FIRST) ? 1 : 0;
	  t->program_index = pi[0];
	  t->path_cache_index = ~0;
	  t->verdict = vd[0];
	  t->current_policy_revision = cilium_srv6_policy_revision (hm, meta->policy_rev_slot);
	  /* D-83: the "current" value of a dependency is the one of *its key*,
	     and the entry is what names the key, so both are only known once
	     the entry has been resolved below. Until then they read as the
	     sentinel, which is also the honest answer for a miss: there is no
	     entry, so there is no key. */
	  t->current_endpoint_revision = CILIUM_SRV6_REV_INVALID;
	  t->current_path_revision = CILIUM_SRV6_REV_INVALID;

	  if (b[0]->current_length >= sizeof (ip6_header_t))
	    t->dst = ((const ip6_header_t *) vlib_buffer_get_current (b[0]))->dst_address;

	  e = (pi[0] == (u32) ~0) ? NULL : cilium_srv6_program_at (hm, pi[0]);
	  if (e != NULL)
	    {
	      t->policy_revision = e->policy_revision;
	      t->endpoint_revision = e->endpoint_revision;
	      t->path_revision = e->path_revision;
	      t->current_endpoint_revision =
		cilium_srv6_endpoint_revision (hm, e->endpoint_rev_slot);
	      t->current_path_revision = (e->path_revision == CILIUM_SRV6_REV_ABSENT) ?
					   CILIUM_SRV6_REV_ABSENT :
					   cilium_srv6_path_revision (hm, e->path_cache_index);
	      t->path_cache_index = e->path_cache_index;
	      t->path_generation = e->path_generation;
	      t->lease_remaining = cilium_srv6_policy_lease_remaining (
		hm, e->policy_rev_slot, e->src_identity, e->policy_revision, now);
	    }
	}
    }

  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);

  return frame->n_vectors;
}

VLIB_REGISTER_NODE (cilium_srv6_program_node) = {
  .name = "cilium-srv6-program",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .format_trace = format_cilium_srv6_program_trace,
  .format_buffer = format_ip6_header,
  .n_errors = CILIUM_SRV6_PROGRAM_N_ERROR,
  .error_counters = cilium_srv6_program_error_counters,
  .n_next_nodes = CILIUM_SRV6_PROGRAM_N_NEXT,
  .next_nodes = {
    [CILIUM_SRV6_PROGRAM_NEXT_DROP] = "ip6-drop",
    [CILIUM_SRV6_PROGRAM_NEXT_ENCAP] = "cilium-srv6-encap",
    [CILIUM_SRV6_PROGRAM_NEXT_PUNT] = "cilium-srv6-punt",
  },
};
