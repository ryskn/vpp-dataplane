/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — node-local conntrack (C10).
 *
 * design/detail/02-headend-dataplane.md §7 (structure, the three branches of
 * D-47, the five-step reply judgement of D-51), 03 §6 (the destination creates
 * UNVERIFIED entries and writes no verified_revision), 00 §2 (D-15, D-19,
 * D-38, D-45, D-49, D-51) and 00 §2.1 (policy decision validity).
 *
 * Synchronisation
 * ---------------
 * Two of the three writers are workers, so structural changes (create,
 * remove, evict, promote) are serialised with a spinlock rather than the
 * worker barrier; the pools are fixed size and the bihash arena is
 * preallocated, so nothing here allocates on the hot path. The control plane
 * paths (srv6_ct_verify, srv6_ct_invalidate, endpoint delete) additionally
 * hold the worker barrier, per D-12.
 *
 * Refreshing an existing entry — last_seen, the counters, the TCP progress
 * bits and the TCP state — is done in place without the lock. Workers never
 * write `key`, `verified_revision`, `policy_rev_slot`, the identities, the
 * path handle or `flags`; every one of those is written under the lock. A
 * lost race can therefore corrupt statistics or TCP progress, never an
 * authorisation: every step of the 02 §7.2 judgement is decided by fields
 * only the control plane writes, plus the PolicyLeaseTable, which is written
 * only by the main thread (D-51).
 */

#include <stdbool.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_hparse.h>
#include <cilium_srv6/cilium_srv6_endcilium.h>
#include <cilium_srv6/cilium_srv6_ct.h>

cilium_srv6_ct_main_t cilium_srv6_ct_main;

static vlib_log_class_t cilium_srv6_ct_log_class;

#define CSCT_LOG_NOTICE(...) vlib_log_notice (cilium_srv6_ct_log_class, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* formatting                                                          */
/* ------------------------------------------------------------------ */

u8 *
format_cilium_srv6_ct_state (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_CT_STATE_INVALID:
      return format (s, "INVALID");
    case CILIUM_SRV6_CT_STATE_UNVERIFIED:
      return format (s, "UNVERIFIED");
    case CILIUM_SRV6_CT_STATE_SYN_SEEN:
      return format (s, "SYN_SEEN");
    case CILIUM_SRV6_CT_STATE_VERIFIED_ESTABLISHED:
      return format (s, "VERIFIED_ESTABLISHED");
    case CILIUM_SRV6_CT_STATE_FIN_WAIT:
      return format (s, "FIN_WAIT");
    case CILIUM_SRV6_CT_STATE_CLOSED:
      return format (s, "CLOSED");
    default:
      return format (s, "unknown(%u)", v);
    }
}

u8 *
format_cilium_srv6_ct_direction (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  return format (s, "%s", v == CILIUM_SRV6_CT_DIR_REPLY ? "reply" : "forward");
}

/* ------------------------------------------------------------------ */
/* quota accounting (D-38 per-local-endpoint, D-42 owner)              */
/* ------------------------------------------------------------------ */

static void
csct_count_add (uword **h, u32 key, int delta)
{
  uword *p = hash_get (*h, (uword) key);
  uword v = p ? p[0] : 0;

  if (delta > 0)
    v += (uword) delta;
  else if (v >= (uword) (-delta))
    v -= (uword) (-delta);
  else
    v = 0;

  if (v == 0)
    hash_unset (*h, (uword) key);
  else
    hash_set (*h, (uword) key, v);
}

static uword
csct_count_get (uword *h, u32 key)
{
  uword *p = hash_get (h, (uword) key);

  return p ? p[0] : 0;
}

/*
 * The same soft quota the ProgramCache and the tombstone store use: a class's
 * budget is its share of the table among the classes that currently hold
 * entries. It is soft — a class may exceed it while the table has room — and
 * only decides who is evicted when the budget is full.
 */
static u32
csct_soft_quota (u32 capacity, u32 n_classes)
{
  if (n_classes < 1)
    n_classes = 1;

  return clib_max (1, capacity / n_classes);
}

static u32
csct_budget_capacity (const cilium_srv6_ct_main_t *ctm, u32 budget)
{
  if (budget == CILIUM_SRV6_CT_BUDGET_UNVERIFIED)
    return ctm->unverified_capacity;

  return ctm->capacity - ctm->unverified_capacity;
}

/* ------------------------------------------------------------------ */
/* age FIFO (one per budget)                                           */
/* ------------------------------------------------------------------ */

/* Insertion ordered, never reordered on refresh: a refresh must not take the
   lock, and expiry is re-evaluated on every read anyway. */
static void
csct_age_append (cilium_srv6_ct_main_t *ctm, u32 budget, u32 index)
{
  cilium_srv6_ct_age_t *a = ctm->age + index;

  a->next = ~0;
  a->prev = ctm->age_tail[budget];

  if (ctm->age_tail[budget] != (u32) ~0)
    ctm->age[ctm->age_tail[budget]].next = index;
  else
    ctm->age_head[budget] = index;

  ctm->age_tail[budget] = index;
}

static void
csct_age_remove (cilium_srv6_ct_main_t *ctm, u32 budget, u32 index)
{
  cilium_srv6_ct_age_t *a = ctm->age + index;

  if (a->prev != (u32) ~0)
    ctm->age[a->prev].next = a->next;
  else
    ctm->age_head[budget] = a->next;

  if (a->next != (u32) ~0)
    ctm->age[a->next].prev = a->prev;
  else
    ctm->age_tail[budget] = a->prev;

  a->prev = a->next = ~0;
}

/* ------------------------------------------------------------------ */
/* insertion and removal (lock held)                                   */
/* ------------------------------------------------------------------ */

static void
csct_remove (cilium_srv6_ct_main_t *ctm, u32 index)
{
  cilium_srv6_ct_entry_t *e = ctm->entries + index;
  clib_bihash_kv_40_8_t kv;
  u32 budget = cilium_srv6_ct_budget_of (e->flags);
  int i;

  for (i = 0; i < 5; i++)
    kv.key[i] = e->key[i];
  kv.value = index;

  /* Unhook first: from here the flow misses and is evaluated by the
     ProgramCache, which is the fail-closed side of every branch. */
  clib_bihash_add_del_40_8 (&ctm->table, &kv, 0 /* del */);

  csct_age_remove (ctm, budget, index);
  csct_count_add (&ctm->ep_count, e->local_context_id, -1);
  csct_count_add (&ctm->owner_count, e->owner_quota_class, -1);

  if (ctm->n_entries[budget] > 0)
    ctm->n_entries[budget]--;

  /* Zeroing leaves state INVALID, so a worker that is still holding the
     index from a concurrent lookup reads an unusable entry. */
  clib_memset (e, 0, sizeof (*e));
  ctm->age[index].prev = ctm->age[index].next = ~0;

  pool_put_index (ctm->entries, index);
}

/*
 * Fair eviction (D-38 / D-42), bounded scan from the oldest entry of the
 * budget being filled:
 *
 *   1. an entry that has already expired,
 *   2. then one whose local endpoint *and* owner are over their soft quota,
 *   3. then one whose owner is over its soft quota,
 *   4. otherwise the oldest entry of the budget,
 *
 * and inside a class the smallest last_seen wins. An entry whose endpoint and
 * owner are both within quota is only evicted when the scan window holds
 * nothing over quota, which is what stops one endpoint's high-cardinality
 * 5-tuples from displacing another's established flows.
 *
 * Lock held. Returns 1 if an entry was evicted.
 */
static int
csct_evict_one (cilium_srv6_ct_main_t *ctm, u32 budget, f64 now)
{
  u32 ep_quota = csct_soft_quota (ctm->capacity, (u32) hash_elts (ctm->ep_count));
  u32 owner_quota = csct_soft_quota (ctm->capacity, (u32) hash_elts (ctm->owner_count));
  u32 index = ctm->age_head[budget];
  u32 victim = ~0;
  u32 best_rank = 0;
  f64 best_last_seen = 0;
  u32 n;

  for (n = 0; n < CILIUM_SRV6_CT_EVICT_SCAN && index != (u32) ~0; n++)
    {
      const cilium_srv6_ct_entry_t *e = ctm->entries + index;
      u32 next = ctm->age[index].next;
      u32 rank = 1;

      if (cilium_srv6_ct_expired (ctm, e, now))
	rank = 4;
      else if (csct_count_get (ctm->owner_count, e->owner_quota_class) > owner_quota)
	rank = (csct_count_get (ctm->ep_count, e->local_context_id) > ep_quota) ? 3 : 2;

      if (victim == (u32) ~0 || rank > best_rank ||
	  (rank == best_rank && e->last_seen < best_last_seen))
	{
	  victim = index;
	  best_rank = rank;
	  best_last_seen = e->last_seen;
	}

      index = next;
    }

  if (victim == (u32) ~0)
    return 0;

  csct_remove (ctm, victim);
  ctm->n_evictions++;

  return 1;
}

/*
 * Make room in one budget. Lock held. `need_pool_slot` is 0 when an entry
 * only moves between budgets (srv6_ct_verify), in which case the pool
 * occupancy does not change and evicting for it would be gratuitous.
 * Returns 1 if the budget can take the entry.
 */
static int
csct_make_room (cilium_srv6_ct_main_t *ctm, u32 budget, f64 now, int need_pool_slot)
{
  while (ctm->n_entries[budget] >= csct_budget_capacity (ctm, budget) ||
	 (need_pool_slot && pool_free_elts (ctm->entries) == 0))
    {
      if (!csct_evict_one (ctm, budget, now))
	{
	  ctm->n_quota_drops++;
	  return 0;
	}
    }

  return 1;
}

/*
 * Create one entry. Lock held. Returns the pool index, or ~0.
 *
 * `verified_revision` is CILIUM_SRV6_REV_INVALID for everything the
 * destination delivery path creates: D-19 / D-45 forbid writing a guessed
 * revision there, and the sentinel is what makes 02 §7.2 send the first reply
 * through the re-authorisation punt.
 */
static u32
csct_create (cilium_srv6_ct_main_t *ctm, const u64 key[5], u8 flags, u8 proto, u8 state,
	     u64 verified_revision, u32 policy_rev_slot, u32 local_context_id,
	     u32 local_endpoint_identity, u32 owner_quota_class, f64 now)
{
  clib_bihash_kv_40_8_t kv;
  cilium_srv6_ct_entry_t *e;
  u32 budget = cilium_srv6_ct_budget_of (flags);
  u32 index;
  int i;

  for (i = 0; i < 5; i++)
    kv.key[i] = key[i];

  /* Another worker may have created the same flow between the failed lookup
     and this point. */
  kv.value = 0;
  if (0 == clib_bihash_search_40_8 (&ctm->table, &kv, &kv))
    return (u32) kv.value;

  if (!csct_make_room (ctm, budget, now, 1 /* needs a pool slot */))
    return ~0;

  pool_get_zero (ctm->entries, e);
  index = (u32) (e - ctm->entries);

  for (i = 0; i < 5; i++)
    e->key[i] = key[i];

  e->verified_revision = verified_revision;
  e->last_seen = now;
  e->local_context_id = local_context_id;
  e->local_endpoint_identity = local_endpoint_identity;
  e->remote_identity = 0;
  e->policy_rev_slot = policy_rev_slot;
  e->path_cache_index = ~0;
  e->path_generation = 0;
  e->owner_quota_class = owner_quota_class;
  e->state = state;
  e->flags = flags;
  e->tcp = 0;
  e->proto = proto;

  for (i = 0; i < 5; i++)
    kv.key[i] = key[i];
  kv.value = index;

  if (clib_bihash_add_del_40_8 (&ctm->table, &kv, 1 /* add */) < 0)
    {
      clib_memset (e, 0, sizeof (*e));
      pool_put_index (ctm->entries, index);
      return ~0;
    }

  ctm->age[index].prev = ctm->age[index].next = ~0;
  csct_age_append (ctm, budget, index);
  csct_count_add (&ctm->ep_count, local_context_id, +1);
  csct_count_add (&ctm->owner_count, owner_quota_class, +1);
  ctm->n_entries[budget]++;
  ctm->n_created[budget]++;

  return index;
}

/* ------------------------------------------------------------------ */
/* per-packet update (no lock, see the file header)                    */
/* ------------------------------------------------------------------ */

/*
 * Per-packet state update. The TCP transition rules themselves are in
 * cilium_srv6_ct_fsm.h.
 */
static_always_inline void
csct_touch (cilium_srv6_ct_entry_t *e, u8 proto, u8 th, int own, u32 length, f64 now)
{
  e->last_seen = now;
  e->pkts[own ? 0 : 1] += 1;
  e->bytes[own ? 0 : 1] += length;

  if (proto == IP_PROTOCOL_TCP)
    cilium_srv6_ct_tcp_step (&e->state, &e->tcp, (e->flags & CILIUM_SRV6_CT_F_VERIFIED) ? 1 : 0,
			     th, own);
}

/* ------------------------------------------------------------------ */
/* headend lookup hook (02 §7.2, D-47)                                 */
/* ------------------------------------------------------------------ */

/*
 * The three branches of D-47.
 *
 * Two probes at most. The forward-direction key is probed first because both
 * keys can exist for one tuple: a local endpoint that initiated a flow has a
 * forward entry from 02 §6 step 1, and the delivery of the peer's answers
 * would otherwise leave a reply entry for the same tuple that its own
 * outbound packets would match. The design counts "conntrack 1" lookup in
 * 02 §1; splitting the direction into the key (02 §7.1) makes it one probe
 * for a flow the endpoint initiated and two for one it answers.
 */
static cilium_srv6_ct_lookup_verdict_t
cilium_srv6_ct_lookup (vlib_main_t *vm, u32 thread_index, vlib_buffer_t *b,
		       const cilium_srv6_ct_query_t *q, cilium_srv6_ct_result_t *res)
{
  cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_headend_meta_t *meta = cilium_srv6_headend_meta (b);
  const cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b);
  const ip6_header_t *ip;
  cilium_srv6_ct_entry_t *e;
  u32 incarnation = hm->current_revision_incarnation;
  u64 published;
  u64 key[5];
  u32 index;
  u8 th;

  if (PREDICT_FALSE (!ctm->initialised))
    return CILIUM_SRV6_CT_MISS;

  /* A non-first fragment carries no ports, so it has no 5-tuple to match on
     (01 §3.1); it is forwarded on the path its first fragment was allowed
     on and never through a conntrack decision. */
  if (PREDICT_FALSE (meta->flags &
		     (CILIUM_SRV6_META_F_FRAG_NON_FIRST | CILIUM_SRV6_META_F_FRAG_RESOLVED)))
    return CILIUM_SRV6_CT_MISS;

  if (PREDICT_FALSE (b->current_length < sizeof (ip6_header_t)))
    return CILIUM_SRV6_CT_MISS;

  ip = (const ip6_header_t *) vlib_buffer_get_current (b);
  th = pm->tcp_flags;

  /*
   * "単なる 5-tuple 一致で ProgramCache を迂回しない" (02 §7.2). A TCP SYN
   * without ACK opens a connection in the forward direction by definition, so
   * it is never a reply, whatever entry happens to match its tuple. Without
   * this, an unsolicited packet delivered to this node earlier could have
   * pre-created a reply entry for a tuple the local endpoint later initiates,
   * and the connection's own first packet would be authorised in the reverse
   * direction.
   */
  if (cilium_srv6_ct_opens_connection (meta->proto == IP_PROTOCOL_TCP, th))
    return CILIUM_SRV6_CT_MISS;

  /* Branch 3: the local endpoint initiated this flow. */
  cilium_srv6_ct_key (key, &ip->src_address, &ip->dst_address, meta->proto, pm->sport, pm->dport,
		      CILIUM_SRV6_CT_DIR_FORWARD);
  if (cilium_srv6_ct_lookup_index (ctm, key, &index))
    return CILIUM_SRV6_CT_MISS;

  /* Branch 3: no reply entry either. */
  cilium_srv6_ct_key (key, &ip->src_address, &ip->dst_address, meta->proto, pm->sport, pm->dport,
		      CILIUM_SRV6_CT_DIR_REPLY);
  if (!cilium_srv6_ct_lookup_index (ctm, key, &index))
    return CILIUM_SRV6_CT_MISS;

  e = ctm->entries + index;

  if (PREDICT_FALSE (e->state == CILIUM_SRV6_CT_STATE_INVALID))
    return CILIUM_SRV6_CT_MISS;

  /*
   * D-15: the entry is bound to the endpoint incarnation it was created for,
   * so an address reused by a new Pod does not inherit the previous Pod's
   * authorisation. The comparison is against the live LocalEndpointTable
   * values the classify stage resolved for this packet.
   */
  if (PREDICT_FALSE (e->local_context_id != q->local_context_id ||
		     e->local_endpoint_identity != q->src_identity))
    {
      ctm->n_incarnation_mismatch++;
      return CILIUM_SRV6_CT_REPLY_REAUTH;
    }

  /* An expired entry describes a flow that is no longer tracked; it is not
     allowed to carry an authorisation forward (02 §7.2 "CLOSED/timeout 後は
     許可しない"). */
  if (PREDICT_FALSE (cilium_srv6_ct_expired (ctm, e, q->now)))
    return CILIUM_SRV6_CT_REPLY_REAUTH;

  /*
   * Protocol state. VERIFIED_ESTABLISHED is the state 02 §7.2 names;
   * FIN_WAIT is admitted with it because it is only reachable from
   * VERIFIED_ESTABLISHED and the design excludes CLOSED and timeout, not a
   * flow that is still exchanging its close.
   */
  if (PREDICT_FALSE (!cilium_srv6_ct_state_admits_bypass (e->state)))
    {
      if (e->state == CILIUM_SRV6_CT_STATE_CLOSED)
	ctm->n_proto_state_denied++;
      return CILIUM_SRV6_CT_REPLY_REAUTH;
    }

  /*
   * Step 2 of 02 §7.2 — policy semantic freshness. The revision an entry
   * stores is the one of the identity that is the *source* of the authorised
   * direction, i.e. the peer (D-30 / D-45). An unauthorised entry holds the
   * sentinel, which no published revision can equal, so it never matches
   * here.
   *
   * This is where a policy change is detected, and it is detected on the
   * first reply after the change regardless of how much lease is left: the
   * two are independent properties (00 §2.1).
   *
   * D-85 (00 §2.23.5, errata #34 item 176): the equality alone is not enough.
   * `verified_revision` is a quotation made by whichever agent process answered
   * the re-authorisation, and the ruling makes *every* quotation of an older
   * incarnation stale — "それ以前の incarnation を quote する Program /
   * Fragment / CT 由来 revision はすべて stale として扱う". For a remote
   * identity the new process no longer knows about, nothing republishes the
   * slot, so the equality keeps passing and this bypass would forward a reply
   * on a decision taken by a process that no longer holds the revision
   * authority — and it forwards it straight to cilium-srv6-encap, where the
   * ProgramCache check that carries the fence never runs. The fence is
   * therefore part of the same predicate the ProgramCache path uses
   * (cilium_srv6_revision_matches), and a refusal is an UNVERIFIED entry as far
   * as this node is concerned: D-47 branch 2, the re-authorisation punt.
   */
  published = cilium_srv6_policy_revision_of (hm, e->policy_rev_slot, e->remote_identity);
  if (PREDICT_FALSE (!cilium_srv6_revision_matches (e->verified_revision, published, incarnation)))
    {
      ctm->n_revision_mismatch++;

      /* A breakdown of the line above, not a second reason: how many of those
	 refusals were the D-85 fence rather than a per-key change. The sentinel
	 is excluded — an UNVERIFIED entry quotes no revision at all, so it is
	 not a quotation of a previous incarnation. */
      if (e->verified_revision != CILIUM_SRV6_REV_INVALID &&
	  e->verified_revision != CILIUM_SRV6_REV_ABSENT &&
	  !cilium_srv6_revision_is_current (e->verified_revision, incarnation))
	ctm->n_stale_incarnation++;

      return CILIUM_SRV6_CT_REPLY_REAUTH;
    }

  /*
   * Steps 3 and 4 — policy watcher liveness (D-49, held by D-51). The lease
   * is read from the PolicyLeaseTable slot of the remote identity and must
   * have been granted for this entry's revision and not have expired.
   * Without them a watcher outage freezes the revision, step 2 keeps passing,
   * and the reply direction stays open until the 8 h TCP timeout.
   */
  if (PREDICT_FALSE (!cilium_srv6_policy_lease_valid (hm, e->policy_rev_slot, e->remote_identity,
						      e->verified_revision, q->now)))
    {
      ctm->n_lease_expired++;
      return CILIUM_SRV6_CT_REPLY_REAUTH;
    }

  /*
   * The path the bypass encapsulates on. 02 §7.1 has no path handle field;
   * it is written by srv6_ct_verify (see the DEVIATION note in the .api) and
   * the caller re-resolves it, degrading to a re-authorisation punt when the
   * handle no longer resolves.
   */
  res->path_cache_index = e->path_cache_index;
  res->path_generation = e->path_generation;

  return CILIUM_SRV6_CT_REPLY_ALLOW;
}

/* ------------------------------------------------------------------ */
/* headend egress hook (02 §6 step 1)                                  */
/* ------------------------------------------------------------------ */

/*
 * Called from cilium-srv6-encap for every packet that is about to be
 * encapsulated, i.e. for every packet this node has authorised.
 *
 *   - a packet that took the 02 §7.2 branch-1 bypass refreshes the reply
 *     entry it matched, and must not create a forward entry: the next reply
 *     of the same flow would then find a forward entry first and be sent to
 *     the ProgramCache, where the reply direction has no ALLOW;
 *   - anything else creates or refreshes the forward entry of its flow.
 */
static void
cilium_srv6_ct_egress (vlib_main_t *vm, u32 thread_index, vlib_buffer_t *b,
		       const cilium_srv6_ct_query_t *q)
{
  cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  const cilium_srv6_headend_meta_t *meta = cilium_srv6_headend_meta (b);
  const cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b);
  const ip6_header_t *ip;
  cilium_srv6_ct_entry_t *e;
  u64 key[5];
  u32 index, length;
  u8 dir, state, th;
  int locked = 0;

  if (PREDICT_FALSE (!ctm->initialised))
    return;

  if (PREDICT_FALSE (meta->flags &
		     (CILIUM_SRV6_META_F_FRAG_NON_FIRST | CILIUM_SRV6_META_F_FRAG_RESOLVED)))
    return;

  if (PREDICT_FALSE (b->current_length < sizeof (ip6_header_t)))
    return;

  ip = (const ip6_header_t *) vlib_buffer_get_current (b);
  th = pm->tcp_flags;
  length = (u32) vlib_buffer_length_in_chain (vm, b);
  dir = (meta->flags & CILIUM_SRV6_META_F_CT_REPLY) ? CILIUM_SRV6_CT_DIR_REPLY :
						      CILIUM_SRV6_CT_DIR_FORWARD;

  cilium_srv6_ct_key (key, &ip->src_address, &ip->dst_address, meta->proto, pm->sport, pm->dport,
		      dir);

  if (PREDICT_TRUE (cilium_srv6_ct_lookup_index (ctm, key, &index)))
    {
      e = ctm->entries + index;

      if (PREDICT_TRUE (e->local_context_id == meta->local_context_id))
	{
	  csct_touch (e, meta->proto, th, 1 /* own direction */, length, q->now);
	  return;
	}

      /* D-15: an entry left from a previous Pod at this address is replaced,
	 never refreshed into the new Pod's flow state. */
      locked = 1;
      clib_spinlock_lock (&ctm->lock);

      if (cilium_srv6_ct_lookup_index (ctm, key, &index) &&
	  ctm->entries[index].local_context_id != meta->local_context_id)
	csct_remove (ctm, index);
    }

  /* A reply-direction entry is only ever created by the destination's
     delivery path (03 §6). If the bypass matched one that has since been
     evicted, the next packet re-authorises; nothing is created here. */
  if (dir == CILIUM_SRV6_CT_DIR_REPLY)
    {
      if (locked)
	clib_spinlock_unlock (&ctm->lock);
      return;
    }

  /*
   * 02 §7.1: "TCP は SYN 受信で SYN_SEEN". A TCP flow that starts with a SYN
   * is tracked through the handshake; anything else (a mid-stream packet
   * after a restart, or a stateless protocol) starts established, because
   * this node has just authorised the packet through the ProgramCache.
   */
  state = cilium_srv6_ct_initial_state (meta->proto == IP_PROTOCOL_TCP, th);

  if (!locked)
    clib_spinlock_lock (&ctm->lock);

  /*
   * The revision recorded here is the one the ProgramCache authorised this
   * packet under, scoped to the local endpoint's identity — a real revision,
   * not the guess D-45 forbids. It is observability only: a forward entry is
   * never an input to the 02 §7.2 bypass (a forward hit is branch 3), so the
   * slot is stored without taking a reference on it and is not compared.
   */
  index = csct_create (ctm, key, CILIUM_SRV6_CT_F_VERIFIED, meta->proto, state,
		       q->policy_revision, meta->policy_rev_slot, meta->local_context_id,
		       meta->src_identity, meta->owner_quota_class, q->now);

  if (PREDICT_TRUE (index != (u32) ~0))
    {
      e = ctm->entries + index;
      e->path_cache_index = pm->path_cache_index;
      e->path_generation = pm->path_generation;
      csct_touch (e, meta->proto, th, 1 /* own direction */, length, q->now);
    }

  clib_spinlock_unlock (&ctm->lock);
}

/* ------------------------------------------------------------------ */
/* destination delivery hook (03 §6 step 2, D-19 / D-45)               */
/* ------------------------------------------------------------------ */

/* Refresh, or create as UNVERIFIED, one delivery-side entry. */
static void
csct_deliver_entry (cilium_srv6_ct_main_t *ctm, const u64 key[5], u8 flags, u8 proto, u8 th,
		    int own, u32 length, const cilium_srv6_local_ep_t *ep, f64 now)
{
  cilium_srv6_ct_entry_t *e;
  u32 index;
  int locked = 0;

  if (PREDICT_TRUE (cilium_srv6_ct_lookup_index (ctm, key, &index)))
    {
      e = ctm->entries + index;

      if (PREDICT_TRUE (e->local_context_id == ep->local_context_id))
	{
	  csct_touch (e, proto, th, own, length, now);
	  return;
	}

      /*
       * D-15: an entry left over from a previous Pod at this address is
       * replaced, never refreshed into the new Pod's flow state, so the new
       * Pod cannot inherit a previous authorisation.
       */
      locked = 1;
      clib_spinlock_lock (&ctm->lock);

      if (cilium_srv6_ct_lookup_index (ctm, key, &index) &&
	  ctm->entries[index].local_context_id != ep->local_context_id)
	csct_remove (ctm, index);
    }

  if (!locked)
    clib_spinlock_lock (&ctm->lock);

  /*
   * D-19 / D-45: state UNVERIFIED and `verified_revision` at the sentinel. The
   * wire carries neither the source identity nor the revision the sending
   * headend authorised under, so this node cannot store a true revision, and
   * storing its own current one would satisfy the 02 §7.2 revision condition
   * by construction — the reply bypass D-19 removed.
   */
  index = csct_create (ctm, key, flags, proto, CILIUM_SRV6_CT_STATE_UNVERIFIED,
		       CILIUM_SRV6_REV_INVALID, 0 /* sentinel slot */, ep->local_context_id,
		       ep->identity, ep->owner_quota_class, now);

  if (PREDICT_TRUE (index != (u32) ~0))
    csct_touch (ctm->entries + index, proto, th, own, length, now);

  clib_spinlock_unlock (&ctm->lock);
}

/*
 * 03 §6 step 2: "forward entry + reply entry を state=UNVERIFIED で
 * create/refresh". The buffer starts at the inner IPv6 header, which the
 * decapsulation has already bounds-checked; the inner chain is walked again
 * here with the same bounded parser the headend uses, because the delivery
 * path never derived a 5-tuple.
 */
static void
cilium_srv6_ct_deliver (vlib_main_t *vm, u32 thread_index, vlib_buffer_t *b,
			const cilium_srv6_ct_ctx_t *ctx)
{
  cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_main_t *gm = &cilium_srv6_main;
  const cilium_srv6_local_ep_t *ep;
  const ip6_header_t *ip;
  cilium_srv6_hparse_t hp;
  u64 key[5];
  u32 index, length;
  f64 now;
  u8 th;

  if (PREDICT_FALSE (!ctm->initialised))
    return;

  /*
   * The conntrack value is defined in terms of the LocalEndpointTable
   * (02 §7.2 compares against its identity and incarnation), so an interface
   * the agent has not installed an endpoint for gets no conntrack state: its
   * packets are never classified by the headend either, so no entry of it
   * could ever be consulted.
   */
  ep = cilium_srv6_local_ep_lookup (hm, gm, ctx->tx_sw_if_index);
  if (PREDICT_FALSE (ep == NULL))
    return;

  if (PREDICT_FALSE (b->current_length < sizeof (ip6_header_t)))
    return;

  length = (u32) vlib_buffer_length_in_chain (vm, b);
  ip = (const ip6_header_t *) vlib_buffer_get_current (b);

  if (PREDICT_FALSE (CILIUM_SRV6_HPARSE_OK !=
		     cilium_srv6_hparse ((const u8 *) ip, b->current_length, length, &hp)))
    return;

  /* No ports, so no 5-tuple: 01 §3.1 forwards these on the first fragment's
     verdict and they never reach a conntrack decision. */
  if (PREDICT_FALSE (hp.frag_kind == CILIUM_SRV6_FRAG_NON_FIRST))
    return;

  /*
   * The delivered packet must be addressed to the endpoint the
   * LocalEndpointTable knows on this interface. End.Cilium has already
   * checked the inner destination against the Context's endpoint address
   * (03 §3), so a mismatch here means the two tables disagree; a reply entry
   * keyed on an address this endpoint may not send from could never be
   * matched anyway, because cilium-srv6-classify anti-spoofs against exactly
   * this address (02 §3). Not creating it keeps the table free of state that
   * cannot be used.
   */
  if (PREDICT_FALSE (!ip6_address_is_equal (&ip->dst_address, &ep->ip)))
    return;

  th = hp.tcp_flags;
  now = vlib_time_now (vm);

  /* The forward entry: the tuple exactly as delivered. */
  cilium_srv6_ct_key (key, &ip->src_address, &ip->dst_address, hp.proto, hp.sport, hp.dport,
		      CILIUM_SRV6_CT_DIR_FORWARD);
  csct_deliver_entry (ctm, key, 0 /* not verified */, hp.proto, th, 1 /* own */, length, ep, now);

  /*
   * The reply entry: the swapped tuple, which is what the local endpoint's
   * answer carries and what 02 §7.2 matches.
   *
   * It is not created when this node's own endpoint initiated a flow with
   * that same tuple — the forward entry of 02 §6 step 1 exists — because such
   * an entry could only ever shadow the endpoint's own outbound direction:
   * the reply bypass would then authorise the forward direction against the
   * reverse direction's policy. The initiator's outbound packets are
   * authorised by the ProgramCache and its peer's packets arrive on the
   * delivery path, which consults no conntrack (D-45/D-48), so nothing is
   * lost by not creating it.
   */
  cilium_srv6_ct_key (key, &ip->dst_address, &ip->src_address, hp.proto, hp.dport, hp.sport,
		      CILIUM_SRV6_CT_DIR_FORWARD);
  if (PREDICT_FALSE (cilium_srv6_ct_lookup_index (ctm, key, &index)))
    {
      cilium_srv6_ct_entry_t *e = ctm->entries + index;

      /* The peer answered: this is the opposite direction of that entry. */
      if (PREDICT_TRUE (e->local_context_id == ep->local_context_id))
	csct_touch (e, hp.proto, th, 0 /* opposite */, length, now);
      return;
    }

  cilium_srv6_ct_key (key, &ip->dst_address, &ip->src_address, hp.proto, hp.dport, hp.sport,
		      CILIUM_SRV6_CT_DIR_REPLY);
  csct_deliver_entry (ctm, key, CILIUM_SRV6_CT_F_REPLY, hp.proto, th, 0 /* opposite */, length, ep,
		      now);
}

/* ------------------------------------------------------------------ */
/* srv6_ct_verify (02 §7.2 branch 2, IF-2)                             */
/* ------------------------------------------------------------------ */

int
cilium_srv6_ct_verify (const ip6_address_t *src, const ip6_address_t *dst, u8 proto, u16 sport,
		       u16 dport, u32 sw_if_index, u32 if_incarnation, u32 local_identity,
		       u32 remote_identity, u64 policy_revision, u32 path_cache_index,
		       u32 path_generation)
{
  cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_main_t *gm = &cilium_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  const cilium_srv6_local_ep_t *ep;
  cilium_srv6_ct_entry_t *e;
  u64 key[5];
  u32 index, slot;
  f64 now;
  int taken, rv = 0;

  if (!ctm->initialised || !hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  /* 00 §4.1: everything is validated before any state is touched. */

  if (ip6_address_is_zero (src) || ip6_address_is_zero (dst))
    return VNET_API_ERROR_INVALID_VALUE;

  /* The sentinel is what "not authorised" means in an entry, so it can never
     be the value of an authorisation. */
  if (policy_revision == CILIUM_SRV6_REV_INVALID)
    return VNET_API_ERROR_INVALID_VALUE;

  /* D-31: the endpoint the punt was issued for must still be the one behind
     this sw_if_index, and it must still carry the identity the decision was
     made for. */
  ep = cilium_srv6_local_ep_lookup (hm, gm, sw_if_index);
  if (ep == NULL)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (ep->if_incarnation != if_incarnation)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (ep->identity != local_identity)
    return VNET_API_ERROR_INVALID_VALUE_3;

  /*
   * The reply's source has to be the address of that endpoint. The punt
   * metadata is the authority on which endpoint sent the packet (02 §3), so a
   * tuple that does not belong to it would bind an authorisation to the wrong
   * flow; refusing is free and keeps the two halves of the message
   * consistent.
   */
  if (!ip6_address_is_equal (&ep->ip, src))
    return VNET_API_ERROR_INVALID_VALUE;

  /* The reply bypass has to name a path to encapsulate on. */
  if (cilium_srv6_path_get (hm, path_cache_index, path_generation) == NULL)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  cilium_srv6_ct_key (key, src, dst, proto, sport, dport, CILIUM_SRV6_CT_DIR_REPLY);

  now = vlib_time_now (vm);

  taken = cilium_srv6_barrier_acquire (vm);
  clib_spinlock_lock (&ctm->lock);

  if (!cilium_srv6_ct_lookup_index (ctm, key, &index))
    {
      /*
       * The entry expired or was evicted between the punt and the answer.
       * Nothing is created here: an entry is a record of an observed flow,
       * and the peer's retransmission recreates it on the delivery path.
       */
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto done;
    }

  e = ctm->entries + index;

  if (e->state == CILIUM_SRV6_CT_STATE_INVALID || e->state == CILIUM_SRV6_CT_STATE_CLOSED)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto done;
    }

  /*
   * D-15: an entry created for a previous incarnation of this endpoint is not
   * rebound to the current one. The Pod behind the address changed while the
   * re-authorisation was in flight, so the flow this entry records is not the
   * flow that was authorised. The delivery path replaces such an entry on the
   * peer's next packet.
   */
  if (e->local_context_id != ep->local_context_id)
    {
      rv = VNET_API_ERROR_NO_SUCH_ENTRY;
      goto done;
    }

  /*
   * D-30 scopes the revision to the source identity of the authorised
   * direction, which for a reply is the peer. The slot of that identity is
   * created if the node does not have one yet and is then retained, exactly
   * as srv6_policy_revision_publish retains the slots it creates; conntrack takes no
   * per-entry reference, so nothing here has to release one from a worker.
   * The entry stores the peer identity alongside the slot, so a slot that is
   * later reused for a different identity fails the comparison instead of
   * matching a foreign revision.
   */
  slot = cilium_srv6_policy_rev_slot_pin (remote_identity);
  if (slot == 0)
    {
      rv = VNET_API_ERROR_LIMIT_EXCEEDED;
      goto done;
    }

  /* D-85 (00 §2.23): the re-authorisation was decided by an agent process that
     no longer holds the revision authority. It is checked before the per-key
     comparison because the per-key one cannot see it: if the peer identity is
     one the current agent process does not know about, the slot still holds the
     previous generation's value and the two would compare equal. Counted apart
     for the same reason srv6_program_add_del counts it apart. */
  if (cilium_srv6_revision_is_stale_incarnation (hm, policy_revision))
    {
      cilium_srv6_headend_main.n_stale_incarnation_quotes++;
      rv = VNET_API_ERROR_INVALID_VALUE_4;
      goto done;
    }

  /* Same rule as srv6_program_add_del: nothing decided under a revision is
     installed once that revision has moved (02 §4.3). */
  if (policy_revision != cilium_srv6_policy_revision_of (hm, slot, remote_identity))
    {
      rv = VNET_API_ERROR_INVALID_VALUE_4;
      goto done;
    }

  if (cilium_srv6_ct_budget_of (e->flags) == CILIUM_SRV6_CT_BUDGET_UNVERIFIED)
    {
      /* Moving out of the D-38 allowance and into the authorised one. The
	 pool occupancy does not change, only the budget. */
      if (!csct_make_room (ctm, CILIUM_SRV6_CT_BUDGET_VERIFIED, now, 0))
	{
	  rv = VNET_API_ERROR_LIMIT_EXCEEDED;
	  goto done;
	}

      /* csct_make_room() evicts, so the index is re-resolved before use. */
      if (!cilium_srv6_ct_lookup_index (ctm, key, &index))
	{
	  rv = VNET_API_ERROR_NO_SUCH_ENTRY;
	  goto done;
	}

      e = ctm->entries + index;

      csct_age_remove (ctm, CILIUM_SRV6_CT_BUDGET_UNVERIFIED, index);
      if (ctm->n_entries[CILIUM_SRV6_CT_BUDGET_UNVERIFIED] > 0)
	ctm->n_entries[CILIUM_SRV6_CT_BUDGET_UNVERIFIED]--;

      e->flags |= CILIUM_SRV6_CT_F_VERIFIED;

      csct_age_append (ctm, CILIUM_SRV6_CT_BUDGET_VERIFIED, index);
      ctm->n_entries[CILIUM_SRV6_CT_BUDGET_VERIFIED]++;
    }

  /*
   * 02 §7.2: "ALLOW のときだけ policy_revision を書き込んで
   * VERIFIED_ESTABLISHED に遷移させる", plus the path handle the bypass
   * needs. No lease is written into the entry: D-51 keeps it in the
   * PolicyLeaseTable, and the refresh below is made against the identity.
   */
  e->remote_identity = remote_identity;
  e->policy_rev_slot = slot;
  e->verified_revision = policy_revision;
  e->path_cache_index = path_cache_index;
  e->path_generation = path_generation;
  /* The identity of an endpoint can change without its incarnation changing
     (a label edit), and the decision above was made for the current one. */
  e->local_endpoint_identity = ep->identity;

  /* The quota class is an accounting key, so a change has to move the count
     rather than only the field. */
  if (e->owner_quota_class != ep->owner_quota_class)
    {
      csct_count_add (&ctm->owner_count, e->owner_quota_class, -1);
      csct_count_add (&ctm->owner_count, ep->owner_quota_class, +1);
      e->owner_quota_class = ep->owner_quota_class;
    }

  e->state = CILIUM_SRV6_CT_STATE_VERIFIED_ESTABLISHED;
  e->last_seen = now;

  /*
   * 02 §5.4: the promotion is one of the four policy_lease_touch paths — the
   * opportunistic refresh that a reauthorization commit performs. The agent
   * only re-authorises while its watchers are healthy and the revision was
   * compared against the published one above, so the promotion itself is
   * liveness evidence for {remote_identity, policy_revision}. Without the
   * refresh the entry would be lease-invalid until the agent's next bulk push,
   * i.e. the very next reply would punt for re-authorisation again.
   * cilium_srv6_policy_lease_touch() re-applies the same exact-revision and
   * no-regression rules the bulk push obeys (Issue #61 invariant 1).
   *
   * Issue #61 invariant 3 applies to this path as well: the transition to
   * VERIFIED_ESTABLISHED above and this refresh are one logical commit. Both
   * are inside the barrier section this function opened (and inside the
   * conntrack spinlock), so no worker can observe an entry whose state says
   * VERIFIED while the PolicyLeaseTable slot still holds the pre-commit lease.
   */
  cilium_srv6_policy_lease_touch (slot, remote_identity, policy_revision, 0 /* default */);

  ctm->n_verified++;

done:
  if (rv != 0)
    ctm->n_verify_rejected++;

  clib_spinlock_unlock (&ctm->lock);
  cilium_srv6_barrier_release (vm, taken);

  return rv;
}

/* ------------------------------------------------------------------ */
/* invalidation (02 §8 srv6_ct_invalidate, 03 §7, D-15)                */
/* ------------------------------------------------------------------ */

/* Remove every entry of one endpoint incarnation in [cursor, cursor + n).
   Lock held. Returns the number removed. */
static u32
csct_invalidate_range (cilium_srv6_ct_main_t *ctm, u32 local_context_id, u32 cursor, u32 n,
		       u32 *next_cursor)
{
  u32 removed = 0;
  u32 i;

  for (i = 0; i < n; i++)
    {
      u32 index = (cursor + i) % ctm->capacity;
      cilium_srv6_ct_entry_t *e;

      if (pool_is_free_index (ctm->entries, index))
	continue;

      e = ctm->entries + index;

      if (e->state == CILIUM_SRV6_CT_STATE_INVALID || e->local_context_id != local_context_id)
	continue;

      csct_remove (ctm, index);
      removed++;
    }

  if (next_cursor)
    *next_cursor = (cursor + n) % ctm->capacity;

  return removed;
}

int
cilium_srv6_ct_invalidate (u32 local_context_id, u32 cursor, u32 max_entries, u32 *n_invalidated,
			   u32 *next_cursor)
{
  cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 n, removed;
  int taken;

  if (n_invalidated)
    *n_invalidated = 0;
  if (next_cursor)
    *next_cursor = 0;

  if (!ctm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (cursor >= ctm->capacity)
    return VNET_API_ERROR_INVALID_VALUE;

  n = max_entries ? max_entries : CILIUM_SRV6_CT_INVALIDATE_PER_CALL;
  n = clib_min (n, ctm->capacity);

  taken = cilium_srv6_barrier_acquire (vm);
  clib_spinlock_lock (&ctm->lock);

  removed = csct_invalidate_range (ctm, local_context_id, cursor, n, next_cursor);
  ctm->n_invalidated += removed;

  clib_spinlock_unlock (&ctm->lock);
  cilium_srv6_barrier_release (vm, taken);

  if (n_invalidated)
    *n_invalidated = removed;

  return 0;
}

/*
 * Endpoint delete. A bounded prefix is swept inside this barrier section and
 * the incarnation is registered with the housekeeping process, which
 * guarantees at least one further full pass over the pool before it forgets
 * it.
 *
 * The sweep is memory reclamation, not enforcement: an entry that outlives it
 * still fails the 02 §7.2 incarnation condition, because that condition
 * compares the entry against the *live* LocalEndpointTable rather than
 * against anything stored at delete time.
 */
void
cilium_srv6_ct_invalidate_endpoint (u32 local_context_id)
{
  cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 removed;
  int taken;

  if (!ctm->initialised)
    return;

  taken = cilium_srv6_barrier_acquire (vm);
  clib_spinlock_lock (&ctm->lock);

  removed =
    csct_invalidate_range (ctm, local_context_id, ctm->sweep_cursor,
			   clib_min (CILIUM_SRV6_CT_INVALIDATE_PER_CALL, ctm->capacity), NULL);
  ctm->n_invalidated += removed;

  /* Keep until the sweep has made a full pass from here. */
  hash_set (ctm->invalidating, (uword) local_context_id, (uword) (ctm->sweep_generation + 2));

  clib_spinlock_unlock (&ctm->lock);
  cilium_srv6_barrier_release (vm, taken);
}

void
cilium_srv6_ct_invalidate_sw_if_index (u32 sw_if_index)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_local_ep_t *ep;

  if (sw_if_index >= vec_len (hm->local_eps))
    return;

  ep = hm->local_eps + sw_if_index;
  if (!ep->valid)
    return;

  cilium_srv6_ct_invalidate_endpoint (ep->local_context_id);
}

/* ------------------------------------------------------------------ */
/* housekeeping                                                        */
/* ------------------------------------------------------------------ */

/*
 * The UNVERIFIED budget has one uniform timeout (D-38, 5 s by default) and
 * its FIFO is insertion ordered, so the expired records are a prefix and the
 * walk can stop at the first entry that is still live.
 */
static u32
csct_gc_unverified (cilium_srv6_ct_main_t *ctm, f64 now)
{
  u32 n = 0;

  clib_spinlock_lock (&ctm->lock);

  while (n < CILIUM_SRV6_CT_GC_PER_TICK &&
	 ctm->age_head[CILIUM_SRV6_CT_BUDGET_UNVERIFIED] != (u32) ~0)
    {
      u32 index = ctm->age_head[CILIUM_SRV6_CT_BUDGET_UNVERIFIED];
      const cilium_srv6_ct_entry_t *e = ctm->entries + index;

      if (!cilium_srv6_ct_expired (ctm, e, now))
	break;

      csct_remove (ctm, index);
      ctm->n_gc++;
      n++;
    }

  clib_spinlock_unlock (&ctm->lock);

  return n;
}

/*
 * The authorised budget mixes timeout classes (8 h TCP next to 60 s UDP), so
 * its FIFO order is not expiry order and a prefix walk would stop early. It
 * is swept with a rotating cursor instead: bounded work per tick, and every
 * slot is visited within one pass. Expiry is enforced on every read
 * regardless (cilium_srv6_ct_expired), so the sweep only reclaims memory.
 *
 * The same pass drops the entries of endpoint incarnations that were
 * invalidated, and forgets an incarnation once a full pass has completed
 * since it was registered.
 */
static u32
csct_sweep (cilium_srv6_ct_main_t *ctm, f64 now)
{
  u32 n = 0;
  u32 i;

  clib_spinlock_lock (&ctm->lock);

  for (i = 0; i < CILIUM_SRV6_CT_SWEEP_PER_TICK; i++)
    {
      u32 index = ctm->sweep_cursor;
      cilium_srv6_ct_entry_t *e;
      uword *p;

      ctm->sweep_cursor++;
      if (ctm->sweep_cursor >= ctm->capacity)
	{
	  ctm->sweep_cursor = 0;
	  ctm->sweep_generation++;

	  /* Forget the incarnations a full pass has now covered. */
	  {
	    u32 *stale = 0, *sp;
	    uword key, value;

	    hash_foreach (key, value, ctm->invalidating, ({
			    if ((u64) value <= ctm->sweep_generation)
			      vec_add1 (stale, (u32) key);
			  }));

	    vec_foreach (sp, stale)
	      hash_unset (ctm->invalidating, (uword) sp[0]);

	    vec_free (stale);
	  }
	}

      if (pool_is_free_index (ctm->entries, index))
	continue;

      e = ctm->entries + index;

      if (e->state == CILIUM_SRV6_CT_STATE_INVALID)
	continue;

      p = hash_get (ctm->invalidating, (uword) e->local_context_id);

      if (p == 0 && !cilium_srv6_ct_expired (ctm, e, now))
	continue;

      csct_remove (ctm, index);

      if (p != 0)
	ctm->n_invalidated++;
      else
	ctm->n_gc++;

      n++;
    }

  clib_spinlock_unlock (&ctm->lock);

  return n;
}

static uword
cilium_srv6_ct_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;

  while (1)
    {
      f64 now;

      vlib_process_wait_for_event_or_clock (vm, CILIUM_SRV6_CT_TICK_INTERVAL);
      (void) vlib_process_get_events (vm, 0);

      if (!ctm->initialised)
	continue;

      now = vlib_time_now (vm);

      csct_gc_unverified (ctm, now);
      csct_sweep (ctm, now);
    }

  return 0;
}

VLIB_REGISTER_NODE (cilium_srv6_ct_process_node, static) = {
  .function = cilium_srv6_ct_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cilium-srv6-ct-process",
  .process_log2_n_stack_bytes = 16,
};

/* ------------------------------------------------------------------ */
/* startup configuration                                               */
/* ------------------------------------------------------------------ */

static clib_error_t *
cilium_srv6_ct_config (vlib_main_t *vm, unformat_input_t *input)
{
  cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  u32 v32;
  f64 v;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "conntrack-capacity %u", &v32) && v32 > 0)
	ctm->capacity = v32;
      else if (unformat (input, "unverified-timeout %f", &v) && v > 0.0)
	ctm->timeout_unverified = v;
      else if (unformat (input, "tcp-established-timeout %f", &v) && v > 0.0)
	ctm->timeout_tcp_established = v;
      else if (unformat (input, "tcp-transient-timeout %f", &v) && v > 0.0)
	ctm->timeout_tcp_transient = v;
      else if (unformat (input, "udp-timeout %f", &v) && v > 0.0)
	ctm->timeout_udp = v;
      else if (unformat (input, "icmp6-timeout %f", &v) && v > 0.0)
	ctm->timeout_icmp6 = v;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (cilium_srv6_ct_config, "cilium-srv6-conntrack");

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

static clib_error_t *
cilium_srv6_ct_init (vlib_main_t *vm)
{
  cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  int i;

  clib_memset (ctm, 0, sizeof (*ctm));

  cilium_srv6_ct_log_class = vlib_log_register_class ("cilium-srv6", "conntrack");

  ctm->capacity = CILIUM_SRV6_CT_CAPACITY_DEFAULT;
  ctm->timeout_unverified = CILIUM_SRV6_CT_TIMEOUT_UNVERIFIED;
  ctm->timeout_tcp_established = CILIUM_SRV6_CT_TIMEOUT_TCP_EST;
  ctm->timeout_tcp_transient = CILIUM_SRV6_CT_TIMEOUT_TCP_TRANS;
  ctm->timeout_udp = CILIUM_SRV6_CT_TIMEOUT_UDP;
  ctm->timeout_icmp6 = CILIUM_SRV6_CT_TIMEOUT_ICMP6;

  for (i = 0; i < CILIUM_SRV6_CT_N_BUDGET; i++)
    ctm->age_head[i] = ctm->age_tail[i] = ~0;

  ctm->process_node_index = cilium_srv6_ct_process_node.index;

  return 0;
}

VLIB_INIT_FUNCTION (cilium_srv6_ct_init);

/*
 * The pool is reserved once and never grown, so the hot path performs no
 * allocation and the pool base pointer is stable for lock-free readers. This
 * runs at main-loop-enter because the capacity comes from the startup
 * configuration, which VLIB applies after the init functions.
 */
static clib_error_t *
cilium_srv6_ct_main_loop_enter (vlib_main_t *vm)
{
  cilium_srv6_ct_main_t *ctm = &cilium_srv6_ct_main;
  u32 nbuckets;
  u32 i;

  if (ctm->initialised)
    return 0;

  ctm->unverified_capacity =
    clib_max (1, ctm->capacity / 100 * CILIUM_SRV6_CT_UNVERIFIED_PERCENT);

  pool_init_fixed (ctm->entries, ctm->capacity);

  vec_validate (ctm->age, ctm->capacity - 1);
  for (i = 0; i < ctm->capacity; i++)
    ctm->age[i].prev = ctm->age[i].next = ~0;

  ctm->ep_count = hash_create (0, sizeof (uword));
  ctm->owner_count = hash_create (0, sizeof (uword));
  ctm->invalidating = hash_create (0, sizeof (uword));

  clib_spinlock_init (&ctm->lock);

  nbuckets = 1 << clib_max (6, max_log2 (ctm->capacity) - 2);
  clib_bihash_init_40_8 (&ctm->table, "cilium-srv6-conntrack", nbuckets,
			 (uword) ctm->capacity * 160);

  ctm->initialised = 1;

  /* From here the 02 §7.2 branches are live; until now cilium-srv6-ct
     classified every packet as branch 3 and cilium-ep-deliver created no
     state, which is the fail-safe default. */
  cilium_srv6_ct_lookup_register (cilium_srv6_ct_lookup);
  cilium_srv6_ct_egress_register (cilium_srv6_ct_egress);
  cilium_srv6_ct_register (cilium_srv6_ct_deliver);

  CSCT_LOG_NOTICE ("conntrack ready: %u entries (UNVERIFIED budget %u), timeouts "
		   "unverified %.0f s, tcp %.0f/%.0f s, udp %.0f s, icmp6 %.0f s",
		   ctm->capacity, ctm->unverified_capacity, ctm->timeout_unverified,
		   ctm->timeout_tcp_established, ctm->timeout_tcp_transient, ctm->timeout_udp,
		   ctm->timeout_icmp6);

  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (cilium_srv6_ct_main_loop_enter);
