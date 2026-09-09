/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — PMTUD (C7, #20), state and slow path.
 *
 * design/detail/02-headend-dataplane.md §9, design/detail/01-packet-format.md
 * §4 (flow entropy), §5 (overhead), §7 (ICMPv6 PTB),
 * design/detail/00-overview.md §2 (D-16, D-21, D-36).
 *
 * Synchronisation. Both writers of the RecentTx table run on workers
 * (cilium-srv6-encap records, cilium-srv6-ptb consumes), so its structural
 * changes are serialised with a spinlock and its pool and bihash arena are
 * reserved at start up, exactly like the FragmentVerdictCache. The
 * PathMtuTable is only ever narrowed with one atomic store (D-21), so the
 * hot path reads it without any lock and the immutable PathCache entry is
 * never rewritten.
 */

#include <stdbool.h>

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip6.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/icmp6.h>
#include <vnet/ip/icmp46_packet.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_endcilium.h>
#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_pmtud.h>

cilium_srv6_pmtud_main_t cilium_srv6_pmtud_main;

static vlib_log_class_t cilium_srv6_pmtud_log_class;

#define CSP_LOG_ERR(...)    vlib_log_err (cilium_srv6_pmtud_log_class, __VA_ARGS__)
#define CSP_LOG_NOTICE(...) vlib_log_notice (cilium_srv6_pmtud_log_class, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* formatting                                                          */
/* ------------------------------------------------------------------ */

u8 *
format_cilium_srv6_ptb_verdict (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_PTB_ACCEPTED:
      return format (s, "accepted");
    case CILIUM_SRV6_PTB_ACCEPTED_UNUSABLE:
      return format (s, "accepted (path unusable, inner MTU would be < 1280)");
    case CILIUM_SRV6_PTB_NOT_READY:
      return format (s, "ignored (headend not configured)");
    case CILIUM_SRV6_PTB_UNTRUSTED_INGRESS:
      return format (s, "ignored (not received on a TRUSTED_FABRIC interface, D-36)");
    case CILIUM_SRV6_PTB_SOURCE_NOT_IN_DOMAIN:
      return format (s, "ignored (source outside the SR domain node set, D-36)");
    case CILIUM_SRV6_PTB_MALFORMED:
      return format (s, "ignored (malformed or unusable quote)");
    case CILIUM_SRV6_PTB_QUOTE_NOT_OURS:
      return format (s, "ignored (quoted source is not this node)");
    case CILIUM_SRV6_PTB_NO_RECORD:
      return format (s, "ignored (no RecentTx record for the quote)");
    case CILIUM_SRV6_PTB_STALE_RECORD:
      return format (s, "ignored (RecentTx record expired)");
    case CILIUM_SRV6_PTB_SIZE_MISMATCH:
      return format (s, "ignored (quoted size larger than anything recorded)");
    case CILIUM_SRV6_PTB_STALE_PATH:
      return format (s, "ignored (path handle no longer resolves)");
    case CILIUM_SRV6_PTB_DA_MISMATCH:
      return format (s, "ignored (quoted DA is not a shift state of the path, D-16)");
    case CILIUM_SRV6_PTB_INNER_MISMATCH:
      return format (s, "ignored (quoted inner addresses do not match the record)");
    case CILIUM_SRV6_PTB_MTU_OUT_OF_RANGE:
      return format (s, "ignored (mtu outside [1280, recorded outer size))");
    default:
      return format (s, "unknown(%u)", v);
    }
}

/* ------------------------------------------------------------------ */
/* RecentTx table (02 §9, D-21)                                        */
/* ------------------------------------------------------------------ */

static_always_inline void
csp_tx_key (clib_bihash_kv_16_8_t *kv, u64 digest, u32 size_class)
{
  kv->key[0] = digest;
  kv->key[1] = (u64) size_class;
  kv->value = 0;
}

/* lock held */
static void
csp_age_append (cilium_srv6_pmtud_main_t *pm, u32 index)
{
  cilium_srv6_recent_tx_t *e = pm->recent_tx + index;

  e->age_next = ~0;
  e->age_prev = pm->age_tail;

  if (pm->age_tail != (u32) ~0)
    pm->recent_tx[pm->age_tail].age_next = index;
  else
    pm->age_head = index;

  pm->age_tail = index;
}

/* lock held */
static void
csp_age_remove (cilium_srv6_pmtud_main_t *pm, u32 index)
{
  cilium_srv6_recent_tx_t *e = pm->recent_tx + index;

  if (e->age_prev != (u32) ~0)
    pm->recent_tx[e->age_prev].age_next = e->age_next;
  else
    pm->age_head = e->age_next;

  if (e->age_next != (u32) ~0)
    pm->recent_tx[e->age_next].age_prev = e->age_prev;
  else
    pm->age_tail = e->age_prev;

  e->age_prev = e->age_next = ~0;
}

static void
csp_count_add (uword **h, uword key, int delta)
{
  uword *p = hash_get (*h, key);
  uword v = p ? p[0] : 0;

  if (delta > 0)
    v += (uword) delta;
  else if (v >= (uword) (-delta))
    v -= (uword) (-delta);
  else
    v = 0;

  if (v == 0)
    hash_unset (*h, key);
  else
    hash_set (*h, key, v);
}

static uword
csp_count_get (uword *h, uword key)
{
  uword *p = hash_get (h, key);

  return p ? p[0] : 0;
}

/*
 * D-42 style soft quota, as used by the ProgramCache and the fragment cache:
 * a class's share of the pool among the classes that currently hold records.
 * Soft, because a class may exceed it while the pool has room; it only
 * decides who is evicted once the pool is full.
 */
static u32
csp_soft_quota (u32 capacity, u32 n_classes)
{
  if (n_classes < 1)
    n_classes = 1;

  return clib_max (1, capacity / n_classes);
}

/* lock held */
static void
csp_tx_remove (cilium_srv6_pmtud_main_t *pm, u32 index)
{
  cilium_srv6_recent_tx_t *e = pm->recent_tx + index;
  clib_bihash_kv_16_8_t kv;

  csp_tx_key (&kv, e->digest, e->size_class);
  kv.value = index;

  clib_bihash_add_del_16_8 (&pm->recent_tx_table, &kv, 0 /* del */);

  csp_age_remove (pm, index);
  csp_count_add (&pm->path_count, (uword) e->path_id, -1);
  csp_count_add (&pm->owner_count, (uword) e->owner_quota_class, -1);

  if (pm->n_records > 0)
    pm->n_records--;

  clib_memset (e, 0, sizeof (*e));
  e->age_prev = e->age_next = ~0;

  pool_put_index (pm->recent_tx, index);
}

/*
 * D-21: evict the oldest record that belongs to a class which is over its
 * soft quota, so that a high-pps flow or another tenant's burst cannot push
 * out the record a legitimate PTB will need. Falls back to the plain oldest
 * record after a bounded scan, so the work per insert stays constant.
 *
 * lock held.
 */
static int
csp_tx_evict_one (cilium_srv6_pmtud_main_t *pm)
{
  u32 path_quota = csp_soft_quota (pm->recent_tx_capacity, (u32) hash_elts (pm->path_count));
  u32 owner_quota = csp_soft_quota (pm->recent_tx_capacity, (u32) hash_elts (pm->owner_count));
  u32 index = pm->age_head;
  u32 n;

  for (n = 0; n < CILIUM_SRV6_RECENT_TX_EVICT_SCAN && index != (u32) ~0; n++)
    {
      const cilium_srv6_recent_tx_t *e = pm->recent_tx + index;
      u32 next = e->age_next;

      if (csp_count_get (pm->path_count, (uword) e->path_id) > path_quota ||
	  csp_count_get (pm->owner_count, (uword) e->owner_quota_class) > owner_quota)
	{
	  csp_tx_remove (pm, index);
	  pm->n_tx_evictions++;
	  return 1;
	}

      index = next;
    }

  if (pm->age_head == (u32) ~0)
    return 0;

  csp_tx_remove (pm, pm->age_head);
  pm->n_tx_evictions++;
  return 1;
}

void
cilium_srv6_pmtud_record_tx (vlib_main_t *vm, const cilium_srv6_pmtud_tx_t *tx)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  cilium_srv6_pmtud_main_t *pm = &cilium_srv6_pmtud_main;
  clib_bihash_kv_16_8_t kv;
  cilium_srv6_recent_tx_t *e;
  u32 index, size_class;
  u64 digest;
  f64 now;

  if (PREDICT_FALSE (!pm->initialised))
    return;

  digest = cilium_srv6_pmtud_digest (hm->flow_hash_seed, &hm->node_address, tx->flow_label);
  size_class = cilium_srv6_pmtud_size_class (tx->outer_size);
  now = vlib_time_now (vm);

  csp_tx_key (&kv, digest, size_class);

  clib_spinlock_lock (&pm->lock);

  if (0 == clib_bihash_search_16_8 (&pm->recent_tx_table, &kv, &kv))
    {
      index = (u32) kv.value;

      if (index < pm->recent_tx_capacity && !pool_is_free_index (pm->recent_tx, index))
	{
	  e = pm->recent_tx + index;

	  /*
	   * 02 §9: "同一 path/flow/size の連続送信で 1 entry を更新する". A
	   * collision between two different paths on the same flow label and
	   * size class takes the newest transmission, which is the one a PTB
	   * can still be in flight for.
	   */
	  if (e->path_id != tx->path_id)
	    {
	      csp_count_add (&pm->path_count, (uword) e->path_id, -1);
	      csp_count_add (&pm->path_count, (uword) tx->path_id, +1);
	      e->path_id = tx->path_id;
	      e->outer_size = 0;
	    }

	  if (e->owner_quota_class != tx->owner_quota_class)
	    {
	      csp_count_add (&pm->owner_count, (uword) e->owner_quota_class, -1);
	      csp_count_add (&pm->owner_count, (uword) tx->owner_quota_class, +1);
	      e->owner_quota_class = tx->owner_quota_class;
	    }

	  e->mtu_index = tx->mtu_index;
	  e->path_index = tx->path_index;
	  e->path_generation = tx->path_generation;
	  e->flow_label = tx->flow_label;
	  e->overhead = tx->overhead;
	  e->next_header = tx->next_header;
	  e->inner_src = tx->inner_src;
	  e->inner_dst = tx->inner_dst;
	  e->recorded_at = now;

	  /* The comparison of 02 §9 is against "recorded_outer_size"; within
	     one 64 byte class the largest transmission is the only one that
	     can legitimately have overflowed a smaller link MTU. */
	  if (tx->outer_size > e->outer_size)
	    e->outer_size = tx->outer_size;

	  /* Refresh the age order so that an active flow is not evicted. */
	  csp_age_remove (pm, index);
	  csp_age_append (pm, index);

	  pm->n_tx_refresh++;
	  goto done;
	}
    }

  {
    u32 path_quota = csp_soft_quota (pm->recent_tx_capacity, (u32) hash_elts (pm->path_count));
    u32 owner_quota = csp_soft_quota (pm->recent_tx_capacity, (u32) hash_elts (pm->owner_count));

    if (pool_free_elts (pm->recent_tx) == 0 &&
	(csp_count_get (pm->path_count, (uword) tx->path_id) >= path_quota ||
	 csp_count_get (pm->owner_count, (uword) tx->owner_quota_class) >= owner_quota))
      {
	/* Over quota and the pool is full: this record is not allowed to
	   displace another class's. Losing it only costs the ability to
	   verify a PTB for this one flow/size. */
	pm->n_tx_quota_drops++;
	goto done;
      }
  }

  while (pool_free_elts (pm->recent_tx) == 0)
    {
      if (!csp_tx_evict_one (pm))
	goto done;
    }

  pool_get_zero (pm->recent_tx, e);
  index = (u32) (e - pm->recent_tx);

  e->digest = digest;
  e->size_class = size_class;
  e->path_id = tx->path_id;
  e->mtu_index = tx->mtu_index;
  e->path_index = tx->path_index;
  e->path_generation = tx->path_generation;
  e->flow_label = tx->flow_label;
  e->owner_quota_class = tx->owner_quota_class;
  e->outer_size = tx->outer_size;
  e->overhead = tx->overhead;
  e->next_header = tx->next_header;
  e->inner_src = tx->inner_src;
  e->inner_dst = tx->inner_dst;
  e->recorded_at = now;
  e->age_prev = e->age_next = ~0;
  e->in_use = 1;

  csp_tx_key (&kv, digest, size_class);
  kv.value = index;

  if (clib_bihash_add_del_16_8 (&pm->recent_tx_table, &kv, 1 /* add */) < 0)
    {
      clib_memset (e, 0, sizeof (*e));
      e->age_prev = e->age_next = ~0;
      pool_put_index (pm->recent_tx, index);
      goto done;
    }

  csp_age_append (pm, index);
  csp_count_add (&pm->path_count, (uword) tx->path_id, +1);
  csp_count_add (&pm->owner_count, (uword) tx->owner_quota_class, +1);
  pm->n_records++;
  pm->n_tx_records++;

done:
  clib_spinlock_unlock (&pm->lock);
}

/* 02 §9: 60 s by default. Bounded work per tick. */
static u32
csp_tx_gc (cilium_srv6_pmtud_main_t *pm, f64 now)
{
  u32 n = 0;

  if (pm->age_head == (u32) ~0)
    return 0;

  clib_spinlock_lock (&pm->lock);

  while (n < CILIUM_SRV6_RECENT_TX_GC_PER_TICK && pm->age_head != (u32) ~0)
    {
      const cilium_srv6_recent_tx_t *e = pm->recent_tx + pm->age_head;

      if (e->recorded_at + pm->recent_tx_timeout > now)
	break;

      csp_tx_remove (pm, pm->age_head);
      pm->n_tx_gc++;
      n++;
    }

  clib_spinlock_unlock (&pm->lock);

  return n;
}

/* ------------------------------------------------------------------ */
/* PTB reception (02 §9, D-16, D-36)                                   */
/* ------------------------------------------------------------------ */

/*
 * Copy the immutable half of a PathCache entry into the shape the pure
 * matcher works on. The entry is immutable once published (D-12), so this
 * needs no lock; the handle was re-resolved by the caller.
 */
static void
csp_path_shape (const cilium_srv6_path_t *p, cilium_srv6_pmtud_path_shape_t *s)
{
  u32 n = p->n_shift_states;

  clib_memset (s, 0, sizeof (*s));

  s->da_template = p->da_template;
  s->service_sid = p->service_sid;
  s->srh_len = p->srh_len;

  if (n > CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES)
    n = CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES;

  s->n_shift_states = (u8) n;

  if (n)
    clib_memcpy_fast (s->shift_states, p->expected_shift_states, n * sizeof (ip6_address_t));

  if (p->srh_len)
    clib_memcpy_fast (s->srh, p->srh_template, p->srh_len);
}

cilium_srv6_ptb_verdict_t
cilium_srv6_pmtud_ptb_receive (vlib_main_t *vm, vlib_buffer_t *b, u32 *state_out, u32 *mtu_out,
			       u64 *path_id_out)
{
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  const cilium_srv6_endcilium_main_t *em = &cilium_srv6_endcilium_main;
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  cilium_srv6_pmtud_main_t *pm = &cilium_srv6_pmtud_main;
  cilium_srv6_pmtud_path_shape_t shape;
  cilium_srv6_pmtud_ptb_t ptb;
  cilium_srv6_pmtud_mtu_result_t mr;
  const cilium_srv6_path_t *path;
  clib_bihash_kv_16_8_t kv;
  cilium_srv6_recent_tx_t rec;
  u32 index, size_class, rx_sw_if_index;
  u16 inner_mtu = 0, cur, want;
  u64 digest;
  f64 now;

  *state_out = 0;
  *mtu_out = 0;
  *path_id_out = 0;

  if (PREDICT_FALSE (!pm->initialised || !hm->initialised || !hm->configured))
    return CILIUM_SRV6_PTB_NOT_READY;

  /*
   * D-36 (a). The node address has to be routable from the Pods (01 §7), so
   * a Pod can address a forged PTB to it. Only a PTB that arrived on a
   * TRUSTED_FABRIC interface may be used for learning; everything else is
   * counted and ignored. This is checked first because it is the cheapest
   * check and the one an attacker cannot influence from inside a Pod.
   */
  rx_sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  if (PREDICT_FALSE (cilium_srv6_trust_get (cm, rx_sw_if_index) !=
		     CILIUM_SRV6_TRUST_TRUSTED_FABRIC))
    return CILIUM_SRV6_PTB_UNTRUSTED_INGRESS;

  /*
   * Bounded parse. The ICMPv6 checksum was already validated by ip6-local
   * before ip6-icmp-input dispatched on the type, so 02 §9's checksum
   * requirement is met upstream of this node.
   */
  if (PREDICT_FALSE (cilium_srv6_pmtud_parse_ptb (vlib_buffer_get_current (b), b->current_length,
						  vlib_buffer_length_in_chain (vm, b), &ptb) !=
		     CILIUM_SRV6_PMTUD_PARSE_OK))
    return CILIUM_SRV6_PTB_MALFORMED;

  /* D-36 (b): the reporter must be an SR domain node or transit address.
     An empty set matches nothing, which is the fail-closed state before the
     agent has configured the domain. */
  if (PREDICT_FALSE (!cilium_srv6_sr_domain_contains (em, &ptb.reporter)))
    return CILIUM_SRV6_PTB_SOURCE_NOT_IN_DOMAIN;

  /* 02 §9: "quoted outer SA" must be this node — a PTB for someone else's
     packet says nothing about our paths. */
  if (PREDICT_FALSE (!ip6_address_is_equal (&ptb.quoted_src, &hm->node_address)))
    return CILIUM_SRV6_PTB_QUOTE_NOT_OURS;

  digest = cilium_srv6_pmtud_digest (hm->flow_hash_seed, &ptb.quoted_src, ptb.quoted_flow_label);
  size_class = cilium_srv6_pmtud_size_class (ptb.quoted_outer_size);

  csp_tx_key (&kv, digest, size_class);

  now = vlib_time_now (vm);

  /* The record is copied out under the lock and every later decision is made
     on the copy, so the table is not held while the PathCache is resolved. */
  clib_spinlock_lock (&pm->lock);

  if (clib_bihash_search_16_8 (&pm->recent_tx_table, &kv, &kv))
    {
      clib_spinlock_unlock (&pm->lock);
      return CILIUM_SRV6_PTB_NO_RECORD;
    }

  index = (u32) kv.value;
  if (index >= pm->recent_tx_capacity || pool_is_free_index (pm->recent_tx, index))
    {
      clib_spinlock_unlock (&pm->lock);
      return CILIUM_SRV6_PTB_NO_RECORD;
    }

  rec = pm->recent_tx[index];

  clib_spinlock_unlock (&pm->lock);

  /* 02 §9: "曖昧・古い・未送信の引用は無視する". */
  if (rec.recorded_at + pm->recent_tx_timeout <= now)
    return CILIUM_SRV6_PTB_STALE_RECORD;

  if (rec.flow_label != ptb.quoted_flow_label || rec.next_header != ptb.quoted_next_header)
    return CILIUM_SRV6_PTB_NO_RECORD;

  /* Within the size class the quote must not be larger than the largest
     packet we actually transmitted. */
  if (ptb.quoted_outer_size > rec.outer_size)
    return CILIUM_SRV6_PTB_SIZE_MISMATCH;

  /* D-12: re-resolve the versioned handle rather than trusting the recorded
     pointer, and confirm the slot still holds the same path. */
  path = cilium_srv6_path_get (hm, rec.path_index, rec.path_generation);
  if (path == NULL || path->path_id != rec.path_id || path->mtu_index != rec.mtu_index)
    return CILIUM_SRV6_PTB_STALE_PATH;

  /*
   * D-16. The transit node quotes the destination address as it saw it,
   * after its own and every previous uN's C-SID shift, so `final_da` alone
   * cannot reproduce it. The quoted address must be one of the states this
   * path can present.
   */
  csp_path_shape (path, &shape);

  if (!cilium_srv6_pmtud_da_match (&shape, &ptb.quoted_dst, state_out))
    return CILIUM_SRV6_PTB_DA_MISMATCH;

  /* When the quote reached the inner header, it must be the flow we
     recorded. A truncated quote simply skips this check. */
  if (ptb.has_inner && (!ip6_address_is_equal (&ptb.inner_src, &rec.inner_src) ||
			!ip6_address_is_equal (&ptb.inner_dst, &rec.inner_dst)))
    return CILIUM_SRV6_PTB_INNER_MISMATCH;

  *path_id_out = rec.path_id;

  /*
   * 02 §9's rule is "1280 <= ptb_mtu < recorded_outer_size". The bound used
   * here is the quoted size rather than the record's, which is the tighter
   * of the two and never rejects a legitimate report: a transit node quotes
   * exactly the packet that did not fit, so its reported MTU is always below
   * that packet's size. The record's size is still enforced, one check
   * earlier, as the upper bound of what we actually transmitted — without it
   * a report could claim an arbitrarily large "too big" packet.
   */
  mr = cilium_srv6_pmtud_mtu_eval (ptb.ptb_mtu, ptb.quoted_outer_size, (u32) rec.overhead,
				   &inner_mtu);

  if (mr == CILIUM_SRV6_PMTUD_MTU_OUT_OF_RANGE)
    return CILIUM_SRV6_PTB_MTU_OUT_OF_RANGE;

  if (rec.mtu_index >= hm->path_capacity || pool_is_free_index (hm->path_mtus, rec.mtu_index))
    return CILIUM_SRV6_PTB_STALE_PATH;

  cur = hm->path_mtus[rec.mtu_index].effective_mtu;

  if (mr == CILIUM_SRV6_PMTUD_MTU_PATH_UNUSABLE)
    {
      /* 02 §9: the path cannot carry a 1280 byte inner packet. Fail closed
	 and let the reconciler switch to an alternative or direct path. */
      want = CILIUM_SRV6_PATH_MTU_UNUSABLE;
    }
  else if (cur == CILIUM_SRV6_PATH_MTU_UNUSABLE)
    {
      /* Already unusable: a later, larger report must not resurrect it.
	 Only the 10 minute decay clears this state. */
      want = CILIUM_SRV6_PATH_MTU_UNUSABLE;
    }
  else if (cur == 0 || inner_mtu < cur)
    {
      want = inner_mtu;
    }
  else
    {
      /* 02 §9: min(current, ptb_mtu - overhead). The learned value only ever
	 shrinks until it decays. */
      want = cur;
    }

  /* Always rewritten, so that a repeated report refreshes the decay timer of
     an already learned value (02 §9 "10 分で減衰"). */
  if (cilium_srv6_path_mtu_update (rec.path_id, want, pm->decay) == 0)
    {
      pm->n_mtu_updates++;

      if (want == CILIUM_SRV6_PATH_MTU_UNUSABLE && cur != CILIUM_SRV6_PATH_MTU_UNUSABLE)
	{
	  pm->n_path_unusable++;
	  CSP_LOG_ERR ("path_id 0x%llx is unusable: a transit node reports an outer MTU of %u, "
		       "which leaves an inner MTU below %u (02 §9)",
		       (unsigned long long) rec.path_id, ptb.ptb_mtu, CILIUM_SRV6_MIN_IPV6_MTU);
	}
    }

  *mtu_out = (want == CILIUM_SRV6_PATH_MTU_UNUSABLE) ? 0 : (u32) want;

  return (want == CILIUM_SRV6_PATH_MTU_UNUSABLE) ? CILIUM_SRV6_PTB_ACCEPTED_UNUSABLE :
						   CILIUM_SRV6_PTB_ACCEPTED;
}

/* ------------------------------------------------------------------ */
/* PTB generation (02 §9 inner direction, 01 §7)                       */
/* ------------------------------------------------------------------ */

/*
 * "encap 前に inner length > 有効値なら ICMPv6 PTB を source Pod へ返し、
 * packet を drop する" (02 §9).
 *
 * The buffer still starts at the inner IPv6 header — cilium-srv6-encap runs
 * this check before it prepends anything — and cilium-srv6-encap keeps
 * ownership of it, so the PTB is built in a freshly allocated buffer.
 *
 * 01 §7: source = the headend node address (which the Pods can route to),
 * MTU = the effective inner MTU, quote = the head of the inner packet capped
 * at 1232 bytes (RFC 4443 §3.2: the whole error must fit in 1280 bytes, and
 * the PTB is not encapsulated, so no encap overhead is subtracted).
 *
 * Like VPP's own ip6-icmp-error, only what is present in the first buffer is
 * quoted; a chained inner packet is quoted up to that point, which is always
 * at least the inner IPv6 header the Pod's PMTU state needs.
 */
void
cilium_srv6_pmtud_ptb_send (vlib_main_t *vm, vlib_buffer_t *b, u16 effective_mtu)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  cilium_srv6_pmtud_main_t *pm = &cilium_srv6_pmtud_main;
  const u32 hdr = sizeof (ip6_header_t) + CILIUM_SRV6_PMTUD_ICMP_LEN;
  const ip6_header_t *inner;
  ip6_header_t *out;
  icmp46_header_t *icmp;
  vlib_buffer_t *p;
  vlib_frame_t *f;
  u32 *to_next;
  u32 bi, quote, room;
  u64 seed, h;
  int bogus = 0;

  if (PREDICT_FALSE (!pm->initialised || !hm->configured))
    return;

  /* RFC 8201: a PTB below the IPv6 minimum link MTU must not be advertised.
     effective_mtu == 0 is the "path unusable" state of 02 §9, for which
     there is no MTU to report at all. */
  if (PREDICT_FALSE (effective_mtu < CILIUM_SRV6_MIN_IPV6_MTU))
    return;

  if (PREDICT_FALSE (b->current_length < sizeof (ip6_header_t)))
    return;

  inner = (const ip6_header_t *) vlib_buffer_get_current (b);

  /* One PTB per (inner src, inner dst) per throttle window: a Pod that keeps
     sending oversized packets must not turn one drop into one transmit. */
  seed = throttle_seed (&pm->ptb_throttle, vm->thread_index, vlib_time_now (vm));
  h = ip6_address_hash_to_u64 (&inner->src_address) ^
      ip6_address_hash_to_u64 (&inner->dst_address);

  if (throttle_check (&pm->ptb_throttle, vm->thread_index, h, seed))
    {
      pm->n_ptb_throttled++;
      return;
    }

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      pm->n_ptb_no_buffer++;
      return;
    }

  p = vlib_get_buffer (vm, bi);

  quote = b->current_length;
  if (quote > CILIUM_SRV6_PMTUD_MAX_QUOTE)
    quote = CILIUM_SRV6_PMTUD_MAX_QUOTE;

  /* Never write past the buffer's data area, whatever it was configured to. */
  room = vlib_buffer_get_default_data_size (vm);
  if (hdr + quote > room)
    quote = (room > hdr) ? room - hdr : 0;

  if (quote < sizeof (ip6_header_t))
    {
      vlib_buffer_free_one (vm, bi);
      pm->n_ptb_no_buffer++;
      return;
    }

  p->current_data = 0;
  p->current_length = hdr + quote;
  p->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  p->error = 0;

  /* Resolve the destination in the FIB of the interface the Pod's packet
     arrived on, which is the table the Pod's address lives in. */
  vnet_buffer (p)->sw_if_index[VLIB_RX] = vnet_buffer (b)->sw_if_index[VLIB_RX];
  vnet_buffer (p)->sw_if_index[VLIB_TX] = ~0;

  out = (ip6_header_t *) vlib_buffer_get_current (p);
  icmp = (icmp46_header_t *) (out + 1);

  out->ip_version_traffic_class_and_flow_label = clib_host_to_net_u32 (0x6 << 28);
  out->payload_length = clib_host_to_net_u16 ((u16) (CILIUM_SRV6_PMTUD_ICMP_LEN + quote));
  out->protocol = IP_PROTOCOL_ICMP6;
  out->hop_limit = 0xff;
  out->src_address = hm->node_address;
  out->dst_address = inner->src_address;

  icmp->type = ICMP6_packet_too_big;
  icmp->code = 0;
  icmp->checksum = 0;

  {
    /* RFC 4443 §3.2: octets 4..7 of the message carry the MTU. */
    u32 mtu_net = clib_host_to_net_u32 ((u32) effective_mtu);

    clib_memcpy_fast ((u8 *) icmp + 4, &mtu_net, sizeof (mtu_net));
  }

  clib_memcpy_fast ((u8 *) icmp + CILIUM_SRV6_PMTUD_ICMP_LEN, inner, quote);

  icmp->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, p, out, &bogus);

  f = vlib_get_frame_to_node (vm, ip6_lookup_node.index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, ip6_lookup_node.index, f);

  pm->n_ptb_sent++;
}

/* ------------------------------------------------------------------ */
/* decay (02 §9: 10 minutes back to the initial value)                 */
/* ------------------------------------------------------------------ */

/*
 * Bounded sweep over the PathMtuTable. Runs on the main thread from the
 * process node, so it cannot race the control plane paths that create and
 * reclaim slots; the value itself is cleared with the same single atomic
 * store the learning path uses (D-21).
 */
static u32
csp_decay (cilium_srv6_pmtud_main_t *pm, f64 now)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  u32 n = 0, scanned;

  if (!hm->initialised || hm->path_capacity == 0)
    return 0;

  for (scanned = 0; scanned < CILIUM_SRV6_PMTU_DECAY_SCAN_PER_TICK; scanned++)
    {
      u32 index = pm->decay_cursor;
      cilium_srv6_path_mtu_t *m;

      pm->decay_cursor = (index + 1 >= hm->path_capacity) ? 0 : index + 1;

      if (index >= hm->path_capacity || pool_is_free_index (hm->path_mtus, index))
	continue;

      m = hm->path_mtus + index;

      if (m->effective_mtu == 0 || m->decay_at > now)
	continue;

      clib_atomic_store_rel_n (&m->effective_mtu, 0);
      m->learned_at = 0.0;
      m->decay_at = 0.0;

      pm->n_decayed++;
      n++;
    }

  return n;
}

/* ------------------------------------------------------------------ */
/* housekeeping process                                                */
/* ------------------------------------------------------------------ */

static uword
cilium_srv6_pmtud_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  cilium_srv6_pmtud_main_t *pm = &cilium_srv6_pmtud_main;

  while (1)
    {
      f64 now;

      vlib_process_wait_for_event_or_clock (vm, CILIUM_SRV6_PMTUD_TICK_INTERVAL);
      (void) vlib_process_get_events (vm, 0);

      if (!pm->initialised)
	continue;

      now = vlib_time_now (vm);

      csp_tx_gc (pm, now);
      csp_decay (pm, now);
    }

  return 0;
}

VLIB_REGISTER_NODE (cilium_srv6_pmtud_process_node, static) = {
  .function = cilium_srv6_pmtud_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cilium-srv6-pmtud-process",
  .process_log2_n_stack_bytes = 16,
};

/* ------------------------------------------------------------------ */
/* CLI (06 §4)                                                         */
/* ------------------------------------------------------------------ */

static clib_error_t *
cilium_srv6_show_pmtud_fn (vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd)
{
  const cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_pmtud_main_t *pm = &cilium_srv6_pmtud_main;
  const cilium_srv6_path_mtu_t *m;
  f64 now = vlib_time_now (vm);
  u32 n_learned = 0, n_unusable = 0;

  if (!pm->initialised)
    {
      vlib_cli_output (vm, "cilium-srv6 PMTUD: not initialised");
      return 0;
    }

  vlib_cli_output (vm,
		   "RecentTx (02 §9, D-21): %u/%u records, timeout %.0f s, "
		   "size class %u bytes\n"
		   "  recorded %llu, refreshed %llu, evicted %llu, quota drops %llu, gc %llu",
		   pm->n_records, pm->recent_tx_capacity, pm->recent_tx_timeout,
		   1u << CILIUM_SRV6_RECENT_TX_SIZE_CLASS_LOG2,
		   (unsigned long long) pm->n_tx_records, (unsigned long long) pm->n_tx_refresh,
		   (unsigned long long) pm->n_tx_evictions,
		   (unsigned long long) pm->n_tx_quota_drops, (unsigned long long) pm->n_tx_gc);

  vlib_cli_output (vm,
		   "PTB out (01 §7): sent %llu, throttled %llu, no buffer %llu\n"
		   "PTB in  (02 §9): mtu updates %llu, paths marked unusable %llu, "
		   "decayed %llu (decay %.0f s)",
		   (unsigned long long) pm->n_ptb_sent, (unsigned long long) pm->n_ptb_throttled,
		   (unsigned long long) pm->n_ptb_no_buffer,
		   (unsigned long long) pm->n_mtu_updates,
		   (unsigned long long) pm->n_path_unusable, (unsigned long long) pm->n_decayed,
		   pm->decay);

  if (!hm->initialised)
    return 0;

  /* clang-format off */
  pool_foreach (m, hm->path_mtus)
    {
      if (m->effective_mtu == 0)
	continue;

      if (m->effective_mtu == CILIUM_SRV6_PATH_MTU_UNUSABLE)
	{
	  n_unusable++;
	  vlib_cli_output (vm, "  path_id 0x%016llx  UNUSABLE      decays in %.0f s",
			   (unsigned long long) m->path_id, m->decay_at - now);
	}
      else
	{
	  n_learned++;
	  vlib_cli_output (vm, "  path_id 0x%016llx  inner mtu %5u  decays in %.0f s",
			   (unsigned long long) m->path_id, (u32) m->effective_mtu,
			   m->decay_at - now);
	}
    }
  /* clang-format on */

  vlib_cli_output (vm, "PathMtuTable: %u learned, %u unusable", n_learned, n_unusable);

  return 0;
}

VLIB_CLI_COMMAND (cilium_srv6_show_pmtud_command, static) = {
  .path = "show cilium srv6 pmtud",
  .short_help = "show cilium srv6 pmtud",
  .function = cilium_srv6_show_pmtud_fn,
};

/* ------------------------------------------------------------------ */
/* startup configuration                                               */
/* ------------------------------------------------------------------ */

static clib_error_t *
cilium_srv6_pmtud_config (vlib_main_t *vm, unformat_input_t *input)
{
  cilium_srv6_pmtud_main_t *pm = &cilium_srv6_pmtud_main;
  u32 v32;
  f64 v;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "recent-tx-capacity %u", &v32) && v32 > 0)
	pm->recent_tx_capacity = v32;
      else if (unformat (input, "recent-tx-timeout %f", &v) && v > 0.0)
	pm->recent_tx_timeout = v;
      else if (unformat (input, "decay %f", &v) && v > 0.0)
	pm->decay = v;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (cilium_srv6_pmtud_config, "cilium-srv6-pmtud");

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

static clib_error_t *
cilium_srv6_pmtud_init (vlib_main_t *vm)
{
  cilium_srv6_pmtud_main_t *pm = &cilium_srv6_pmtud_main;

  clib_memset (pm, 0, sizeof (*pm));

  cilium_srv6_pmtud_log_class = vlib_log_register_class ("cilium-srv6", "pmtud");

  pm->recent_tx_capacity = CILIUM_SRV6_RECENT_TX_CAPACITY_DEFAULT;
  pm->recent_tx_timeout = CILIUM_SRV6_RECENT_TX_TIMEOUT_DEFAULT;
  pm->decay = CILIUM_SRV6_PMTU_DECAY_DEFAULT;
  pm->age_head = pm->age_tail = ~0;
  pm->process_node_index = cilium_srv6_pmtud_process_node.index;

  /*
   * 02 §9 / D-36: a transit-originated PTB is delivered to this node by
   * ip6-local -> ip6-icmp-input, i.e. only for packets addressed to a local
   * address and only after the ICMPv6 checksum has been validated. Nothing
   * else in VPP claims ICMPv6 type 2, so no existing handler is displaced;
   * the node passes every packet on to ip6-punt afterwards, which is exactly
   * where an unclaimed Packet Too Big went before, so the plugin only taps
   * the type and never changes its disposition.
   *
   * The dispatch table of ip6-icmp-input holds one node per type, so
   * configuring a punt socket for ICMPv6 type 2 at run time
   * (punt_socket_register_l4 in vnet/ip/punt.c) would replace this
   * registration and silently stop MTU learning. That is an operator
   * decision this plugin cannot override; the accepted counter of
   * cilium-srv6-ptb staying at 0 is the symptom.
   */
  icmp6_register_type (vm, ICMP6_packet_too_big, cilium_srv6_ptb_node.index);

  return 0;
}

VLIB_INIT_FUNCTION (cilium_srv6_pmtud_init) = {
  .runs_after = VLIB_INITS ("icmp6_init"),
};

/*
 * The pool and the bihash arena are reserved once, so the hot path performs
 * no allocation (02 §9 / 03 §9). This runs at main-loop-enter because the
 * capacities come from the startup configuration, which VLIB applies after
 * the init functions.
 */
static clib_error_t *
cilium_srv6_pmtud_main_loop_enter (vlib_main_t *vm)
{
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  cilium_srv6_pmtud_main_t *pm = &cilium_srv6_pmtud_main;
  u32 nbuckets;

  if (pm->initialised)
    return 0;

  pool_init_fixed (pm->recent_tx, pm->recent_tx_capacity);

  pm->path_count = hash_create (0, sizeof (uword));
  pm->owner_count = hash_create (0, sizeof (uword));

  clib_spinlock_init (&pm->lock);

  nbuckets = 1 << clib_max (6, max_log2 (pm->recent_tx_capacity) - 2);
  clib_bihash_init_16_8 (&pm->recent_tx_table, "cilium-srv6-recent-tx", nbuckets,
			 (uword) pm->recent_tx_capacity * 128);

  throttle_init (&pm->ptb_throttle, tm->n_vlib_mains, CILIUM_SRV6_PTB_THROTTLE_BUCKETS,
		 CILIUM_SRV6_PTB_THROTTLE_TIME);

  pm->initialised = 1;

  /* Only now may cilium-srv6-encap reach the table. */
  cilium_srv6_ptb_send_register (cilium_srv6_pmtud_ptb_send);

  CSP_LOG_NOTICE ("PMTUD ready: RecentTx %u entries (timeout %.0f s, size class %u bytes), "
		  "learned MTU decay %.0f s",
		  pm->recent_tx_capacity, pm->recent_tx_timeout,
		  1u << CILIUM_SRV6_RECENT_TX_SIZE_CLASS_LOG2, pm->decay);

  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (cilium_srv6_pmtud_main_loop_enter);
