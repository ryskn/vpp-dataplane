/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — EndpointContextTable and tombstone store
 * (C8-c), control plane.
 *
 * design/detail/03-destination-dataplane.md §2, §4, §7, §9
 * design/detail/00-overview.md §2 (D-12, D-25, D-35, D-42)
 * design/detail/04-context-allocator.md §4, §5
 * design/detail/06-observability.md §2, §3, §4
 *
 * Ordering rules implemented here, in the words of the design:
 *
 *  - `context_add` completes the ACTIVE install before it acks, because the
 *    agent must not advertise the endpoint route before the ack (04 §5).
 *  - `context_invalidate` removes the entry from the ActiveContextTable
 *    under the worker barrier *first* and records the tombstone afterwards,
 *    so that a full tombstone store can never delay or block an invalidate
 *    (03 §2). A Context ID that could not be recorded degrades from
 *    DROP_INVALID_CONTEXT to DROP_UNKNOWN_CONTEXT; both are fail-closed.
 *  - The ACTIVE pool index and the DPO are reclaimed only when the D-12
 *    grace period has elapsed, and the capacity accounting follows the pool
 *    index, not the ack (M-6 / 03 §2).
 */

#include <stdbool.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/dpo/dpo.h>
#include <vnet/dpo/interface_tx_dpo.h>
#include <vnet/interface.h>
#include <vnet/interface_funcs.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_context.h>
#include <cilium_srv6/cilium_srv6_endcilium.h>
#include <cilium_srv6/cilium_srv6_ct.h>

cilium_srv6_context_main_t cilium_srv6_context_main;

static vlib_log_class_t cilium_srv6_context_log_class;

#define CSC_LOG_ERR(fmt, ...)                                                                      \
  vlib_log_err (cilium_srv6_context_log_class, fmt, __VA_ARGS__)
#define CSC_LOG_NOTICE(fmt, ...)                                                                   \
  vlib_log_notice (cilium_srv6_context_log_class, fmt, __VA_ARGS__)

/* ------------------------------------------------------------------ */
/* formatting                                                          */
/* ------------------------------------------------------------------ */

u8 *
format_cilium_srv6_context_state (u8 *s, va_list *args)
{
  u32 state = va_arg (*args, u32);

  switch (state)
    {
    case CILIUM_SRV6_CONTEXT_INVALID:
      return format (s, "INVALID");
    case CILIUM_SRV6_CONTEXT_ACTIVE:
      return format (s, "ACTIVE");
    case CILIUM_SRV6_CONTEXT_SUSPENDED:
      return format (s, "SUSPENDED");
    default:
      return format (s, "UNKNOWN(%u)", state);
    }
}

/* ------------------------------------------------------------------ */
/* capacity accounting (M-6 / 03 §2)                                   */
/* ------------------------------------------------------------------ */

/*
 * The number of ACTIVE pool indices that exist. Entries inside their grace
 * period are counted: their index has not been returned to the pool, so
 * accepting a context_add against that budget would install nothing and burn
 * a Context ID (04 §5).
 */
u32
cilium_srv6_context_n_reserved (void)
{
  const cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;

  if (!cxm->initialised)
    return 0;

  return (u32) pool_elts (cxm->entries);
}

/* ------------------------------------------------------------------ */
/* tombstone store: owner accounting (D-42)                            */
/* ------------------------------------------------------------------ */

static cilium_srv6_ts_owner_t *
csc_ts_owner_get (cilium_srv6_context_main_t *cxm, u32 owner_quota_class, int create)
{
  uword *p = hash_get (cxm->ts_owner_by_class, (uword) owner_quota_class);
  cilium_srv6_ts_owner_t *o;

  if (p)
    return pool_elt_at_index (cxm->ts_owners, (u32) p[0]);

  if (!create)
    return NULL;

  pool_get_zero (cxm->ts_owners, o);
  o->owner_quota_class = owner_quota_class;
  o->n_tombstones = 0;
  hash_set (cxm->ts_owner_by_class, (uword) owner_quota_class, (uword) (o - cxm->ts_owners));

  return o;
}

static void
csc_ts_owner_release (cilium_srv6_context_main_t *cxm, cilium_srv6_ts_owner_t *o)
{
  if (o->n_tombstones != 0)
    return;

  hash_unset (cxm->ts_owner_by_class, (uword) o->owner_quota_class);
  pool_put (cxm->ts_owners, o);
}

/*
 * D-42 soft quota: the tombstone store is divided evenly between the owners
 * that currently hold tombstones. It is soft in both directions — an owner
 * may exceed it while the store has room, and it is only enforced when the
 * store is full: an over-quota owner is the eviction victim, and an
 * over-quota owner cannot displace another owner's record.
 */
static u32
csc_ts_soft_quota (const cilium_srv6_context_main_t *cxm)
{
  u32 n_owners = (u32) pool_elts (cxm->ts_owners);

  if (n_owners < 1)
    n_owners = 1;

  return clib_max (1, cxm->tombstone_capacity / n_owners);
}

/* ------------------------------------------------------------------ */
/* tombstone store: age-ordered FIFO                                   */
/* ------------------------------------------------------------------ */

static void
csc_ts_age_append (cilium_srv6_context_main_t *cxm, u32 index)
{
  cilium_srv6_tombstone_t *t = pool_elt_at_index (cxm->tombstones, index);

  t->age_next = ~0;
  t->age_prev = cxm->ts_age_tail;

  if (cxm->ts_age_tail != (u32) ~0)
    pool_elt_at_index (cxm->tombstones, cxm->ts_age_tail)->age_next = index;
  else
    cxm->ts_age_head = index;

  cxm->ts_age_tail = index;
}

static void
csc_ts_age_remove (cilium_srv6_context_main_t *cxm, u32 index)
{
  cilium_srv6_tombstone_t *t = pool_elt_at_index (cxm->tombstones, index);

  if (t->age_prev != (u32) ~0)
    pool_elt_at_index (cxm->tombstones, t->age_prev)->age_next = t->age_next;
  else
    cxm->ts_age_head = t->age_next;

  if (t->age_next != (u32) ~0)
    pool_elt_at_index (cxm->tombstones, t->age_next)->age_prev = t->age_prev;
  else
    cxm->ts_age_tail = t->age_prev;

  t->age_prev = t->age_next = ~0;
}

/*
 * Drop one tombstone. Must be called with the worker barrier held: the
 * bihash delete is visible to the dataplane, which turns a subsequent packet
 * for that Context ID from DROP_INVALID_CONTEXT into DROP_UNKNOWN_CONTEXT.
 *
 * The tombstone pool index itself needs no grace period — the dataplane only
 * uses the bihash hit/miss and never dereferences a tombstone record.
 */
static void
csc_ts_drop (cilium_srv6_context_main_t *cxm, u32 index)
{
  cilium_srv6_tombstone_t *t = pool_elt_at_index (cxm->tombstones, index);
  cilium_srv6_ts_owner_t *o;
  clib_bihash_kv_8_8_t kv;

  kv.key = (u64) t->context_id;
  kv.value = index;
  clib_bihash_add_del_8_8 (&cxm->tombstone_table, &kv, 0 /* del */);

  o = csc_ts_owner_get (cxm, t->owner_quota_class, 0 /* create */);
  if (o != NULL)
    {
      if (o->n_tombstones > 0)
	o->n_tombstones--;
      csc_ts_owner_release (cxm, o);
    }

  csc_ts_age_remove (cxm, index);
  pool_put_index (cxm->tombstones, index);
}

/*
 * Fair eviction (03 §2). The FIFO is age ordered, so the scan starts at the
 * oldest record and picks the first one whose owner is over the soft quota;
 * if no such record is found within CILIUM_SRV6_TOMBSTONE_EVICT_SCAN steps
 * the oldest record is evicted. Bounded work, and an owner that stays within
 * its quota is only ever evicted on age.
 *
 * Returns the owner_quota_class of the evicted record, or ~0 if the store
 * was empty.
 */
static u32
csc_ts_evict_one (cilium_srv6_context_main_t *cxm)
{
  u32 quota = csc_ts_soft_quota (cxm);
  u32 index = cxm->ts_age_head;
  u32 victim = cxm->ts_age_head;
  u32 n;

  if (index == (u32) ~0)
    return ~0;

  for (n = 0; n < CILIUM_SRV6_TOMBSTONE_EVICT_SCAN && index != (u32) ~0; n++)
    {
      cilium_srv6_tombstone_t *t = pool_elt_at_index (cxm->tombstones, index);
      cilium_srv6_ts_owner_t *o = csc_ts_owner_get (cxm, t->owner_quota_class, 0);

      if (o != NULL && o->n_tombstones > quota)
	{
	  victim = index;
	  break;
	}

      index = t->age_next;
    }

  {
    cilium_srv6_tombstone_t *t = pool_elt_at_index (cxm->tombstones, victim);
    u32 class = t->owner_quota_class;

    csc_ts_drop (cxm, victim);
    cxm->n_tombstone_evictions++;
    return class;
  }
}

/*
 * Record one tombstone (03 §2). Must be called with the worker barrier held.
 * Returns 1 if the record was made.
 *
 * A failure here is deliberately not an error for the caller: 03 §2 requires
 * invalidate and the release of the ACTIVE slot to take priority over
 * recording, and an unrecordable ID stays fail-closed as UNKNOWN.
 */
static int
csc_ts_record (cilium_srv6_context_main_t *cxm, u32 context_id, u32 owner_quota_class, f64 now)
{
  cilium_srv6_ts_owner_t *o;
  cilium_srv6_tombstone_t *t;
  clib_bihash_kv_8_8_t kv;
  u32 index;

  if (pool_free_elts (cxm->tombstones) == 0)
    {
      /* Full. An owner that is already over its soft quota must not displace
       * another owner's record (D-42 fairness); it simply fails to record. */
      o = csc_ts_owner_get (cxm, owner_quota_class, 0 /* create */);
      if (o != NULL && o->n_tombstones > csc_ts_soft_quota (cxm))
	{
	  cxm->n_tombstone_record_failures_quota++;
	  return 0;
	}

      if (csc_ts_evict_one (cxm) == (u32) ~0)
	{
	  cxm->n_tombstone_record_failures_full++;
	  return 0;
	}
    }

  o = csc_ts_owner_get (cxm, owner_quota_class, 1 /* create */);
  if (o == NULL)
    {
      cxm->n_tombstone_record_failures_full++;
      return 0;
    }

  pool_get_zero (cxm->tombstones, t);
  index = (u32) (t - cxm->tombstones);

  t->context_id = context_id;
  t->owner_quota_class = owner_quota_class;
  t->invalidated_at = now;
  t->age_prev = t->age_next = ~0;

  csc_ts_age_append (cxm, index);
  o->n_tombstones++;

  kv.key = (u64) context_id;
  kv.value = index;
  if (clib_bihash_add_del_8_8 (&cxm->tombstone_table, &kv, 1 /* add */) < 0)
    {
      csc_ts_age_remove (cxm, index);
      o->n_tombstones--;
      csc_ts_owner_release (cxm, o);
      pool_put_index (cxm->tombstones, index);
      cxm->n_tombstone_record_failures_full++;
      return 0;
    }

  return 1;
}

/* ------------------------------------------------------------------ */
/* grace period (D-12)                                                 */
/* ------------------------------------------------------------------ */

u64
cilium_srv6_grace_log_oldest_seq (void)
{
  const cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;

  if (cxm->grace_next_seq <= (u64) cxm->grace_log_size)
    return 0;

  return cxm->grace_next_seq - (u64) cxm->grace_log_size;
}

u32
cilium_srv6_grace_remaining_ms (u32 context_id, f64 now)
{
  const cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  uword *p = hash_get (cxm->grace_by_context_id, (uword) context_id);
  f64 left;

  if (p == NULL)
    return 0;

  left = (f64) p[0] - now * 1e3;
  return left > 0.0 ? (u32) left : 0;
}

static void
csc_grace_log_append (cilium_srv6_context_main_t *cxm, u32 context_id, f64 now)
{
  cilium_srv6_grace_log_t *g;

  g = cxm->grace_log + (cxm->grace_next_seq & (u64) (cxm->grace_log_size - 1));
  g->seq = cxm->grace_next_seq;
  g->context_id = context_id;
  g->released_at = now;

  cxm->grace_next_seq++;
}

/*
 * Reclaim every ACTIVE pool index whose grace period has elapsed.
 *
 * The entries are appended with a constant grace period, so the pending
 * vector is ordered by free_after and the elapsed ones are a prefix.
 */
static u32
csc_grace_reclaim (vlib_main_t *vm, f64 now)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  u32 n = 0;
  int taken;

  if (vec_len (cxm->grace_pending) == 0)
    return 0;

  if (cxm->grace_pending[0].free_after > now)
    return 0;

  taken = cilium_srv6_barrier_acquire (vm);

  while (n < vec_len (cxm->grace_pending) && n < CILIUM_SRV6_GRACE_RECLAIM_MAX_PER_TICK &&
	 cxm->grace_pending[n].free_after <= now)
    {
      cilium_srv6_grace_pending_t *p = cxm->grace_pending + n;
      cilium_srv6_context_entry_t *e;
      dpo_id_t dpo = DPO_INVALID;

      if (!pool_is_free_index (cxm->entries, p->pool_index))
	{
	  e = pool_elt_at_index (cxm->entries, p->pool_index);

	  cilium_srv6_context_entry_dpo (e, &dpo);
	  dpo_reset (&dpo);

	  /* Drop the delivery arc with the object it points at, so that a
	   * reader that beat the grace period cannot transmit through it. */
	  cilium_srv6_delivery_set (p->pool_index, ~0);

	  /* Wipe before returning the index: a stale reader that beat the
	   * grace period must not find a usable handle (03 §4). */
	  clib_memset (e, 0, sizeof (*e));
	  e->state = CILIUM_SRV6_CONTEXT_INVALID;

	  pool_put_index (cxm->entries, p->pool_index);
	}

      hash_unset (cxm->grace_by_context_id, (uword) p->context_id);
      csc_grace_log_append (cxm, p->context_id, now);
      cxm->n_grace_completions++;
      n++;
    }

  vec_delete (cxm->grace_pending, n, 0);

  cilium_srv6_barrier_release (vm, taken);

  return n;
}

/* ------------------------------------------------------------------ */
/* srv6_context_add (03 §7, 04 §5)                                     */
/* ------------------------------------------------------------------ */

int
cilium_srv6_context_add (u32 context_id, const ip6_address_t *endpoint_ip, u32 sw_if_index,
			 u32 owner_quota_class)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  cilium_srv6_context_entry_t *e;
  clib_bihash_kv_8_8_t search, kv;
  dpo_id_t dpo = DPO_INVALID;
  u32 pool_index;
  u32 delivery_next;
  f64 now;
  int taken;

  if (!cxm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  /* 04 §1: context_id 0 is reserved and never allocated. */
  if (context_id == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  if (endpoint_ip == NULL || ip6_address_is_zero (endpoint_ip))
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (vnet_get_sw_interface_or_null (vnm, sw_if_index) == NULL)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /*
   * D-35 / 03 §1.1: no new Context may be installed while the guard
   * coverage is incomplete or the dead-man switch is active. Existing ACTIVE
   * delivery is unaffected, which is what keeps the dead-man switch from
   * being usable as an availability attack.
   */
  if (!cilium_srv6_guard_context_install_allowed ())
    {
      cxm->n_install_blocked++;
      return VNET_API_ERROR_FEATURE_DISABLED;
    }

  /*
   * An add for a Context ID that is already installed is either an agent
   * retry after a lost ack or a violation of the non-reuse invariant
   * (04 §1). An exact repeat is idempotent and mutates nothing — D-12
   * forbids modifying an ACTIVE entry in place — anything else is refused.
   */
  search.key = (u64) context_id;
  search.value = 0;
  if (0 == clib_bihash_search_8_8 (&cxm->active_table, &search, &kv))
    {
      e = pool_elt_at_index (cxm->entries, (u32) kv.value);

      if (e->state == CILIUM_SRV6_CONTEXT_ACTIVE && e->tx_sw_if_index == sw_if_index &&
	  0 == memcmp (&e->endpoint_ip, endpoint_ip, sizeof (*endpoint_ip)) &&
	  e->owner_quota_class == owner_quota_class)
	return 0;

      return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
    }

  /*
   * 04 §1 invariant: a Context ID is issued once per locator namespace. An
   * add for an ID that this node has already invalidated therefore cannot be
   * legitimate, and accepting it would make one ID both ACTIVE and
   * tombstoned — exactly the collision the non-reuse invariant exists to
   * prevent (04 §4). Both stores are consulted: the tombstone covers the
   * retention window, the grace index covers an ID whose tombstone could not
   * be recorded because the store was full (03 §2).
   */
  if (cilium_srv6_context_lookup_tombstone (context_id) ||
      hash_get (cxm->grace_by_context_id, (uword) context_id) != NULL)
    return VNET_API_ERROR_VALUE_EXIST;

  /*
   * D-25 / M-6: the ACTIVE budget counts pool indices that exist, which
   * includes entries still inside their grace period. Refusing here is
   * ERR_ACTIVE_CAPACITY: the caller must not proceed to the BGP
   * advertisement (03 §2, 04 §5).
   */
  if (pool_free_elts (cxm->entries) == 0)
    {
      cxm->n_capacity_rejections++;
      return VNET_API_ERROR_LIMIT_EXCEEDED;
    }

  /*
   * Build the forwarding object before taking the barrier: DPO construction
   * may allocate and may fail, and neither belongs inside a barrier section
   * that every worker is blocked on. (The bihash insert below still
   * allocates its value page from the heap on occasion; that is inherent to
   * a table update and is the standard VPP control plane pattern.)
   *
   * The delivery next-node arc (dpoi_next_node) is not part of the identity
   * of the object and is not stored in the entry (03 §2 fixes the entry at
   * one cache line). It is resolved here into the parallel table
   * cilium-ep-deliver reads (03 §6 step 4), which is also why it has to
   * happen before the barrier is taken: resolving the arc may have to add a
   * graph edge, and that takes the worker barrier itself.
   */
  interface_tx_dpo_add_or_lock (DPO_PROTO_IP6, sw_if_index, &dpo);

  delivery_next = cilium_srv6_delivery_resolve (&dpo);
  if (delivery_next == (u32) ~0)
    {
      dpo_reset (&dpo);
      return VNET_API_ERROR_UNSPECIFIED;
    }

  now = vlib_time_now (vm);

  taken = cilium_srv6_barrier_acquire (vm);

  pool_get_zero (cxm->entries, e);
  pool_index = (u32) (e - cxm->entries);

  e->context_id = context_id;
  e->entry_generation = ++cxm->next_generation;
  e->endpoint_ip = *endpoint_ip;
  e->tx_sw_if_index = sw_if_index;
  e->dpo_index = dpo.dpoi_index;
  e->dpo_type = dpo.dpoi_type;
  e->dpo_proto = dpo.dpoi_proto;
  e->owner_quota_class = owner_quota_class;
  e->allocated_at = now;
  e->pkts = 0;
  e->bytes = 0;

  /* 03 §6 step 4: the arc cilium-ep-deliver transmits on. Published before
   * the entry becomes reachable. */
  cilium_srv6_delivery_set (pool_index, delivery_next);

  /* The entry is fully built before it becomes reachable. */
  e->state = CILIUM_SRV6_CONTEXT_ACTIVE;

  kv.key = (u64) context_id;
  kv.value = pool_index;

  if (clib_bihash_add_del_8_8 (&cxm->active_table, &kv, 1 /* add */) < 0)
    {
      cilium_srv6_delivery_set (pool_index, ~0);
      clib_memset (e, 0, sizeof (*e));
      e->state = CILIUM_SRV6_CONTEXT_INVALID;
      pool_put_index (cxm->entries, pool_index);
      cilium_srv6_barrier_release (vm, taken);
      dpo_reset (&dpo);
      return VNET_API_ERROR_TABLE_TOO_BIG;
    }

  cxm->n_active++;
  cxm->n_adds++;

  cilium_srv6_barrier_release (vm, taken);

  return 0;
}

/* ------------------------------------------------------------------ */
/* srv6_context_invalidate (03 §7, D-25)                               */
/* ------------------------------------------------------------------ */

int
cilium_srv6_context_invalidate (u32 context_id, u8 *tombstone_recorded)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  vlib_main_t *vm = vlib_get_main ();
  cilium_srv6_context_entry_t *e;
  cilium_srv6_grace_pending_t *p;
  clib_bihash_kv_8_8_t search, kv;
  u32 pool_index;
  u32 owner_quota_class;
  f64 now;
  int taken;
  int recorded;

  if (tombstone_recorded)
    *tombstone_recorded = 0;

  if (!cxm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (context_id == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  search.key = (u64) context_id;
  search.value = 0;
  if (clib_bihash_search_8_8 (&cxm->active_table, &search, &kv))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool_index = (u32) kv.value;
  if (pool_is_free_index (cxm->entries, pool_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  now = vlib_time_now (vm);

  taken = cilium_srv6_barrier_acquire (vm);

  e = pool_elt_at_index (cxm->entries, pool_index);
  owner_quota_class = e->owner_quota_class;

  /*
   * 03 §4: remove from the ActiveContextTable and mark the entry INVALID
   * first. From here a packet that already captured the handle fails the
   * D-12 re-check in cilium-ep-deliver (DROP_CONTEXT_RECYCLED) instead of
   * being delivered. The generation is bumped so that the stale handle
   * cannot match even if the index is later reused.
   */
  kv.key = (u64) context_id;
  kv.value = pool_index;
  clib_bihash_add_del_8_8 (&cxm->active_table, &kv, 0 /* del */);

  if (e->state == CILIUM_SRV6_CONTEXT_ACTIVE && cxm->n_active > 0)
    cxm->n_active--;
  else if (e->state == CILIUM_SRV6_CONTEXT_SUSPENDED && cxm->n_suspended > 0)
    cxm->n_suspended--;

  e->state = CILIUM_SRV6_CONTEXT_INVALID;
  e->entry_generation = ++cxm->next_generation;

  /*
   * 03 §7 / D-15 (C10): the conntrack entries of the endpoint behind this
   * Context are invalidated in this same barrier section. The call resolves
   * the endpoint incarnation from the delivery interface through the
   * LocalEndpointTable, which is the same authority 02 §7.2 compares a
   * conntrack entry against; it sweeps a bounded prefix here and leaves the
   * remainder to the conntrack housekeeping process. Enforcement does not
   * depend on the sweep completing: the entries stop matching as soon as the
   * endpoint's incarnation changes.
   */
  cilium_srv6_ct_invalidate_sw_if_index (e->tx_sw_if_index);

  /* 03 §2: recording is best effort and must not hold up the invalidate. */
  recorded = csc_ts_record (cxm, context_id, owner_quota_class, now);

  cilium_srv6_barrier_release (vm, taken);

  /*
   * D-12: the pool index and the DPO stay reserved until every worker and
   * frame that could still hold this index is quiescent. The capacity
   * accounting follows the index, not this ack (M-6).
   */
  vec_add2 (cxm->grace_pending, p, 1);
  p->pool_index = pool_index;
  p->context_id = context_id;
  p->free_after = now + cxm->grace_period;

  hash_set (cxm->grace_by_context_id, (uword) context_id, (uword) (p->free_after * 1e3));

  cxm->n_invalidates++;

  if (tombstone_recorded)
    *tombstone_recorded = recorded ? 1 : 0;

  return 0;
}

/* ------------------------------------------------------------------ */
/* srv6_context_gc (03 §7, retention)                                  */
/* ------------------------------------------------------------------ */

/*
 * Reclaim tombstones past the retention target. The FIFO is age ordered, so
 * the expired records are a prefix and the walk stops at the first record
 * that is still within retention.
 */
int
cilium_srv6_context_gc (f64 retention, u32 max_entries, u32 *n_reclaimed, u32 *n_remaining)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  vlib_main_t *vm = vlib_get_main ();
  f64 now;
  u32 n = 0;
  int taken;

  if (n_reclaimed)
    *n_reclaimed = 0;
  if (n_remaining)
    *n_remaining = 0;

  if (!cxm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (max_entries == 0 || max_entries == (u32) ~0)
    max_entries = cxm->gc_max_per_call;

  /*
   * The caller may ask for a longer retention than configured but not a
   * shorter one: 04 §4 counts the tombstone retention as a defence line, and
   * shortening it moves stale packets from DROP_INVALID_CONTEXT to
   * DROP_UNKNOWN_CONTEXT earlier than the node's own policy allows.
   */
  if (retention < cxm->tombstone_retention)
    retention = cxm->tombstone_retention;

  now = vlib_time_now (vm);

  taken = cilium_srv6_barrier_acquire (vm);

  while (n < max_entries && cxm->ts_age_head != (u32) ~0)
    {
      cilium_srv6_tombstone_t *t = pool_elt_at_index (cxm->tombstones, cxm->ts_age_head);

      if ((now - t->invalidated_at) <= retention)
	break;

      csc_ts_drop (cxm, cxm->ts_age_head);
      cxm->n_tombstone_gc_reclaimed++;
      n++;
    }

  cilium_srv6_barrier_release (vm, taken);

  if (n_reclaimed)
    *n_reclaimed = n;
  if (n_remaining)
    *n_remaining = (u32) pool_elts (cxm->tombstones);

  return 0;
}

/* ------------------------------------------------------------------ */
/* delivery suspend / resume (03 §1.1)                                 */
/* ------------------------------------------------------------------ */

/*
 * 03 §1.1: when immediate quarantine cannot be guaranteed, the local SID is
 * removed under the worker barrier and every ACTIVE entry is moved to
 * SUSPENDED so that delivery stops. Contexts stay installed — this is not an
 * invalidate and produces no tombstone — and a suspended Context drops with
 * DROP_SRV6_NOT_READY (03 §3).
 */
void
cilium_srv6_context_suspend_all (const char *reason)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  vlib_main_t *vm = vlib_get_main ();
  cilium_srv6_context_entry_t *e;
  u32 n = 0;
  int taken;

  if (!cxm->initialised)
    return;

  taken = cilium_srv6_barrier_acquire (vm);

  pool_foreach (e, cxm->entries)
    {
      if (e->state != CILIUM_SRV6_CONTEXT_ACTIVE)
	continue;
      e->state = CILIUM_SRV6_CONTEXT_SUSPENDED;
      n++;
    }

  cxm->n_suspended += n;
  cxm->n_active -= clib_min (cxm->n_active, n);

  cilium_srv6_barrier_release (vm, taken);

  CSC_LOG_NOTICE ("suspended %u ACTIVE Context entries: %s", n, reason);
}

void
cilium_srv6_context_resume_all (const char *reason)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  vlib_main_t *vm = vlib_get_main ();
  cilium_srv6_context_entry_t *e;
  u32 n = 0;
  int taken;

  if (!cxm->initialised)
    return;

  taken = cilium_srv6_barrier_acquire (vm);

  pool_foreach (e, cxm->entries)
    {
      if (e->state != CILIUM_SRV6_CONTEXT_SUSPENDED)
	continue;
      e->state = CILIUM_SRV6_CONTEXT_ACTIVE;
      n++;
    }

  cxm->n_active += n;
  cxm->n_suspended -= clib_min (cxm->n_suspended, n);

  cilium_srv6_barrier_release (vm, taken);

  CSC_LOG_NOTICE ("resumed %u SUSPENDED Context entries: %s", n, reason);
}

/* ------------------------------------------------------------------ */
/* grace period process node                                           */
/* ------------------------------------------------------------------ */

static uword
cilium_srv6_context_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  while (1)
    {
      f64 now;

      vlib_process_wait_for_event_or_clock (vm, CILIUM_SRV6_CONTEXT_TICK_INTERVAL);
      (void) vlib_process_get_events (vm, 0);

      now = vlib_time_now (vm);

      csc_grace_reclaim (vm, now);
    }

  return 0;
}

VLIB_REGISTER_NODE (cilium_srv6_context_process_node, static) = {
  .function = cilium_srv6_context_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cilium-srv6-context-process",
  .process_log2_n_stack_bytes = 16,
};

/* ------------------------------------------------------------------ */
/* startup configuration                                               */
/* ------------------------------------------------------------------ */

/*
 * A separate configuration section from the guard's `cilium-srv6 { }`:
 * VLIB config functions run after the init functions, so the table sizes
 * cannot be applied from cilium_srv6_context_init(). The tables are built in
 * the main-loop-enter function below, which runs after configuration.
 */
static clib_error_t *
cilium_srv6_context_config (vlib_main_t *vm, unformat_input_t *input)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  u32 v32;
  f64 v;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "active-capacity %u", &v32) && v32 > 0)
	cxm->active_capacity = v32;
      else if (unformat (input, "tombstone-capacity %u", &v32) && v32 > 0)
	cxm->tombstone_capacity = v32;
      else if (unformat (input, "tombstone-retention %f", &v) && v > 0.0)
	cxm->tombstone_retention = v;
      else if (unformat (input, "grace-period %f", &v) && v > 0.0)
	cxm->grace_period = v;
      else if (unformat (input, "gc-max-per-call %u", &v32) && v32 > 0)
	cxm->gc_max_per_call = v32;
      else if (unformat (input, "grace-log-size %u", &v32) && v32 > 0)
	cxm->grace_log_size = 1 << max_log2 (v32);
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (cilium_srv6_context_config, "cilium-srv6-context");

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

static clib_error_t *
cilium_srv6_context_init (vlib_main_t *vm)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;

  clib_memset (cxm, 0, sizeof (*cxm));

  cilium_srv6_context_log_class = vlib_log_register_class ("cilium-srv6", "context");

  cxm->active_capacity = CILIUM_SRV6_ACTIVE_CAPACITY_DEFAULT;
  cxm->tombstone_capacity = CILIUM_SRV6_TOMBSTONE_CAPACITY_DEFAULT;
  cxm->tombstone_retention = CILIUM_SRV6_TOMBSTONE_RETENTION_DEFAULT;
  cxm->grace_period = CILIUM_SRV6_GRACE_PERIOD_DEFAULT;
  cxm->gc_max_per_call = CILIUM_SRV6_GC_MAX_PER_CALL_DEFAULT;
  cxm->grace_log_size = CILIUM_SRV6_GRACE_LOG_SIZE_DEFAULT;

  cxm->ts_age_head = ~0;
  cxm->ts_age_tail = ~0;

  cxm->process_node_index = cilium_srv6_context_process_node.index;

  return 0;
}

VLIB_INIT_FUNCTION (cilium_srv6_context_init);

/*
 * 03 §9: the pools are reserved once, at start up, and never grown, so the
 * hot path performs no memory allocation and the pool base pointers are
 * stable for lock-free readers.
 *
 * This runs at main-loop-enter rather than init because the capacities come
 * from the startup configuration, which VLIB applies after the init
 * functions.
 */
static clib_error_t *
cilium_srv6_context_main_loop_enter (vlib_main_t *vm)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  u32 nbuckets;

  if (cxm->initialised)
    return 0;

  pool_init_fixed (cxm->entries, cxm->active_capacity);
  pool_init_fixed (cxm->tombstones, cxm->tombstone_capacity);

  cxm->ts_owner_by_class = hash_create (0, sizeof (uword));
  cxm->grace_by_context_id = hash_create (0, sizeof (uword));

  vec_validate_aligned (cxm->grace_log, cxm->grace_log_size - 1, CLIB_CACHE_LINE_BYTES);
  vec_alloc (cxm->grace_pending, cxm->active_capacity);

  /* ~4 keys per bucket; bihash_8_8 keeps the first page at bucket level, so
   * the buckets are allocated once here and never on the hot path. */
  nbuckets = 1 << clib_max (6, max_log2 (cxm->active_capacity) - 2);
  clib_bihash_init_8_8 (&cxm->active_table, "cilium-srv6-active-context", nbuckets,
			(uword) cxm->active_capacity * 128);

  nbuckets = 1 << clib_max (6, max_log2 (cxm->tombstone_capacity) - 2);
  clib_bihash_init_8_8 (&cxm->tombstone_table, "cilium-srv6-context-tombstone", nbuckets,
			(uword) cxm->tombstone_capacity * 128);

  cxm->initialised = 1;

  CSC_LOG_NOTICE ("Context tables ready: ACTIVE capacity %u, tombstone capacity %u "
		  "(retention %.0f s), grace period %.1f s",
		  cxm->active_capacity, cxm->tombstone_capacity, cxm->tombstone_retention,
		  cxm->grace_period);

  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (cilium_srv6_context_main_loop_enter);
