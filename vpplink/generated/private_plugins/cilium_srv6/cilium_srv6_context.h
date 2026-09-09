/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — EndpointContextTable and tombstone store (C8-c).
 *
 * Two independent bounded stores (D-25):
 *
 *   ActiveContextTable   bihash_8_8: context_id -> ACTIVE pool index.
 *                        The pool is reserved at start up (default 64K) and
 *                        is never grown, so the hot path performs no memory
 *                        allocation and the pool base pointer is stable for
 *                        lock-free readers.
 *   ContextTombstoneTable
 *                        bihash_8_8: context_id -> tombstone pool index.
 *                        Separate pool (default 256K, 24 h retention) with a
 *                        per-owner soft quota and fair eviction, so that a
 *                        create/delete storm cannot consume ACTIVE capacity.
 *
 * Lookup order (03 §3): the tombstone table is consulted only when the
 * ActiveContextTable misses, so a normal ACTIVE packet still costs exactly
 * one Context lookup (03 §1 NFR-5 budget).
 *
 * Design references:
 *   design/detail/03-destination-dataplane.md §2 (table definition), §3
 *     (lookup order and drop reasons), §4 (D-12 synchronisation), §7 (IF-2),
 *     §9 (no hot path allocation, one cache line per entry)
 *   design/detail/00-overview.md §2 (D-12, D-25, D-42)
 *   design/detail/04-context-allocator.md §4, §5 (ack / grace period)
 *   design/detail/06-observability.md §2, §3, §4
 */

#ifndef __included_cilium_srv6_context_h__
#define __included_cilium_srv6_context_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/ip/ip6_packet.h>
#include <vppinfra/bihash_8_8.h>

#include <cilium_srv6/cilium_srv6_guard.h>

/*
 * 03 §2 / §9: the ACTIVE pool is reserved for delivery and is not shared
 * with tombstones. Reaching the limit makes srv6_context_add fail closed
 * with ERR_ACTIVE_CAPACITY, so the Context is never advertised over BGP
 * (04 §5 step 3).
 */
#define CILIUM_SRV6_ACTIVE_CAPACITY_DEFAULT (64 * 1024)

/* 03 §2: separate bounded tombstone store, target retention 24 h. */
#define CILIUM_SRV6_TOMBSTONE_CAPACITY_DEFAULT	(256 * 1024)
#define CILIUM_SRV6_TOMBSTONE_RETENTION_DEFAULT (24.0 * 3600.0)

/*
 * D-12 grace period. invalidate removes the entry from the ActiveContextTable
 * under the worker barrier; the pool index and the DPO are only reclaimed
 * once every worker/frame that could still hold the old index is quiescent.
 *
 * A worker barrier sync already establishes that no worker is inside a graph
 * node, so the timed period is a margin on top of that, not the mechanism
 * itself. It is deliberately far longer than any frame lifetime.
 */
#define CILIUM_SRV6_GRACE_PERIOD_DEFAULT 2.0

/* Interval at which the grace period / bookkeeping process node runs. */
#define CILIUM_SRV6_CONTEXT_TICK_INTERVAL 0.5

/*
 * Bound on the fair-eviction search (03 §2). The tombstone FIFO is ordered
 * by invalidation time, so the scan starts at the oldest record and stops at
 * the first record belonging to an over-quota owner; if none is found within
 * this many steps the oldest record is evicted. Bounded work per insert.
 */
#define CILIUM_SRV6_TOMBSTONE_EVICT_SCAN 16

/* Default bound on the number of tombstones reclaimed by one
 * srv6_context_gc call, so that a single API message cannot hold the worker
 * barrier for an unbounded time. */
#define CILIUM_SRV6_GC_MAX_PER_CALL_DEFAULT 4096

/* Same reasoning for grace period completion: a delete storm can leave tens
 * of thousands of pool indices waiting, and they must not all be reclaimed
 * inside one barrier section. The remainder is picked up on the next tick. */
#define CILIUM_SRV6_GRACE_RECLAIM_MAX_PER_TICK 4096

/*
 * Size of the grace-completion log (see cilium_srv6_grace_log_t). Ring of
 * the most recent grace completions, read with srv6_context_grace_dump.
 * Must be a power of two.
 */
#define CILIUM_SRV6_GRACE_LOG_SIZE_DEFAULT 4096

/*
 * Context entry state.
 *
 *   ACTIVE     delivering (03 §2)
 *   SUSPENDED  delivery temporarily disabled while the guard is fail-closed
 *              (03 §1.1); distinct from a tombstone
 *   INVALID    invalidated, waiting for the D-12 grace period to complete.
 *              The entry is already out of the ActiveContextTable; the pool
 *              index is still reserved so that it cannot be reused
 *              (03 §4, and the M-6 capacity accounting rule of 03 §2).
 *
 * INVALID is 0 so that a zero-filled slot is never treated as deliverable,
 * matching the fail-safe convention of the guard trust map.
 */
typedef enum
{
  CILIUM_SRV6_CONTEXT_INVALID = 0,
  CILIUM_SRV6_CONTEXT_ACTIVE = 1,
  CILIUM_SRV6_CONTEXT_SUSPENDED = 2,
  CILIUM_SRV6_CONTEXT_N_STATE,
} cilium_srv6_context_state_t;

/*
 * ACTIVE pool entry (03 §2). Exactly one cache line (03 §9) so that the
 * quad-loop of cilium-end-cilium touches a single line per packet.
 *
 * The entry is immutable while ACTIVE (D-12) except for the pkts/bytes
 * counters, which are per-entry statistics rather than forwarding state.
 * An update is a new entry plus an atomic bihash replacement under the
 * worker barrier; the pool index is never mutated in place.
 *
 * `dpo_index` is stored together with `dpo_type` / `dpo_proto`, which are the
 * remaining fields of the dpo_id_t the index belongs to; without them the
 * index cannot be interpreted or unlocked. See
 * cilium_srv6_context_entry_dpo().
 */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u32 context_id;	     /* integrity re-check (03 §4) */
  u32 entry_generation;	     /* immutable handle version (D-12) */
  ip6_address_t endpoint_ip; /* expected inner DA (03 §3) */
  u32 tx_sw_if_index;	     /* Pod interface */
  u32 dpo_index;	     /* delivery forwarding object */
  u8 dpo_type;
  u8 dpo_proto;
  u8 state; /* cilium_srv6_context_state_t */
  u8 pad0;
  u32 owner_quota_class; /* D-42 owner(namespace) quota class */
  f64 allocated_at;	 /* observability (06 §4.1) */
  u64 pkts;
  u64 bytes;
} cilium_srv6_context_entry_t;

STATIC_ASSERT (sizeof (cilium_srv6_context_entry_t) <= CLIB_CACHE_LINE_BYTES,
	       "Context pool entry must fit in one cache line (03 §9)");

/*
 * Tombstone record (03 §2): {context_id, owner_quota_class, invalidated_at}.
 *
 * The dataplane never dereferences a tombstone — the bihash hit/miss alone
 * decides between DROP_INVALID_CONTEXT and DROP_UNKNOWN_CONTEXT — so
 * tombstone pool indices need no grace period and may be reused immediately.
 *
 * age_prev/age_next form a FIFO ordered by invalidated_at. Because every
 * record is appended at the tail with a monotonically increasing timestamp,
 * FIFO order is age order, which is what both retention GC and fair eviction
 * walk.
 */
typedef struct
{
  u32 context_id;
  u32 owner_quota_class;
  f64 invalidated_at;
  u32 age_prev;
  u32 age_next;
} cilium_srv6_tombstone_t;

/* Per-owner tombstone accounting for the D-42 soft quota. */
typedef struct
{
  u32 owner_quota_class;
  u32 n_tombstones;
} cilium_srv6_ts_owner_t;

/* One ACTIVE pool index waiting for its D-12 grace period to complete. */
typedef struct
{
  u32 pool_index;
  u32 context_id;
  f64 free_after;
} cilium_srv6_grace_pending_t;

/*
 * Grace-completion record.
 *
 * DEVIATION (see the plugin README section in cilium_srv6_context.c): the
 * IF-2 message set of 03 §7 has no message telling the agent that a grace
 * period completed, but the C2 allocator (pkg/srv6ec/contextalloc) has a
 * NotifyGraceComplete(ContextID) entry point and 03 §2 / 04 §5 make the
 * ACTIVE capacity accounting depend on that event. The plugin therefore
 * keeps a bounded, read-only log of completions that the agent polls with
 * srv6_context_grace_dump; the plugin holds no per-reader state.
 */
typedef struct
{
  u64 seq;
  u32 context_id;
  f64 released_at;
} cilium_srv6_grace_log_t;

typedef struct
{
  /* ---- hot path ---- */

  /* ActiveContextTable: key = context_id zero-extended, value = pool index */
  clib_bihash_8_8_t active_table;

  /* Fixed-size pool, allocated once at start up (03 §9). The base pointer
   * never moves, so a worker may index it without holding the barrier. */
  cilium_srv6_context_entry_t *entries;

  /* ContextTombstoneTable: key = context_id, value = tombstone pool index.
   * Consulted only on an ActiveContextTable miss (03 §2). */
  clib_bihash_8_8_t tombstone_table;

  /* ---- control plane ---- */

  cilium_srv6_tombstone_t *tombstones; /* fixed-size pool */
  u32 ts_age_head;		       /* oldest record, ~0 if empty */
  u32 ts_age_tail;		       /* newest record, ~0 if empty */
  cilium_srv6_ts_owner_t *ts_owners;
  uword *ts_owner_by_class; /* owner_quota_class -> ts_owners index */

  u32 active_capacity;
  u32 tombstone_capacity;
  f64 tombstone_retention;
  f64 grace_period;
  u32 gc_max_per_call;

  cilium_srv6_grace_pending_t *grace_pending; /* ordered by free_after */
  /* context_id -> free_after in milliseconds, for every entry still inside
   * its grace period. Lets srv6_context_add reject a Context ID that is
   * being reclaimed in constant time, and lets the dump report the remaining
   * grace period without scanning the pending vector per entry. */
  uword *grace_by_context_id;
  cilium_srv6_grace_log_t *grace_log; /* ring, grace_log_size long */
  u32 grace_log_size;		      /* power of two */
  u64 grace_next_seq;		      /* seq of the next completion */

  u32 next_generation;

  /* counters and gauges (06 §3) */
  u32 n_active;
  u32 n_suspended;
  u64 n_capacity_rejections;
  u64 n_install_blocked;
  u64 n_tombstone_evictions;
  u64 n_tombstone_record_failures_full;
  u64 n_tombstone_record_failures_quota;
  u64 n_tombstone_gc_reclaimed;
  u64 n_grace_completions;
  u64 n_adds;
  u64 n_invalidates;

  u32 process_node_index;
  u8 initialised;
} cilium_srv6_context_main_t;

extern cilium_srv6_context_main_t cilium_srv6_context_main;

/* Result of the two-stage Context resolution of 03 §3. */
typedef enum
{
  /* ActiveContextTable hit; the caller must still check entry state. */
  CILIUM_SRV6_CTX_FOUND = 0,
  /* ActiveContextTable miss, tombstone hit -> DROP_INVALID_CONTEXT */
  CILIUM_SRV6_CTX_INVALIDATED,
  /* miss in both -> DROP_UNKNOWN_CONTEXT */
  CILIUM_SRV6_CTX_UNKNOWN,
} cilium_srv6_ctx_lookup_result_t;

/*
 * ActiveContextTable lookup (03 §2/§3): one bihash lookup, no allocation.
 * Returns 1 and sets *pool_index on a hit.
 */
static_always_inline int
cilium_srv6_context_lookup_active (u32 context_id, u32 *pool_index)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  clib_bihash_kv_8_8_t kv;

  if (PREDICT_FALSE (!cxm->initialised))
    return 0;

  kv.key = (u64) context_id;
  kv.value = 0;

  if (clib_bihash_search_inline_8_8 (&cxm->active_table, &kv))
    return 0;

  *pool_index = (u32) kv.value;
  return 1;
}

/*
 * ContextTombstoneTable lookup (03 §2/§3). Only ever called after an
 * ActiveContextTable miss, so a normal ACTIVE packet does not pay for it.
 */
static_always_inline int
cilium_srv6_context_lookup_tombstone (u32 context_id)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;
  clib_bihash_kv_8_8_t kv;

  if (PREDICT_FALSE (!cxm->initialised))
    return 0;

  kv.key = (u64) context_id;
  kv.value = 0;

  return 0 == clib_bihash_search_inline_8_8 (&cxm->tombstone_table, &kv);
}

/*
 * The full 03 §3 resolution, in the order the design mandates. An eviction
 * or a completed retention GC turns an INVALIDATED result into UNKNOWN;
 * both are fail-closed, only the drop reason differs (D-25).
 */
static_always_inline cilium_srv6_ctx_lookup_result_t
cilium_srv6_context_resolve (u32 context_id, u32 *pool_index)
{
  if (PREDICT_TRUE (cilium_srv6_context_lookup_active (context_id, pool_index)))
    return CILIUM_SRV6_CTX_FOUND;

  if (cilium_srv6_context_lookup_tombstone (context_id))
    return CILIUM_SRV6_CTX_INVALIDATED;

  return CILIUM_SRV6_CTX_UNKNOWN;
}

/*
 * Pool entry accessor for the dataplane. The pool is fixed size and its base
 * pointer is stable, so this is a plain bounds-checked index. Returns NULL
 * for an out-of-range index rather than asserting.
 */
static_always_inline cilium_srv6_context_entry_t *
cilium_srv6_context_entry_at (u32 pool_index)
{
  cilium_srv6_context_main_t *cxm = &cilium_srv6_context_main;

  if (PREDICT_FALSE (pool_index >= cxm->active_capacity))
    return NULL;

  return cxm->entries + pool_index;
}

/*
 * D-12 re-check performed by cilium-ep-deliver (03 §4/§6) on the
 * {pool_index, context_id, entry_generation} triple carried in the buffer
 * metadata. A mismatch means the entry was reclaimed underneath a packet in
 * flight and must be counted as DROP_CONTEXT_RECYCLED.
 */
static_always_inline int
cilium_srv6_context_handle_valid (u32 pool_index, u32 context_id, u32 entry_generation)
{
  const cilium_srv6_context_entry_t *e = cilium_srv6_context_entry_at (pool_index);

  if (PREDICT_FALSE (e == NULL))
    return 0;

  return e->context_id == context_id && e->entry_generation == entry_generation &&
	 e->state == CILIUM_SRV6_CONTEXT_ACTIVE;
}

/* Rebuild the dpo_id_t the entry's forwarding object belongs to. */
static_always_inline void
cilium_srv6_context_entry_dpo (const cilium_srv6_context_entry_t *e, dpo_id_t *dpo)
{
  dpo->dpoi_type = e->dpo_type;
  dpo->dpoi_proto = e->dpo_proto;
  dpo->dpoi_next_node = 0;
  dpo->dpoi_index = e->dpo_index;
}

/* Number of ACTIVE pool indices that exist, i.e. the capacity accounting of
 * M-6: ACTIVE + SUSPENDED + entries still inside their grace period. */
u32 cilium_srv6_context_n_reserved (void);

/* 06 §3 context_active_reserved: entries whose grace period has not
 * completed and whose pool index is therefore not reusable. */
static_always_inline u32
cilium_srv6_context_n_grace_pending (void)
{
  return vec_len (cilium_srv6_context_main.grace_pending);
}

/* Control plane entry points (cilium_srv6_context.c). */
int cilium_srv6_context_add (u32 context_id, const ip6_address_t *endpoint_ip, u32 sw_if_index,
			     u32 owner_quota_class);
int cilium_srv6_context_invalidate (u32 context_id, u8 *tombstone_recorded);
int cilium_srv6_context_gc (f64 retention, u32 max_entries, u32 *n_reclaimed, u32 *n_remaining);
void cilium_srv6_context_suspend_all (const char *reason);
void cilium_srv6_context_resume_all (const char *reason);

/* Oldest sequence number still present in the grace-completion ring. An
 * agent whose cursor is below this value has missed completions and must
 * reconcile with srv6_context_dump. */
u64 cilium_srv6_grace_log_oldest_seq (void);

/* Time left before the grace period of this Context ID completes, 0 if it is
 * not inside one. */
u32 cilium_srv6_grace_remaining_ms (u32 context_id, f64 now);

u8 *format_cilium_srv6_context_state (u8 *s, va_list *args);

#endif /* __included_cilium_srv6_context_h__ */
