/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — node-local conntrack (C10).
 *
 * design/detail/02-headend-dataplane.md §7 is the primary reference; the
 * destination half is 03 §6. The table is written from three places:
 *
 *   cilium-ep-deliver   03 §6 step 2: forward + reply entry, state
 *                       UNVERIFIED, `verified_revision` left at the sentinel
 *                       (D-19 / D-45)
 *   cilium-srv6-encap   02 §6 step 1: the egress hook creates/refreshes the
 *                       forward entry of a packet the ProgramCache allowed,
 *                       or refreshes the reply entry of a packet that took
 *                       the 02 §7.2 branch-1 bypass
 *   srv6_ct_verify      02 §7.2 branch 2: the agent's reply re-authorisation
 *                       promotes one entry to VERIFIED_ESTABLISHED under the
 *                       worker barrier
 *
 * and read from one:
 *
 *   cilium-srv6-ct      02 §7.2 / D-47: the three-way reply-bypass /
 *                       re-authorisation / miss branch
 *
 * Why an entry alone never authorises anything
 * --------------------------------------------
 * D-19 makes the destination create conntrack state *before* anything has
 * been authorised, so a 5-tuple match must not be sufficient to bypass the
 * ProgramCache. 02 §7.2 gates the bypass on five conditions, in order:
 *
 *   1. state == VERIFIED_ESTABLISHED, which only srv6_ct_verify can set, and
 *      the entry's local_context_id and identity still equal the live
 *      LocalEndpointTable values (D-15: an IP reused by a new Pod does not
 *      inherit the previous Pod's authorisation), and the protocol state is
 *      consistent — a TCP SYN that opens a new connection is never treated
 *      as a reply, and a CLOSED flow is not forwarded;
 *   2. `verified_revision` equals the currently published revision of the
 *      *remote* identity (D-30 scopes the revision to the source identity of
 *      the authorised direction, which for a reply is the peer). This is
 *      where a policy change is detected, immediately and regardless of how
 *      much lease is left;
 *   3. the PolicyLeaseTable slot of that remote identity holds a lease
 *      granted for that very revision;
 *   4. that lease has not expired;
 *   5. otherwise ALLOW.
 *
 * Conditions 2 and 3/4 check independent properties (00 §2.1): 2 is policy
 * semantic freshness, 3 and 4 are policy watcher liveness. D-49 is conditions
 * 3 and 4: without them a watcher outage freezes the revision, condition 2
 * keeps passing, and the reply direction stays open for the whole 8 h TCP
 * established timeout.
 *
 * D-51: the lease is not a field of the entry. The entry carries the
 * dependency pair (remote_identity, verified_revision) and the lease lives in
 * the PolicyLeaseTable, which is what gives this table a lease renewal path
 * at all: srv6_lease_extend renews per identity, so a long-lived flow no
 * longer has to re-authorise once per lease period (Issue #42).
 *
 * Bounding (D-38)
 * ---------------
 * The table has a capacity, a per-local-endpoint and a per-owner soft quota
 * with fair eviction, and UNVERIFIED entries live in a separate budget with
 * a 5 s timeout, so that the entries created before authorisation cannot
 * displace the authorised ones.
 *
 * Design references:
 *   design/detail/02-headend-dataplane.md §2 (table list), §7.1 (structure),
 *     §7.2 (the three branches), §8 (IF-2)
 *   design/detail/03-destination-dataplane.md §6 (delivery), §7 (IF-2)
 *   design/detail/00-overview.md §2 (D-12, D-15, D-19, D-30, D-31, D-38,
 *     D-42, D-45, D-47, D-49, D-51), §2.1 (policy decision validity),
 *     §4.1 (message validation)
 *   design/detail/06-observability.md §3 (conntrack metrics)
 */

#ifndef __included_cilium_srv6_ct_h__
#define __included_cilium_srv6_ct_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/hash.h>
#include <vppinfra/lock.h>

#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_ct_fsm.h>

/* ------------------------------------------------------------------ */
/* capacities, quotas and timeouts (02 §7.1, D-38)                     */
/* ------------------------------------------------------------------ */

/*
 * 02 §7.1: "table 上限 (既定 1M entry)". The pool is reserved at start up and
 * never grown, so this default costs 128 MB of pool plus the age vector and
 * the bihash arena. Deployments that cannot afford it lower
 * `conntrack-capacity` in the `cilium-srv6-conntrack` startup configuration
 * stanza; correctness never depends on the size — a table that is too small
 * loses reply bypasses, which re-authorise instead of being forwarded.
 */
#define CILIUM_SRV6_CT_CAPACITY_DEFAULT (1024 * 1024)

/*
 * 02 §7.1 / D-38: "UNVERIFIED は別枠 (既定 5%)". Entries created by the
 * destination delivery path before anything is authorised share this budget
 * and can only ever evict each other.
 */
#define CILIUM_SRV6_CT_UNVERIFIED_PERCENT 5

/* Bounded fair-eviction search, as in the ProgramCache and the tombstone
   store: constant work per insertion. */
#define CILIUM_SRV6_CT_EVICT_SCAN 16

/*
 * 02 §7.1 timeouts. "TCP established 8h, TCP transient 30s, UDP 60s,
 * ICMPv6 10s ... UNVERIFIED は別枠・短 timeout (既定 5 秒)".
 *
 * The design names four protocol classes. Everything that is neither TCP,
 * UDP nor ICMPv6 has no protocol state to track and uses the UDP timeout;
 * that is an implementation choice, not a design statement.
 */
#define CILIUM_SRV6_CT_TIMEOUT_UNVERIFIED  5.0
#define CILIUM_SRV6_CT_TIMEOUT_TCP_EST	   (8 * 3600.0)
#define CILIUM_SRV6_CT_TIMEOUT_TCP_TRANS   30.0
#define CILIUM_SRV6_CT_TIMEOUT_UDP	   60.0
#define CILIUM_SRV6_CT_TIMEOUT_ICMP6	   10.0

/* Housekeeping: bounded work per tick, like every other store here. */
#define CILIUM_SRV6_CT_TICK_INTERVAL	0.5
#define CILIUM_SRV6_CT_GC_PER_TICK	4096
#define CILIUM_SRV6_CT_SWEEP_PER_TICK	4096

/* Slots examined inside the barrier section of one srv6_ct_invalidate call
   or one endpoint delete; the remainder is swept by the housekeeping
   process. See cilium_srv6_ct_invalidate_endpoint() for why the fail-closed
   behaviour does not depend on the sweep having finished. */
#define CILIUM_SRV6_CT_INVALIDATE_PER_CALL 1024

/* ------------------------------------------------------------------ */
/* entry                                                               */
/* ------------------------------------------------------------------ */

/*
 * The state enum, the direction, the entry flags and the TCP state machine
 * live in cilium_srv6_ct_fsm.h, which has no vlib dependency so that the
 * transition rules can be exercised on their own.
 */

/*
 * 02 §7.1 value, in two cache lines. The first line holds the key and
 * everything the 02 §7.2 allow conditions compare; the second the counters,
 * the identities and the versioned path handle.
 *
 * `verified_revision` deliberately has no default: it is
 * CILIUM_SRV6_REV_INVALID (the sentinel of 02 §4) for as long as the entry is
 * UNVERIFIED, and is only ever written by srv6_ct_verify. D-45 forbids the
 * destination from writing a guessed one, because the 02 §7.2 revision
 * condition would then be satisfied by construction and the reply bypass
 * D-19 removed would be back.
 *
 * The age links live in a parallel vector (cilium_srv6_ct_age_t) rather than
 * in the entry, which keeps the entry at exactly two cache lines.
 */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u64 key[5];		 /* the bihash key, so eviction and the sweep can
		       delete without re-deriving it */
  u64 verified_revision; /* sentinel while UNVERIFIED (D-19 / D-45) */
  f64 last_seen;

  u64 pkts[2];	/* [0] own direction, [1] opposite */
  u64 bytes[2];

  u32 local_context_id;		/* endpoint incarnation (D-15) */
  u32 local_endpoint_identity;	/* LocalEndpointTable identity */
  u32 remote_identity;		/* peer identity the revision is scoped to */
  u32 policy_rev_slot;		/* PolicyLeaseTable slot of remote_identity */
  u32 path_cache_index;		/* versioned handle for the reply bypass */
  u32 path_generation;
  u32 owner_quota_class; /* D-42 owner(namespace) quota class */

  u8 state; /* cilium_srv6_ct_state_t */
  u8 flags; /* CILIUM_SRV6_CT_F_* */
  u8 tcp;   /* CILIUM_SRV6_CT_TCP_* progress bits */
  u8 proto;
} cilium_srv6_ct_entry_t;

STATIC_ASSERT (sizeof (cilium_srv6_ct_entry_t) <= 2 * CLIB_CACHE_LINE_BYTES,
	       "conntrack entry must fit in two cache lines (02 §7.1)");

/* Age FIFO links, one pair per pool slot. Kept out of the entry so that the
   entry stays two cache lines; only the control paths touch them. */
typedef struct
{
  u32 prev;
  u32 next;
} cilium_srv6_ct_age_t;

/* Budget index: 0 = UNVERIFIED (D-38 separate allowance), 1 = everything
   that has been authorised, whether by the ProgramCache (forward) or by
   srv6_ct_verify (reply). */
#define CILIUM_SRV6_CT_BUDGET_UNVERIFIED 0
#define CILIUM_SRV6_CT_BUDGET_VERIFIED	 1
#define CILIUM_SRV6_CT_N_BUDGET		 2

static_always_inline u32
cilium_srv6_ct_budget_of (u8 flags)
{
  return (flags & CILIUM_SRV6_CT_F_VERIFIED) ? CILIUM_SRV6_CT_BUDGET_VERIFIED :
					       CILIUM_SRV6_CT_BUDGET_UNVERIFIED;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

typedef struct
{
  /* ---- hot path ---- */

  /* ConntrackTable: bihash_40_8 key -> pool index. */
  clib_bihash_40_8_t table;
  cilium_srv6_ct_entry_t *entries; /* fixed size pool */

  /* ---- control plane ---- */

  cilium_srv6_ct_age_t *age; /* parallel to `entries` */
  u32 age_head[CILIUM_SRV6_CT_N_BUDGET];
  u32 age_tail[CILIUM_SRV6_CT_N_BUDGET];
  u32 n_entries[CILIUM_SRV6_CT_N_BUDGET];

  uword *ep_count;    /* local_context_id -> entries (D-38 per-endpoint) */
  uword *owner_count; /* owner_quota_class -> entries (D-42) */

  /*
   * Endpoint incarnations whose entries are still being reclaimed, mapping
   * local_context_id -> the sweep generation at which the id may be
   * forgotten. See cilium_srv6_ct_invalidate_endpoint().
   */
  uword *invalidating;
  u32 sweep_cursor;
  u64 sweep_generation;

  /* Structural changes (create, remove, promote) are serialised with this
     lock, because two of the three writers are workers. In-place field
     updates of an existing entry are done without it; see the note in
     cilium_srv6_ct.c. */
  clib_spinlock_t lock;

  u32 capacity;
  u32 unverified_capacity;

  f64 timeout_unverified;
  f64 timeout_tcp_established;
  f64 timeout_tcp_transient;
  f64 timeout_udp;
  f64 timeout_icmp6;

  u32 process_node_index;

  /* 06 §3 counters. */
  u64 n_created[CILIUM_SRV6_CT_N_BUDGET];
  u64 n_verified;
  u64 n_verify_rejected;
  u64 n_quota_drops;
  u64 n_evictions;
  u64 n_gc;
  u64 n_invalidated;
  u64 n_reply_allow;
  u64 n_reply_reauth;
  u64 n_forward;
  u64 n_incarnation_mismatch;
  u64 n_revision_mismatch;
  /* D-85 (00 §2.23.5, errata #34 item 176): of the `n_revision_mismatch`
     refusals above, how many were the agent-revision-incarnation fence — the
     entry's `verified_revision` was quoted by an agent process that no longer
     holds the revision authority — rather than a per-key policy change. A
     subset, not a separate reason, because the remedy for the packet is the
     same (D-47 branch 2) while the remedy for the *node* is not: a per-key
     change is fixed by the next re-authorisation, this one only by the new
     agent process finishing its seed. CLI only: adding a field to
     srv6_conntrack_stats_reply would change that message's CRC. */
  u64 n_stale_incarnation;
  u64 n_lease_expired;
  u64 n_proto_state_denied;

  u8 initialised;
} cilium_srv6_ct_main_t;

extern cilium_srv6_ct_main_t cilium_srv6_ct_main;

/* ------------------------------------------------------------------ */
/* key construction                                                    */
/* ------------------------------------------------------------------ */

/*
 * 02 §7.1 key. The addresses take four words and the remaining 48 bits of
 * the fifth hold {direction, proto, sport, dport}. The incarnation is
 * deliberately *not* part of the key (M-8): it lives in the value, so that a
 * packet for a reused IP finds the stale entry and fails the 02 §7.2
 * incarnation condition instead of silently creating a second one.
 */
static_always_inline void
cilium_srv6_ct_key (u64 key[5], const ip6_address_t *src, const ip6_address_t *dst, u8 proto,
		    u16 sport, u16 dport, u8 direction)
{
  key[0] = src->as_u64[0];
  key[1] = src->as_u64[1];
  key[2] = dst->as_u64[0];
  key[3] = dst->as_u64[1];
  key[4] = ((u64) direction << 48) | ((u64) proto << 32) | ((u64) sport << 16) | (u64) dport;
}

static_always_inline int
cilium_srv6_ct_lookup_index (const cilium_srv6_ct_main_t *cm, const u64 key[5], u32 *index)
{
  clib_bihash_kv_40_8_t kv;
  int i;

  if (PREDICT_FALSE (!cm->initialised))
    return 0;

  for (i = 0; i < 5; i++)
    kv.key[i] = key[i];
  kv.value = 0;

  if (clib_bihash_search_inline_40_8 ((clib_bihash_40_8_t *) &cm->table, &kv))
    return 0;

  *index = (u32) kv.value;

  if (PREDICT_FALSE (*index >= cm->capacity))
    return 0;

  return 1;
}

/*
 * Expiry of one entry (02 §7.1). UNVERIFIED has its own short timeout
 * (D-38); a TCP flow uses the established timeout only once both directions
 * have been seen to acknowledge, which is the "SYN-ACK と ACK を確認して"
 * clause applied to the timeout class.
 */
static_always_inline f64
cilium_srv6_ct_timeout (const cilium_srv6_ct_main_t *cm, const cilium_srv6_ct_entry_t *e)
{
  const u8 acked = CILIUM_SRV6_CT_TCP_ACK_OWN | CILIUM_SRV6_CT_TCP_ACK_OPP;

  if (!(e->flags & CILIUM_SRV6_CT_F_VERIFIED))
    return cm->timeout_unverified;

  switch (e->proto)
    {
    case IP_PROTOCOL_TCP:
      if (e->state == CILIUM_SRV6_CT_STATE_VERIFIED_ESTABLISHED && (e->tcp & acked) == acked)
	return cm->timeout_tcp_established;
      return cm->timeout_tcp_transient;

    case IP_PROTOCOL_ICMP6:
      return cm->timeout_icmp6;

    default:
      /* UDP and everything without protocol state. */
      return cm->timeout_udp;
    }
}

static_always_inline int
cilium_srv6_ct_expired (const cilium_srv6_ct_main_t *cm, const cilium_srv6_ct_entry_t *e, f64 now)
{
  return now > e->last_seen + cilium_srv6_ct_timeout (cm, e);
}

/* ------------------------------------------------------------------ */
/* control plane entry points (cilium_srv6_ct.c)                       */
/* ------------------------------------------------------------------ */

/*
 * srv6_ct_verify (02 §7.2 branch 2, IF-2).
 *
 * Promotes the reply-direction entry of {src, dst, proto, sport, dport} to
 * VERIFIED_ESTABLISHED after the agent re-authorised the forward direction.
 * The 5-tuple is the reply packet's, i.e. exactly what was punted.
 *
 * Everything is validated before any state is touched (00 §4.1) and the
 * transition happens under the worker barrier (D-12):
 *
 *   - `policy_revision` must not be the reserved sentinel, because that is
 *     what "not authorised" means in an entry;
 *   - the revision must still be the one this node publishes for
 *     `remote_identity`, and the promotion grants that identity a lease for
 *     it (02 §5.4), which is what lets the very next reply take the bypass
 *     instead of waiting for the agent's next bulk push;
 *   - the local endpoint must still be the one the punt was issued for,
 *     keyed (sw_if_index, if_incarnation) per D-31, and still carry
 *     `local_identity`;
 *   - the path handle must resolve, so that the hot path bypass has a path
 *     to encapsulate on (see the DEVIATION note in the .api);
 *   - a CLOSED entry is not promoted.
 *
 * Returns 0, or a VNET_API_ERROR_* value.
 */
int cilium_srv6_ct_verify (const ip6_address_t *src, const ip6_address_t *dst, u8 proto, u16 sport,
			   u16 dport, u32 sw_if_index, u32 if_incarnation, u32 local_identity,
			   u32 remote_identity, u64 policy_revision, u32 path_cache_index,
			   u32 path_generation);

/*
 * srv6_ct_invalidate (02 §8 / 03 §7, D-15).
 *
 * Removes every entry bound to one endpoint incarnation. Bounded work per
 * call: `max_entries` pool slots are examined inside the barrier section
 * starting at `cursor`, and `next_cursor` says where to continue. The
 * housekeeping process finishes any remainder on its own, so a caller that
 * does not iterate is still correct.
 */
int cilium_srv6_ct_invalidate (u32 local_context_id, u32 cursor, u32 max_entries,
			       u32 *n_invalidated, u32 *next_cursor);

/*
 * Endpoint delete, called from the plugin itself (LocalEndpointTable delete,
 * interface deletion, Context invalidate). Sweeps a bounded prefix
 * immediately and leaves the rest to the housekeeping process.
 *
 * Reclaiming the entries is not what makes the delete safe: an entry that
 * survives the sweep still fails the 02 §7.2 incarnation condition, because
 * that condition compares against the *live* LocalEndpointTable. The sweep
 * exists to return the memory and to satisfy the "purge" half of D-15.
 */
void cilium_srv6_ct_invalidate_endpoint (u32 local_context_id);

/* Same, for a delivery interface: resolves the endpoint incarnation from the
   LocalEndpointTable and invalidates it. A no-op when the interface has no
   local endpoint. */
void cilium_srv6_ct_invalidate_sw_if_index (u32 sw_if_index);

u8 *format_cilium_srv6_ct_state (u8 *s, va_list *args);
u8 *format_cilium_srv6_ct_direction (u8 *s, va_list *args);

#endif /* __included_cilium_srv6_ct_h__ */
