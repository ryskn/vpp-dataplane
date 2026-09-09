/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — PMTUD and flow entropy (C7, #20).
 *
 * design/detail/02-headend-dataplane.md §9 describes two independent MTU
 * mechanisms and this component implements both:
 *
 *   inner direction   cilium-srv6-encap finds inner length > effective MTU,
 *                     drops the packet (DROP_INNER_MTU_EXCEEDED) and calls
 *                     cilium_srv6_ptb_send_hook, which is registered here and
 *                     returns an ICMPv6 Packet Too Big to the source Pod
 *                     (01 §7: source = node address, quote <= 1232 bytes).
 *
 *   outer direction   a transit node reports a Packet Too Big for one of our
 *                     encapsulated packets. cilium-srv6-ptb validates it and,
 *                     only if every condition of 02 §9 and D-36 holds, lowers
 *                     PathMtuTable[path_id].effective_mtu.
 *
 * The two are joined by the RecentTx table (D-21). Every transmitted outer
 * packet larger than the IPv6 minimum link MTU leaves one record per
 * (path, flow, size class); a PTB is only believed when its quoted packet
 * resolves to such a record and the quoted, shift-processed destination
 * address is one this path really presented to a transit node (D-16).
 *
 * Why the record is not per packet (D-21): a per-packet record would be
 * evicted by any high-pps flow long before the PTB comes back, and one
 * tenant's burst would evict another tenant's records, which turns a
 * legitimate PTB into an unverifiable one and the path into an MTU black
 * hole. The state is therefore keyed on the flow and rounded to a 64 byte
 * size class, and holds per-path and per-owner soft quotas so that the
 * eviction victim is chosen from the class that is over its share.
 *
 * Why the interface and the source are checked (D-36): the node address must
 * be routable from the Pods (01 §7), so a Pod can send a PTB to it. Every
 * correlation input a forged PTB needs — quoted source and destination
 * address, flow label, size class — is computable or guessable by that Pod,
 * so RecentTx correlation alone does not stop it. Learning is therefore
 * restricted to PTBs received on a TRUSTED_FABRIC interface whose source is
 * in the SR domain node set, and the flow label seed is a node-local secret.
 *
 * Design references:
 *   design/detail/02-headend-dataplane.md §9, §4.4 (PathCache/PathMtuTable)
 *   design/detail/01-packet-format.md §2 (CSID container), §4 (flow entropy),
 *     §5 (encapsulation overhead), §7 (ICMPv6 PTB)
 *   design/detail/00-overview.md §2 (D-16, D-21, D-36)
 *   design/detail/06-observability.md §3 (effective_mtu, ptb_rejected_total)
 */

#ifndef __included_cilium_srv6_pmtud_h__
#define __included_cilium_srv6_pmtud_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/util/throttle.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/hash.h>
#include <vppinfra/lock.h>

#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_pmtud_parse.h>

/* The pure matcher mirrors the PathCache bounds; keep the two in step. */
STATIC_ASSERT (CILIUM_SRV6_PMTUD_MAX_SHIFT_STATES == CILIUM_SRV6_PATH_MAX_SHIFT_STATES,
	       "PMTUD shift state bound diverged from the PathCache bound");
STATIC_ASSERT (CILIUM_SRV6_PMTUD_MAX_SRH_BYTES == CILIUM_SRV6_PATH_MAX_SRH_BYTES,
	       "PMTUD SRH bound diverged from the PathCache bound");
STATIC_ASSERT (CILIUM_SRV6_PMTUD_MIN_MTU == CILIUM_SRV6_MIN_IPV6_MTU,
	       "PMTUD minimum MTU diverged from the headend constant");

/* 02 §9: "既定 64K entry、60 秒、size-class は 64 byte 刻み". */
#define CILIUM_SRV6_RECENT_TX_CAPACITY_DEFAULT 65536
#define CILIUM_SRV6_RECENT_TX_TIMEOUT_DEFAULT  60.0
#define CILIUM_SRV6_RECENT_TX_SIZE_CLASS_LOG2  6

/* 02 §9: "更新は 10 分で減衰し初期値へ戻る (経路復旧の再学習)". */
#define CILIUM_SRV6_PMTU_DECAY_DEFAULT 600.0

/* Housekeeping cadence and the per-tick work bounds. */
#define CILIUM_SRV6_PMTUD_TICK_INTERVAL	   1.0
#define CILIUM_SRV6_RECENT_TX_GC_PER_TICK  4096
#define CILIUM_SRV6_PMTU_DECAY_SCAN_PER_TICK 4096

/* Bound on the fair-eviction search, as elsewhere in this plugin. */
#define CILIUM_SRV6_RECENT_TX_EVICT_SCAN 16

/*
 * Rate limit on headend-originated PTBs. A Pod that keeps sending oversized
 * packets would otherwise turn one drop into one generated packet, so the
 * generation is throttled per (inner src, inner dst) pair in the same way
 * VPP throttles its own ip6-icmp-error.
 */
#define CILIUM_SRV6_PTB_THROTTLE_BUCKETS 1024
#define CILIUM_SRV6_PTB_THROTTLE_TIME	 1.0

/*
 * One RecentTx record (02 §9, D-21).
 *
 * The unit of state is (path, flow, size class), not the packet: repeated
 * transmissions on the same path with the same flow label whose outer size
 * falls in the same 64 byte class refresh one record instead of adding one.
 *
 * `digest` is the keyed digest of the quotable, shift-invariant part of the
 * outer header (source address and flow label) under the node-local secret
 * of D-36. It is also the first half of the lookup key, so a PTB is resolved
 * with one bihash lookup and no scan over paths.
 */
typedef struct
{
  u64 digest;	/* keyed digest, key[0] */
  u64 path_id;	/* 02 §4.4 path identity, the PathMtuTable key */
  f64 recorded_at;

  u32 mtu_index;	 /* PathMtuTable slot, so the update needs no lookup */
  u32 path_index;	 /* D-12 versioned handle ... */
  u32 path_generation;	 /* ... re-resolved when the PTB arrives */
  u32 flow_label;	 /* 01 §4, checked against the quote */
  u32 size_class;	 /* outer size >> 6, key[1] */
  u32 owner_quota_class; /* D-42 fair eviction subject */

  /* Largest outer size seen in this class. 02 §9 compares ptb_mtu against
     "recorded_outer_size"; keeping the maximum makes the comparison the
     loosest one that is still bounded by something we actually sent. */
  u32 outer_size;
  u16 overhead;	    /* 40 + srh_len (01 §5) */
  u8 next_header;   /* 41 or 43, must match the quote */
  u8 in_use;

  ip6_address_t inner_src; /* checked when the quote reaches the inner header */
  ip6_address_t inner_dst;

  u32 age_prev;
  u32 age_next;
} cilium_srv6_recent_tx_t;

/*
 * What cilium-srv6-encap hands over for one transmitted packet. It is a
 * struct rather than an argument list so that the hot path call site stays
 * one store sequence and one indirect call.
 */
typedef struct
{
  u64 path_id;
  u32 mtu_index;
  u32 path_index;
  u32 path_generation;
  u32 flow_label;
  u32 outer_size; /* 40 + srh_len + inner length */
  u32 owner_quota_class;
  u16 overhead;
  u8 next_header;
  u8 pad;
  ip6_address_t inner_src;
  ip6_address_t inner_dst;
} cilium_srv6_pmtud_tx_t;

/*
 * Verdicts of cilium-srv6-ptb. Every non-OK value is a reason label of the
 * 06 §3 `ptb_rejected_total` counter and has one node error counter.
 */
typedef enum
{
  CILIUM_SRV6_PTB_ACCEPTED = 0,
  CILIUM_SRV6_PTB_ACCEPTED_UNUSABLE,
  CILIUM_SRV6_PTB_NOT_READY,
  CILIUM_SRV6_PTB_UNTRUSTED_INGRESS,
  CILIUM_SRV6_PTB_SOURCE_NOT_IN_DOMAIN,
  CILIUM_SRV6_PTB_MALFORMED,
  CILIUM_SRV6_PTB_QUOTE_NOT_OURS,
  CILIUM_SRV6_PTB_NO_RECORD,
  CILIUM_SRV6_PTB_STALE_RECORD,
  CILIUM_SRV6_PTB_SIZE_MISMATCH,
  CILIUM_SRV6_PTB_STALE_PATH,
  CILIUM_SRV6_PTB_DA_MISMATCH,
  CILIUM_SRV6_PTB_INNER_MISMATCH,
  CILIUM_SRV6_PTB_MTU_OUT_OF_RANGE,
  CILIUM_SRV6_PTB_N_VERDICT,
} cilium_srv6_ptb_verdict_t;

typedef struct
{
  /* ---- hot path ---- */

  /* RecentTx index: (digest, size class) -> pool index. */
  clib_bihash_16_8_t recent_tx_table;
  cilium_srv6_recent_tx_t *recent_tx; /* fixed size pool */

  /* Written from workers (cilium-srv6-encap and cilium-srv6-ptb both run on
     workers), so structural changes are serialised with a spinlock rather
     than the worker barrier, exactly like the FragmentVerdictCache. */
  clib_spinlock_t lock;

  /* Throttle on headend-originated PTBs. */
  throttle_t ptb_throttle;

  /* ---- control plane ---- */

  u32 recent_tx_capacity;
  f64 recent_tx_timeout;
  f64 decay;

  /* Age FIFO and D-42 quota accounting over the RecentTx pool. */
  u32 age_head;
  u32 age_tail;
  u32 n_records;
  uword *path_count;  /* path_id -> records */
  uword *owner_count; /* owner_quota_class -> records */

  /* Cursor of the decay sweep over PathMtuTable, so that the work per tick
     is bounded independently of the PathCache size. */
  u32 decay_cursor;

  u32 process_node_index;

  /* 06 §3 counters that are not per-node error counters. */
  u64 n_tx_records;
  u64 n_tx_refresh;
  u64 n_tx_evictions;
  u64 n_tx_quota_drops;
  u64 n_tx_gc;
  u64 n_ptb_sent;
  u64 n_ptb_throttled;
  u64 n_ptb_no_buffer;
  u64 n_mtu_updates;
  u64 n_path_unusable;
  u64 n_decayed;

  u8 initialised;
} cilium_srv6_pmtud_main_t;

extern cilium_srv6_pmtud_main_t cilium_srv6_pmtud_main;

extern vlib_node_registration_t cilium_srv6_ptb_node;

/*
 * D-36: the digest is keyed with the node-local flow entropy secret, over
 * the part of the outer header that every transit node quotes identically.
 *
 * The hop limit is excluded because it is decremented at each hop, and the
 * traffic class because a transit node may remark DSCP; the destination
 * address is excluded because it is exactly what the C-SID shift changes,
 * which is why it is validated separately against the path's shift states
 * (D-16) instead of being folded in here.
 */
static_always_inline u64
cilium_srv6_pmtud_digest (u64 secret, const ip6_address_t *outer_src, u32 flow_label)
{
  u64 buf[3];

  buf[0] = outer_src->as_u64[0];
  buf[1] = outer_src->as_u64[1];
  buf[2] = (u64) flow_label;

  return (u64) hash_memory (buf, sizeof (buf), (uword) secret);
}

/* 02 §9: "size-class は 64 byte 刻み". */
static_always_inline u32
cilium_srv6_pmtud_size_class (u32 outer_size)
{
  return outer_size >> CILIUM_SRV6_RECENT_TX_SIZE_CLASS_LOG2;
}

/*
 * Record one transmitted outer packet (02 §9). Called from cilium-srv6-encap
 * through cilium_srv6_pmtud_tx_record_hook.
 *
 * Packets whose outer size is at most the IPv6 minimum link MTU are not
 * recorded: no conforming router can report a Packet Too Big for them
 * (RFC 8200 requires every link to carry 1280 bytes), and a PTB claiming an
 * MTU below 1280 is refused by 02 §9 anyway. This keeps the common
 * small-packet path free of the table update. The caller applies that test
 * (CILIUM_SRV6_PMTUD_RECORD_MIN_SIZE) so that the common case is not even a
 * call.
 */
#define CILIUM_SRV6_PMTUD_RECORD_MIN_SIZE CILIUM_SRV6_MIN_IPV6_MTU

void cilium_srv6_pmtud_record_tx (vlib_main_t *vm, const cilium_srv6_pmtud_tx_t *tx);

/*
 * 02 §9 inner direction: generate an ICMPv6 Packet Too Big towards the
 * source Pod. Registered as cilium_srv6_ptb_send_hook, exposed for the CLI
 * and for tests.
 */
void cilium_srv6_pmtud_ptb_send (vlib_main_t *vm, vlib_buffer_t *b, u16 effective_mtu);

/* Validate one received ICMPv6 PTB and, if it is legitimate, narrow the
 * path's MTU. Implemented in cilium_srv6_pmtud.c and called from the
 * cilium-srv6-ptb node. */
cilium_srv6_ptb_verdict_t cilium_srv6_pmtud_ptb_receive (vlib_main_t *vm, vlib_buffer_t *b,
							 u32 *state_out, u32 *mtu_out,
							 u64 *path_id_out);

u8 *format_cilium_srv6_ptb_verdict (u8 *s, va_list *args);

#endif /* __included_cilium_srv6_pmtud_h__ */
