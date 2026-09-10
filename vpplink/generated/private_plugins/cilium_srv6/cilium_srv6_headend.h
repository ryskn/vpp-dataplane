/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — headend graph nodes and tables (C7).
 *
 * The headend half of design/detail/02-headend-dataplane.md:
 *
 *   pod-if (tap/memif)
 *     -> cilium-srv6-guard      03 §1.1 ingress guard, already present (C8-a)
 *     -> cilium-srv6-classify   02 §3: local endpoint / identity resolution,
 *                               src IP anti-spoof, bounded inner EH and
 *                               fragment parse, L4 discriminator (D-41)
 *     -> cilium-srv6-ct         02 §7.2 / D-47: reply bypass, re-authorisation,
 *                               miss
 *     -> cilium-srv6-program    02 §4.2: ProgramCache lookup, dependency
 *                               revision compare, PolicyLeaseTable check
 *     -> cilium-srv6-encap      02 §6: flow entropy, outer IPv6, optional SRH
 *     -> ip6-lookup -> ip6-output -> NIC
 *   (miss / stale / re-auth)
 *     -> cilium-srv6-punt       02 §5: IF-3 punt with a one-shot token
 *
 * Tables owned by this component (02 §2), all written through IF-2:
 *
 *   LocalEndpointTable    (sw_if_index, if_incarnation) -> endpoint  (D-31)
 *   ProgramCache          (src_identity, dst, proto, l4_disc) -> verdict
 *   PolicyLeaseTable      identity -> {revision, lease revision, deadline}
 *                         (00 §2.1, D-30 + D-51). It is also the POLICY key
 *                         space of the per-key revision namespaces (D-83)
 *   EndpointRevTable      destination IPv6 -> revision (D-83 ENDPOINT keys,
 *                         including the reserved `::` absent-endpoint key)
 *   PathRevTable          PathCache index -> revision (D-83 PATH keys)
 *   PathCache             immutable versioned handle -> DA/SRH template
 *   PathMtuTable          path_id -> learned effective MTU (mutable, D-21)
 *   FragmentVerdictCache  (src, dst, frag id, next header) -> verdict (D-43)
 *
 * Synchronisation follows D-12 and the existing plugin convention: structural
 * changes happen under the worker barrier, immutable entries carry a
 * generation, and a reclaimed index is only reused after a grace period.
 *
 * Design references:
 *   design/detail/02-headend-dataplane.md §1..§9
 *   design/detail/01-packet-format.md §1, §2, §3.1, §4, §5
 *   design/detail/00-overview.md §2 (D-12, D-17, D-20, D-21, D-26, D-30,
 *     D-31, D-36, D-38, D-41, D-42, D-43, D-47, D-49, D-51), §2.1,
 *     §4.1, §6
 *   design/detail/06-observability.md §2 (drop reasons), §3 (metrics)
 */

#ifndef __included_cilium_srv6_headend_h__
#define __included_cilium_srv6_headend_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/buffer.h>
#include <vnet/ip/ip6_packet.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_8_8.h>
#include <vppinfra/hash.h>
#include <vppinfra/lock.h>
#include <vppinfra/random_buffer.h>

#include <cilium_srv6/cilium_srv6_guard.h>
/* The IF-3 serializer only. It carries no vlib and no vnet dependency of its
   own, so including it here does not widen what a headend consumer pulls in;
   cilium_srv6_hparse.h deliberately stays out (it reaches vnet/srv6), and the
   one place its fragment enum has to agree with the wire is asserted in
   cilium_srv6_classify_node.c, where that value is produced. */
#include <cilium_srv6/cilium_srv6_punt_wire.h>

/* ------------------------------------------------------------------ */
/* capacities and defaults                                             */
/* ------------------------------------------------------------------ */

/*
 * 02 §5.3: "ProgramCache pool 上限 (既定 1M entry)". The pool is reserved at
 * start up and never grown (no hot path allocation), so this default costs
 * roughly 128 MB of pool plus a comparable bihash arena. Deployments that
 * cannot afford it lower `program-capacity` in the `cilium-srv6-headend`
 * startup configuration stanza; correctness does not depend on the size,
 * only the punt rate does.
 */
#define CILIUM_SRV6_PROGRAM_CAPACITY_DEFAULT (1024 * 1024)

/*
 * 02 §5.3: "negative entry の別枠 (既定 pool の 25%)". DENY entries are
 * budgeted separately so that scan traffic cannot evict the ALLOW entries of
 * established flows.
 */
#define CILIUM_SRV6_PROGRAM_NEGATIVE_PERCENT 25

/*
 * Bound on the fair-eviction search, in the same spirit as the tombstone
 * store's CILIUM_SRV6_TOMBSTONE_EVICT_SCAN: bounded work per install.
 */
#define CILIUM_SRV6_PROGRAM_EVICT_SCAN 16

/*
 * PathCache / PathMtuTable capacity. 02 §4.4 says the reconciler precomputes
 * one entry per (RemoteEndpoint x used color) but names no bound, so this is
 * an implementation limit, configurable with `path-capacity`.
 */
#define CILIUM_SRV6_PATH_CAPACITY_DEFAULT 16384

/* 01 §3.1: "fragment cache は最大 64K entry/node、timeout 60 秒". */
#define CILIUM_SRV6_FRAG_CAPACITY_DEFAULT 65536
#define CILIUM_SRV6_FRAG_TIMEOUT_DEFAULT  60.0

/*
 * 01 §2.4 / §5: v1 targets paths that fit one DA container and implements the
 * SRH case functionally. The SRH template is bounded so that a PathCache
 * entry is a fixed-size object the hot path can copy without allocating.
 */
#define CILIUM_SRV6_PATH_MAX_SEGMENTS	  8
#define CILIUM_SRV6_PATH_MAX_SRH_BYTES	  (8 + 16 * CILIUM_SRV6_PATH_MAX_SEGMENTS)
#define CILIUM_SRV6_PATH_MAX_SHIFT_STATES 8

/* 01 §5: node setting `srv6_inner_mtu`, default 1460. */
#define CILIUM_SRV6_INNER_MTU_DEFAULT 1460
/* RFC 8200 minimum link MTU; a path below this is unusable (02 §9). */
#define CILIUM_SRV6_MIN_IPV6_MTU 1280

/*
 * 02 §9: "結果が 1280 未満の inner MTU になる path は unusable として
 * alternative/direct path へ切替え、なければ fail-closed".
 *
 * The dataplane half of that is the fail-closed half: the PMTUD component
 * stores this sentinel in PathMtuTable[path_id].effective_mtu and
 * cilium_srv6_path_effective_mtu() reports an effective MTU of 0, which
 * cilium-srv6-encap turns into a drop with no ICMPv6 PTB — there is no legal
 * MTU below 1280 to advertise to the Pod (01 §7). Switching to an
 * alternative or direct path is a reconciler decision (02 §4.4: the direct
 * path entry always exists), driven by the counter and the CLI/API view of
 * this state; the dataplane never picks a different path by itself.
 *
 * The value is deliberately below CILIUM_SRV6_MIN_IPV6_MTU so that it can
 * never collide with a learned value, every one of which is >= 1280.
 */
#define CILIUM_SRV6_PATH_MTU_UNUSABLE 1

/* 01 §1: outer Hop Limit, configurable. */
#define CILIUM_SRV6_HOP_LIMIT_DEFAULT 64

/*
 * 02 §5.2: "punt queue は有界 (global 4096)", hierarchical owner -> identity
 * quota (D-42) with the owner budget defaulting to global/8 and the identity
 * budget to 256.
 */
#define CILIUM_SRV6_PUNT_CAPACITY_DEFAULT	4096
#define CILIUM_SRV6_PUNT_OWNER_QUOTA_DEFAULT	(CILIUM_SRV6_PUNT_CAPACITY_DEFAULT / 8)
#define CILIUM_SRV6_PUNT_IDENTITY_QUOTA_DEFAULT 256

/*
 * D-38 / D-43 give the reply re-authorisation and the fragment path their own
 * queues so that neither can saturate the compile queue. Their sizes are not
 * specified; they default to a quarter of the compile queue.
 */
#define CILIUM_SRV6_PUNT_REAUTH_CAPACITY_DEFAULT   (CILIUM_SRV6_PUNT_CAPACITY_DEFAULT / 4)
#define CILIUM_SRV6_PUNT_FRAGMENT_CAPACITY_DEFAULT (CILIUM_SRV6_PUNT_CAPACITY_DEFAULT / 4)

/*
 * A punt token is one-shot and also expires, so that an agent that stops
 * redeeming tokens releases the quota it holds instead of wedging the slow
 * path permanently.
 */
#define CILIUM_SRV6_PUNT_TOKEN_TIMEOUT_DEFAULT 5.0

/*
 * 02 §5.4: the ALLOW lease is refreshed per identity by srv6_lease_extend
 * (periodic bulk refresh), and opportunistically by a successful install or
 * conntrack verification, which is what bridges the gap between a commit and
 * the next bulk push. This default is the length used by the opportunistic
 * refresh; the bulk push carries its own length, so the agent's
 * configured lease governs the steady state. Configurable with
 * `allow-lease-ms` so that a deployment which shortens the agent's lease can
 * shorten the bridge with it.
 */
#define CILIUM_SRV6_ALLOW_LEASE_DEFAULT_MS 30000

/* Number of PolicyLeaseTable slots, i.e. of tracked identities (D-30, D-51). */
#define CILIUM_SRV6_POLICY_REV_CAPACITY_DEFAULT 65536

/*
 * Number of EndpointRevTable slots, i.e. of destination addresses this node
 * publishes an ENDPOINT revision for (D-83). One per remote endpoint the
 * reconciler has published, plus the reserved `::` key.
 */
#define CILIUM_SRV6_ENDPOINT_REV_CAPACITY_DEFAULT 65536

/* D-12 grace period and housekeeping interval, mirroring the Context store. */
#define CILIUM_SRV6_HEADEND_GRACE_PERIOD_DEFAULT 2.0
#define CILIUM_SRV6_HEADEND_TICK_INTERVAL	 0.5
#define CILIUM_SRV6_HEADEND_RECLAIM_PER_TICK	 1024
#define CILIUM_SRV6_HEADEND_FRAG_GC_PER_TICK	 4096

/*
 * Sentinel revision. Slot 0 of the policy and endpoint revision tables is the
 * "key has no slot" slot and holds this value, which no published revision can
 * take, so an entry that depends on an unknown key never matches and punts
 * (fail-closed).
 */
#define CILIUM_SRV6_REV_INVALID ((u64) ~0)

/*
 * D-83 value range, shared by the three revision namespaces (ENDPOINT keyed by
 * destination IPv6, PATH keyed by PathCache index, POLICY keyed by
 * SecurityIdentity):
 *
 *   0                        the key does not exist. A publish of 0 withdraws
 *                            the key; no install may quote it; a slot whose
 *                            revision reads 0 never matches a quotation.
 *   1 .. CILIUM_SRV6_REV_INVALID-1
 *                            a real revision. Same value again = idempotent,
 *                            lower = refused, higher = advance.
 *   CILIUM_SRV6_REV_INVALID  reserved sentinel, always refused on publish.
 *
 * 0 is deliberately not "revision zero": the agent's revision counters start
 * at 1, so making 0 mean absence removes the case in which a freshly created
 * slot compares equal to a quotation that was made before it existed.
 *
 * The one place a quoted 0 is legal is `path_revision` of a DENY ProgramCache
 * entry, which has no path dependency at all (02 §4.3: a DENY must not be
 * invalidated by an unrelated route flap).
 */
#define CILIUM_SRV6_REV_ABSENT ((u64) 0)

/*
 * ENDPOINT_ABSENCE_REVISION — the reserved ENDPOINT revision key `::`
 * (D-83, 02 §4.3.1, errata #34 item 153).
 *
 * A destination that is a published endpoint of this node depends on its own
 * ENDPOINT key. A destination that is not has no key of its own and depends on
 * this reserved one, whose revision is the revision of the statement "this
 * destination is not a published endpoint of this node". It advances only on a
 * membership change of the published endpoint key set (a destination appearing
 * in it or disappearing from it), never on a semantic update of a destination
 * that stays in the set.
 *
 *   `::` MUST NOT represent a real endpoint revision key and MUST be accepted
 *   only as the reserved endpoint-absence revision key.
 *
 * Enforcement in this plugin:
 *   - `srv6_program_add_del` refuses `dst == ::`, so `::` can never be the
 *     destination of a ProgramCache entry and therefore never a real key.
 *   - `srv6_endpoint_revision_publish` refuses a withdraw (revision 0) of `::`:
 *     withdrawing it is treating it as a real key, and it would leave every
 *     negative install failing the missing-key check until the agent
 *     republished it.
 *   - a positive (ALLOW) ProgramCache entry whose ENDPOINT key resolves to `::`
 *     is refused and counted in `n_program_absence_key_installs`: an ALLOW
 *     forwards to a destination this node publishes as an endpoint, so it must
 *     depend on that destination's own revision. The converse — a negative
 *     entry quoting a real destination's positive revision — cannot be
 *     expressed, because the ENDPOINT key is resolved here from `dst` and is
 *     never quoted by the agent: an absent destination resolves to `::` and a
 *     published one resolves to its own key, so the exact-match comparison
 *     below refuses the crossed pair.
 *
 * The reserved key is the unspecified address, which is also what
 * `csh_endpoint_rev_resolve` falls back to.
 */
#define CILIUM_SRV6_ENDPOINT_ABSENCE_KEY_UNSPECIFIED 1

/*
 * The PathCache index of a ProgramCache entry that has no path dependency.
 * Same value as the agent's `compiler.NoPathIndex`.
 *
 * 02 §4.3.1: the only two legal {verdict, path} combinations are
 *
 *   DENY   path_cache_index = CILIUM_SRV6_NO_PATH_INDEX, path_revision = 0
 *   ALLOW  path_cache_index = a valid PathCache index,   path_revision > 0
 *
 * and `srv6_program_add_del` refuses the cross product.
 */
#define CILIUM_SRV6_NO_PATH_INDEX ((u32) ~0)

/* ------------------------------------------------------------------ */
/* LocalEndpointTable (02 §2, §3, D-31)                                */
/* ------------------------------------------------------------------ */

/*
 * The logical key is (sw_if_index, if_incarnation) per D-31. The vector index
 * supplies sw_if_index and `if_incarnation` is stored alongside, exactly as
 * the guard trust map does: a lookup only succeeds when the stored
 * incarnation equals the live incarnation of that interface, so an
 * sw_if_index reused by a new interface can never resolve to the previous
 * Pod's identity.
 *
 * 02 §3 assumes one global unicast address per endpoint (v1 is IPv6
 * single stack, Pod-to-Pod only).
 */
typedef struct
{
  u32 if_incarnation;
  u32 identity;	       /* src identity handed to policy evaluation */
  u32 local_context_id;	 /* endpoint incarnation, 02 §7.1 local_context_id */
  u32 owner_quota_class; /* D-42 owner(namespace) quota class */
  u32 policy_rev_slot;	 /* index into policy_rev[] (D-30) */
  ip6_address_t ip;	 /* the endpoint's address (02 §3 anti-spoof) */
  u8 valid;
  u8 pad[3];
} cilium_srv6_local_ep_t;

/* ------------------------------------------------------------------ */
/* PathCache and PathMtuTable (02 §4.4, D-12, D-21)                    */
/* ------------------------------------------------------------------ */

typedef enum
{
  CILIUM_SRV6_PATH_FREE = 0,
  CILIUM_SRV6_PATH_PUBLISHED = 1,
  /* Removed from the index, waiting for the D-12 grace period. */
  CILIUM_SRV6_PATH_RETIRED = 2,
} cilium_srv6_path_state_t;

/*
 * Immutable PathCache entry. Once published nothing in it is written again
 * (D-12); an update installs a new entry with a new generation and retires
 * the old one after the grace period. The mutable PMTU value deliberately
 * lives in a separate table (D-21) and is reached through `mtu_index`, which
 * keeps the reference an index rather than a hash lookup (02 §1).
 */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u32 generation;   /* handle version (D-12) */
  u32 mtu_index;    /* PathMtuTable slot of path_id (D-21) */
  u64 path_id;	    /* Color + locator owner + segment fingerprint */
  ip6_address_t da_template;  /* 01 §2.1 / §2.2 initial DA */
  ip6_address_t service_sid;  /* 01 §2.3 final Service SID */
  u16 base_mtu;		      /* from the path configuration; never rewritten */
  u8 srh_len;		      /* 0 = no SRH */
  u8 state;		      /* cilium_srv6_path_state_t */
  u8 n_shift_states;
  u8 pad[3];

  /* 01 §2.5: the SRH as it goes on the wire, validated at install time. */
  u8 srh_template[CILIUM_SRV6_PATH_MAX_SRH_BYTES];

  /* 02 §4.4: PTB correlation input, consumed by the PMTUD work (#20). */
  ip6_address_t expected_shift_states[CILIUM_SRV6_PATH_MAX_SHIFT_STATES];
} cilium_srv6_path_t;

/*
 * The immutable content of a PathCache entry, i.e. everything a caller
 * specifies and nothing the plugin owns (no index, no generation, no
 * mtu_index, no state). It is the unit the staging transaction of D-61 works
 * in, and comparing two of them is what decides whether a republished path is
 * the same path: an entry whose specification is unchanged keeps its handle,
 * anything else is a different path and gets a different one.
 */
typedef struct
{
  u64 path_id;
  ip6_address_t da_template;
  ip6_address_t service_sid;
  u16 base_mtu;
  u8 srh_len;
  u8 n_shift_states;
  u8 pad[4];
  u8 srh_template[CILIUM_SRV6_PATH_MAX_SRH_BYTES];
  ip6_address_t expected_shift_states[CILIUM_SRV6_PATH_MAX_SHIFT_STATES];
} cilium_srv6_path_spec_t;

/*
 * One entry of an open staging transaction (D-61). It lives outside the
 * PathCache pool's published set: the reserved slot is taken out of the pool
 * so that nothing else can hand it out, but its content is written only at
 * commit, so a worker resolving the handle before the commit finds a slot that
 * is not PUBLISHED and fails the lookup.
 */
typedef struct
{
  u64 client_path_id; /* the caller's identity for this staged entry */
  u64 spec_fp;	      /* fingerprint of spec, for duplicate detection */
  u32 path_index;     /* reserved handle */
  u32 generation;
  /* PathMtuTable slot of spec.path_id (D-21). A new entry takes its reference
     at staging time so that the commit cannot fail on an allocation; a kept
     entry quotes the reference it already holds. */
  u32 mtu_index;
  /* 1 = the handle names an entry that is already published with exactly
     this specification, so the commit keeps it rather than installing it. */
  u8 reused;
  u8 pad[3];
  cilium_srv6_path_spec_t spec;
} cilium_srv6_path_staged_t;

/*
 * Mutable per-path_id MTU state (D-21). Updated with a single atomic store by
 * the PMTUD path and never by a PathCache publish, so the immutability of the
 * PathCache entry holds. `effective_mtu == 0` means nothing has been learned.
 */
typedef struct
{
  u64 path_id;
  f64 learned_at;
  f64 decay_at;
  u32 refcount; /* PathCache entries pointing at this slot */
  u16 effective_mtu;
  u16 pad;
} cilium_srv6_path_mtu_t;

/* ------------------------------------------------------------------ */
/* ProgramCache (02 §4)                                                */
/* ------------------------------------------------------------------ */

typedef enum
{
  CILIUM_SRV6_VERDICT_DENY = 0,
  CILIUM_SRV6_VERDICT_ALLOW = 1,
} cilium_srv6_verdict_t;

/*
 * The forwarding action of an ALLOW ProgramCache entry (D-80, 02 §4.3.1,
 * 00 §2.20).
 *
 * D-80 answers "what happens when the destination is a Pod on this node" with
 * "the same semantic compiler, a different forwarding action". The verdict is
 * still the NetworkPolicy answer and is produced by exactly the evaluation a
 * remote destination gets; only what an ALLOW does with the packet differs.
 * Making it an action rather than a third verdict is what keeps that true: a
 * DENY for a local destination is an ordinary DENY, and every revision and
 * lease rule of 02 §4 applies unchanged to both actions.
 *
 * ENCAP is value 0 so that a zero-initialised or older-agent install is the
 * remote action, which cannot deliver to a local interface by accident.
 *
 * LOCAL_DELIVER carries the exact `(target_sw_if_index, target_if_incarnation)`
 * of the destination endpoint plus the identity the policy decision was taken
 * against. It never encapsulates, never builds an SRH and never loops the
 * packet back through a local SID: 00 §2.20 rules self-encapsulation out.
 */
typedef enum
{
  CILIUM_SRV6_ACTION_ENCAP = 0,
  CILIUM_SRV6_ACTION_LOCAL_DELIVER = 1,
} cilium_srv6_program_action_t;

/*
 * 02 §4.1 value. Two cache lines: the first holds everything 02 §4.2 reads
 * per packet, the second the statistics and the eviction bookkeeping.
 *
 * D-51: there is no `allow_lease_until` here. The lease lives in the
 * PolicyLeaseTable, keyed by the entry's dependency identity
 * (`src_identity`), and the entry only carries the dependency pair
 * (`src_identity`, `policy_revision`) the hot path checks it against. That is
 * what makes srv6_lease_extend O(identities) instead of a walk of this pool.
 */
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  u32 src_identity;	/* key component, also the quota subject */
  u32 policy_rev_slot;	/* POLICY key slot of src_identity (D-30) */
  u32 path_cache_index; /* versioned handle (D-12) */
  u32 path_generation;
  u64 policy_revision;
  u64 endpoint_revision;
  u64 path_revision;
  u8 verdict; /* cilium_srv6_verdict_t */
  u8 in_use;
  u8 action; /* cilium_srv6_program_action_t (D-80) */
  u8 pad0;
  u32 owner_quota_class; /* D-42 */
  /* D-83: ENDPOINT key slot this entry's `dst` resolved to at install time,
     or the slot of the reserved `::` key when `dst` was not a published
     endpoint. Resolving the key once here is what keeps the hot path free of
     a second hash lookup: 02 §4.2 still performs exactly one bihash lookup
     per packet (the ProgramCache one), and the revision comparison is three
     indexed loads. */
  u32 endpoint_rev_slot;
  /* D-80: the LOCAL_DELIVER target. It is an interface *lifetime*
     (D-31/D-68), never a bare index: an sw_if_index is reused the moment the
     interface is deleted, so an entry holding only the index would deliver a
     Pod's traffic into whatever Pod inherited the number. All three are 0 for
     CILIUM_SRV6_ACTION_ENCAP, and srv6_program_add_del refuses an ENCAP entry
     that carries any of them. */
  u32 target_sw_if_index;
  u32 target_if_incarnation;
  /* The Security Identity the destination endpoint had when the policy
     decision was taken (D-69). The delivery node compares it against the live
     LocalEndpointTable entry, so an identity change closes the program on the
     very next packet rather than waiting for the ENDPOINT revision publish to
     land. */
  u32 target_identity;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  u64 packets;
  u64 bytes;
  f64 last_used; /* eviction input (02 §5.3) */
  u64 key[3];	 /* the bihash key, so eviction can delete without rebuilding */
  u32 age_prev;
  u32 age_next;
} cilium_srv6_program_t;

/* 02 §4.1 keeps everything the hot path reads per packet in the first cache
   line and the statistics in the second. The D-80 target fields were placed in
   the padding the first line already had, so the entry did not grow; asserting
   it here makes a future field that would have spilled a build failure rather
   than a silent second cache miss per packet. */
STATIC_ASSERT (sizeof (cilium_srv6_program_t) <= 2 * CLIB_CACHE_LINE_BYTES,
	       "a ProgramCache entry must fit in two cache lines (02 §4.1)");

/* ------------------------------------------------------------------ */
/* FragmentVerdictCache (01 §3.1, D-20, D-43)                          */
/* ------------------------------------------------------------------ */

/*
 * D-20: the fragment path is bound to exactly the same things the
 * ProgramCache entry is bound to, so a policy revoke or an IP reuse cannot be
 * survived by re-using a cached fragment verdict. D-51 included: the lease is
 * read from the PolicyLeaseTable slot of `src_identity`, not stored here.
 *
 * `punt_id` and `reinject_pending` are the one-shot reinjection capability of
 * Issue #90 (decision of 2026-09-01, "punt operation に束縛された one-shot
 * reinjection capability"). D-43 drops every first fragment whose key is
 * already recorded, which would also drop the punted first fragment when the
 * agent hands it back — the record it is about to be forwarded under is its
 * own. The capability is what lets exactly that one packet through:
 *
 *   punt_id           the punt operation this record answers, issued by the
 *                     dataplane at punt time (cilium_srv6_punt_id_next) and
 *                     echoed by the agent in srv6_fragment_verdict_add and in
 *                     the reinject. 0 means "no punt is associated with this
 *                     record", which is what the dataplane writer
 *                     (cilium_srv6_frag_record) installs: a ProgramCache hit
 *                     forwarded the first fragment itself, so no reinject is
 *                     coming and none may be accepted.
 *   reinject_pending  1 while the capability is unspent. It is spent by one
 *                     authenticated reinject carrying the same punt_id, and
 *                     by nothing else — in particular a first fragment
 *                     received from the network never spends it, which is
 *                     what stops an attacker from consuming the capability of
 *                     a datagram it did not send and having the legitimate
 *                     reinject dropped instead.
 *
 * The capability has no lifetime of its own: it expires with the record
 * (`expires_at`), because a punt whose record is gone has nothing left to be
 * a continuation of.
 *
 * The capability is local to the fragment class. Only a fragment-class punt
 * installs a record here, so only a fragment-class reinjection is judged
 * against one; a reinjection of another authenticated punt class (D-38
 * conntrack re-authorisation) follows its own continuation semantics and
 * requires no capability. The classifier decides which of the two a packet is
 * from the queue recorded in the token it redeemed, never from the agent.
 * See the continuation-class comment at the head of
 * cilium_srv6_classify_node.c.
 */
typedef struct
{
  u32 src_identity;
  u32 local_context_id;
  u32 policy_rev_slot;
  u32 owner_quota_class;
  /* D-83: as cilium_srv6_program_t.endpoint_rev_slot. D-20 requires the
     fragment path to be bound to exactly what the ProgramCache entry is bound
     to, so it resolves the same key. */
  u32 endpoint_rev_slot;
  u32 pad0;
  u64 policy_revision;
  u64 endpoint_revision;
  u64 path_revision;
  f64 expires_at;
  /* Issue #90: the punt operation this record answers, 0 when there is none. */
  u64 punt_id;
  u32 path_cache_index;
  u32 path_generation;
  ip6_address_t src;
  ip6_address_t dst;
  u32 frag_id; /* network order */
  u8 next_header;
  u8 verdict;
  u8 in_use;
  /* Issue #90: 1 while the one-shot reinjection capability is unspent. */
  u8 reinject_pending;
  u32 age_prev;
  u32 age_next;
} cilium_srv6_frag_entry_t;

/* ------------------------------------------------------------------ */
/* PolicyLeaseTable (00 §2.1, D-30 + D-51)                             */
/* ------------------------------------------------------------------ */

/*
 * One slot per identity. This single structure is the PolicyLeaseTable of
 * D-51: it holds both halves of "policy decision validity" for one identity,
 * so the hot path resolves them with one indexed read rather than two lookups
 * (00 §2.1, 02 §4.2).
 *
 *   policy_revision   the currently published revision of this identity,
 *                     i.e. policy *semantic freshness* (D-30). A stored
 *                     decision is fresh while its revision equals this.
 *   lease_revision    the revision the current lease was granted for. A lease
 *                     granted for revision R must not keep a decision made
 *                     under a different revision alive, so the lease is bound
 *                     to the revision rather than being a bare deadline.
 *   lease_valid_until the deadline of that lease, i.e. policy *watcher
 *                     liveness* (D-49). When the agent's watcher is
 *                     disconnected it stops pushing and stops installing, so
 *                     every decision that depends on this identity — forward
 *                     (ProgramCache, FragmentVerdictCache) and reply
 *                     (conntrack) alike — fails closed once this passes.
 *
 * Writers: the four policy_lease_touch paths of 02 §5.4 —
 * srv6_lease_extend (periodic bulk refresh, per identity),
 * srv6_program_add_del(ALLOW), a successful srv6_ct_verify and
 * srv6_fragment_verdict_add(ALLOW) (refresh of the exact revision they
 * committed under). Neither DENY form is a writer: a DENY is fail-safe and
 * consults no lease.
 */
typedef struct
{
  u32 identity;
  u32 refcount;
  u64 policy_revision;
  u64 lease_revision;
  f64 lease_valid_until;
} cilium_srv6_policy_rev_t;

/* ------------------------------------------------------------------ */
/* EndpointRevTable (02 §4.3, D-17 + D-83)                             */
/* ------------------------------------------------------------------ */

/*
 * One slot per ENDPOINT revision key, i.e. per destination address this node
 * publishes a revision for. D-83 forbids a node-global endpoint revision: a
 * single value made every endpoint change stale every ProgramCache entry on
 * the node, which is a cluster-scale fail-closed trigger available to any
 * tenant that can make an endpoint churn — the same attack surface D-30
 * removed from the policy revision.
 *
 *   dst        the key. The unspecified address `::` is the reserved
 *              "this destination is not a published endpoint" key that
 *              negative entries depend on (see the .api comment on
 *              srv6_endpoint_revision).
 *   revision   the currently published revision, or CILIUM_SRV6_REV_ABSENT
 *              after a withdraw. Slot 0 holds CILIUM_SRV6_REV_INVALID and is
 *              the "no slot" sentinel, so a resolution that fails never
 *              matches a quotation.
 *   hwm        the highest revision ever published for this key. A withdraw
 *              does not lose it, so a republish cannot move the key backwards
 *              and make an entry that quotes the old revision valid again.
 *              The slot — and with it the high water mark — is only released
 *              once nothing references it, and a stale quotation of the key
 *              is exactly what holds a reference, so the mark cannot be lost
 *              while it still protects something.
 *   refcount   one reference per ProgramCache / FragmentVerdictCache entry
 *              resolved to this slot, plus one held by the publication itself
 *              while the key is present.
 */
typedef struct
{
  ip6_address_t dst;
  u32 refcount;
  u8 present; /* 0 after a withdraw whose slot is still referenced */
  u8 pad[3];
  u64 revision;
  u64 hwm;
} cilium_srv6_endpoint_rev_t;

/* ------------------------------------------------------------------ */
/* punt / slow path (02 §5, IF-3)                                      */
/* ------------------------------------------------------------------ */

typedef enum
{
  /* ProgramCache miss / stale / lease expired: the compile queue. */
  CILIUM_SRV6_PUNT_Q_COMPILE = 0,
  /* D-38: reply re-authorisation has its own queue so that a flood of
     5-tuples cannot saturate the compile path. */
  CILIUM_SRV6_PUNT_Q_REAUTH = 1,
  /* D-43 / 01 §3.1: fragment-derived punts use a dedicated queue. */
  CILIUM_SRV6_PUNT_Q_FRAGMENT = 2,
  CILIUM_SRV6_PUNT_N_Q,
} cilium_srv6_punt_queue_t;

typedef enum
{
  CILIUM_SRV6_PUNT_REASON_MISS = 0,
  CILIUM_SRV6_PUNT_REASON_STALE_REVISION,
  CILIUM_SRV6_PUNT_REASON_LEASE_EXPIRED,
  CILIUM_SRV6_PUNT_REASON_STALE_PATH,
  CILIUM_SRV6_PUNT_REASON_REPLY_REAUTH,
  CILIUM_SRV6_PUNT_N_REASON,
} cilium_srv6_punt_reason_t;

/*
 * Both enums above are wire values (`02` §5.6.4). The IF-3 serializer copies
 * cilium_srv6_punt_reason_t straight into the `cause` byte, so the two lists
 * must not drift apart; likewise for the fragment classification of the
 * bounded parser (`02` §5.6.5). Asserting it here makes a renumbering a build
 * failure rather than a wrong byte on the wire.
 */
STATIC_ASSERT ((int) CILIUM_SRV6_PUNT_REASON_MISS == CILIUM_SRV6_IF3_CAUSE_MISS &&
		 (int) CILIUM_SRV6_PUNT_REASON_STALE_REVISION ==
		   CILIUM_SRV6_IF3_CAUSE_STALE_REVISION &&
		 (int) CILIUM_SRV6_PUNT_REASON_LEASE_EXPIRED ==
		   CILIUM_SRV6_IF3_CAUSE_LEASE_EXPIRED &&
		 (int) CILIUM_SRV6_PUNT_REASON_STALE_PATH == CILIUM_SRV6_IF3_CAUSE_STALE_PATH &&
		 (int) CILIUM_SRV6_PUNT_REASON_REPLY_REAUTH == CILIUM_SRV6_IF3_CAUSE_REPLY_REAUTH &&
		 (int) CILIUM_SRV6_PUNT_N_REASON == CILIUM_SRV6_IF3_N_CAUSE,
	       "the punt reason enum no longer matches the 02 §5.6.4 cause enum");

/*
 * The punt queue *is* the wire opcode (`02` §5.6.1): there is no separate
 * `queue` field, which is what makes it impossible for the queue and the
 * reason to disagree on the wire. The serializer therefore writes
 * `OP_PUNT_COMPILE + queue`, and that arithmetic is only correct while the
 * two lists stay parallel.
 */
STATIC_ASSERT ((int) CILIUM_SRV6_PUNT_Q_COMPILE + CILIUM_SRV6_IF3_OP_PUNT_COMPILE ==
		   CILIUM_SRV6_IF3_OP_PUNT_COMPILE &&
		 (int) CILIUM_SRV6_PUNT_Q_REAUTH + CILIUM_SRV6_IF3_OP_PUNT_COMPILE ==
		   CILIUM_SRV6_IF3_OP_PUNT_REAUTH &&
		 (int) CILIUM_SRV6_PUNT_Q_FRAGMENT + CILIUM_SRV6_IF3_OP_PUNT_COMPILE ==
		   CILIUM_SRV6_IF3_OP_PUNT_FRAGMENT,
	       "the punt queues no longer map onto the 02 §5.6.2 punt opcodes");

/*
 * The bounded parser's fragment classification (cilium_srv6_frag_kind_t) is
 * also a wire enum (`02` §5.6.5). The equivalence is asserted in
 * cilium_srv6_classify_node.c, which is the file that produces the value and
 * the one that includes the parser header.
 */

/*
 * The punt handoff type — **plugin internal, not a wire format** (D-76,
 * `00` §2.18.1).
 *
 * This structure used to describe itself as "the IF-3 metadata layout", and
 * the agent's decoder described a different one. Connecting the two would
 * have failed on the first punt (errata #34 item 152): 72 host-endian bytes
 * against 92 big-endian ones, a 64-bit token against a 16-byte capability, a
 * `length` that meant the header against one that means the frame. D-76
 * settles the authority: the wire is `02` §5.6 and
 * pkg/srv6ec/compiler/wire.go, and this type is the value the headend graph
 * hands to the transport, which serialises it.
 *
 * Two consequences are load-bearing.
 *
 *   - `sizeof (cilium_srv6_punt_meta_t)` is nobody's business but this
 *     plugin's. It may change with a field added for a plugin-internal
 *     consumer and no IF-3 peer notices, because no byte of it is written to
 *     the socket as-is: cilium_srv6_if3_punt_encode() writes explicit widths
 *     to explicit offsets.
 *   - every value in `w` comes from the classify stage (`02` §3) or from the
 *     token the punt was admitted with. The transport MUST NOT re-parse the
 *     packet to derive one (`00` §2.18.2): a second parser that disagrees
 *     with the bounded parser of `01` §3.1 installs entries under a key the
 *     hot path does not look up, which is a permanent punt — the same failure
 *     `02` §5.1 forbids on the agent side, reproduced inside the plugin.
 *
 * The fields `02` §5.6.8 keeps off the wire — `local_context_id`,
 * `owner_quota_class`, the queue, `tcp_flags` — live outside `w`. They stay
 * here because plugin-internal consumers use them (the quota accounting, and
 * a future IF-3 extension for `local_context_id` if a consumer ever appears);
 * being in this structure is precisely not a claim that they travel.
 */
typedef struct
{
  /* Exactly the values `02` §5.6.2 puts on the wire, in host order. */
  cilium_srv6_if3_punt_t w;

  /* ---- plugin internal, never serialised (02 §5.6.8) ---- */

  /* D-42 owner class. The agent resolves the D-42 owner itself (D-74), so the
     dataplane has no authority to state one on the wire (00 §2.16). */
  u32 owner_quota_class;
  /* The endpoint incarnation identifier of the receiving Pod. No agent
     consumer exists, so it does not travel; a future consumer extends the
     protocol rather than reading a spare field. */
  u32 local_context_id;
  /* cilium_srv6_punt_queue_t. It is on the wire *as the opcode* (02 §5.6.1),
     never as a field of its own, so that the queue and the reason cannot
     disagree. Kept here because the quota accounting is per queue. */
  u8 queue;
  /* Length of the packet that follows the header in the frame. */
  u32 packet_length;
} cilium_srv6_punt_meta_t;

/*
 * The IF-3 punt transport.
 *
 * The hook is called from a worker thread with the buffer still owned by
 * cilium-srv6-punt: it must copy what it needs and return before the node
 * frees the buffer. `00` §2.18.7 forbids it from doing socket I/O — a worker
 * only serialises and enqueues; a single transport owner connects, writes,
 * reads and reconnects.
 *
 * The three results are distinguished so that the queue counters keep their
 * meaning (02 §5.2, 06 §3):
 *
 *   SENT          the frame is in the bounded queue and the token is live.
 *   NO_TRANSPORT  no transport is registered, or it is not connected. This is
 *                 the same disposition as before a transport existed:
 *                 fail-closed drop, counted in punt_no_transport.
 *   QUEUE_FULL    the queue hit its entry cap or its byte cap. Also a
 *                 fail-closed drop, counted separately so that "the agent is
 *                 gone" and "the agent is too slow" are not one number.
 *
 * In every non-SENT case the caller releases the token and drops the packet;
 * the packet is never forwarded around the miss (02 §5.2).
 */
typedef enum
{
  CILIUM_SRV6_PUNT_TX_NO_TRANSPORT = 0,
  CILIUM_SRV6_PUNT_TX_SENT = 1,
  CILIUM_SRV6_PUNT_TX_QUEUE_FULL = 2,
} cilium_srv6_punt_tx_result_t;

typedef cilium_srv6_punt_tx_result_t (*cilium_srv6_punt_tx_fn) (
  vlib_main_t *vm, vlib_buffer_t *b, const cilium_srv6_punt_meta_t *meta);

void cilium_srv6_punt_tx_register (cilium_srv6_punt_tx_fn fn);

/* Whether an IF-3 transport is registered. While it is not, every punt fails
 * closed and is counted in punt_no_transport. */
int cilium_srv6_punt_transport_registered (void);

/*
 * Reinject of 02 §5.1 step 8. The 16-byte token is validated first: it must
 * exist, be unredeemed, be unexpired, and the interface it was issued on must
 * still be the same interface (same incarnation). The packet re-enters at
 * cilium-srv6-classify so that identity, source address and discriminator are
 * recomputed from the bytes rather than taken from agent-supplied metadata,
 * and so that the hot path revision checks run again.
 *
 * `punt_id` is the value the punt carried (Issue #90). It is not a second
 * authorisation — the token is — but the reinjected packet is marked with it
 * so that cilium-srv6-classify can tell the continuation of *this* punt from
 * the continuation of some other one, which is what the FragmentVerdictCache
 * capability is bound to. The dataplane checks it against the value it
 * recorded for the token, so an agent that echoes the wrong one is refused
 * here rather than being allowed to spend another datagram's capability.
 *
 * Must be called from the main thread: it enqueues a frame to
 * cilium-srv6-classify, which requires the worker barrier.
 *
 * Returns 0 on success, a VNET_API_ERROR_* value otherwise.
 */
int cilium_srv6_punt_reinject (const u8 *token, u64 punt_id, const u8 *data, u32 len);

/*
 * Release of 02 §5.6.3 / `00` §2.18.6, the DENY half of the protocol.
 *
 * It is a plugin-internal entry point on purpose: D-76 states that `opRelease`
 * is part of IF-3 but needs no VPP binary API, because its only caller is this
 * plugin's own IF-3 transport, which already authenticated the peer through
 * the D-27 socket. Exposing it as a binary API would widen the set of clients
 * that can free another client's punt slot for no gain.
 *
 * Without it the token of a DENYed punt — and with it the D-42 quota slot it
 * holds — stays reserved until the punt token timeout, so a burst of DENY
 * starves the slow path of a tenant that is behaving correctly.
 *
 * `drop_reason` is a CILIUM_SRV6_IF3_DROP_* value in 1..5; it is counted
 * against the `06` §2 reason it names. An unknown or already consumed token
 * changes no dataplane state: it is counted and refused (`00` §2.18.6).
 *
 * Must be called from the main thread. Returns 0 on success.
 */
int cilium_srv6_punt_release (const u8 *token, u8 drop_reason);

/*
 * Issue #90: draw the next punt operation identity. Never returns 0, which is
 * the "no punt" value a FragmentVerdictCache record written by the dataplane
 * carries.
 *
 * The value is {boot nonce, monotonic counter}: the low bits come from a
 * per-process counter and the high bits from a nonce drawn once at init, so
 * that identities issued before a restart cannot collide with identities
 * issued after one. It is deliberately not derived from packet content —
 * see the note on cilium_srv6_punt_meta_t.w.punt_id.
 */
u64 cilium_srv6_punt_id_next (void);

/* ------------------------------------------------------------------ */
/* conntrack hooks (C10, 02 §7)                                        */
/* ------------------------------------------------------------------ */

typedef enum
{
  /* No entry, or a forward-direction packet: continue to
     cilium-srv6-program (02 §7.2 branch 3). */
  CILIUM_SRV6_CT_MISS = 0,
  /* 02 §7.2 branch 1: reply hit satisfying every allow condition. The hook
     must fill in a usable path handle; see the note on the reply path in
     cilium_srv6_ct_node.c. */
  CILIUM_SRV6_CT_REPLY_ALLOW,
  /* 02 §7.2 branch 2: reply hit that is UNVERIFIED, revision-mismatched or
     past its lease -> re-authorisation punt. */
  CILIUM_SRV6_CT_REPLY_REAUTH,
} cilium_srv6_ct_lookup_verdict_t;

/*
 * Everything the conntrack stage is allowed to compare against (02 §7.2):
 * the live local endpoint identity/context, the currently published policy
 * revision of the packet's identity, and the current time for the D-49 lease
 * check.
 *
 * D-83 removed the endpoint and path revisions from this structure. They were
 * the two node-global values, and there are no node-global values any more:
 * an ENDPOINT revision is keyed by destination and a PATH revision by
 * PathCache index, neither of which the conntrack stage resolves. Nothing
 * read them — 02 §7.2 compares the entry's stored `verified_revision` against
 * the policy revision of the *remote* identity and nothing else — so keeping
 * a field that could only be filled with an invented value would be the
 * cluster-global state D-45 forbids on this path.
 */
typedef struct
{
  u32 src_identity;
  u32 local_context_id;
  u32 owner_quota_class;
  u64 policy_revision;
  f64 now;
} cilium_srv6_ct_query_t;

typedef struct
{
  u32 path_cache_index;
  u32 path_generation;
} cilium_srv6_ct_result_t;

typedef cilium_srv6_ct_lookup_verdict_t (*cilium_srv6_ct_lookup_fn) (
  vlib_main_t *vm, u32 thread_index, vlib_buffer_t *b, const cilium_srv6_ct_query_t *q,
  cilium_srv6_ct_result_t *res);

/* 02 §6 step 1: create/refresh the egress flow entry. */
typedef void (*cilium_srv6_ct_egress_fn) (vlib_main_t *vm, u32 thread_index, vlib_buffer_t *b,
					  const cilium_srv6_ct_query_t *q);

extern cilium_srv6_ct_lookup_fn cilium_srv6_ct_lookup_hook;
extern cilium_srv6_ct_egress_fn cilium_srv6_ct_egress_hook;

void cilium_srv6_ct_lookup_register (cilium_srv6_ct_lookup_fn fn);
void cilium_srv6_ct_egress_register (cilium_srv6_ct_egress_fn fn);

/* ------------------------------------------------------------------ */
/* ICMPv6 PTB hook (02 §9, implemented by the PMTUD work)              */
/* ------------------------------------------------------------------ */

/*
 * 02 §9: "encap 前に inner length > 有効値なら ICMPv6 PTB を source Pod へ
 * 返し、packet を drop する". The drop and its counter live here; generating
 * the PTB is part of the PMTUD component and plugs in through this hook.
 */
typedef void (*cilium_srv6_ptb_send_fn) (vlib_main_t *vm, vlib_buffer_t *b, u16 effective_mtu);

extern cilium_srv6_ptb_send_fn cilium_srv6_ptb_send_hook;

void cilium_srv6_ptb_send_register (cilium_srv6_ptb_send_fn fn);

/* ------------------------------------------------------------------ */
/* buffer metadata                                                     */
/* ------------------------------------------------------------------ */

typedef enum
{
  CILIUM_SRV6_META_F_FRAG_FIRST = 1 << 0,
  CILIUM_SRV6_META_F_FRAG_NON_FIRST = 1 << 1,
  /* the fragment path already resolved a verdict, so cilium-srv6-ct and
     cilium-srv6-program are bypassed (01 §3.1) */
  CILIUM_SRV6_META_F_FRAG_RESOLVED = 1 << 2,
  /* cilium-srv6-ct took the reply bypass, so no ProgramCache entry backs
     this packet (D-47) */
  CILIUM_SRV6_META_F_CT_REPLY = 1 << 3,
  /*
   * The bounded parse found a Fragment header with offset 0 and M=0
   * (CILIUM_SRV6_FRAG_ATOMIC). Every later *forwarding* stage treats such a
   * packet as an ordinary one (`01` §3.1), which is why it has no bit of its
   * own in the two above.
   *
   * It has one here because the IF-3 punt frame reports `frag_kind` and the
   * validity of `fragment_id` / `frag_next_header` follows from it
   * (`02` §5.6.5, D-76 §2.18.5). Without this bit the transport would have to
   * choose between reporting NONE — producing a frame whose non-zero
   * `fragment_id` contradicts its own `frag_kind`, which the agent drops as a
   * field violation, so every punt of an atomically fragmented flow is lost —
   * and guessing from `frag_id != 0`, which is wrong for the legitimate
   * Identification 0. D-76 §2.18.2 is explicit that the value the classifier
   * found is what travels, so the classifier records it.
   */
  CILIUM_SRV6_META_F_FRAG_ATOMIC = 1 << 4,
} cilium_srv6_meta_flags_t;

/*
 * The `02` §5.6.5 fragment classification the classify stage recorded, back
 * out of the flag bits. It is the value the bounded parser produced
 * (cilium_srv6_frag_kind_t), which is also the wire value.
 */
static_always_inline u8
cilium_srv6_meta_frag_kind (u8 flags)
{
  if (flags & CILIUM_SRV6_META_F_FRAG_NON_FIRST)
    return CILIUM_SRV6_IF3_FRAG_NON_FIRST;
  if (flags & CILIUM_SRV6_META_F_FRAG_FIRST)
    return CILIUM_SRV6_IF3_FRAG_FIRST;
  if (flags & CILIUM_SRV6_META_F_FRAG_ATOMIC)
    return CILIUM_SRV6_IF3_FRAG_ATOMIC;
  return CILIUM_SRV6_IF3_FRAG_NONE;
}

/*
 * Classification result, written once by cilium-srv6-classify and read by
 * every later stage. It lives in the vnet opaque scratch area, which is
 * exactly 24 bytes, hence the tight layout: values that can be re-derived
 * from the packet are not carried, and values that must not change under the
 * packet (identity, incarnation-checked context, quota class) are.
 */
typedef struct
{
  u32 src_identity;
  u32 policy_rev_slot;
  u32 local_context_id;
  u32 owner_quota_class;
  u32 frag_id; /* network order, 0 when not fragmented */
  u16 l4_discriminator;
  u8 proto;
  u8 flags; /* cilium_srv6_meta_flags_t */
} cilium_srv6_headend_meta_t;

STATIC_ASSERT (sizeof (cilium_srv6_headend_meta_t) <= VNET_BUFFER_OPAQUE_SIZE,
	       "headend metadata does not fit the vnet opaque scratch area");

static_always_inline cilium_srv6_headend_meta_t *
cilium_srv6_headend_meta (vlib_buffer_t *b)
{
  return (cilium_srv6_headend_meta_t *) vnet_buffer_get_opaque (b);
}

/*
 * Resolved forwarding decision plus the flow entropy inputs that cannot be
 * re-derived cheaply. Written by whichever of cilium-srv6-classify (fragment
 * bypass), cilium-srv6-ct (reply bypass) or cilium-srv6-program produced it,
 * and read by cilium-srv6-encap. Kept in the second opaque scratch area
 * because the first one is full.
 */
typedef struct
{
  u32 path_cache_index;
  u32 path_generation;
  u32 program_index; /* ProgramCache entry to charge, ~0 if bypassed */
  u16 sport;	     /* 01 §4 flow entropy input, from the bounded parse */
  u16 dport;
  u8 punt_reason; /* cilium_srv6_punt_reason_t, set by whoever punts */
  u8 punt_queue;  /* cilium_srv6_punt_queue_t (D-38, D-43) */
  /* Fragment header Next Header: the FragmentVerdictCache key component and
     the fragment flow entropy input (01 §3.1, §4). See the note on
     cilium_srv6_hparse_t.frag_next_header for why this is not `proto`. */
  u8 frag_next_header;
  /* TCP control bits from the bounded parse, the input of the conntrack
     state machine of 02 §7.2 (C10). 0 for every other protocol. */
  u8 tcp_flags;
} cilium_srv6_path_meta_t;

STATIC_ASSERT (sizeof (cilium_srv6_path_meta_t) <=
		 sizeof (((vnet_buffer_opaque2_t *) 0)->unused),
	       "headend path metadata does not fit the vnet opaque2 scratch area");

static_always_inline cilium_srv6_path_meta_t *
cilium_srv6_path_meta (vlib_buffer_t *b)
{
  return (cilium_srv6_path_meta_t *) vnet_buffer2 (b)->unused;
}

/*
 * Issue #90: "this buffer is a reinject, not a packet received on a wire".
 *
 * It is a vlib buffer flag rather than a field of the metadata above for one
 * reason: it has to be unforgeable from outside. A packet received on an
 * interface reaches cilium-srv6-classify through the feature arc with the
 * scratch areas holding whatever the previous user of the buffer left there,
 * so no *value* in them can distinguish a reinject from a wire packet. The
 * AVAIL flags, on the other hand, are cleared by the buffer allocator on every
 * allocation and are set by nothing on the receive path, so the only way this
 * bit is set on a buffer entering classify is that cilium_srv6_punt_reinject()
 * set it — and that function is reachable only from the IF-3 socket, which
 * D-27 restricts to the agent by peer credential.
 *
 * classify consumes the bit (it clears it) so that it cannot survive into a
 * later stage or a later use of the same buffer.
 */
#define CILIUM_SRV6_BUFFER_F_REINJECT VNET_BUFFER_F_AVAIL1

/*
 * The metadata a reinject carries into cilium-srv6-classify. It occupies the
 * same scratch area as cilium_srv6_path_meta_t and is read exactly once, at
 * the top of the classify stage, immediately before that stage initialises the
 * path metadata over it. The two therefore never coexist: the reinject
 * metadata is an input to classification, the path metadata is its output.
 *
 * Nothing here is trusted as classification input. The packet is re-parsed and
 * re-classified from its bytes exactly as before (02 §5.1 step 8, 00 §4.1);
 * `punt_id` only says which punt operation this packet is the continuation of,
 * and the value was produced by the dataplane, not by the agent.
 */
typedef struct
{
  u64 punt_id;
  /*
   * The queue the punt was admitted on (cilium_srv6_punt_queue_t), recovered
   * from the redeemed token rather than sent by the agent.
   *
   * It is here because only a fragment-class punt produces a
   * FragmentVerdictCache record for a reinjection to be measured against. A
   * first fragment can also be punted by cilium-srv6-ct on the D-38
   * re-authorisation queue, and that punt installs no record at all, so
   * applying the "no record, therefore stale" rule to it would drop a
   * reinjection that has nothing to do with the fragment path.
   */
  u8 punt_queue;
} cilium_srv6_reinject_meta_t;

STATIC_ASSERT (sizeof (cilium_srv6_reinject_meta_t) <=
		 sizeof (((vnet_buffer_opaque2_t *) 0)->unused),
	       "reinject metadata does not fit the vnet opaque2 scratch area");

static_always_inline cilium_srv6_reinject_meta_t *
cilium_srv6_reinject_meta (vlib_buffer_t *b)
{
  return (cilium_srv6_reinject_meta_t *) vnet_buffer2 (b)->unused;
}

/* ------------------------------------------------------------------ */
/* headend main                                                        */
/* ------------------------------------------------------------------ */

typedef struct
{
  u32 capacity;
  u32 owner_quota;
  u32 identity_quota;
  u32 n_outstanding;
  /* Bumped after the transport accepted the frame, i.e. outside punt_lock and
     from any worker, so it is an atomic. It used to be a plain increment,
     which lost counts under concurrent punts — the one counter of this
     structure that was not protected by the lock (errata #34 item 152). */
  u64 n_punted;
  u64 n_drop_global;
  u64 n_drop_owner;
  u64 n_drop_identity;
  u64 n_drop_no_token;
  u64 n_drop_no_transport;
  /* The transport's bounded queue was full: the entry cap (4096, 02 §5.2) or
     the byte cap (00 §2.18.7) was reached. Counted apart from
     n_drop_no_transport because "no agent" and "the agent is not keeping up"
     call for different operator action. */
  u64 n_drop_ring_full;
  /* A frame that was being written when the connection failed. It is not
     resent (00 §2.18.8): with no ACK protocol a resend risks a double
     reinject, which is worse than a drop. */
  u64 n_drop_write_failed;
  u64 n_expired;
  u64 n_reinjected;
  u64 n_reinject_rejected;
  /* Tokens released without a reinject: the agent's opRelease (02 §5.6.3),
     and the local release of a frame whose write was interrupted
     (00 §2.18.8, which also counts n_drop_write_failed above). */
  u64 n_released;
} cilium_srv6_punt_queue_state_t;

typedef struct
{
  /*
   * The 16-byte opaque capability that travels on IF-3 (D-76 §2.18.4). It is
   * drawn from the plugin's CSPRNG and encodes nothing: the pool slot is
   * recovered through hm->punt_token_index, not by taking the token apart.
   *
   * The predecessor packed {slot index, nonce} into a u64, which made
   * guessing a slot the same as guessing most of a token. Unpredictability is
   * defence in depth here — the D-27 socket authenticates the peer — but
   * there is no reason to keep the weaker construction.
   */
  u8 token[CILIUM_SRV6_IF3_TOKEN_LEN];
  u8 in_use;
  u8 queue;
  u16 pad;
  u32 owner_quota_class;
  u32 src_identity;
  u32 rx_sw_if_index;
  u32 rx_if_incarnation;
  f64 expires_at;
  /* Issue #90: the punt operation identity handed to the agent with this
     token. Kept here so that a reinject's echoed punt_id is checked against
     what the dataplane issued, rather than being taken on trust. */
  u64 punt_id;
} cilium_srv6_punt_token_t;

/* ------------------------------------------------------------------ */
/* IF-3 transport (02 §5.6.9)                                          */
/* ------------------------------------------------------------------ */

/*
 * Reconnect backoff (02 §5.6.9): 200 ms after the first failure, doubling to
 * 5 s. The agent restarting is a routine event, so the first retry is quick;
 * an agent that is not coming back must not turn into a connect() storm.
 */
#define CILIUM_SRV6_IF3_BACKOFF_MIN 0.2
#define CILIUM_SRV6_IF3_BACKOFF_MAX 5.0

/*
 * Entry cap of the punt queue (00 §2.18.7): the 4096 of `02` §5.2. The second
 * bound, the byte budget, is configurable and lives with the rest of the
 * startup configuration (cilium_srv6_guard.h,
 * CILIUM_SRV6_IF3_QUEUE_BYTES_DEFAULT).
 */
#define CILIUM_SRV6_IF3_QUEUE_ENTRIES CILIUM_SRV6_PUNT_CAPACITY_DEFAULT

/* Read-out of the transport's state for `show cilium srv6 headend` and for
   srv6_headend_status_get. Filled on the main thread. */
typedef struct
{
  u8 configured; /* a punt socket path is set */
  u8 connected;
  u64 n_connects;	  /* successful connects, i.e. 1 + reconnects */
  u64 n_connect_failures; /* connect() attempts that did not succeed */
  u64 n_disconnects;	  /* connections lost after being established */
  u64 n_frames_sent;
  u64 n_bytes_sent;
  u64 n_frames_received;
  u64 n_reinjects_received;
  u64 n_releases_received;
  /* Rejections split the way 00 §2.18.9 splits them: framing violations close
     the connection (ipc_message_rejections_total), semantic ones drop one
     frame (ipc_frame_drops_total). Indexed by cilium_srv6_if3_result_t. */
  u64 n_rejections[CILIUM_SRV6_IF3_N_RESULT];
  /* Releases by 06 §2 drop reason, indexed by CILIUM_SRV6_IF3_DROP_*. */
  u64 n_release_reason[CILIUM_SRV6_IF3_N_DROP_REASON];
  /* Reinject / release frames whose token was unknown or already consumed.
     They change no dataplane state (00 §2.18.6). */
  u64 n_unknown_token;
  /* Punts the serializer refused before they reached the queue, because a
     classify result was outside the wire's range (02 §5.6.2). A non-zero
     value is a plugin bug, not an agent one: the frame would have been
     dropped by the agent as a field violation and the flow would punt for
     ever. Expected 0. */
  u64 n_encode_refused;
  /* Current queue occupancy and its bounds. */
  u32 queue_entries;
  u32 queue_entry_cap;
  u32 queue_bytes;
  u32 queue_byte_cap;
  u32 queue_high_water_bytes;
} cilium_srv6_punt_transport_stats_t;

void cilium_srv6_punt_transport_stats (cilium_srv6_punt_transport_stats_t *out);

/* One PathCache index waiting for its D-12 grace period. */
typedef struct
{
  u32 path_index;
  u32 mtu_index;
  f64 free_after;
} cilium_srv6_path_pending_t;

typedef struct
{
  /* ---- hot path ---- */

  /* LocalEndpointTable, indexed by sw_if_index (D-31 key completed by the
     stored incarnation). Grown only under the worker barrier. */
  cilium_srv6_local_ep_t *local_eps;

  /* ProgramCache: bihash_24_8 key -> pool index (02 §4.1). */
  clib_bihash_24_8_t program_table;
  cilium_srv6_program_t *programs; /* fixed size pool */

  /* PathCache: fixed size pool of immutable entries (D-12). */
  cilium_srv6_path_t *paths;
  cilium_srv6_path_mtu_t *path_mtus; /* D-21 mutable side table */

  /* FragmentVerdictCache: bihash_40_8 key -> pool index (D-43). */
  clib_bihash_40_8_t frag_table;
  cilium_srv6_frag_entry_t *frags;

  /* PolicyLeaseTable: one slot per identity, holding the published policy
     revision and the lease granted for it (D-30, D-51). Slot 0 is the
     sentinel. */
  cilium_srv6_policy_rev_t *policy_rev;

  /* EndpointRevTable: the ENDPOINT key space of D-83, one slot per
     destination address. Slot 0 is the sentinel. */
  cilium_srv6_endpoint_rev_t *endpoint_rev;

  /* PathRevTable: the PATH key space of D-83, dense by PathCache index so
     that the hot path resolves it with one indexed load and no hash lookup.
     `path_revs[i]` is CILIUM_SRV6_REV_ABSENT while index i has no published
     revision, which includes every retired index: retiring an index clears
     it, and every entry that quoted the old incarnation also fails the
     generation half of the handle check. */
  u64 *path_revs;

  /* 01 §1 outer header parameters. */
  ip6_address_t node_address;
  u32 outer_fib_index;
  u16 inner_mtu;
  u8 hop_limit;
  u8 copy_dscp;
  u8 configured;

  /* D-36: node-local secret seed of the flow entropy hash (01 §4). */
  u64 flow_hash_seed;

  /* ---- control plane ---- */

  u32 program_capacity;
  u32 program_negative_capacity;
  u32 path_capacity;
  u32 frag_capacity;
  u32 policy_rev_capacity;
  u32 endpoint_rev_capacity;
  /* Length of the lease an install grants to its dependency identity
     (02 §5.4). `allow-lease-ms` in the startup configuration. */
  u32 allow_lease_ms;
  f64 frag_timeout;
  f64 grace_period;
  u32 outer_table_id;

  /* ProgramCache eviction bookkeeping (02 §5.3). Two age-ordered FIFOs, one
     per budget, so that a negative entry never evicts an ALLOW entry. */
  u32 prog_age_head[2]; /* [0] = negative (DENY), [1] = ALLOW */
  u32 prog_age_tail[2];
  u32 n_programs[2];
  uword *prog_owner_count;    /* owner_quota_class -> entries */
  uword *prog_identity_count; /* src_identity -> entries */

  /* FragmentVerdictCache age FIFO and quota accounting (D-42). Mutated from
     workers, hence frag_lock. */
  u32 frag_age_head;
  u32 frag_age_tail;
  u32 n_frags;
  uword *frag_owner_count;
  uword *frag_identity_count;
  clib_spinlock_t frag_lock;

  /* identity -> PolicyLeaseTable slot, and path_id -> PathMtuTable slot. */
  uword *policy_rev_by_identity;
  /* destination -> EndpointRevTable slot (D-83). Control plane only: the hot
     path reads the slot index the install resolved, never this table. */
  clib_bihash_16_8_t endpoint_rev_by_dst;
  clib_bihash_8_8_t path_mtu_table;

  /* D-12 grace period for retired PathCache indices. */
  cilium_srv6_path_pending_t *path_pending;

  /* PathCache staging transaction (D-61, Issue #99). Main thread only: no
     worker reads any of it, which is what makes "staging does not alter the
     worker-visible PathCache" a property of the data layout rather than of
     the order of the writes.

     path_txn_id is the open transaction, 0 when none is open.
     path_txn_committed is the one that committed last, so that a commit whose
     reply was lost can be repeated; 0 before the first commit. */
  u64 path_txn_id;
  u64 path_txn_committed;
  /* PathCache slots the open transaction reserved but has not published. They
     occupy pool slots and are therefore not free capacity, but they are not
     part of the PathCache, so every count of the table subtracts them. */
  u32 path_txn_reserved;
  cilium_srv6_path_staged_t *path_staged;
  /* client_path_id -> path_staged index, and specification fingerprint ->
     path_staged index. Both exist so that staging a complete table stays
     linear in its size instead of quadratic. */
  uword *path_staged_by_client;
  uword *path_staged_by_spec;
  /* One byte per PathCache index, set while a staged entry keeps that
     published index (a reused handle), so that the commit can tell "still
     wanted" from "leaving the table" in one pass. */
  u8 *path_claimed;
  /* Fingerprint of a published entry's specification -> its index. It is the
     index that makes "is this exact path already published" a lookup instead
     of a scan of the whole pool per staged entry. A fingerprint collision only
     costs a reuse opportunity: every hit is confirmed by comparing the whole
     specification. */
  uword *path_spec_index;

  /* punt state (02 §5.2). The token store and the quota counters are
     mutated from workers, hence punt_lock. */
  cilium_srv6_punt_queue_state_t punt_q[CILIUM_SRV6_PUNT_N_Q];
  cilium_srv6_punt_token_t *punt_tokens;
  uword *punt_owner_count;    /* (queue, owner) -> outstanding */
  uword *punt_identity_count; /* (queue, identity) -> outstanding */
  /*
   * D-76 §2.18.4: the external token is opaque, so the issuer keeps the
   * token -> slot map instead of encoding the slot in it. Keyed by the
   * 16 token bytes, which live in the token slot itself; the slot pool is
   * fixed size (pool_init_fixed), so the key memory never moves under the
   * hash. Mutated under punt_lock like the rest of the token store, and
   * never persisted: a token issued by a previous plugin instance resolves
   * to nothing, which is the "invalid across plugin instances" property.
   */
  uword *punt_token_index;
  /*
   * The token source. ISAAC, seeded at init with a full-width seed read from
   * /dev/urandom, so that a token is not predictable from other tokens.
   * Drawn under punt_lock because every worker draws from it.
   */
  clib_random_buffer_t punt_rng;
  f64 punt_token_timeout;
  clib_spinlock_t punt_lock;
  u32 punt_token_capacity;

  /* Issue #90: the {boot nonce, monotonic counter} punt operation identity
     space. `punt_id_nonce` is drawn once at init and never changes;
     `punt_id_seq` is bumped under punt_lock on every punt. */
  u64 punt_id_nonce;
  u64 punt_id_seq;

  u32 classify_node_index;
  u32 process_node_index;

  /* 06 §3 counters that are not per-node error counters. */
  u64 n_program_installs;
  u64 n_program_deletes;
  u64 n_program_quota_drops;
  u64 n_program_fair_evictions;
  u64 n_program_stale_installs;
  /* D-83: srv6_program_add_del refused because a referenced revision key does
     not exist at all — the identity, the destination (with no `::` fallback
     published) or the PathCache index has never been published. It is counted
     apart from `n_program_stale_installs` because the two mean different
     things: a stale install is a lost race a recompile fixes, while a missing
     key means the mandatory order of D-83 (publish + ACK, then install) was
     violated and recompiling alone loops forever. */
  u64 n_program_missing_key_installs;
  /* D-83 / errata #34 item 153: a positive Program install —
     srv6_program_add_del(ALLOW) or srv6_fragment_verdict_add(ALLOW) — refused
     because its ENDPOINT key resolved to the reserved absence key `::`, so the
     destination is not a published endpoint of this node: there is nothing to
     forward to and no destination revision to depend on. It is counted apart
     from both neighbours because it is neither a lost race nor a missing
     publication: it is a compiler that produced a positive Program for a
     destination it has no endpoint key for, which no republication of any key
     can fix. CLI only — adding a field to srv6_headend_status_reply would
     change that message's CRC, and the retval
     (VNET_API_ERROR_INVALID_DST_ADDRESS) already tells the agent which of the
     three refusals it hit. */
  u64 n_program_absence_key_installs;
  /* D-80 / 02 §4.3.1: srv6_program_add_del refused because the
     {verdict, action, path, target} combination is not one of the three legal
     ones. It is its own counter for the same reason
     n_program_absence_key_installs is: it is a wiring error in the compiler,
     not a lost race and not a missing publication, so neither a recompile nor
     a republication makes the install legal. CLI only (adding a field to
     srv6_headend_status_reply would change that message's CRC); the retval
     VNET_API_ERROR_INVALID_ARGUMENT is what the agent sees. */
  u64 n_program_illegal_action_installs;
  /* D-80: a LOCAL_DELIVER install whose (target_sw_if_index,
     target_if_incarnation) is not a live LocalEndpointTable lifetime. The
     target is not something the caller may assert: an index alone is reused
     (D-31), so an entry installed for a lifetime that has already ended would
     deliver into whatever Pod inherited the number. CLI only; the retval is
     VNET_API_ERROR_INVALID_INTERFACE. */
  u64 n_program_local_target_unbound;
  /* D-80: a LOCAL_DELIVER install whose target lifetime is live but does not
     carry this destination — the endpoint's address is not `dst`, or its
     identity is not the one the decision was taken against. Counted apart
     from `unbound` because the two point at different faults: unbound is a
     stale handle, a mismatch is a compiler that resolved the destination to
     the wrong endpoint. Same retval. */
  u64 n_program_local_target_mismatch;
  u64 n_lease_extends;
  u64 n_revision_publishes;
  u64 n_frag_evictions;
  u64 n_frag_quota_drops;
  u64 n_frag_gc;
  /* srv6_fragment_verdict_add(ALLOW) refused at step 3 or 4 of the fourth
     policy_lease_touch path (D-51, Issue #83): the identity holds no usable
     exact-revision lease, so no record was published. CLI only — adding a
     field to srv6_counters_details would change that message's CRC. */
  u64 n_frag_lease_rejects;
  /* srv6_fragment_verdict_add refused because a live record for the same key
     answers a different punt operation (Issue #90). The verdict of a datagram
     is decided once; a second punt_id for a key whose record has not expired
     means the agent is answering a punt this node no longer has, so the
     record is left alone. CLI only, same reason as above. */
  u64 n_frag_punt_id_conflicts;
  /* Reinjects refused by cilium_srv6_punt_reinject() because the echoed
     punt_id is not the one the redeemed token was issued with (Issue #90).
     Expected 0: the agent echoes what it received. CLI only. */
  u64 n_reinject_punt_id_mismatch;

  u8 initialised;
} cilium_srv6_headend_main_t;

extern cilium_srv6_headend_main_t cilium_srv6_headend_main;

extern vlib_node_registration_t cilium_srv6_classify_node;
extern vlib_node_registration_t cilium_srv6_ct_node;
extern vlib_node_registration_t cilium_srv6_program_node;
extern vlib_node_registration_t cilium_srv6_local_deliver_node;
extern vlib_node_registration_t cilium_srv6_encap_node;
extern vlib_node_registration_t cilium_srv6_punt_node;

/* ------------------------------------------------------------------ */
/* hot path lookups                                                    */
/* ------------------------------------------------------------------ */

/*
 * 02 §3: one LocalEndpointTable lookup per packet. The D-31 key is completed
 * by comparing the stored incarnation with the live one from the guard trust
 * map, which is the authority on what incarnation the receiving interface
 * currently has.
 */
static_always_inline const cilium_srv6_local_ep_t *
cilium_srv6_local_ep_lookup (const cilium_srv6_headend_main_t *hm, const cilium_srv6_main_t *cm,
			     u32 sw_if_index)
{
  const cilium_srv6_local_ep_t *e;

  if (PREDICT_FALSE (sw_if_index >= vec_len (hm->local_eps)))
    return NULL;

  e = hm->local_eps + sw_if_index;

  if (PREDICT_FALSE (!e->valid))
    return NULL;

  if (PREDICT_FALSE (sw_if_index >= vec_len (cm->ifs)))
    return NULL;

  /* D-31: a stale classification for a reused sw_if_index must not resolve. */
  if (PREDICT_FALSE (e->if_incarnation != cm->ifs[sw_if_index].incarnation))
    return NULL;

  return e;
}

/*
 * 02 §4.1 key, 24 bytes: {src_identity, dst, proto, l4_discriminator}. The
 * u32 identity, the u8 protocol and the u16 discriminator share the third
 * word, which is exactly the packing the design's struct describes.
 */
static_always_inline void
cilium_srv6_program_key (u64 key[3], u32 src_identity, const ip6_address_t *dst, u8 proto,
			 u16 l4_discriminator)
{
  key[0] = dst->as_u64[0];
  key[1] = dst->as_u64[1];
  key[2] = ((u64) src_identity << 32) | ((u64) proto << 16) | (u64) l4_discriminator;
}

static_always_inline cilium_srv6_program_t *
cilium_srv6_program_at (const cilium_srv6_headend_main_t *hm, u32 index)
{
  if (PREDICT_FALSE (index >= hm->program_capacity))
    return NULL;

  return hm->programs + index;
}

static_always_inline int
cilium_srv6_program_lookup (const cilium_srv6_headend_main_t *hm, const u64 key[3], u32 *index)
{
  clib_bihash_kv_24_8_t kv;

  if (PREDICT_FALSE (!hm->initialised))
    return 0;

  kv.key[0] = key[0];
  kv.key[1] = key[1];
  kv.key[2] = key[2];
  kv.value = 0;

  if (clib_bihash_search_inline_24_8 ((clib_bihash_24_8_t *) &hm->program_table, &kv))
    return 0;

  *index = (u32) kv.value;
  return 1;
}

/*
 * PathCache handle resolution (02 §4.2 "PathCache.get(index, generation)").
 * A retired or re-published entry fails the generation compare, which the
 * caller turns into a stale-handle punt.
 */
static_always_inline const cilium_srv6_path_t *
cilium_srv6_path_get (const cilium_srv6_headend_main_t *hm, u32 index, u32 generation)
{
  const cilium_srv6_path_t *p;

  if (PREDICT_FALSE (index >= hm->path_capacity))
    return NULL;

  p = hm->paths + index;

  if (PREDICT_FALSE (p->state != CILIUM_SRV6_PATH_PUBLISHED || p->generation != generation))
    return NULL;

  return p;
}

/*
 * 02 §9 / D-21: min(PathCache.base_mtu, PathMtuTable[path_id].effective_mtu),
 * with an unlearned slot contributing nothing.
 *
 * Returns 0 when the learned value is CILIUM_SRV6_PATH_MTU_UNUSABLE, i.e.
 * when a validated PTB proved that this path cannot carry a 1280 byte inner
 * packet. 0 is not an MTU: it means "no packet fits", and the caller must
 * fail closed instead of generating a PTB (see the constant's comment).
 */
static_always_inline u16
cilium_srv6_path_effective_mtu (const cilium_srv6_headend_main_t *hm,
				const cilium_srv6_path_t *p)
{
  const cilium_srv6_path_mtu_t *m;
  u16 learned;

  if (PREDICT_FALSE (p->mtu_index >= hm->path_capacity))
    return p->base_mtu;

  m = hm->path_mtus + p->mtu_index;
  learned = m->effective_mtu;

  if (PREDICT_FALSE (learned == CILIUM_SRV6_PATH_MTU_UNUSABLE))
    return 0;

  if (PREDICT_TRUE (learned == 0 || learned >= p->base_mtu))
    return p->base_mtu;

  return learned;
}

/* 01 §3.1 FragmentVerdictCache key: (src, dst, fragment-id, next-header). */
static_always_inline void
cilium_srv6_frag_key (u64 key[5], const ip6_address_t *src, const ip6_address_t *dst, u32 frag_id,
		      u8 next_header)
{
  key[0] = src->as_u64[0];
  key[1] = src->as_u64[1];
  key[2] = dst->as_u64[0];
  key[3] = dst->as_u64[1];
  key[4] = ((u64) frag_id << 8) | (u64) next_header;
}

static_always_inline int
cilium_srv6_frag_lookup (const cilium_srv6_headend_main_t *hm, const u64 key[5], u32 *index)
{
  clib_bihash_kv_40_8_t kv;
  int i;

  if (PREDICT_FALSE (!hm->initialised))
    return 0;

  for (i = 0; i < 5; i++)
    kv.key[i] = key[i];
  kv.value = 0;

  if (clib_bihash_search_inline_40_8 ((clib_bihash_40_8_t *) &hm->frag_table, &kv))
    return 0;

  *index = (u32) kv.value;
  return 1;
}

/* Currently published policy revision of one slot (D-30). */
static_always_inline u64
cilium_srv6_policy_revision (const cilium_srv6_headend_main_t *hm, u32 slot)
{
  if (PREDICT_FALSE (slot >= vec_len (hm->policy_rev)))
    return CILIUM_SRV6_REV_INVALID;

  return hm->policy_rev[slot].policy_revision;
}

/*
 * Same, for a holder that stored the identity next to the slot instead of
 * taking a reference on it (the conntrack table, C10). A slot that was
 * released and handed to another identity fails the identity comparison and
 * reports the sentinel, so the holder's stored revision can never match a
 * foreign identity's revision.
 */
static_always_inline u64
cilium_srv6_policy_revision_of (const cilium_srv6_headend_main_t *hm, u32 slot, u32 identity)
{
  if (PREDICT_FALSE (slot == 0 || slot >= vec_len (hm->policy_rev)))
    return CILIUM_SRV6_REV_INVALID;

  if (PREDICT_FALSE (hm->policy_rev[slot].identity != identity))
    return CILIUM_SRV6_REV_INVALID;

  return hm->policy_rev[slot].policy_revision;
}

/* Currently published ENDPOINT revision of one slot (D-83). */
static_always_inline u64
cilium_srv6_endpoint_revision (const cilium_srv6_headend_main_t *hm, u32 slot)
{
  if (PREDICT_FALSE (slot == 0 || slot >= vec_len (hm->endpoint_rev)))
    return CILIUM_SRV6_REV_INVALID;

  return hm->endpoint_rev[slot].revision;
}

/* Currently published PATH revision of one PathCache index (D-83). */
static_always_inline u64
cilium_srv6_path_revision (const cilium_srv6_headend_main_t *hm, u32 path_index)
{
  if (PREDICT_FALSE (path_index >= vec_len (hm->path_revs)))
    return CILIUM_SRV6_REV_INVALID;

  return hm->path_revs[path_index];
}

/*
 * 02 §4.2 dependency check, shared by cilium-srv6-program and the fragment
 * bypass so that both are bound to the same three revisions (D-20).
 *
 * D-83: each of the three is resolved in its own namespace, by its own key,
 * and never against a node-global value. The cost of that, per packet, is
 * three indexed loads and no additional hash lookup, because the two key
 * resolutions that would need one were done at install time and stored in the
 * entry:
 *
 *   policy    hm->policy_rev[policy_rev_slot]     slot resolved at install
 *   endpoint  hm->endpoint_rev[endpoint_rev_slot] slot resolved at install
 *   path      hm->path_revs[path_cache_index]     dense by index
 *
 * The endpoint load is the one new cache line this check touches; the policy
 * load was already in the 02 §4.2 budget, and the path load is on a dense u64
 * array indexed exactly like the PathCache entry the caller resolves two
 * steps later, so it shares that entry's index locality (8 keys per line)
 * rather than adding a lookup. NFR-5's "lookup count does not grow" therefore
 * still holds: the only hash lookup on the hot path is the ProgramCache one.
 *
 * `path_revision == CILIUM_SRV6_REV_ABSENT` means "this entry has no path
 * dependency", which is what a DENY carries (02 §4.3: a DENY must not be
 * invalidated by an unrelated route flap). It is unambiguous because 0 is
 * never a published revision.
 */
static_always_inline int
cilium_srv6_revisions_match (const cilium_srv6_headend_main_t *hm, u32 policy_rev_slot,
			     u64 policy_revision, u32 endpoint_rev_slot, u64 endpoint_revision,
			     u32 path_cache_index, u64 path_revision)
{
  if (policy_revision != cilium_srv6_policy_revision (hm, policy_rev_slot))
    return 0;

  if (endpoint_revision != cilium_srv6_endpoint_revision (hm, endpoint_rev_slot))
    return 0;

  if (path_revision == CILIUM_SRV6_REV_ABSENT)
    return 1;

  return path_revision == cilium_srv6_path_revision (hm, path_cache_index);
}

/*
 * The lease half of "policy decision validity" (00 §2.1, D-51).
 *
 * The caller has already established revision validity — that
 * `dependency_revision` equals the identity's currently published revision —
 * so what is left is whether the control plane has vouched for that revision
 * recently enough:
 *
 *   1. the slot must still belong to `identity` (a slot handed to another
 *      identity reports nothing usable, as in
 *      cilium_srv6_policy_revision_of);
 *   2. the lease must have been granted for this very revision, so that a
 *      lease pushed for an older or newer revision does not keep this
 *      decision alive;
 *   3. the deadline must not have passed.
 *
 * One indexed read of the slot answers all three; there is no second table
 * and no per-entry field, which is what keeps srv6_lease_extend O(identities)
 * (02 §5.4).
 */
static_always_inline int
cilium_srv6_policy_lease_valid (const cilium_srv6_headend_main_t *hm, u32 slot, u32 identity,
				u64 dependency_revision, f64 now)
{
  const cilium_srv6_policy_rev_t *r;

  if (PREDICT_FALSE (slot == 0 || slot >= vec_len (hm->policy_rev)))
    return 0;

  r = hm->policy_rev + slot;

  if (PREDICT_FALSE (r->identity != identity))
    return 0;

  if (PREDICT_FALSE (dependency_revision == CILIUM_SRV6_REV_INVALID ||
		     r->lease_revision != dependency_revision))
    return 0;

  return now < r->lease_valid_until;
}

/*
 * Seconds left on the lease of one dependency pair, for the CLI and the dump
 * APIs. 0.0 means "not leased", which covers an unknown slot, a lease granted
 * for another revision and an expired one.
 */
static_always_inline f64
cilium_srv6_policy_lease_remaining (const cilium_srv6_headend_main_t *hm, u32 slot, u32 identity,
				    u64 dependency_revision, f64 now)
{
  if (!cilium_srv6_policy_lease_valid (hm, slot, identity, dependency_revision, now))
    return 0.0;

  return hm->policy_rev[slot].lease_valid_until - now;
}

/*
 * 01 §4 flow entropy. The seed is a node-local secret (D-36), so the mapping
 * from a 5-tuple to a Flow Label cannot be reproduced from another node. The
 * input never contains time or a counter, so one inner flow always hashes to
 * the same value; a fragmented datagram hashes (src, dst, fragment id, next
 * header) so that every fragment shares one label.
 *
 * The stability of this value is also what makes the PTB correlation of
 * 02 §9 possible: the flow label is the one entropy field a transit node
 * quotes back unchanged, so it is part of the RecentTx key.
 *
 * 01 §4 assumptions this code depends on but cannot verify itself:
 *   - transit ECMP hashes on the flow label. That is a configuration
 *     requirement on the SR domain, not something the headend can enforce.
 *   - destination RSS on the flow label is recommended but not required
 *     [V-5, still open]. The outer destination address carries the Context,
 *     so a NIC that hashes on addresses only still spreads per destination
 *     endpoint; only per-flow spreading towards one endpoint is lost.
 * Neither assumption affects correctness of this function, and V-5 is a
 * verification task, not an implementation one.
 */
static_always_inline u32
cilium_srv6_flow_label (const cilium_srv6_headend_main_t *hm, const ip6_address_t *src,
			const ip6_address_t *dst, u8 proto, u16 sport, u16 dport, u32 frag_id,
			u8 fragmented)
{
  u64 buf[5];
  uword h;

  buf[0] = src->as_u64[0];
  buf[1] = src->as_u64[1];
  buf[2] = dst->as_u64[0];
  buf[3] = dst->as_u64[1];

  if (fragmented)
    buf[4] = ((u64) frag_id << 8) | (u64) proto;
  else
    buf[4] = ((u64) proto << 32) | ((u64) sport << 16) | (u64) dport;

  h = hash_memory (buf, sizeof (buf), (uword) hm->flow_hash_seed);

  return (u32) h & 0xfffff;
}

/* ------------------------------------------------------------------ */
/* control plane entry points (cilium_srv6_headend.c)                  */
/* ------------------------------------------------------------------ */

int cilium_srv6_local_ep_add_del (u32 sw_if_index, u32 if_incarnation, u32 identity,
				  const ip6_address_t *ip, u32 local_context_id,
				  u32 owner_quota_class, u8 is_add);

/*
 * The PathCache index and generation are assigned by the plugin, not by the
 * agent: the pool belongs to the dataplane and D-12 requires the generation
 * to be the plugin's own record of how many times the slot has been reused.
 * The agent gets both back and quotes them in srv6_program_add_del.
 */
int cilium_srv6_path_add (u64 path_id, const ip6_address_t *da_template,
			  const ip6_address_t *service_sid, u16 base_mtu, const u8 *srh,
			  u32 srh_len, const ip6_address_t *shift_states, u32 n_shift_states,
			  u32 *path_index_out, u32 *generation_out);

int cilium_srv6_path_del (u32 path_index, u32 generation);

/*
 * PathCache staging transaction (D-61, Issue #99). The four calls are the
 * publication surface of C3:
 *
 *   begin   opens the staging table (idempotent for the open transaction)
 *   put     stages one entry and reserves its handle. The handle is not
 *           usable until the commit succeeded; nothing may quote it before
 *           then.
 *   commit  validates the staging table, then installs it and retires
 *           everything it does not contain, under one worker barrier.
 *           Idempotent for the transaction that committed last.
 *   abort   drops the staging table and releases its reservations.
 *
 * Every failure before a successful commit leaves the published PathCache
 * exactly as it was.
 */
int cilium_srv6_path_txn_begin (u64 txn_id);

int cilium_srv6_path_txn_put (u64 txn_id, u64 client_path_id,
			      const cilium_srv6_path_spec_t *spec, u32 *path_index_out,
			      u32 *generation_out);

int cilium_srv6_path_txn_commit (u64 txn_id);

int cilium_srv6_path_txn_abort (u64 txn_id);

/*
 * D-51: no lease_ms. An ALLOW install grants a lease to its dependency
 * identity for the revision it installed under (02 §5.4), using
 * hm->allow_lease_ms; the steady-state length is the one the agent sends in
 * srv6_lease_extend.
 */
int cilium_srv6_program_add_del (u32 src_identity, const ip6_address_t *dst, u8 proto,
				 u16 l4_discriminator, u8 verdict, u8 action, u64 policy_revision,
				 u64 endpoint_revision, u64 path_revision, u32 path_cache_index,
				 u32 path_generation, u32 target_sw_if_index,
				 u32 target_if_incarnation, u32 target_identity,
				 u32 owner_quota_class, u8 is_add);

int cilium_srv6_policy_revision_publish (const u32 *identities, const u64 *revisions,
					 u32 n_policy);
int cilium_srv6_endpoint_revision_publish (const ip6_address_t *dsts, const u64 *revisions,
					   u32 n_endpoint);
int cilium_srv6_path_revision_publish (const u32 *indices, const u64 *revisions, u32 n_path);

/*
 * Find, or create and retain, the PolicyLeaseTable slot of one identity
 * (D-30, D-51). Used by the conntrack table (C10), whose reply entries are
 * bound to the revision of the *peer* identity — an identity this node may
 * never have compiled a ProgramCache entry for. The slot is retained the same
 * way srv6_policy_revision_publish retains the slots it creates, so no caller has to
 * release one, and a fresh slot starts at revision 0 with no lease and
 * therefore does not validate a decision made under a later revision
 * (fail-closed).
 *
 * Returns 0 (the sentinel slot) when the table is full. Must be called with
 * the worker barrier held.
 */
u32 cilium_srv6_policy_rev_slot_pin (u32 identity);

/*
 * policy_lease_touch: refresh the lease of one identity for one revision
 * (00 §2.1, 02 §5.4, D-51). This is the opportunistic entry point, used by
 * srv6_ct_verify; srv6_program_add_del(ALLOW) and
 * srv6_fragment_verdict_add(ALLOW) use the file-local form and
 * srv6_lease_extend performs the same operation in bulk. All four share one
 * rule set (Issue #61 invariant 1): the slot must still belong to `identity`,
 * `revision` must be the revision this node currently publishes for it, and
 * the lease revision never moves backwards. The opportunistic form never
 * shortens an existing lease. The slot must already exist; nothing is created
 * here.
 */
void cilium_srv6_policy_lease_touch (u32 slot, u32 identity, u64 revision, u32 lease_ms);

/*
 * srv6_lease_extend (02 §8, D-51). Updates the PolicyLeaseTable only: for
 * every (identity, revision) pair whose revision is still the one this node
 * publishes, the lease is (re)granted for that revision with the supplied
 * length. Identities with no slot have no dependent state on this node and
 * are counted in `n_skipped` rather than given one, so a push cannot grow the
 * table. The work is O(n_policy) and never touches an entry.
 */
int cilium_srv6_lease_extend (const u32 *identities, const u64 *revisions, u32 n_policy,
			      u32 lease_ms, u32 *n_updated, u32 *n_skipped);

int cilium_srv6_headend_config_set (const ip6_address_t *node_address, u32 outer_table_id,
				    u16 inner_mtu, u8 hop_limit, u8 copy_dscp);

/* PathMtuTable write path used by the PMTUD component (02 §9). */
int cilium_srv6_path_mtu_update (u64 path_id, u16 effective_mtu, f64 decay_seconds);

u8 *format_cilium_srv6_verdict (u8 *s, va_list *args);
u8 *format_cilium_srv6_punt_reason (u8 *s, va_list *args);
u8 *format_cilium_srv6_punt_queue (u8 *s, va_list *args);

/*
 * Record the verdict of a first fragment (01 §3.1 / D-20). Called from a
 * worker; the FragmentVerdictCache is the one table this component mutates
 * from the dataplane, and it serialises with a spinlock rather than the
 * worker barrier. Returns 1 if the record was made.
 */
int cilium_srv6_frag_record (vlib_main_t *vm, const ip6_address_t *src, const ip6_address_t *dst,
			     u32 frag_id, u8 next_header, const cilium_srv6_headend_meta_t *meta,
			     const cilium_srv6_program_t *prog, u8 verdict, u32 path_cache_index,
			     u32 path_generation);

/*
 * srv6_fragment_verdict_add (02 §8, 01 §3.1, D-20): the other producer of a
 * FragmentVerdictCache record — the verdict the agent compiled for a first
 * fragment that punted because the ProgramCache had no entry to derive one
 * from. Called from the main thread and takes the worker barrier itself.
 *
 * `frag_id` is in network byte order, i.e. the Identification field as it
 * appears in the packet, because that is what the cache key is built from
 * (cilium_srv6_frag_key). The API layer converts.
 *
 * `local_context_id`, the D-30 revision slot and the D-42 quota class are not
 * parameters: they are read from the LocalEndpointTable entry that
 * (sw_if_index, if_incarnation) resolves to, so that the caller cannot bind a
 * record to an incarnation, a slot or a quota class of its choosing.
 *
 * `punt_id` is the identity of the punt this verdict answers (Issue #90),
 * echoed from the punt metadata. It arms the one-shot reinjection capability
 * of the record. Zero means "this verdict answers no punt": the record is
 * installed with no capability and the reinject of any punt is refused
 * against it. The reinstall rules are on the definition.
 *
 * Returns 0, or a VNET_API_ERROR_* the API layer reports unchanged.
 */
int cilium_srv6_frag_verdict_add (const ip6_address_t *src, const ip6_address_t *dst, u32 frag_id,
				  u8 next_header, u32 sw_if_index, u32 if_incarnation,
				  u32 src_identity, u8 verdict, u64 policy_revision,
				  u64 endpoint_revision, u64 path_revision, u32 path_cache_index,
				  u32 path_generation, u32 timeout_ms, u64 punt_id);

/* Punt admission + transmit, called from cilium-srv6-punt (cilium_srv6_punt.c).
 * Returns 1 if the packet was handed to the agent. */
int cilium_srv6_punt_one (vlib_main_t *vm, vlib_buffer_t *b, u8 queue, u8 reason);

void cilium_srv6_punt_init (vlib_main_t *vm);
void cilium_srv6_punt_expire_tokens (vlib_main_t *vm, f64 now);

#endif /* __included_cilium_srv6_headend_h__ */
