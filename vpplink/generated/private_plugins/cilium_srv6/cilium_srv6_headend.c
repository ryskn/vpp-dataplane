/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — headend tables (C7), control plane.
 *
 * design/detail/02-headend-dataplane.md §2 (table list), §3
 * (LocalEndpointTable), §4 (ProgramCache, PathCache), §4.3 (dependency
 * revisions and ALLOW lease), §5.3 (eviction), §8 (IF-2), §9 (PathMtuTable)
 * design/detail/01-packet-format.md §2.5 (SRH layout), §3.1 (fragment cache)
 * design/detail/00-overview.md §2 (D-12, D-20, D-21, D-26, D-30, D-31, D-42,
 *   D-43), §4.1 (message validation)
 *
 * Synchronisation rules implemented here:
 *
 *  - every structural change to a table the dataplane reads happens under the
 *    worker barrier (D-12), using the shared helpers of cilium_srv6_guard.h;
 *  - a retired PathCache index keeps its slot until the grace period has
 *    elapsed, so an index is never reused underneath a packet that already
 *    captured the handle (D-12);
 *  - the FragmentVerdictCache is the one table written from workers, so its
 *    structural changes are serialised with a spinlock rather than the
 *    barrier; the pools are fixed size, so no allocation happens there.
 */

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/feature/feature.h>
#include <vnet/fib/fib_table.h>
#include <vnet/interface.h>
#include <vnet/interface_funcs.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>
#include <vnet/srv6/sr_packet.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_ct.h>

cilium_srv6_headend_main_t cilium_srv6_headend_main;

cilium_srv6_ct_lookup_fn cilium_srv6_ct_lookup_hook;
cilium_srv6_ct_egress_fn cilium_srv6_ct_egress_hook;
cilium_srv6_ptb_send_fn cilium_srv6_ptb_send_hook;

static vlib_log_class_t cilium_srv6_headend_log_class;

#define CSH_LOG_ERR(...)    vlib_log_err (cilium_srv6_headend_log_class, __VA_ARGS__)
#define CSH_LOG_NOTICE(...) vlib_log_notice (cilium_srv6_headend_log_class, __VA_ARGS__)

#define CSH_ARC_NAME  "ip6-unicast"
#define CSH_NODE_NAME "cilium-srv6-classify"

/* ------------------------------------------------------------------ */
/* formatting                                                          */
/* ------------------------------------------------------------------ */

u8 *
format_cilium_srv6_verdict (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_VERDICT_DENY:
      return format (s, "DENY");
    case CILIUM_SRV6_VERDICT_ALLOW:
      return format (s, "ALLOW");
    default:
      return format (s, "UNKNOWN(%u)", v);
    }
}

u8 *
format_cilium_srv6_punt_reason (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_PUNT_REASON_MISS:
      return format (s, "ProgramCache miss");
    case CILIUM_SRV6_PUNT_REASON_STALE_REVISION:
      return format (s, "dependency revision mismatch");
    case CILIUM_SRV6_PUNT_REASON_LEASE_EXPIRED:
      return format (s, "ALLOW lease expired");
    case CILIUM_SRV6_PUNT_REASON_STALE_PATH:
      return format (s, "stale path handle");
    case CILIUM_SRV6_PUNT_REASON_REPLY_REAUTH:
      return format (s, "reply re-authorisation");
    default:
      return format (s, "unknown(%u)", v);
    }
}

u8 *
format_cilium_srv6_punt_queue (u8 *s, va_list *args)
{
  u32 v = va_arg (*args, u32);

  switch (v)
    {
    case CILIUM_SRV6_PUNT_Q_COMPILE:
      return format (s, "compile");
    case CILIUM_SRV6_PUNT_Q_REAUTH:
      return format (s, "reply-reauth");
    case CILIUM_SRV6_PUNT_Q_FRAGMENT:
      return format (s, "fragment");
    default:
      return format (s, "unknown(%u)", v);
    }
}

/* ------------------------------------------------------------------ */
/* PolicyLeaseTable slots (00 §2.1, D-30 + D-51)                       */
/* ------------------------------------------------------------------ */

/*
 * Slot 0 is the sentinel: it holds CILIUM_SRV6_REV_INVALID and no lease, so
 * anything that resolves to it fails both halves of the validity check of
 * 00 §2.1 and punts. That is the fail-closed behaviour required when an
 * identity has no slot (table exhausted, or a not yet published identity).
 */
#define CSH_POLICY_REV_SENTINEL 0

static u32
csh_policy_rev_slot_find (cilium_srv6_headend_main_t *hm, u32 identity)
{
  uword *p = hash_get (hm->policy_rev_by_identity, (uword) identity);

  return p ? (u32) p[0] : CSH_POLICY_REV_SENTINEL;
}

/*
 * Get, or create, the slot of one identity and take a reference on it.
 * Returns CSH_POLICY_REV_SENTINEL when the table is exhausted, which makes
 * the caller's entry permanently stale rather than silently unbound.
 */
static u32
csh_policy_rev_slot_ref (cilium_srv6_headend_main_t *hm, u32 identity)
{
  cilium_srv6_policy_rev_t *r;
  u32 slot;

  slot = csh_policy_rev_slot_find (hm, identity);
  if (slot != CSH_POLICY_REV_SENTINEL)
    {
      hm->policy_rev[slot].refcount++;
      return slot;
    }

  if (pool_free_elts (hm->policy_rev) == 0)
    return CSH_POLICY_REV_SENTINEL;

  pool_get_zero (hm->policy_rev, r);
  slot = (u32) (r - hm->policy_rev);

  r->identity = identity;
  r->refcount = 1;
  /*
   * A brand new slot starts at revision 0. An agent that installs an entry
   * carrying a different revision is refused (stale install) and republishes;
   * that is the same retry loop 02 §4.3 already prescribes.
   */
  r->policy_revision = 0;

  /*
   * D-51: and with no lease. The sentinel revision cannot be a dependency
   * revision, and the deadline is in the past, so nothing validates against a
   * slot that has never been leased (fail-closed).
   */
  r->lease_revision = CILIUM_SRV6_REV_INVALID;
  r->lease_valid_until = 0.0;

  hash_set (hm->policy_rev_by_identity, (uword) identity, (uword) slot);

  return slot;
}

static void
csh_policy_rev_slot_unref (cilium_srv6_headend_main_t *hm, u32 slot)
{
  cilium_srv6_policy_rev_t *r;

  if (slot == CSH_POLICY_REV_SENTINEL || slot >= vec_len (hm->policy_rev))
    return;

  if (pool_is_free_index (hm->policy_rev, slot))
    return;

  r = hm->policy_rev + slot;

  if (r->refcount > 0)
    r->refcount--;

  if (r->refcount != 0)
    return;

  hash_unset (hm->policy_rev_by_identity, (uword) r->identity);

  /* A reader that still holds this slot index must not match a future
     identity's revision or inherit its lease, so the slot is poisoned before
     it is released. */
  r->policy_revision = CILIUM_SRV6_REV_INVALID;
  r->lease_revision = CILIUM_SRV6_REV_INVALID;
  r->lease_valid_until = 0.0;
  r->identity = ~0;

  pool_put_index (hm->policy_rev, slot);
}

/*
 * C10 needs the slot of an identity it does not hold a ProgramCache entry
 * for (the peer of a reply), so the slot is created on demand and then
 * retained, exactly like the slots srv6_policy_revision_publish creates. Retaining
 * rather than reference counting keeps the conntrack table out of this pool
 * entirely: no worker ever has to release a slot.
 */
u32
cilium_srv6_policy_rev_slot_pin (u32 identity)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  u32 slot;

  if (!hm->initialised)
    return CSH_POLICY_REV_SENTINEL;

  slot = csh_policy_rev_slot_find (hm, identity);
  if (slot != CSH_POLICY_REV_SENTINEL)
    return slot;

  return csh_policy_rev_slot_ref (hm, identity);
}

/* ------------------------------------------------------------------ */
/* EndpointRevTable (02 §4.3, D-17 + D-83)                             */
/* ------------------------------------------------------------------ */

/*
 * Slot 0 is the sentinel, exactly as in the policy table: it holds
 * CILIUM_SRV6_REV_INVALID, so a resolution that failed can never match a
 * quotation and always punts (fail-closed).
 */
#define CSH_ENDPOINT_REV_SENTINEL 0

static u32
csh_endpoint_rev_slot_find (cilium_srv6_headend_main_t *hm, const ip6_address_t *dst)
{
  clib_bihash_kv_16_8_t kv;

  kv.key[0] = dst->as_u64[0];
  kv.key[1] = dst->as_u64[1];
  kv.value = 0;

  if (clib_bihash_search_16_8 (&hm->endpoint_rev_by_dst, &kv, &kv))
    return CSH_ENDPOINT_REV_SENTINEL;

  return (u32) kv.value;
}

/*
 * Get, or create, the slot of one destination and take a reference on it.
 * Returns CSH_ENDPOINT_REV_SENTINEL when the table is exhausted, which makes
 * the caller's entry permanently stale rather than silently unbound.
 */
static u32
csh_endpoint_rev_slot_ref (cilium_srv6_headend_main_t *hm, const ip6_address_t *dst)
{
  clib_bihash_kv_16_8_t kv;
  cilium_srv6_endpoint_rev_t *r;
  u32 slot;

  slot = csh_endpoint_rev_slot_find (hm, dst);
  if (slot != CSH_ENDPOINT_REV_SENTINEL)
    {
      hm->endpoint_rev[slot].refcount++;
      return slot;
    }

  if (pool_free_elts (hm->endpoint_rev) == 0)
    return CSH_ENDPOINT_REV_SENTINEL;

  pool_get_zero (hm->endpoint_rev, r);
  slot = (u32) (r - hm->endpoint_rev);

  r->dst = *dst;
  r->refcount = 1;
  /*
   * A brand new slot exists but publishes nothing: CILIUM_SRV6_REV_ABSENT is
   * "the key does not exist", so an install quoting any revision for it is
   * refused until a publish arrives. That is the D-83 fail-closed direction,
   * and it is why the agent must publish a key before it may install anything
   * that depends on it.
   */
  r->present = 0;
  r->revision = CILIUM_SRV6_REV_ABSENT;
  r->hwm = CILIUM_SRV6_REV_ABSENT;

  kv.key[0] = dst->as_u64[0];
  kv.key[1] = dst->as_u64[1];
  kv.value = slot;
  clib_bihash_add_del_16_8 (&hm->endpoint_rev_by_dst, &kv, 1 /* add */);

  return slot;
}

static void
csh_endpoint_rev_slot_unref (cilium_srv6_headend_main_t *hm, u32 slot)
{
  clib_bihash_kv_16_8_t kv;
  cilium_srv6_endpoint_rev_t *r;

  if (slot == CSH_ENDPOINT_REV_SENTINEL || slot >= vec_len (hm->endpoint_rev))
    return;

  if (pool_is_free_index (hm->endpoint_rev, slot))
    return;

  r = hm->endpoint_rev + slot;

  if (r->refcount > 0)
    r->refcount--;

  if (r->refcount != 0)
    return;

  /*
   * D-83: the high water mark may only be dropped together with the last
   * reference to the key. A reference is exactly what a ProgramCache entry
   * that still quotes a revision of this key holds, so once the count reaches
   * zero there is nothing left that a republished lower revision could
   * revalidate, and forgetting the mark is safe.
   */
  kv.key[0] = r->dst.as_u64[0];
  kv.key[1] = r->dst.as_u64[1];
  kv.value = slot;
  clib_bihash_add_del_16_8 (&hm->endpoint_rev_by_dst, &kv, 0 /* del */);

  /* A reader that still holds this slot index must not match a future key's
     revision, so the slot is poisoned before it is released. */
  r->revision = CILIUM_SRV6_REV_INVALID;
  r->hwm = CILIUM_SRV6_REV_INVALID;
  r->present = 0;
  clib_memset (&r->dst, 0, sizeof (r->dst));

  pool_put_index (hm->endpoint_rev, slot);
}

/*
 * Resolve the ENDPOINT key of one ProgramCache entry (D-83).
 *
 * A destination that is a published endpoint of this node depends on its own
 * key. A destination that is not depends on the reserved `::` key, which is
 * the revision of the statement "this destination is not a published
 * endpoint": without it a negative entry compiled because the destination was
 * absent would never be invalidated by the destination *appearing*.
 *
 * A withdrawn key (present == 0) is not a published endpoint any more, so it
 * resolves to `::` as well. Its slot is kept — it still holds the high water
 * mark for the entries that quote it — but it is no longer the key a fresh
 * compile depends on.
 *
 * The key is resolved here rather than quoted by the agent, which is what makes
 * "a negative Program MUST NOT quote a real destination's positive revision"
 * unexpressible: an entry for a destination that is not published resolves to
 * `::` whatever the agent believed, and the exact-match comparison then refuses
 * a quotation of the destination's own revision.
 *
 * `*is_absence_key`, when not NULL, reports whether the answer is the reserved
 * ENDPOINT_ABSENCE_REVISION key rather than the destination's own key. Callers
 * use it to refuse a positive Program that resolved to `::`.
 */
static u32
csh_endpoint_rev_resolve (cilium_srv6_headend_main_t *hm, const ip6_address_t *dst,
			  int *is_absence_key)
{
  ip6_address_t absent;
  u32 slot;

  slot = csh_endpoint_rev_slot_find (hm, dst);
  if (slot != CSH_ENDPOINT_REV_SENTINEL && hm->endpoint_rev[slot].present)
    {
      if (is_absence_key)
	*is_absence_key = 0;
      return slot;
    }

  if (is_absence_key)
    *is_absence_key = 1;

  clib_memset (&absent, 0, sizeof (absent));
  return csh_endpoint_rev_slot_find (hm, &absent);
}

/*
 * policy_lease_touch: the one lease refresh operation of D-51 (00 §2.1,
 * 02 §5.4).
 *
 * A lease is not "srv6_lease_extend arrived". It is evidence that a control
 * plane whose policy watcher is healthy was recently active for this
 * {identity, revision}. Four health-gated control-plane operations produce
 * that evidence, and they are the same operation, not one rule plus three
 * exceptions:
 *
 *   srv6_lease_extend             periodic bulk refresh, `may_shorten` set:
 *                                 the length it carries is the agent's
 *                                 configured lease and letting it govern is
 *                                 what makes a reconfigured (shorter) lease
 *                                 take effect within one push interval.
 *   srv6_program_add_del(ALLOW)   opportunistic refresh on a decision commit.
 *   srv6_ct_verify (success)      opportunistic refresh on a reauthorization
 *                                 commit.
 *   srv6_fragment_verdict_add     installation-time refresh on the fourth
 *     (ALLOW)                     policy-dependent state installation path
 *                                 (Issue #83). Same grounds as the ALLOW
 *                                 install: it is a decision commit that the
 *                                 agent only emits with healthy watchers and
 *                                 that this node re-validates the revision of.
 *
 * srv6_program_add_del(DENY) and srv6_fragment_verdict_add(DENY) have no
 * refresh path at all: a DENY is fail-safe and consults no lease, so nothing
 * is gained by giving the lease one more writer.
 *
 * All four obey the same rules, which is why they are enforced here instead
 * of at each call site (Issue #61 invariant 1, "no lease regression by a stale
 * revision"):
 *
 *   1. the slot must still belong to `identity`. A slot released and handed to
 *      another identity must not inherit a refresh aimed at the old one.
 *   2. the sentinel revision is never leasable.
 *   3. `revision` must be the revision this node currently publishes for that
 *      identity. An operation decided under an older revision — a
 *      program_add_del(revision=42) delayed behind a publish that moved the
 *      identity to 43 — refreshes nothing. Each caller already refuses such a
 *      message, and repeating the comparison here is what makes the rule a
 *      property of the table rather than of three call sites.
 *   4. the lease revision never moves backwards. Rule 3 implies this while
 *      `policy_revision` is monotonic (srv6_policy_revision_publish enforces that),
 *      but the invariant is stated as its own rule, so it is checked rather
 *      than assumed: a regression would re-validate decisions taken under a
 *      superseded revision.
 *
 * Store order matters. `lease_valid_until` is written first and
 * `lease_revision` second, so that a worker reading the pair without a lock
 * can observe either the old pair, the new pair, or {old revision, new
 * deadline} — never {new revision, old deadline}. The first two are correct;
 * the third would validate a decision under the new revision using a deadline
 * that was granted for the old one, which is the only combination that could
 * be more permissive than either complete state. Both fields are naturally
 * aligned 8 byte values that the hot path only reads, so no barrier is
 * needed.
 *
 * Returns 1 when the lease was refreshed, 0 when the operation was ignored.
 */
static int
csh_policy_lease_touch (cilium_srv6_headend_main_t *hm, u32 slot, u32 identity, u64 revision,
			f64 until, int may_shorten)
{
  cilium_srv6_policy_rev_t *r;

  if (slot == CSH_POLICY_REV_SENTINEL || slot >= vec_len (hm->policy_rev))
    return 0;

  if (pool_is_free_index (hm->policy_rev, slot))
    return 0;

  r = hm->policy_rev + slot;

  /* Rules 1 and 2. */
  if (r->identity != identity || revision == CILIUM_SRV6_REV_INVALID)
    return 0;

  /* Rule 3: only the currently published revision may be vouched for. */
  if (r->policy_revision != revision)
    return 0;

  /* Rule 4: never regress the lease revision. */
  if (r->lease_revision != CILIUM_SRV6_REV_INVALID && r->lease_revision > revision)
    return 0;

  if (may_shorten || r->lease_valid_until < until)
    r->lease_valid_until = until;

  r->lease_revision = revision;

  return 1;
}

/*
 * The opportunistic refresh, for a caller outside this file (srv6_ct_verify in
 * cilium_srv6_ct.c). It is the same operation as the bulk push, minus the
 * permission to shorten.
 */
void
cilium_srv6_policy_lease_touch (u32 slot, u32 identity, u64 revision, u32 lease_ms)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_main_t *vm = vlib_get_main ();

  if (!hm->initialised)
    return;

  if (lease_ms == 0)
    lease_ms = hm->allow_lease_ms;

  csh_policy_lease_touch (hm, slot, identity, revision, vlib_time_now (vm) + (f64) lease_ms * 1e-3,
			  0 /* may_shorten */);
}

/* ------------------------------------------------------------------ */
/* PathMtuTable slots (D-21)                                           */
/* ------------------------------------------------------------------ */

/*
 * One slot per path_id, shared by every PathCache generation of that path, so
 * that "path_id が同一なら PathMtuTable の学習値は引き継ぐ" holds across a
 * republish and the value is dropped once the last entry of that path_id is
 * gone.
 */
static u32
csh_path_mtu_ref (cilium_srv6_headend_main_t *hm, u64 path_id)
{
  clib_bihash_kv_8_8_t kv;
  cilium_srv6_path_mtu_t *m;
  u32 index;

  kv.key = path_id;
  kv.value = 0;

  if (0 == clib_bihash_search_8_8 (&hm->path_mtu_table, &kv, &kv))
    {
      index = (u32) kv.value;
      if (!pool_is_free_index (hm->path_mtus, index))
	{
	  hm->path_mtus[index].refcount++;
	  return index;
	}
    }

  if (pool_free_elts (hm->path_mtus) == 0)
    return ~0;

  pool_get_zero (hm->path_mtus, m);
  index = (u32) (m - hm->path_mtus);

  m->path_id = path_id;
  m->effective_mtu = 0; /* nothing learned yet */
  m->refcount = 1;

  kv.key = path_id;
  kv.value = index;
  if (clib_bihash_add_del_8_8 (&hm->path_mtu_table, &kv, 1 /* add */) < 0)
    {
      pool_put_index (hm->path_mtus, index);
      return ~0;
    }

  return index;
}

static void
csh_path_mtu_unref (cilium_srv6_headend_main_t *hm, u32 index)
{
  clib_bihash_kv_8_8_t kv;
  cilium_srv6_path_mtu_t *m;

  if (index >= hm->path_capacity || pool_is_free_index (hm->path_mtus, index))
    return;

  m = hm->path_mtus + index;

  if (m->refcount > 0)
    m->refcount--;

  if (m->refcount != 0)
    return;

  kv.key = m->path_id;
  kv.value = index;
  clib_bihash_add_del_8_8 (&hm->path_mtu_table, &kv, 0 /* del */);

  clib_memset (m, 0, sizeof (*m));
  pool_put_index (hm->path_mtus, index);
}

/*
 * 02 §9: the PMTUD component narrows a path's MTU with a single atomic store;
 * the immutable PathCache entry is never rewritten. The clamping and the
 * "unusable below 1280" rule live in that component, so this entry point only
 * enforces the invariants the table itself must keep.
 */
int
cilium_srv6_path_mtu_update (u64 path_id, u16 effective_mtu, f64 decay_seconds)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  clib_bihash_kv_8_8_t kv;
  cilium_srv6_path_mtu_t *m;
  f64 now;
  u32 index;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  /* 0 clears the learned value (decay, 02 §9) and
     CILIUM_SRV6_PATH_MTU_UNUSABLE marks the path unusable; every other value
     is a learned inner MTU and must be a legal IPv6 MTU. */
  if (effective_mtu != 0 && effective_mtu != CILIUM_SRV6_PATH_MTU_UNUSABLE &&
      effective_mtu < CILIUM_SRV6_MIN_IPV6_MTU)
    return VNET_API_ERROR_INVALID_VALUE;

  kv.key = path_id;
  kv.value = 0;
  if (clib_bihash_search_8_8 (&hm->path_mtu_table, &kv, &kv))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  index = (u32) kv.value;
  if (index >= hm->path_capacity || pool_is_free_index (hm->path_mtus, index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  now = vlib_time_now (vlib_get_main ());
  m = hm->path_mtus + index;

  m->learned_at = now;
  m->decay_at = now + decay_seconds;

  /* Single aligned store; the hot path reads it without any lock (D-21). */
  clib_atomic_store_rel_n (&m->effective_mtu, effective_mtu);

  return 0;
}

/* ------------------------------------------------------------------ */
/* PathCache (02 §4.4, D-12)                                           */
/* ------------------------------------------------------------------ */

/*
 * 01 §2.4 / §2.5 / §3.2: an SRH that goes on the wire verbatim is validated
 * once, here, so that the encap node can copy it without inspecting it per
 * packet. The template is the Reduced SRH of D-62.
 */
static int
csh_srh_template_ok (const u8 *srh, u32 len)
{
  const ip6_sr_header_t *h = (const ip6_sr_header_t *) srh;
  u32 declared, seg_bytes;

  if (len < 8 || (len & 7) != 0 || len > CILIUM_SRV6_PATH_MAX_SRH_BYTES)
    return 0;

  /* Hdr Ext Len is in 8 octet units and excludes the first 8 octets. */
  declared = ((u32) h->length + 1) << 3;
  if (declared != len)
    return 0;

  if (h->type != ROUTING_HEADER_TYPE_SR)
    return 0;

  /* 01 §3: the SRH is followed by the inner IPv6 packet. */
  if (h->protocol != IP_PROTOCOL_IPV6)
    return 0;

  /* Last Entry is the zero based index of the last segment. */
  seg_bytes = ((u32) h->last_entry + 1) << 4;
  if (8 + seg_bytes > len)
    return 0;

  /*
   * RFC 8754 §4.3.1.1 makes an SRH malformed only when
   * Segments Left > Last Entry + 1; that is the one condition an endpoint
   * treats as a parameter problem. Segments Left == Last Entry + 1 is the
   * legal upper bound and is exactly what a Reduced SRH carries: the first
   * segment of the SR Policy is in the destination address and is left out
   * of the Segment List (RFC 8754 §4.1), so the list is one shorter than the
   * segment count while Segments Left still counts the segments that remain.
   *
   * 01 §2.4 / §2.5 (D-62) make that the template this headend emits, so
   * rejecting it would reject the only SRH the design produces. The typical
   * <transit container, Service SID> pair gives Last Entry = 0 and
   * Segments Left = 1: the last transit endpoint decrements it to 0 and
   * loads the Service SID into the destination address. An SRH built with
   * Segments Left == Last Entry instead would make that node stop SRH
   * processing and decapsulate one hop early (Issue #99).
   *
   * The bound stays: Segments Left == Last Entry + 2 is still refused, and
   * the addition is done in u32 so that last_entry == 255 does not wrap.
   */
  if ((u32) h->segments_left > (u32) h->last_entry + 1)
    return 0;

  return 1;
}

/*
 * The specification of a path is everything the caller supplies; the index,
 * the generation, the PathMtuTable slot and the state are the plugin's. Two
 * entries are the same path exactly when their specifications are equal,
 * which is what lets a republication keep the handle of a path that did not
 * change (D-61).
 */
static int
csh_path_spec_validate (const cilium_srv6_path_spec_t *spec)
{
  if (ip6_address_is_zero (&spec->da_template))
    return VNET_API_ERROR_INVALID_VALUE;

  /* 00 §4.1: every declared length is validated before it is used. */
  if (spec->srh_len > CILIUM_SRV6_PATH_MAX_SRH_BYTES)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (spec->srh_len != 0 && !csh_srh_template_ok (spec->srh_template, spec->srh_len))
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (spec->n_shift_states > CILIUM_SRV6_PATH_MAX_SHIFT_STATES)
    return VNET_API_ERROR_INVALID_VALUE_3;

  /*
   * 02 §9: base_mtu comes from the path configuration and is never rewritten.
   * A path whose inner MTU is already below the IPv6 minimum is unusable and
   * is refused rather than installed as a black hole.
   */
  if (spec->base_mtu < CILIUM_SRV6_MIN_IPV6_MTU)
    return VNET_API_ERROR_INVALID_VALUE_4;

  return 0;
}

static int
csh_path_spec_eq (const cilium_srv6_path_spec_t *a, const cilium_srv6_path_spec_t *b)
{
  if (a->path_id != b->path_id || a->base_mtu != b->base_mtu || a->srh_len != b->srh_len ||
      a->n_shift_states != b->n_shift_states)
    return 0;

  if (!ip6_address_is_equal (&a->da_template, &b->da_template) ||
      !ip6_address_is_equal (&a->service_sid, &b->service_sid))
    return 0;

  if (a->srh_len != 0 && memcmp (a->srh_template, b->srh_template, a->srh_len) != 0)
    return 0;

  if (a->n_shift_states != 0 &&
      memcmp (a->expected_shift_states, b->expected_shift_states,
	      (uword) a->n_shift_states * sizeof (ip6_address_t)) != 0)
    return 0;

  return 1;
}

/*
 * A fingerprint of the fields csh_path_spec_eq compares, so that "is this
 * exact path published already" is a hash lookup rather than a scan of the
 * whole pool. It is only ever used to find a candidate: every hit is
 * confirmed with csh_path_spec_eq, so a collision costs a reuse opportunity
 * and nothing else. The padding of the specification struct is deliberately
 * not hashed.
 */
static u64
csh_path_spec_fingerprint (const cilium_srv6_path_spec_t *spec)
{
  u8 buf[8 + 16 + 16 + 4 + CILIUM_SRV6_PATH_MAX_SRH_BYTES +
	 CILIUM_SRV6_PATH_MAX_SHIFT_STATES * sizeof (ip6_address_t)];
  u32 off = 0;

  clib_memset (buf, 0, sizeof (buf));

  clib_memcpy_fast (buf + off, &spec->path_id, sizeof (spec->path_id));
  off += sizeof (spec->path_id);
  clib_memcpy_fast (buf + off, &spec->da_template, sizeof (spec->da_template));
  off += sizeof (spec->da_template);
  clib_memcpy_fast (buf + off, &spec->service_sid, sizeof (spec->service_sid));
  off += sizeof (spec->service_sid);
  clib_memcpy_fast (buf + off, &spec->base_mtu, sizeof (spec->base_mtu));
  off += sizeof (spec->base_mtu);
  buf[off++] = spec->srh_len;
  buf[off++] = spec->n_shift_states;

  if (spec->srh_len != 0)
    clib_memcpy_fast (buf + off, spec->srh_template, spec->srh_len);
  off += CILIUM_SRV6_PATH_MAX_SRH_BYTES;

  if (spec->n_shift_states != 0)
    clib_memcpy_fast (buf + off, spec->expected_shift_states,
		      (uword) spec->n_shift_states * sizeof (ip6_address_t));

  return (u64) hash_memory (buf, sizeof (buf), 0);
}

static void
csh_path_spec_from_entry (const cilium_srv6_path_t *p, cilium_srv6_path_spec_t *out)
{
  clib_memset (out, 0, sizeof (*out));

  out->path_id = p->path_id;
  out->da_template = p->da_template;
  out->service_sid = p->service_sid;
  out->base_mtu = p->base_mtu;
  out->srh_len = p->srh_len;
  out->n_shift_states = p->n_shift_states;

  if (p->srh_len != 0)
    clib_memcpy_fast (out->srh_template, p->srh_template, p->srh_len);
  if (p->n_shift_states != 0)
    clib_memcpy_fast (out->expected_shift_states, p->expected_shift_states,
		      (uword) p->n_shift_states * sizeof (ip6_address_t));
}

/*
 * Specification fingerprint -> published index. Only the first entry with a
 * given fingerprint is indexed, and an entry only removes the mapping it owns,
 * so the index never names a slot that is not the one it was built for.
 */
static void
csh_path_spec_index_add (cilium_srv6_headend_main_t *hm, u64 fp, u32 index)
{
  if (hm->path_spec_index == 0 || hash_get (hm->path_spec_index, fp) != 0)
    return;

  hash_set (hm->path_spec_index, fp, index);
}

static void
csh_path_spec_index_del (cilium_srv6_headend_main_t *hm, u64 fp, u32 index)
{
  uword *v;

  if (hm->path_spec_index == 0)
    return;

  v = hash_get (hm->path_spec_index, fp);
  if (v != 0 && (u32) v[0] == index)
    hash_unset (hm->path_spec_index, fp);
}

/* The published index carrying exactly this specification, or ~0. */
static u32
csh_path_spec_lookup (cilium_srv6_headend_main_t *hm, const cilium_srv6_path_spec_t *spec, u64 fp)
{
  cilium_srv6_path_spec_t cur;
  uword *v;
  u32 index;

  if (hm->path_spec_index == 0)
    return ~0;

  v = hash_get (hm->path_spec_index, fp);
  if (v == 0)
    return ~0;

  index = (u32) v[0];
  if (index >= hm->path_capacity || pool_is_free_index (hm->paths, index))
    return ~0;

  if (hm->paths[index].state != CILIUM_SRV6_PATH_PUBLISHED)
    return ~0;

  csh_path_spec_from_entry (hm->paths + index, &cur);
  if (!csh_path_spec_eq (&cur, spec))
    return ~0;

  return index;
}

/*
 * Reserve a free PathCache slot and the generation its next occupant will
 * carry. Nothing in the slot is written, so the reservation is invisible to
 * the workers: the slot is not PUBLISHED, so no handle resolves to it. This is
 * what makes "staging does not alter the worker-visible PathCache" (D-61)
 * true of the reservation as well as of the content.
 */
static int
csh_path_reserve (cilium_srv6_headend_main_t *hm, u32 *index_out, u32 *generation_out)
{
  cilium_srv6_path_t *p;
  u32 generation;

  if (pool_free_elts (hm->paths) == 0)
    return VNET_API_ERROR_LIMIT_EXCEEDED;

  pool_get (hm->paths, p);

  /*
   * The generation is per slot and survives a reclaim (csh_path_reclaim
   * wipes everything but this field), so a handle issued for a previous
   * occupant of the index can never match the new one (D-12).
   */
  generation = p->generation + 1;
  if (generation == 0)
    generation = 1;

  *index_out = (u32) (p - hm->paths);
  *generation_out = generation;

  return 0;
}

/*
 * Give a reservation back. The reserved generation is burned rather than
 * returned: a handle a staging put already reported must never name anything
 * else, so the slot's next occupant takes a further generation.
 */
static void
csh_path_unreserve (cilium_srv6_headend_main_t *hm, u32 index, u32 generation)
{
  cilium_srv6_path_t *p;

  if (index >= hm->path_capacity || pool_is_free_index (hm->paths, index))
    return;

  p = hm->paths + index;

  clib_memset (p, 0, sizeof (*p));
  p->generation = generation;
  p->state = CILIUM_SRV6_PATH_FREE;

  pool_put_index (hm->paths, index);
}

/* Fill a reserved slot and make it reachable. The caller holds the barrier. */
static void
csh_path_entry_publish (cilium_srv6_headend_main_t *hm, u32 index, u32 generation, u32 mtu_index,
			const cilium_srv6_path_spec_t *spec, u64 fp)
{
  cilium_srv6_path_t *p = hm->paths + index;

  clib_memset (p, 0, sizeof (*p));

  p->path_id = spec->path_id;
  p->mtu_index = mtu_index;
  p->da_template = spec->da_template;
  p->service_sid = spec->service_sid;
  p->base_mtu = spec->base_mtu;
  p->srh_len = spec->srh_len;
  p->n_shift_states = spec->n_shift_states;

  if (spec->srh_len != 0)
    clib_memcpy_fast (p->srh_template, spec->srh_template, spec->srh_len);
  if (spec->n_shift_states != 0)
    clib_memcpy_fast (p->expected_shift_states, spec->expected_shift_states,
		      (uword) spec->n_shift_states * sizeof (ip6_address_t));

  p->generation = generation;

  /* The entry is complete before it becomes reachable (D-12). */
  CLIB_MEMORY_STORE_BARRIER ();
  p->state = CILIUM_SRV6_PATH_PUBLISHED;

  csh_path_spec_index_add (hm, fp, index);
}

/*
 * Take a published entry out of the table and queue its index for the D-12
 * grace period. From here the handle no longer resolves
 * (cilium_srv6_path_get checks the state), so a packet that captured it punts
 * as a stale handle instead of being encapsulated with a path that is going
 * away. The caller holds the barrier.
 */
static void
csh_path_entry_retire (cilium_srv6_headend_main_t *hm, u32 index, f64 now)
{
  cilium_srv6_path_spec_t cur;
  cilium_srv6_path_pending_t *pend;
  cilium_srv6_path_t *p = hm->paths + index;

  csh_path_spec_from_entry (p, &cur);
  csh_path_spec_index_del (hm, csh_path_spec_fingerprint (&cur), index);

  p->state = CILIUM_SRV6_PATH_RETIRED;

  /*
   * D-83: the PATH revision key dies with the entry. Clearing it here rather
   * than waiting for the reclaim is what makes "the key does not exist" and
   * "the handle does not resolve" become true at the same instant, so an
   * install racing the retirement cannot be accepted against a revision whose
   * handle has already gone.
   */
  if (index < vec_len (hm->path_revs))
    hm->path_revs[index] = CILIUM_SRV6_REV_ABSENT;

  /* D-12: the index is not reusable until every worker that could still hold
     it is quiescent. */
  vec_add2 (hm->path_pending, pend, 1);
  pend->path_index = index;
  pend->mtu_index = p->mtu_index;
  pend->free_after = now + hm->grace_period;
}

int
cilium_srv6_path_add (u64 path_id, const ip6_address_t *da_template,
		      const ip6_address_t *service_sid, u16 base_mtu, const u8 *srh, u32 srh_len,
		      const ip6_address_t *shift_states, u32 n_shift_states, u32 *path_index_out,
		      u32 *generation_out)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_main_t *vm = vlib_get_main ();
  cilium_srv6_path_spec_t spec;
  u32 index, mtu_index, generation;
  u64 fp;
  int taken, rv;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  /* D-61: the single-entry API and a staging transaction would install two
     different desired tables. While one is open this one is refused, so the
     staging table is always a function of the table the commit found. */
  if (hm->path_txn_id != 0)
    return VNET_API_ERROR_INSTANCE_IN_USE;

  if (da_template == NULL || service_sid == NULL)
    return VNET_API_ERROR_INVALID_VALUE;

  if (srh_len > CILIUM_SRV6_PATH_MAX_SRH_BYTES)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (srh_len != 0 && srh == NULL)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (n_shift_states > CILIUM_SRV6_PATH_MAX_SHIFT_STATES)
    return VNET_API_ERROR_INVALID_VALUE_3;

  clib_memset (&spec, 0, sizeof (spec));
  spec.path_id = path_id;
  spec.da_template = *da_template;
  spec.service_sid = *service_sid;
  spec.base_mtu = base_mtu;
  spec.srh_len = (u8) srh_len;
  spec.n_shift_states = (u8) n_shift_states;
  if (srh_len != 0)
    clib_memcpy_fast (spec.srh_template, srh, srh_len);
  if (n_shift_states != 0)
    clib_memcpy_fast (spec.expected_shift_states, shift_states,
		      (uword) n_shift_states * sizeof (ip6_address_t));

  rv = csh_path_spec_validate (&spec);
  if (rv != 0)
    return rv;

  mtu_index = csh_path_mtu_ref (hm, path_id);
  if (mtu_index == (u32) ~0)
    return VNET_API_ERROR_LIMIT_EXCEEDED;

  rv = csh_path_reserve (hm, &index, &generation);
  if (rv != 0)
    {
      csh_path_mtu_unref (hm, mtu_index);
      return rv;
    }

  fp = csh_path_spec_fingerprint (&spec);

  taken = cilium_srv6_barrier_acquire (vm);
  csh_path_entry_publish (hm, index, generation, mtu_index, &spec, fp);
  cilium_srv6_barrier_release (vm, taken);

  if (path_index_out)
    *path_index_out = index;
  if (generation_out)
    *generation_out = generation;

  return 0;
}

int
cilium_srv6_path_del (u32 path_index, u32 generation)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_main_t *vm = vlib_get_main ();
  cilium_srv6_path_t *p;
  f64 now;
  int taken;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  /* D-61: see cilium_srv6_path_add. */
  if (hm->path_txn_id != 0)
    return VNET_API_ERROR_INSTANCE_IN_USE;

  if (path_index >= hm->path_capacity || pool_is_free_index (hm->paths, path_index))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  p = hm->paths + path_index;

  if (p->state != CILIUM_SRV6_PATH_PUBLISHED || p->generation != generation)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  now = vlib_time_now (vm);

  taken = cilium_srv6_barrier_acquire (vm);
  csh_path_entry_retire (hm, path_index, now);
  cilium_srv6_barrier_release (vm, taken);

  return 0;
}

/* ------------------------------------------------------------------ */
/* PathCache staging transaction (D-61, Issue #99)                     */
/* ------------------------------------------------------------------ */

/*
 * Drop the bookkeeping of the transaction that is closing. It does not
 * release reservations: commit turns them into published entries and abort
 * releases them, and doing it here as well would either publish nothing or
 * free a slot that is now reachable.
 */
static void
csh_path_txn_reset (cilium_srv6_headend_main_t *hm)
{
  cilium_srv6_path_staged_t *st;

  vec_foreach (st, hm->path_staged)
    {
      if (st->path_index < hm->path_capacity)
	hm->path_claimed[st->path_index] = 0;
    }

  vec_reset_length (hm->path_staged);

  if (hm->path_staged_by_client != 0)
    hash_free (hm->path_staged_by_client);
  if (hm->path_staged_by_spec != 0)
    hash_free (hm->path_staged_by_spec);

  hm->path_staged_by_client = hash_create (0, sizeof (uword));
  hm->path_staged_by_spec = hash_create (0, sizeof (uword));

  hm->path_txn_reserved = 0;
  hm->path_txn_id = 0;
}

/* Release every reservation the open transaction holds. */
static void
csh_path_txn_release (cilium_srv6_headend_main_t *hm)
{
  cilium_srv6_path_staged_t *st;

  vec_foreach (st, hm->path_staged)
    {
      if (st->reused)
	continue;

      csh_path_unreserve (hm, st->path_index, st->generation);
      csh_path_mtu_unref (hm, st->mtu_index);
    }
}

int
cilium_srv6_path_txn_begin (u64 txn_id)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  /* 0 is the reserved "no transaction" value of hm->path_txn_id. */
  if (txn_id == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  /* A repeated begin for the transaction that is already open keeps its
     staging table, so a lost reply costs nothing. */
  if (hm->path_txn_id == txn_id)
    return 0;

  if (hm->path_txn_id != 0)
    return VNET_API_ERROR_INSTANCE_IN_USE;

  /* Reusing the identity of the transaction that committed last would make a
     commit retry indistinguishable from a new publication. */
  if (txn_id == hm->path_txn_committed)
    return VNET_API_ERROR_VALUE_EXIST;

  csh_path_txn_reset (hm);
  hm->path_txn_id = txn_id;

  return 0;
}

int
cilium_srv6_path_txn_put (u64 txn_id, u64 client_path_id, const cilium_srv6_path_spec_t *spec,
			  u32 *path_index_out, u32 *generation_out)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  cilium_srv6_path_staged_t *st;
  u32 index, generation, mtu_index, slot;
  u64 fp;
  uword *v;
  u8 reused;
  int rv;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (spec == NULL)
    return VNET_API_ERROR_INVALID_VALUE;

  if (txn_id == 0 || hm->path_txn_id == 0 || hm->path_txn_id != txn_id)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  rv = csh_path_spec_validate (spec);
  if (rv != 0)
    return rv;

  fp = csh_path_spec_fingerprint (spec);

  /*
   * Operation identity (D-61): the same put repeated returns the same handle,
   * which is what makes a lost reply retryable. The plugin infers nothing else
   * from a matching client_path_id — a different specification under the same
   * identity is a different operation and is refused.
   */
  v = hash_get (hm->path_staged_by_client, client_path_id);
  if (v != 0)
    {
      st = hm->path_staged + v[0];

      if (!csh_path_spec_eq (&st->spec, spec))
	return VNET_API_ERROR_VALUE_EXIST;

      if (path_index_out)
	*path_index_out = st->path_index;
      if (generation_out)
	*generation_out = st->generation;
      return 0;
    }

  /* Two entries of one desired table cannot be the same path. */
  v = hash_get (hm->path_staged_by_spec, fp);
  if (v != 0 && csh_path_spec_eq (&hm->path_staged[v[0]].spec, spec))
    return VNET_API_ERROR_VALUE_EXIST;

  /*
   * D-12 reuse: a path whose specification did not change keeps its handle,
   * so republishing an unchanged table invalidates nothing. Anything else
   * takes a slot that is free right now, never the index of an entry this
   * commit is about to retire.
   */
  index = csh_path_spec_lookup (hm, spec, fp);
  if (index != (u32) ~0 && hm->path_claimed[index] != 0)
    index = ~0;

  if (index != (u32) ~0)
    {
      generation = hm->paths[index].generation;
      mtu_index = hm->paths[index].mtu_index;
      reused = 1;
    }
  else
    {
      /*
       * D-21: the PathMtuTable reference is taken here rather than at commit
       * time, exactly as cilium_srv6_path_add takes it before its barrier, so
       * that the commit cannot fail on an allocation.
       */
      mtu_index = csh_path_mtu_ref (hm, spec->path_id);
      if (mtu_index == (u32) ~0)
	return VNET_API_ERROR_LIMIT_EXCEEDED;

      rv = csh_path_reserve (hm, &index, &generation);
      if (rv != 0)
	{
	  csh_path_mtu_unref (hm, mtu_index);
	  return rv;
	}
      reused = 0;
      hm->path_txn_reserved++;
    }

  slot = vec_len (hm->path_staged);
  vec_add2 (hm->path_staged, st, 1);

  clib_memset (st, 0, sizeof (*st));
  st->client_path_id = client_path_id;
  st->spec_fp = fp;
  st->path_index = index;
  st->generation = generation;
  st->mtu_index = mtu_index;
  st->reused = reused;
  st->spec = *spec;

  if (reused)
    hm->path_claimed[index] = 1;

  hash_set (hm->path_staged_by_client, client_path_id, slot);
  if (hash_get (hm->path_staged_by_spec, fp) == 0)
    hash_set (hm->path_staged_by_spec, fp, slot);

  if (path_index_out)
    *path_index_out = index;
  if (generation_out)
    *generation_out = generation;

  return 0;
}

int
cilium_srv6_path_txn_commit (u64 txn_id)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_main_t *vm = vlib_get_main ();
  cilium_srv6_path_spec_t cur;
  cilium_srv6_path_staged_t *st;
  cilium_srv6_path_t *p;
  f64 now;
  u32 i;
  int taken;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (txn_id == 0)
    return VNET_API_ERROR_INVALID_VALUE;

  if (hm->path_txn_id == 0)
    {
      /* A commit whose reply was lost: the snapshot it installed is still the
	 active one and the handles its puts returned still name the same
	 entries, so repeating it changes nothing. */
      if (txn_id == hm->path_txn_committed)
	return 0;
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  if (hm->path_txn_id != txn_id)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  /*
   * Validate the staging table as a whole before anything is installed. The
   * content of every entry was validated when it was staged; what is checked
   * here is that every kept handle still names the entry it was matched
   * against. Failing here leaves the published table untouched and the
   * transaction open, so the caller can abort it.
   */
  vec_foreach (st, hm->path_staged)
    {
      if (!st->reused)
	continue;

      if (st->path_index >= hm->path_capacity || pool_is_free_index (hm->paths, st->path_index))
	return VNET_API_ERROR_INVALID_VALUE;

      p = hm->paths + st->path_index;
      if (p->state != CILIUM_SRV6_PATH_PUBLISHED || p->generation != st->generation)
	return VNET_API_ERROR_INVALID_VALUE;

      csh_path_spec_from_entry (p, &cur);
      if (!csh_path_spec_eq (&cur, &st->spec))
	return VNET_API_ERROR_INVALID_VALUE;
    }

  now = vlib_time_now (vm);

  taken = cilium_srv6_barrier_acquire (vm);

  /*
   * Retiring what the staging table does not keep and publishing what it
   * reserved happen in this one barrier section, so a worker observes the
   * previous complete table or the new complete table and never a mixture of
   * the two.
   */
  pool_foreach_index (i, hm->paths)
    {
      if (hm->paths[i].state != CILIUM_SRV6_PATH_PUBLISHED || hm->path_claimed[i] != 0)
	continue;

      csh_path_entry_retire (hm, i, now);
    }

  vec_foreach (st, hm->path_staged)
    {
      if (st->reused)
	continue;

      csh_path_entry_publish (hm, st->path_index, st->generation, st->mtu_index, &st->spec,
			      st->spec_fp);
    }

  cilium_srv6_barrier_release (vm, taken);

  csh_path_txn_reset (hm);
  hm->path_txn_committed = txn_id;

  return 0;
}

int
cilium_srv6_path_txn_abort (u64 txn_id)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  /*
   * txn_id 0 is the recovery form: it discards whatever transaction is open
   * and succeeds when there is none. An agent that restarted does not know
   * the identity of the transaction its predecessor left behind, and an
   * abandoned staging table must not be able to block publication forever.
   * Discarding it is always safe because nothing staged is published.
   */
  if (txn_id != 0 && (hm->path_txn_id == 0 || hm->path_txn_id != txn_id))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (hm->path_txn_id == 0)
    return 0;

  csh_path_txn_release (hm);
  csh_path_txn_reset (hm);

  return 0;
}

/* Reclaim retired PathCache indices whose grace period elapsed. */
static u32
csh_path_reclaim (vlib_main_t *vm, f64 now)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  u32 n = 0;
  int taken;

  if (vec_len (hm->path_pending) == 0 || hm->path_pending[0].free_after > now)
    return 0;

  taken = cilium_srv6_barrier_acquire (vm);

  while (n < vec_len (hm->path_pending) && n < CILIUM_SRV6_HEADEND_RECLAIM_PER_TICK &&
	 hm->path_pending[n].free_after <= now)
    {
      cilium_srv6_path_pending_t *pend = hm->path_pending + n;

      if (!pool_is_free_index (hm->paths, pend->path_index))
	{
	  cilium_srv6_path_t *p = hm->paths + pend->path_index;
	  u32 generation = p->generation;

	  /* Wipe everything but the generation: a stale reader that beat the
	     grace period must not find a usable handle, and the next install
	     in this slot must not be able to reuse the retired generation. */
	  clib_memset (p, 0, sizeof (*p));
	  p->generation = generation;
	  p->state = CILIUM_SRV6_PATH_FREE;

	  pool_put_index (hm->paths, pend->path_index);
	}

      csh_path_mtu_unref (hm, pend->mtu_index);
      n++;
    }

  vec_delete (hm->path_pending, n, 0);

  cilium_srv6_barrier_release (vm, taken);

  return n;
}

/* ------------------------------------------------------------------ */
/* ProgramCache quota accounting and eviction (02 §5.3, D-26, D-42)    */
/* ------------------------------------------------------------------ */

static void
csh_count_add (uword **h, u32 key, int delta)
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
csh_count_get (uword *h, u32 key)
{
  uword *p = hash_get (h, (uword) key);

  return p ? p[0] : 0;
}

/*
 * D-42 soft quota, computed the same way the tombstone store computes its
 * own: the budget of one class is its share of the pool among the classes
 * that currently hold entries. It is soft — a class may exceed it while the
 * pool has room — and only decides who is evicted when the pool is full.
 */
static u32
csh_soft_quota (u32 capacity, u32 n_classes)
{
  if (n_classes < 1)
    n_classes = 1;

  return clib_max (1, capacity / n_classes);
}

/* budget index: 1 = ALLOW, 0 = negative (DENY). */
static inline u32
csh_budget_of (u8 verdict)
{
  return verdict == CILIUM_SRV6_VERDICT_ALLOW ? 1 : 0;
}

static void
csh_prog_age_append (cilium_srv6_headend_main_t *hm, u32 budget, u32 index)
{
  cilium_srv6_program_t *e = hm->programs + index;

  e->age_next = ~0;
  e->age_prev = hm->prog_age_tail[budget];

  if (hm->prog_age_tail[budget] != (u32) ~0)
    hm->programs[hm->prog_age_tail[budget]].age_next = index;
  else
    hm->prog_age_head[budget] = index;

  hm->prog_age_tail[budget] = index;
}

static void
csh_prog_age_remove (cilium_srv6_headend_main_t *hm, u32 budget, u32 index)
{
  cilium_srv6_program_t *e = hm->programs + index;

  if (e->age_prev != (u32) ~0)
    hm->programs[e->age_prev].age_next = e->age_next;
  else
    hm->prog_age_head[budget] = e->age_next;

  if (e->age_next != (u32) ~0)
    hm->programs[e->age_next].age_prev = e->age_prev;
  else
    hm->prog_age_tail[budget] = e->age_prev;

  e->age_prev = e->age_next = ~0;
}

/* Remove one entry from every index it appears in. Worker barrier held. */
static void
csh_program_remove (cilium_srv6_headend_main_t *hm, u32 index)
{
  cilium_srv6_program_t *e = hm->programs + index;
  clib_bihash_kv_24_8_t kv;
  u32 budget = csh_budget_of (e->verdict);

  kv.key[0] = e->key[0];
  kv.key[1] = e->key[1];
  kv.key[2] = e->key[2];
  kv.value = index;
  clib_bihash_add_del_24_8 (&hm->program_table, &kv, 0 /* del */);

  csh_prog_age_remove (hm, budget, index);
  csh_count_add (&hm->prog_owner_count, e->owner_quota_class, -1);
  csh_count_add (&hm->prog_identity_count, e->src_identity, -1);
  csh_policy_rev_slot_unref (hm, e->policy_rev_slot);
  csh_endpoint_rev_slot_unref (hm, e->endpoint_rev_slot);

  if (hm->n_programs[budget] > 0)
    hm->n_programs[budget]--;

  clib_memset (e, 0, sizeof (*e));
  e->age_prev = e->age_next = ~0;

  pool_put_index (hm->programs, index);
}

/*
 * Fair eviction (02 §5.3 / D-26 / D-42). Bounded scan from the oldest entry
 * of the budget being filled:
 *
 *   1. prefer an entry whose owner *and* identity are over their soft quota,
 *   2. then an entry whose owner is over its soft quota,
 *   3. otherwise the oldest entry of the budget,
 *
 * and inside a preference class the smallest last_used wins. That is the
 * design's "quota 超過が最大の owner -> その中で最大の identity から
 * last_used 順" reduced to constant work per install: an entry belonging to
 * an owner and identity that are both within quota is only ever evicted when
 * nothing over quota exists in the scan window, which is what keeps one
 * tenant's high-cardinality keys from displacing another tenant.
 *
 * Returns 1 if an entry was evicted. Worker barrier held.
 */
static int
csh_program_evict_one (cilium_srv6_headend_main_t *hm, u32 budget)
{
  /*
   * The per-owner and per-identity counts are pool-wide (one entry counts
   * once, whichever budget it is in), so the quota they are compared against
   * is derived from the pool-wide capacity as well. Using the per-budget
   * capacity here would compare a pool-wide numerator with a per-budget
   * denominator and put almost every entry over quota, which would collapse
   * the ranking below into a plain LRU.
   */
  u32 owner_quota =
    csh_soft_quota (hm->program_capacity, (u32) hash_elts (hm->prog_owner_count));
  u32 identity_quota =
    csh_soft_quota (hm->program_capacity, (u32) hash_elts (hm->prog_identity_count));
  u32 index = hm->prog_age_head[budget];
  u32 victim = ~0;
  u32 best_rank = 0;
  f64 best_last_used = 0;
  u32 n;

  for (n = 0; n < CILIUM_SRV6_PROGRAM_EVICT_SCAN && index != (u32) ~0; n++)
    {
      const cilium_srv6_program_t *e = hm->programs + index;
      u32 rank = 1; /* within quota */

      if (csh_count_get (hm->prog_owner_count, e->owner_quota_class) > owner_quota)
	rank = (csh_count_get (hm->prog_identity_count, e->src_identity) > identity_quota) ? 3 : 2;

      if (victim == (u32) ~0 || rank > best_rank ||
	  (rank == best_rank && e->last_used < best_last_used))
	{
	  victim = index;
	  best_rank = rank;
	  best_last_used = e->last_used;
	}

      index = e->age_next;
    }

  if (victim == (u32) ~0)
    return 0;

  csh_program_remove (hm, victim);
  hm->n_program_fair_evictions++;

  return 1;
}

/* ------------------------------------------------------------------ */
/* srv6_program_add_del (02 §4, §8)                                    */
/* ------------------------------------------------------------------ */

int
cilium_srv6_program_add_del (u32 src_identity, const ip6_address_t *dst, u8 proto,
			     u16 l4_discriminator, u8 verdict, u8 action, u64 policy_revision,
			     u64 endpoint_revision, u64 path_revision, u32 path_cache_index,
			     u32 path_generation, u32 target_sw_if_index, u32 target_if_incarnation,
			     u32 target_identity, u32 owner_quota_class, u8 is_add)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_main_t *gm = &cilium_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  clib_bihash_kv_24_8_t kv;
  cilium_srv6_program_t *e;
  u64 key[3];
  u32 index, budget, capacity, slot, endpoint_slot;
  f64 now;
  int taken;
  int endpoint_key_is_absence = 0;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  /*
   * D-83 / errata #34 item 153: `::` MUST NOT represent a real endpoint
   * revision key and MUST be accepted only as the reserved endpoint-absence
   * revision key. A ProgramCache entry whose destination is `::` would make it
   * one, because the ENDPOINT key of an entry is its destination.
   */
  if (dst == NULL || ip6_address_is_zero (dst))
    return VNET_API_ERROR_INVALID_VALUE;

  if (verdict != CILIUM_SRV6_VERDICT_ALLOW && verdict != CILIUM_SRV6_VERDICT_DENY)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (action != CILIUM_SRV6_ACTION_ENCAP && action != CILIUM_SRV6_ACTION_LOCAL_DELIVER)
    return VNET_API_ERROR_INVALID_VALUE_2;

  cilium_srv6_program_key (key, src_identity, dst, proto, l4_discriminator);

  kv.key[0] = key[0];
  kv.key[1] = key[1];
  kv.key[2] = key[2];
  kv.value = 0;

  if (!is_add)
    {
      if (clib_bihash_search_24_8 (&hm->program_table, &kv, &kv))
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      index = (u32) kv.value;
      if (index >= hm->program_capacity || pool_is_free_index (hm->programs, index))
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      taken = cilium_srv6_barrier_acquire (vm);
      csh_program_remove (hm, index);
      hm->n_program_deletes++;
      cilium_srv6_barrier_release (vm, taken);

      return 0;
    }

  /*
   * 02 §4.3: "compiler は ... VPP install 直前に再比較する。一つでも変化
   * したら結果を install せず再試行する". The plugin enforces the same
   * comparison on its own side, so a revision that moved between the agent's
   * last check and this message can never install an entry that claims a
   * revision the node is not currently publishing.
   *
   * D-83 makes that comparison per key. Each quoted revision is resolved in
   * its own namespace — POLICY by src_identity, ENDPOINT by dst (with the
   * reserved `::` key standing in for "dst is not a published endpoint") and
   * PATH by path_cache_index — and the install is accepted only when every
   * referenced key exists and every quotation matches it exactly.
   *
   * "Exists" is checked separately from "matches", and reported separately,
   * because the two mean different things to the agent: a mismatch is a lost
   * race that a recompile fixes, while a missing key means the mandatory
   * order of D-83 was violated (publish + ACK must precede the install) and a
   * recompile alone will loop forever.
   */
  slot = csh_policy_rev_slot_find (hm, src_identity);
  endpoint_slot = csh_endpoint_rev_resolve (hm, dst, &endpoint_key_is_absence);

  /*
   * D-83 / errata #34 item 153: a positive Program depends on the actual
   * destination's endpoint revision; only a negative Program may depend on
   * ENDPOINT_ABSENCE_REVISION. An ALLOW whose ENDPOINT key resolved to the
   * reserved `::` key is refused.
   *
   * This is checked before "does the key exist" and before the revision
   * comparison because it is neither a race nor a missing publication: this
   * node does not publish the destination as an endpoint at all, so there is
   * nothing to forward to, and no republication of any key turns the install
   * into a legal one. Reporting it as a stale install would make the agent
   * recompile forever; reporting it as a missing key would make an operator
   * look for a publication that is not the problem.
   *
   * The mirror rule — a negative Program MUST NOT quote a real destination's
   * positive revision — needs no check of its own: the ENDPOINT key is
   * resolved here from `dst` rather than quoted, so an entry for a destination
   * this node does not publish resolves to `::`, and the exact-match
   * comparison below refuses a quotation of the destination's own revision.
   */
  if (verdict == CILIUM_SRV6_VERDICT_ALLOW && endpoint_key_is_absence)
    {
      hm->n_program_absence_key_installs++;
      return VNET_API_ERROR_INVALID_DST_ADDRESS;
    }

  /*
   * D-80 / 00 §2.20 / 02 §4.3.1: the legal {verdict, action, path, target}
   * combinations are exhaustive, and the cross product is refused here.
   *
   *   DENY           ENCAP          NoPathIndex / 0    no target
   *   ALLOW          ENCAP          valid index / >0   no target
   *   ALLOW          LOCAL_DELIVER  NoPathIndex / 0    live (index, incarnation)
   *
   * A DENY for a local destination is an *ordinary* DENY: the ruling says the
   * verdict semantics of a local destination are identical to a remote one, so
   * there is no LOCAL_DELIVER DENY to express — the packet is dropped, and
   * nothing about the drop depends on which interface would have received it.
   * A LOCAL_DELIVER carrying a path would mean the entry both encapsulates and
   * delivers; an ENCAP carrying a target would mean an entry the delivery node
   * could act on if it were ever reached with the wrong action. Neither is a
   * race, so both are their own counter rather than a stale or missing-key
   * report.
   */
  {
    int has_target =
      (target_sw_if_index != 0 || target_if_incarnation != 0 || target_identity != 0);
    int illegal = 0;

    if (action == CILIUM_SRV6_ACTION_LOCAL_DELIVER)
      illegal = (verdict != CILIUM_SRV6_VERDICT_ALLOW || path_revision != CILIUM_SRV6_REV_ABSENT ||
		 path_cache_index != CILIUM_SRV6_NO_PATH_INDEX || path_generation != 0);
    else
      illegal = has_target;

    if (illegal)
      {
	hm->n_program_illegal_action_installs++;
	return VNET_API_ERROR_INVALID_ARGUMENT;
      }
  }

  /*
   * D-80: the local destination resolution authority is the LocalEndpoint
   * state, and this is where the plugin refuses to take the agent's word for
   * it. The target must name a *live* interface lifetime (D-31/D-68) that
   * currently carries exactly this destination:
   *
   *   - `cilium_srv6_local_ep_lookup` already fails when the stored
   *     incarnation is not the live one, so a reused sw_if_index resolves to
   *     nothing rather than to the new Pod;
   *   - the incarnation the caller quoted must be the one the table holds, so
   *     an install for a lifetime that ended is refused rather than aimed at
   *     whatever now holds the index;
   *   - the endpoint's address must be `dst`, which is the same check
   *     cilium_srv6_ct_deliver makes before creating delivery-side conntrack
   *     state (03 §6): an entry that would deliver a destination to an
   *     interface that does not hold it is a misdelivery, not a stale entry;
   *   - the identity must be the one the decision was taken against (D-69), so
   *     an identity change refuses the install instead of installing an
   *     authorisation for the previous identity.
   */
  if (action == CILIUM_SRV6_ACTION_LOCAL_DELIVER)
    {
      const cilium_srv6_local_ep_t *ep = cilium_srv6_local_ep_lookup (hm, gm, target_sw_if_index);

      if (ep == NULL || ep->if_incarnation != target_if_incarnation)
	{
	  hm->n_program_local_target_unbound++;
	  return VNET_API_ERROR_INVALID_INTERFACE;
	}
      if (!ip6_address_is_equal (&ep->ip, dst) || ep->identity != target_identity)
	{
	  hm->n_program_local_target_mismatch++;
	  return VNET_API_ERROR_INVALID_INTERFACE;
	}
    }

  {
    u64 cur_policy = cilium_srv6_policy_revision (hm, slot);
    u64 cur_endpoint = cilium_srv6_endpoint_revision (hm, endpoint_slot);
    u64 cur_path = cilium_srv6_path_revision (hm, path_cache_index);

    /* The sentinel is refused explicitly: without this a message carrying it
       would compare equal to a sentinel slot, install an entry that can never
       match a real revision, and take a reference for it. */
    if (policy_revision == CILIUM_SRV6_REV_INVALID ||
	endpoint_revision == CILIUM_SRV6_REV_INVALID || path_revision == CILIUM_SRV6_REV_INVALID)
      {
	hm->n_program_stale_installs++;
	return VNET_API_ERROR_INVALID_VALUE_3;
      }

    /*
     * D-85 (00 §2.23): a quotation from another agent process generation.
     *
     * It is checked before the per-key comparison below, because the two are
     * not the same fault and the per-key one cannot see this case at all: an
     * entry for a key the current agent process never republished still finds
     * the old value in the slot and would compare equal. Checking it here is
     * what makes "the agent that decided this is gone" refuse the install
     * without enumerating or deleting a single old key.
     *
     * A DENY's `path_revision == 0` is excluded, exactly as it is excluded from
     * the missing-key and per-key checks: it states "no path dependency" and is
     * not a member of the revision namespace.
     */
    if (cilium_srv6_revision_is_stale_incarnation (hm, policy_revision) ||
	cilium_srv6_revision_is_stale_incarnation (hm, endpoint_revision) ||
	cilium_srv6_revision_is_stale_incarnation (hm, path_revision))
      {
	hm->n_stale_incarnation_quotes++;
	hm->n_program_stale_installs++;
	return VNET_API_ERROR_INVALID_VALUE_3;
      }

    /* Missing key: fail-closed, and distinguishable from a stale quotation. A
       DENY quotes path_revision 0 ("no path dependency"), which is not a
       reference to a PATH key and is therefore not checked here. */
    if (cur_policy == CILIUM_SRV6_REV_INVALID || cur_policy == CILIUM_SRV6_REV_ABSENT ||
	cur_endpoint == CILIUM_SRV6_REV_INVALID || cur_endpoint == CILIUM_SRV6_REV_ABSENT ||
	(path_revision != CILIUM_SRV6_REV_ABSENT &&
	 (cur_path == CILIUM_SRV6_REV_INVALID || cur_path == CILIUM_SRV6_REV_ABSENT)))
      {
	hm->n_program_missing_key_installs++;
	return VNET_API_ERROR_INVALID_VALUE_4;
      }

    if (policy_revision != cur_policy || endpoint_revision != cur_endpoint ||
	(path_revision != CILIUM_SRV6_REV_ABSENT && path_revision != cur_path))
      {
	hm->n_program_stale_installs++;
	return VNET_API_ERROR_INVALID_VALUE_3;
      }

    /*
     * An ALLOW that *encapsulates* forwards on a path, so it must depend on
     * that path's key; a DENY must not (02 §4.3: an unrelated route flap may
     * not invalidate it), and neither must an ALLOW that delivers locally,
     * because it never resolves a PathCache entry at all (D-80). 02 §4.3.1
     * makes the legal combinations exhaustive:
     *
     *   DENY                   path_cache_index = NO_PATH_INDEX, path_revision = 0
     *   ALLOW + ENCAP          path_cache_index = a valid index, path_revision > 0
     *   ALLOW + LOCAL_DELIVER  path_cache_index = NO_PATH_INDEX, path_revision = 0
     *
     * and the cross product is refused here (the LOCAL_DELIVER row was already
     * enforced above, together with its target rules). Refusing it keeps the
     * hot path's "path_revision == 0 means no path dependency" rule exact, and
     * keeps an entry that must not reach the PathCache from naming an index.
     */
    if (verdict == CILIUM_SRV6_VERDICT_ALLOW && action == CILIUM_SRV6_ACTION_ENCAP &&
	(path_revision == CILIUM_SRV6_REV_ABSENT || path_cache_index == CILIUM_SRV6_NO_PATH_INDEX))
      {
	hm->n_program_missing_key_installs++;
	return VNET_API_ERROR_INVALID_VALUE_4;
      }
    if (verdict == CILIUM_SRV6_VERDICT_DENY &&
	(path_revision != CILIUM_SRV6_REV_ABSENT ||
	 path_cache_index != CILIUM_SRV6_NO_PATH_INDEX))
      {
	hm->n_program_stale_installs++;
	return VNET_API_ERROR_INVALID_VALUE_3;
      }
  }

  if (verdict == CILIUM_SRV6_VERDICT_ALLOW && action == CILIUM_SRV6_ACTION_ENCAP)
    {
      /* An ALLOW without a resolvable path would encapsulate nowhere. */
      if (cilium_srv6_path_get (hm, path_cache_index, path_generation) == NULL)
	return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
  else
    {
      /* Nothing that could make a DENY — or a LOCAL_DELIVER, which resolves no
	 path either — forward through the encapsulation may be carried, so that
	 neither can be turned into an encapsulating decision. The checks above
	 already refused such an entry if it named an index, so this only
	 normalises `path_generation`; the assignment is kept so that the
	 invariant holds by construction and not only by those checks. */
      path_cache_index = CILIUM_SRV6_NO_PATH_INDEX;
      path_generation = 0;
    }

  /* Same normalisation on the other side: an ENCAP entry holds no target, so
     the delivery node can never act on one even if it were reached with a
     buffer whose action byte was wrong. */
  if (action != CILIUM_SRV6_ACTION_LOCAL_DELIVER)
    {
      target_sw_if_index = 0;
      target_if_incarnation = 0;
      target_identity = 0;
    }

  budget = csh_budget_of (verdict);
  capacity = budget ? (hm->program_capacity - hm->program_negative_capacity) :
		      hm->program_negative_capacity;

  now = vlib_time_now (vm);

  taken = cilium_srv6_barrier_acquire (vm);

  /* Re-install of an existing key replaces the entry (02 §8: every message
     is idempotent, "同一 key への再 install は上書き"). */
  if (0 == clib_bihash_search_24_8 (&hm->program_table, &kv, &kv))
    {
      index = (u32) kv.value;
      if (index < hm->program_capacity && !pool_is_free_index (hm->programs, index))
	csh_program_remove (hm, index);
    }

  /*
   * D-26: the two budgets are independent, so a flood of DENY entries can
   * only evict DENY entries. Reaching a budget evicts inside it; failing to
   * evict is a quota drop rather than an unbounded pool.
   */
  while (hm->n_programs[budget] >= capacity || pool_free_elts (hm->programs) == 0)
    {
      if (!csh_program_evict_one (hm, budget))
	{
	  hm->n_program_quota_drops++;
	  cilium_srv6_barrier_release (vm, taken);
	  return VNET_API_ERROR_LIMIT_EXCEEDED;
	}
    }

  slot = csh_policy_rev_slot_ref (hm, src_identity);
  /* Re-resolved rather than reusing the index taken above: nothing between
     the two can change the answer (a present key holds the publication's own
     reference, so no eviction can free it), and resolving where the reference
     is taken keeps the two from drifting apart if that ever stops holding.
     The reference is what pins the key — and with it the D-83 high water mark
     — for as long as this entry quotes its revision. */
  endpoint_slot = csh_endpoint_rev_resolve (hm, dst, NULL);
  if (endpoint_slot != CSH_ENDPOINT_REV_SENTINEL)
    hm->endpoint_rev[endpoint_slot].refcount++;

  pool_get_zero (hm->programs, e);
  index = (u32) (e - hm->programs);

  e->src_identity = src_identity;
  e->policy_rev_slot = slot;
  e->endpoint_rev_slot = endpoint_slot;
  e->path_cache_index = path_cache_index;
  e->path_generation = path_generation;
  e->policy_revision = policy_revision;
  e->endpoint_revision = endpoint_revision;
  e->path_revision = path_revision;
  e->verdict = verdict;
  e->action = action;
  e->target_sw_if_index = target_sw_if_index;
  e->target_if_incarnation = target_if_incarnation;
  e->target_identity = target_identity;
  e->owner_quota_class = owner_quota_class;
  e->last_used = now;
  e->key[0] = key[0];
  e->key[1] = key[1];
  e->key[2] = key[2];
  e->age_prev = e->age_next = ~0;
  e->in_use = 1;

  kv.key[0] = key[0];
  kv.key[1] = key[1];
  kv.key[2] = key[2];
  kv.value = index;

  if (clib_bihash_add_del_24_8 (&hm->program_table, &kv, 1 /* add */) < 0)
    {
      csh_policy_rev_slot_unref (hm, slot);
      csh_endpoint_rev_slot_unref (hm, endpoint_slot);
      clib_memset (e, 0, sizeof (*e));
      pool_put_index (hm->programs, index);
      cilium_srv6_barrier_release (vm, taken);
      return VNET_API_ERROR_TABLE_TOO_BIG;
    }

  csh_prog_age_append (hm, budget, index);
  csh_count_add (&hm->prog_owner_count, owner_quota_class, +1);
  csh_count_add (&hm->prog_identity_count, src_identity, +1);
  hm->n_programs[budget]++;
  hm->n_program_installs++;

  /*
   * D-51 / 02 §5.4: the install is one of the four policy_lease_touch paths.
   * The agent only installs while its watchers are healthy, and the revision
   * was compared against the published one above, so the install itself is
   * liveness evidence for {src_identity, policy_revision}. Without the refresh
   * the entry would be lease-invalid until the next bulk push, i.e. every
   * compile after a revision bump would immediately punt again.
   *
   * DENY entries are fail-safe and never consult the lease, so nothing is
   * refreshed for them.
   *
   * Issue #61 invariant 3 — "a successful ALLOW installation MUST NOT become
   * dataplane-visible before the corresponding exact-revision lease is
   * usable" — holds structurally rather than by ordering these two writes.
   * The bihash insert above and this refresh are both inside the barrier
   * section opened before the insert and closed on the next line, and
   * cilium_srv6_barrier_acquire() guarantees the barrier is held either way
   * (it returns 0 only when the caller already holds it). Every worker is
   * therefore stopped across both writes, so no packet can observe the entry
   * without also observing the lease: the pair is one logical commit. The
   * writes are kept in this order so that a bihash insert that fails rolls
   * back without having refreshed a lease for a decision that was not
   * committed.
   */
  if (verdict == CILIUM_SRV6_VERDICT_ALLOW)
    csh_policy_lease_touch (hm, slot, src_identity, policy_revision,
			    now + (f64) hm->allow_lease_ms * 1e-3, 0 /* may_shorten */);

  cilium_srv6_barrier_release (vm, taken);

  return 0;
}

/* ------------------------------------------------------------------ */
/* per-key revision publication / srv6_lease_extend (02 §4.3, §8, D-83) */
/* ------------------------------------------------------------------ */

/*
 * D-83 replaced the single node-global srv6_revision_publish with one typed
 * message per namespace. The three functions below share one shape, and the
 * shape is the contract:
 *
 *   1. every element is validated first, against the current value of its own
 *      key. Nothing is written while validating;
 *   2. if any element is rejected, nothing is applied at all;
 *   3. otherwise the whole message is applied inside one worker barrier
 *      section, so a packet never observes a partially applied publish
 *      (02 §4.3).
 *
 * All-or-nothing is what makes a successful reply an acknowledgement for
 * every key in the message, which is what the mandatory D-83 order needs:
 * authority change -> per-key revision publish ACK -> old Program becomes
 * stale -> new Program publication. A partially applied publish would leave
 * the agent unable to say which keys it may compile against.
 *
 * Per key: the same revision again is idempotent, a lower one is refused, a
 * higher one advances the key. Nothing is walked when a key advances: an
 * entry that quotes the old revision fails the comparison of 02 §4.2 at its
 * next packet and punts. That is the whole point of comparing per packet
 * rather than invalidating eagerly — the cost of a revision bump is
 * independent of the number of entries that depend on it.
 *
 * Revision 0 withdraws a key. It is accepted whatever the current value is
 * (it is not a backwards move: it is the statement that the key stopped
 * existing), and every entry quoting the key becomes stale, because 0 never
 * equals a quotation.
 */

/* Common per-element validation. Returns 0 when the value may be published. */
static int
csh_revision_value_check (u64 revision, u64 current, int *rv)
{
  if (revision == CILIUM_SRV6_REV_INVALID)
    {
      *rv = VNET_API_ERROR_INVALID_VALUE_3;
      return -1;
    }

  /* A withdraw is always legal. */
  if (revision == CILIUM_SRV6_REV_ABSENT)
    return 0;

  /* Monotonic per key (02 §4.3): going backwards would let a revoked ALLOW
     become valid again. `current` is the high water mark rather than the live
     value, so a withdraw cannot be used to launder a lower revision back in
     while entries that quote the old one are still resident. */
  if (current != CILIUM_SRV6_REV_ABSENT && current != CILIUM_SRV6_REV_INVALID && revision < current)
    {
      *rv = VNET_API_ERROR_INVALID_VALUE_2;
      return -1;
    }

  return 0;
}

/*
 * D-85 (00 §2.23), the publish half: the agent revision incarnation carried in
 * the high 32 bits of every published revision.
 *
 * Per element, in the same validation pass and with the same all-or-nothing
 * discipline as csh_revision_value_check():
 *
 *   below `hm->current_revision_incarnation`  refused. A publish from an agent
 *       process that no longer holds the revision authority is a backwards move
 *       of the whole namespace, so it is refused with the same retval a
 *       backwards move of one key gets (VNET_API_ERROR_INVALID_VALUE_2).
 *   equal                                     nothing to do; the per-key rules
 *       of csh_revision_value_check() decide.
 *   above                                      accepted, and `*next` is raised.
 *       The caller writes `*next` into hm->current_revision_incarnation inside
 *       the barrier, so the advance happens exactly when the message is applied.
 *
 * A withdraw (revision 0) carries no incarnation and is skipped: it says a key
 * stopped existing, which is true under any generation.
 *
 * Advancing is what makes every quotation of an older incarnation stale, with
 * no walk of the ProgramCache and no dump of the old key set: the comparison
 * lives in cilium_srv6_revisions_match(), on the packet.
 */
static int
csh_revision_incarnation_check (const cilium_srv6_headend_main_t *hm, u64 revision, u32 *next,
				int *rv)
{
  u32 incarnation;

  if (revision == CILIUM_SRV6_REV_ABSENT || revision == CILIUM_SRV6_REV_INVALID)
    return 0;

  incarnation = CILIUM_SRV6_REV_INCARNATION (revision);

  if (incarnation < hm->current_revision_incarnation)
    {
      *rv = VNET_API_ERROR_INVALID_VALUE_2;
      return -1;
    }

  if (incarnation > *next)
    *next = incarnation;

  return 0;
}

/*
 * D-30 + D-84: the POLICY namespace, keyed by SecurityIdentity. The producer
 * is the agent's policy revision bumper, which seeds the whole identity
 * snapshot before ProgramCache publication opens and then publishes only the
 * identities it reports as changed. Remote identities are included, because
 * the reply re-authorisation of 02 §7.2 compares against the revision of the
 * forward direction's source identity.
 */
int
cilium_srv6_policy_revision_publish (const u32 *identities, const u64 *revisions, u32 n_policy)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 i, n_new = 0;
  /* D-85: the incarnation this message would leave the plugin at. */
  u32 next_incarnation = hm->current_revision_incarnation;
  int taken;
  int rv = 0;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (n_policy != 0 && (identities == NULL || revisions == NULL))
    return VNET_API_ERROR_INVALID_VALUE;

  for (i = 0; i < n_policy; i++)
    {
      u32 slot = csh_policy_rev_slot_find (hm, identities[i]);
      u64 current = CILIUM_SRV6_REV_ABSENT;

      if (slot == CSH_POLICY_REV_SENTINEL)
	{
	  if (revisions[i] != CILIUM_SRV6_REV_ABSENT)
	    n_new++;
	}
      else
	current = hm->policy_rev[slot].policy_revision;

      if (csh_revision_incarnation_check (hm, revisions[i], &next_incarnation, &rv))
	return rv;

      if (csh_revision_value_check (revisions[i], current, &rv))
	return rv;
    }

  if (n_new > pool_free_elts (hm->policy_rev))
    return VNET_API_ERROR_LIMIT_EXCEEDED;

  taken = cilium_srv6_barrier_acquire (vm);

  for (i = 0; i < n_policy; i++)
    {
      u32 slot = csh_policy_rev_slot_find (hm, identities[i]);

      if (revisions[i] == CILIUM_SRV6_REV_ABSENT)
	{
	  /*
	   * A withdrawn identity keeps neither a revision nor a lease. The
	   * slot itself is left alone: it is reference counted by the entries
	   * and the conntrack pins that still name it, and releasing it here
	   * would hand its index to another identity while they still read it.
	   */
	  if (slot != CSH_POLICY_REV_SENTINEL)
	    {
	      hm->policy_rev[slot].policy_revision = CILIUM_SRV6_REV_ABSENT;
	      hm->policy_rev[slot].lease_revision = CILIUM_SRV6_REV_INVALID;
	      hm->policy_rev[slot].lease_valid_until = 0.0;
	    }
	  continue;
	}

      if (slot == CSH_POLICY_REV_SENTINEL)
	{
	  /* The reference taken here belongs to the publication itself: a
	     published identity keeps its slot even with no entries, so that
	     the next install compares against the revision the agent knows. */
	  slot = csh_policy_rev_slot_ref (hm, identities[i]);
	  if (slot == CSH_POLICY_REV_SENTINEL)
	    {
	      /* Cannot happen: capacity was checked above with the barrier not
		 yet taken and nothing releases slots in between. */
	      rv = VNET_API_ERROR_LIMIT_EXCEEDED;
	      continue;
	    }
	}

      hm->policy_rev[slot].policy_revision = revisions[i];
    }

  /* D-85: the advance happens with the message, inside the barrier, so no
     packet can observe the new incarnation before the revisions that carry
     it — nor the revisions before the incarnation. */
  hm->current_revision_incarnation = next_incarnation;

  hm->n_revision_publishes++;

  cilium_srv6_barrier_release (vm, taken);

  return rv;
}

/*
 * D-83: the ENDPOINT namespace, keyed by destination IPv6 address.
 *
 * The unspecified address `::` is ENDPOINT_ABSENCE_REVISION, the reserved key
 * negative entries depend on (02 §4.3.1, errata #34 item 153). It advances like
 * any other key — the agent moves it when the membership of the published
 * endpoint key set changes — but it is not a real endpoint key:
 *
 *   `::` MUST NOT represent a real endpoint revision key and MUST be accepted
 *   only as the reserved endpoint-absence revision key.
 *
 * The one publication that would treat it as a real key is a withdraw. A real
 * key is withdrawn when its destination stops being a published endpoint; the
 * absence key has no destination to stop being one, and withdrawing it would
 * make every negative install fail the missing-key check — indistinguishable
 * from a genuine ordering violation — until it was republished. It is refused
 * here, in the validation pass, so that the message stays all-or-nothing.
 */
int
cilium_srv6_endpoint_revision_publish (const ip6_address_t *dsts, const u64 *revisions,
				       u32 n_endpoint)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 i, n_new = 0;
  /* D-85: the incarnation this message would leave the plugin at. The absence
     seed of 00 §2.23 is an ordinary member of this namespace, which is what
     makes a node with zero endpoints able to advance it at all. */
  u32 next_incarnation = hm->current_revision_incarnation;
  int taken;
  int rv = 0;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (n_endpoint != 0 && (dsts == NULL || revisions == NULL))
    return VNET_API_ERROR_INVALID_VALUE;

  for (i = 0; i < n_endpoint; i++)
    {
      u32 slot;
      /* The high water mark, not the live revision: a withdrawn key must not
	 be revivable at a lower revision while entries still quote the old
	 one. */
      u64 current = CILIUM_SRV6_REV_ABSENT;

      /* The reserved absence key may only advance, never be withdrawn. */
      if (ip6_address_is_zero (dsts + i) && revisions[i] == CILIUM_SRV6_REV_ABSENT)
	return VNET_API_ERROR_INVALID_DST_ADDRESS;

      slot = csh_endpoint_rev_slot_find (hm, dsts + i);

      if (slot == CSH_ENDPOINT_REV_SENTINEL)
	{
	  if (revisions[i] != CILIUM_SRV6_REV_ABSENT)
	    n_new++;
	}
      else
	current = hm->endpoint_rev[slot].hwm;

      if (csh_revision_incarnation_check (hm, revisions[i], &next_incarnation, &rv))
	return rv;

      if (csh_revision_value_check (revisions[i], current, &rv))
	return rv;
    }

  if (n_new > pool_free_elts (hm->endpoint_rev))
    return VNET_API_ERROR_LIMIT_EXCEEDED;

  taken = cilium_srv6_barrier_acquire (vm);

  for (i = 0; i < n_endpoint; i++)
    {
      u32 slot = csh_endpoint_rev_slot_find (hm, dsts + i);

      if (revisions[i] == CILIUM_SRV6_REV_ABSENT)
	{
	  if (slot == CSH_ENDPOINT_REV_SENTINEL)
	    continue;

	  if (hm->endpoint_rev[slot].present)
	    {
	      hm->endpoint_rev[slot].present = 0;
	      hm->endpoint_rev[slot].revision = CILIUM_SRV6_REV_ABSENT;
	      /* Drop the publication's own reference. The slot survives while
		 ProgramCache entries still quote it — that is what keeps the
		 high water mark alive exactly as long as it protects
		 something — and is released with the last of them. */
	      csh_endpoint_rev_slot_unref (hm, slot);
	    }
	  continue;
	}

      if (slot == CSH_ENDPOINT_REV_SENTINEL)
	{
	  /* Creating the slot takes the publication's reference. */
	  slot = csh_endpoint_rev_slot_ref (hm, dsts + i);
	  if (slot == CSH_ENDPOINT_REV_SENTINEL)
	    {
	      rv = VNET_API_ERROR_LIMIT_EXCEEDED;
	      continue;
	    }
	}
      else if (!hm->endpoint_rev[slot].present)
	{
	  /* A withdrawn key coming back: retake the publication reference the
	     withdraw dropped. */
	  hm->endpoint_rev[slot].refcount++;
	}

      hm->endpoint_rev[slot].present = 1;
      hm->endpoint_rev[slot].revision = revisions[i];
      if (revisions[i] > hm->endpoint_rev[slot].hwm)
	hm->endpoint_rev[slot].hwm = revisions[i];
    }

  /* D-85: see the policy publish. */
  hm->current_revision_incarnation = next_incarnation;

  hm->n_revision_publishes++;

  cilium_srv6_barrier_release (vm, taken);

  return rv;
}

/*
 * D-83: the PATH namespace, keyed by PathCache index. The index must name a
 * currently published entry (D-61 committed it), because a revision for a
 * handle that does not resolve could only ever produce an ALLOW that punts.
 */
int
cilium_srv6_path_revision_publish (const u32 *indices, const u64 *revisions, u32 n_path)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 i;
  /* D-85: the incarnation this message would leave the plugin at. */
  u32 next_incarnation = hm->current_revision_incarnation;
  int taken;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (n_path != 0 && (indices == NULL || revisions == NULL))
    return VNET_API_ERROR_INVALID_VALUE;

  for (i = 0; i < n_path; i++)
    {
      int rv = 0;

      if (indices[i] >= vec_len (hm->path_revs))
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      /* A withdraw needs no entry: the index may already have been retired. */
      if (revisions[i] != CILIUM_SRV6_REV_ABSENT &&
	  (pool_is_free_index (hm->paths, indices[i]) ||
	   hm->paths[indices[i]].state != CILIUM_SRV6_PATH_PUBLISHED))
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      if (csh_revision_incarnation_check (hm, revisions[i], &next_incarnation, &rv))
	return rv;

      if (csh_revision_value_check (revisions[i], hm->path_revs[indices[i]], &rv))
	return rv;
    }

  taken = cilium_srv6_barrier_acquire (vm);

  for (i = 0; i < n_path; i++)
    hm->path_revs[indices[i]] = revisions[i];

  /* D-85: see the policy publish. */
  hm->current_revision_incarnation = next_incarnation;

  hm->n_revision_publishes++;

  cilium_srv6_barrier_release (vm, taken);

  return 0;
}

/*
 * srv6_lease_extend (D-51, 02 §5.4): the *periodic bulk refresh* path of
 * policy_lease_touch. It is not the only path — an ALLOW install, a
 * successful srv6_ct_verify and an accepted srv6_fragment_verdict_add(ALLOW)
 * refresh the same exact-revision lease
 * opportunistically — but it is the one that is independent of packet and flow
 * rate, so it is what maintains the steady state.
 *
 * The message updates the PolicyLeaseTable and nothing else. For each
 * (identity, revision) pair whose revision is still the one this node
 * publishes, the lease is refreshed for that revision. Work is O(n_policy):
 * no entry of any table is read or written, which is the whole point of
 * moving the lease off the entry —
 *
 *   - refreshing from the hot path is one punt per entry per lease period,
 *     i.e. 1M entries / 30 s = 33k punt/s against a 4096-deep queue;
 *   - refreshing per entry from here is a walk of up to 1M pool slots plus a
 *     write to each one, every push;
 *   - and neither of them reached the conntrack table at all, so every
 *     long-lived flow re-authorised once per lease period (Issue #42).
 *
 * An identity with no slot has no dependent state on this node, so it is
 * counted as skipped rather than given a slot: a push must not be able to
 * grow the table.
 *
 * A pair whose revision has already moved is also skipped, by rule 3 of
 * csh_policy_lease_touch(). Its entries fail the revision comparison of
 * 02 §4.2 anyway, so extending would change nothing; leaving the lease alone
 * keeps the two halves of 00 §2.1 independent.
 *
 * No worker barrier: the only writes are the two aligned 8 byte fields of
 * csh_policy_lease_touch(), which the hot path only reads, and no slot is
 * created or released here.
 */
int
cilium_srv6_lease_extend (const u32 *identities, const u64 *revisions, u32 n_policy, u32 lease_ms,
			  u32 *n_updated, u32 *n_skipped)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 n_upd = 0, n_skip = 0, i;
  f64 until;

  if (n_updated)
    *n_updated = 0;
  if (n_skipped)
    *n_skipped = 0;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (n_policy != 0 && (identities == NULL || revisions == NULL))
    return VNET_API_ERROR_INVALID_VALUE;

  /* 00 §4.1: everything is validated before any state is touched. The
     sentinel is what "no revision" means, so it can never be leased. */
  for (i = 0; i < n_policy; i++)
    if (revisions[i] == CILIUM_SRV6_REV_INVALID)
      return VNET_API_ERROR_INVALID_VALUE_2;

  if (lease_ms == 0)
    lease_ms = hm->allow_lease_ms;

  until = vlib_time_now (vm) + (f64) lease_ms * 1e-3;

  for (i = 0; i < n_policy; i++)
    {
      u32 slot = csh_policy_rev_slot_find (hm, identities[i]);

      /*
       * The same operation the two opportunistic paths use, with the one
       * difference the bulk push is allowed: it may shorten a lease, because
       * the length it carries is the agent's configured lease and letting it
       * govern is what makes a reconfigured (shorter) lease take effect within
       * one push interval. Shortening is the fail-closed direction.
       *
       * Everything else — unknown identity, sentinel revision, a revision that
       * is no longer the published one, a revision that would move the lease
       * backwards — is the shared rule set of csh_policy_lease_touch() and is
       * reported as skipped.
       */
      if (csh_policy_lease_touch (hm, slot, identities[i], revisions[i], until,
				  1 /* may_shorten */))
	n_upd++;
      else
	n_skip++;
    }

  hm->n_lease_extends++;

  if (n_updated)
    *n_updated = n_upd;
  if (n_skipped)
    *n_skipped = n_skip;

  return 0;
}

/* ------------------------------------------------------------------ */
/* LocalEndpointTable (02 §3, D-31)                                    */
/* ------------------------------------------------------------------ */

/*
 * cilium-srv6-classify is enabled per interface rather than globally: the
 * graph of 02 §1 starts at a Pod interface, and putting it on every interface
 * would put it on the host TAP, which never has a LocalEndpointTable entry
 * (03 §1.1 / D-58).
 *
 * Which interfaces it belongs on is cilium_srv6_classify_wanted()
 * (cilium_srv6_classify_scope.h). It is deliberately not "an interface with a
 * local endpoint": see errata #34 item 191 and the header comment there.
 */
static int
csh_classify_feature_set (u32 sw_if_index, int enable)
{
  int rv = vnet_feature_enable_disable (CSH_ARC_NAME, CSH_NODE_NAME, sw_if_index, enable, 0, 0);

  if (rv != 0)
    CSH_LOG_ERR ("classify feature %s failed on sw_if_index %u: %d", enable ? "enable" : "disable",
		 sw_if_index, rv);

  return rv;
}

/*
 * Drive the classify feature of one interface to `want`.
 *
 * vnet_feature_enable_disable() is reference counted per (arc, feature,
 * interface), so the state has to be tracked rather than re-asserted; this is
 * the same shape as csg_guard_feature_set() and it is what makes every caller
 * below able to call unconditionally. The flag lives in the trust map entry
 * because it belongs to the interface lifetime, not to any one local endpoint.
 *
 * The caller must hold the worker barrier.
 */
static int
csh_classify_set (u32 sw_if_index, int want)
{
  cilium_srv6_main_t *cm = &cilium_srv6_main;
  cilium_srv6_guard_if_t *e;
  u8 w = want ? 1 : 0;
  int rv;

  if (sw_if_index >= vec_len (cm->ifs))
    return 0;

  e = vec_elt_at_index (cm->ifs, sw_if_index);

  if (w == e->classify_installed)
    return 0;

  rv = csh_classify_feature_set (sw_if_index, w);
  if (rv != 0)
    return rv;

  e->classify_installed = w;
  return 0;
}

/*
 * Bring the classify feature of one interface in line with
 * cilium_srv6_classify_wanted(), i.e. with the current trust classification
 * (D-73) and the current LocalEndpointTable content. Safe to call from every
 * event that can change either input; errata #34 item 191.
 *
 * The caller must hold the worker barrier: the answer is read from the trust
 * map and the LocalEndpointTable, both of which the dataplane reads.
 */
int
cilium_srv6_headend_classify_refresh (u32 sw_if_index)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  int has_local_ep;

  if (!hm->initialised)
    return 0;

  if (sw_if_index >= vec_len (cm->ifs) || !cm->ifs[sw_if_index].valid)
    return 0;

  has_local_ep = (sw_if_index < vec_len (hm->local_eps) && hm->local_eps[sw_if_index].valid);

  return csh_classify_set (sw_if_index,
			   cilium_srv6_classify_wanted (cm->ifs[sw_if_index].trust, has_local_ep));
}

int
cilium_srv6_local_ep_add_del (u32 sw_if_index, u32 if_incarnation, u32 identity,
			      const ip6_address_t *ip, u32 local_context_id,
			      u32 owner_quota_class, u8 is_add)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  vnet_main_t *vnm = vnet_get_main ();
  cilium_srv6_local_ep_t *e;
  u32 slot;
  u32 deleted_context_id;
  int taken;
  int rv;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (vnet_get_sw_interface_or_null (vnm, sw_if_index) == NULL)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (sw_if_index >= vec_len (cm->ifs) || !cm->ifs[sw_if_index].valid)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  /*
   * D-31: the write is keyed on (sw_if_index, if_incarnation). A message that
   * carries the incarnation of an interface lifetime that has already ended
   * is refused, so a reused index can never inherit the previous Pod's
   * identity through a late reconcile.
   */
  if (cm->ifs[sw_if_index].incarnation != if_incarnation)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (!is_add)
    {
      if (sw_if_index >= vec_len (hm->local_eps) || !hm->local_eps[sw_if_index].valid)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      taken = cilium_srv6_barrier_acquire (vm);

      e = hm->local_eps + sw_if_index;
      deleted_context_id = e->local_context_id;
      csh_policy_rev_slot_unref (hm, e->policy_rev_slot);
      clib_memset (e, 0, sizeof (*e));

      /* Item 191: not an unconditional disable. The endpoint is gone, but the
	 interface is still whatever D-73 classified it as, and while it is
	 UNTRUSTED its packets must keep reaching classify — which now answers
	 DROP_UNKNOWN_SOURCE_EP (02 §3) instead of letting them fall through
	 the arc into ip6-lookup. */
      cilium_srv6_headend_classify_refresh (sw_if_index);

      cilium_srv6_barrier_release (vm, taken);

      /*
       * D-15 / 02 §8 srv6_ct_invalidate: purge the conntrack entries of this
       * endpoint incarnation. The endpoint stopped resolving inside the
       * barrier section above, which is what makes the delete enforcing: from
       * that point every conntrack entry of this incarnation fails the
       * 02 §7.2 comparison against the live LocalEndpointTable and its
       * packets are re-authorised. The purge below only returns the memory.
       */
      cilium_srv6_ct_invalidate_endpoint (deleted_context_id);

      return 0;
    }

  if (ip == NULL || ip6_address_is_zero (ip))
    return VNET_API_ERROR_INVALID_VALUE;

  /* 02 §3 assumes one global unicast address per endpoint; a link-local
     address as the endpoint address would make the anti-spoof comparison
     meaningless. */
  if (ip6_address_is_link_local_unicast (ip))
    return VNET_API_ERROR_INVALID_VALUE_3;

  taken = cilium_srv6_barrier_acquire (vm);

  vec_validate_init_empty (hm->local_eps, sw_if_index, (cilium_srv6_local_ep_t){ 0 });
  e = hm->local_eps + sw_if_index;

  if (e->valid)
    csh_policy_rev_slot_unref (hm, e->policy_rev_slot);

  slot = csh_policy_rev_slot_ref (hm, identity);

  e->if_incarnation = if_incarnation;
  e->identity = identity;
  e->local_context_id = local_context_id;
  e->owner_quota_class = owner_quota_class;
  e->policy_rev_slot = slot;
  e->ip = *ip;

  /* Complete before it becomes reachable. */
  CLIB_MEMORY_STORE_BARRIER ();
  e->valid = 1;

  rv = cilium_srv6_headend_classify_refresh (sw_if_index);
  if (rv != 0)
    {
      /* Without the feature the endpoint is not classified at all, which is
	 not fail-closed for the headend: undo the install. */
      csh_policy_rev_slot_unref (hm, e->policy_rev_slot);
      clib_memset (e, 0, sizeof (*e));
      cilium_srv6_barrier_release (vm, taken);
      return VNET_API_ERROR_UNSPECIFIED;
    }

  cilium_srv6_barrier_release (vm, taken);

  if (slot == CSH_POLICY_REV_SENTINEL)
    CSH_LOG_ERR ("no policy revision slot for identity %u: every flow of "
		 "sw_if_index %u will punt",
		 identity, sw_if_index);

  return 0;
}

/*
 * D-31 again, from the other side: when VPP frees an sw_if_index the local
 * endpoint bound to it must stop resolving before the index can be handed to
 * a new interface.
 */
static clib_error_t *
cilium_srv6_headend_sw_interface_add_del (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 deleted_context_id;
  int taken;

  if (is_add || !hm->initialised)
    return NULL;

  /*
   * The classify feature is retired here even when there was no endpoint on
   * this index. sw_if_index values are reused (D-31) and VPP does not clear
   * an interface's feature arc configuration on delete, so a feature left
   * behind would be inherited by the next interface to take the index — for
   * classify that means the next interface's packets are classified against
   * whatever LocalEndpointTable entry that index later acquires.
   */
  if (sw_if_index < vec_len (cilium_srv6_main.ifs))
    {
      taken = cilium_srv6_barrier_acquire (vm);
      csh_classify_set (sw_if_index, 0 /* disable */);
      cilium_srv6_barrier_release (vm, taken);
    }

  if (sw_if_index >= vec_len (hm->local_eps) || !hm->local_eps[sw_if_index].valid)
    return NULL;

  taken = cilium_srv6_barrier_acquire (vm);
  deleted_context_id = hm->local_eps[sw_if_index].local_context_id;
  csh_policy_rev_slot_unref (hm, hm->local_eps[sw_if_index].policy_rev_slot);
  clib_memset (hm->local_eps + sw_if_index, 0, sizeof (hm->local_eps[0]));
  cilium_srv6_barrier_release (vm, taken);

  /* D-15: same purge as the explicit delete above. */
  cilium_srv6_ct_invalidate_endpoint (deleted_context_id);

  return NULL;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (cilium_srv6_headend_sw_interface_add_del);

/* ------------------------------------------------------------------ */
/* FragmentVerdictCache (01 §3.1, D-20, D-43)                          */
/* ------------------------------------------------------------------ */

static void
csh_frag_age_append (cilium_srv6_headend_main_t *hm, u32 index)
{
  cilium_srv6_frag_entry_t *f = hm->frags + index;

  f->age_next = ~0;
  f->age_prev = hm->frag_age_tail;

  if (hm->frag_age_tail != (u32) ~0)
    hm->frags[hm->frag_age_tail].age_next = index;
  else
    hm->frag_age_head = index;

  hm->frag_age_tail = index;
}

static void
csh_frag_age_remove (cilium_srv6_headend_main_t *hm, u32 index)
{
  cilium_srv6_frag_entry_t *f = hm->frags + index;

  if (f->age_prev != (u32) ~0)
    hm->frags[f->age_prev].age_next = f->age_next;
  else
    hm->frag_age_head = f->age_next;

  if (f->age_next != (u32) ~0)
    hm->frags[f->age_next].age_prev = f->age_prev;
  else
    hm->frag_age_tail = f->age_prev;

  f->age_prev = f->age_next = ~0;
}

/* frag_lock held. */
static void
csh_frag_remove (cilium_srv6_headend_main_t *hm, u32 index)
{
  cilium_srv6_frag_entry_t *f = hm->frags + index;
  clib_bihash_kv_40_8_t kv;
  u64 key[5];
  int i;

  cilium_srv6_frag_key (key, &f->src, &f->dst, f->frag_id, f->next_header);
  for (i = 0; i < 5; i++)
    kv.key[i] = key[i];
  kv.value = index;

  /* Unhook first: from here a fragment for this datagram misses and drops as
     DROP_FRAGMENT_UNRESOLVED, which is the fail-closed side. */
  clib_bihash_add_del_40_8 (&hm->frag_table, &kv, 0 /* del */);

  csh_frag_age_remove (hm, index);
  csh_count_add (&hm->frag_owner_count, f->owner_quota_class, -1);
  csh_count_add (&hm->frag_identity_count, f->src_identity, -1);

  if (hm->n_frags > 0)
    hm->n_frags--;

  clib_memset (f, 0, sizeof (*f));
  f->age_prev = f->age_next = ~0;

  pool_put_index (hm->frags, index);
}

/*
 * The one writer of the FragmentVerdictCache, shared by the two producers of
 * 02 §2: the dataplane record of a ProgramCache-resolved first fragment
 * (cilium_srv6_frag_record, from a worker) and the IF-2 write of a verdict
 * the agent compiled for a punted one (cilium_srv6_frag_verdict_add, from the
 * main thread). Having one writer is what makes the two paths agree:
 * whichever of them gets there first, the entry that ends up in the table
 * carries the full D-20 binding set of its caller, is charged to the same
 * D-42 owner/identity counters, joins the same age FIFO, and is bounded by
 * the same 01 §3.1 capacity and timeout. The per-packet checks in
 * cilium-srv6-classify therefore do not need to know which path wrote it.
 *
 * `frag_lock` is held by the caller. Nothing here allocates: the pool is
 * fixed size and the bihash arena is preallocated.
 *
 * `replace` is the one behavioural difference between the two callers and it
 * is deliberate:
 *
 *   0 (dataplane)  D-43's "同一 (src, dst, fragment-id) に対する first
 *                  fragment の再受信は DROP". cilium-srv6-classify already
 *                  refuses a first fragment whose key is present; if one
 *                  still races to here the existing record wins, so two
 *                  workers racing on the same datagram cannot produce two
 *                  different verdicts for it.
 *   1 (IF-2)       02 §8's "すべて冪等 (同一 key への再 install は上書き)".
 *                  A duplicate punt (02 §5.2 tolerates them) recompiles the
 *                  same decision, and this is a control-plane write, not a
 *                  packet arriving on an interface, so D-43's arrival rule
 *                  does not apply to it.
 *
 * Issue #90 adds one rule that cuts across both: this function never invents
 * a one-shot reinjection capability and never revives a spent one. It stores
 * whatever {punt_id, reinject_pending} its caller put in `tmpl`, and the two
 * callers are responsible for the semantics —
 * cilium_srv6_frag_record() always passes {0, 0} because a first fragment it
 * forwarded itself has no punt to be the continuation of, and
 * cilium_srv6_frag_verdict_add() carries the existing record's
 * `reinject_pending` forward when it replaces a record for the same punt.
 *
 * Both orders of the two writers converge on the same invariant, because a
 * record is only ever readable while every binding it was written with still
 * holds (cilium_srv6_frag_entry_usable() re-checks identity, incarnation,
 * slot, the three revisions and the expiry on every packet, and the lease is
 * read live from the PolicyLeaseTable). A record written by one path and then
 * replaced by the other is therefore never wider than what its own writer
 * validated, and a stale one stops being usable without having to be found
 * and deleted.
 *
 * Returns 0 on success, a VNET_API_ERROR_* otherwise.
 */
static int
csh_frag_install (cilium_srv6_headend_main_t *hm, const u64 key[5],
		  const cilium_srv6_frag_entry_t *tmpl, int replace)
{
  clib_bihash_kv_40_8_t kv;
  cilium_srv6_frag_entry_t *f;
  u32 index;
  u32 owner_quota, identity_quota;
  int i;

  for (i = 0; i < 5; i++)
    kv.key[i] = key[i];
  kv.value = 0;

  if (0 == clib_bihash_search_40_8 (&hm->frag_table, &kv, &kv))
    {
      if (!replace)
	return VNET_API_ERROR_VALUE_EXIST;

      index = (u32) kv.value;
      if (index < hm->frag_capacity && !pool_is_free_index (hm->frags, index))
	csh_frag_remove (hm, index);
    }

  /* D-42 hierarchical quota; over-quota classes cannot displace others. */
  owner_quota = csh_soft_quota (hm->frag_capacity, (u32) hash_elts (hm->frag_owner_count));
  identity_quota = csh_soft_quota (hm->frag_capacity, (u32) hash_elts (hm->frag_identity_count));

  if (csh_count_get (hm->frag_owner_count, tmpl->owner_quota_class) >= owner_quota ||
      csh_count_get (hm->frag_identity_count, tmpl->src_identity) >= identity_quota)
    {
      hm->n_frag_quota_drops++;
      return VNET_API_ERROR_LIMIT_EXCEEDED;
    }

  while (pool_free_elts (hm->frags) == 0)
    {
      /* Age-ordered eviction; the oldest record is the one whose datagram is
	 most likely already gone. */
      if (hm->frag_age_head == (u32) ~0)
	return VNET_API_ERROR_LIMIT_EXCEEDED;

      csh_frag_remove (hm, hm->frag_age_head);
      hm->n_frag_evictions++;
    }

  pool_get_zero (hm->frags, f);
  index = (u32) (f - hm->frags);

  *f = *tmpl;
  f->age_prev = f->age_next = ~0;
  f->in_use = 1;

  for (i = 0; i < 5; i++)
    kv.key[i] = key[i];
  kv.value = index;

  if (clib_bihash_add_del_40_8 (&hm->frag_table, &kv, 1 /* add */) < 0)
    {
      clib_memset (f, 0, sizeof (*f));
      pool_put_index (hm->frags, index);
      return VNET_API_ERROR_TABLE_TOO_BIG;
    }

  csh_frag_age_append (hm, index);
  csh_count_add (&hm->frag_owner_count, f->owner_quota_class, +1);
  csh_count_add (&hm->frag_identity_count, f->src_identity, +1);
  hm->n_frags++;

  return 0;
}

/*
 * Record the verdict of a first fragment (01 §3.1). Called from a worker, so
 * the structural change is serialised with frag_lock.
 *
 * Returns 1 if the record was made. A failure is not fatal: the datagram's
 * later fragments simply drop as DROP_FRAGMENT_UNRESOLVED.
 */
int
cilium_srv6_frag_record (vlib_main_t *vm, const ip6_address_t *src, const ip6_address_t *dst,
			 u32 frag_id, u8 next_header, const cilium_srv6_headend_meta_t *meta,
			 const cilium_srv6_program_t *prog, u8 verdict, u32 path_cache_index,
			 u32 path_generation)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  cilium_srv6_frag_entry_t tmpl;
  u64 key[5];
  f64 now = vlib_time_now (vm);
  int rv;

  cilium_srv6_frag_key (key, src, dst, frag_id, next_header);

  clib_memset (&tmpl, 0, sizeof (tmpl));

  tmpl.src = *src;
  tmpl.dst = *dst;
  tmpl.frag_id = frag_id;
  tmpl.next_header = next_header;
  tmpl.verdict = verdict;

  /* D-20: bound to identity, endpoint incarnation, the three dependency
     revisions and the versioned path handle, exactly like the ProgramCache
     entry it was derived from. The lease is not copied either: D-51 puts it
     in the PolicyLeaseTable slot of `src_identity`, which is the same slot
     the ProgramCache entry consults, so the fragment path cannot outlive the
     lease of the decision it came from. */
  tmpl.src_identity = meta->src_identity;
  tmpl.local_context_id = meta->local_context_id;
  tmpl.policy_rev_slot = meta->policy_rev_slot;
  tmpl.owner_quota_class = meta->owner_quota_class;

  if (prog != NULL)
    {
      tmpl.policy_revision = prog->policy_revision;
      tmpl.endpoint_revision = prog->endpoint_revision;
      tmpl.path_revision = prog->path_revision;
      /* D-83: the same ENDPOINT key the ProgramCache entry resolved, so the
	 record is bound to exactly what the decision was bound to (D-20). No
	 reference is taken on it, for the same reason none is taken on
	 `policy_rev_slot`: this runs on a worker, and the reference counts of
	 the revision tables are main-thread state. The binding is safe because
	 the entry this record was derived from holds the reference, a released
	 slot is poisoned with the sentinel before its index is reused, and the
	 record expires within `frag_timeout` regardless. */
      tmpl.endpoint_rev_slot = prog->endpoint_rev_slot;
    }
  else
    {
      tmpl.policy_revision = CILIUM_SRV6_REV_INVALID;
      tmpl.endpoint_revision = CILIUM_SRV6_REV_INVALID;
      tmpl.path_revision = CILIUM_SRV6_REV_INVALID;
      tmpl.endpoint_rev_slot = CSH_ENDPOINT_REV_SENTINEL;
    }

  tmpl.path_cache_index = path_cache_index;
  tmpl.path_generation = path_generation;
  tmpl.expires_at = now + hm->frag_timeout;

  /*
   * Issue #90: no reinjection capability. This record is written because the
   * ProgramCache already had the answer, so the first fragment was forwarded
   * by this node and never left it — there is no punt operation for a
   * reinjection to be the continuation of, and cilium-srv6-classify refuses
   * every reinjection presented against a record whose punt_id is 0.
   *
   * Written explicitly rather than left to the memset above, because the
   * absence of a capability is a property of this writer and not an
   * initialisation detail.
   */
  tmpl.punt_id = 0;
  tmpl.reinject_pending = 0;

  clib_spinlock_lock (&hm->frag_lock);
  rv = csh_frag_install (hm, key, &tmpl, 0 /* replace */);
  clib_spinlock_unlock (&hm->frag_lock);

  return rv == 0;
}

/*
 * srv6_fragment_verdict_add (IF-2, 02 §8, 01 §3.1, D-20).
 *
 * The slow path half of the FragmentVerdictCache: the verdict the agent
 * compiled for a first fragment that punted, which cilium_srv6_frag_record()
 * cannot produce because there was no ProgramCache entry to derive it from.
 *
 * Everything 00 §4.1 requires is validated before any state is touched, and
 * the three bindings the caller must not be able to choose are taken from the
 * live LocalEndpointTable rather than from the message:
 *
 *   local_context_id    the endpoint incarnation the record is bound to
 *                       (D-15/D-20). Reading it from the table is what makes
 *                       a record unusable the moment the Pod behind the
 *                       address is replaced.
 *   policy_rev_slot     the D-30 slot cilium-srv6-classify compares against.
 *                       It has to be the slot the LocalEndpointTable entry
 *                       already holds a reference on, both because the hot
 *                       path compares `f->policy_rev_slot` against the slot
 *                       it resolved from that same entry, and because a
 *                       fragment record takes no reference of its own.
 *   owner_quota_class   the D-42 accounting key.
 *
 * An ALLOW accepted here is the *fourth* `policy_lease_touch` path of D-51
 * (Issue #83, decision of 2026-09-01). 02 §5.4 originally enumerated three
 * triggers and excluded the fragment record on the grounds that it "IF-2
 * message を持たず"; this message is that IF-2 message, so the exclusion
 * lapsed with it. The decision text:
 *
 *   srv6_fragment_verdict_add(ALLOW) is the fourth policy-dependent state
 *   installation path of D-51: the handler MUST perform a policy_lease_touch
 *   for the exact current revision, and the FragmentVerdictCache entry MUST
 *   NOT become dataplane-visible before that exact-revision lease is usable.
 *   A DENY verdict MUST NOT refresh the policy lease.
 *
 * Which makes the handler five ordered steps:
 *
 *   1. validate the request bindings (identity, incarnation, the three
 *      dependency revisions, the versioned path handle) — above;
 *   2. confirm the policy revision is exactly the one this node publishes for
 *      the identity (cilium_srv6_revisions_match, above);
 *   3. policy_lease_touch(src_identity, policy_revision), which applies the
 *      shared rules of csh_policy_lease_touch() — a stale revision refreshes
 *      nothing and no lease revision moves backwards;
 *   4. confirm the exact-revision lease is usable;
 *   5. publish the record.
 *
 * Steps 3 to 5 run under one barrier + frag_lock section, so a worker sees
 * either neither the refreshed lease nor the record, or both: the pair is one
 * logical commit, exactly as srv6_program_add_del(ALLOW) makes it. The order
 * within the section is deliberate and asymmetric. A touch that succeeds and
 * an insert that then fails is safe — a lease is a few seconds longer and no
 * ALLOW state exists to use it — while the reverse, a visible record whose
 * lease was never granted, is the state invariant 3 of 00 §2.1 forbids, so it
 * is never constructed.
 *
 * The watcher-health half of the rule is not re-implemented here. D-51's
 * invariant 2 ("no operation capable of refreshing a PolicyLeaseTable entry
 * may be emitted after watcher health becomes false") is an emission-time gate
 * on the agent, and this message is gated by it like every other one: the
 * plugin has no view of the agent's policy watcher, so a second check here
 * would be a check of nothing. What the plugin does own is the revision half,
 * and that is steps 2 to 4.
 *
 * Reinstall semantics (Issue #90, decision of 2026-09-01)
 * -------------------------------------------------------
 *
 * `punt_id` arms the record's one-shot reinjection capability, so "install"
 * is no longer a pure overwrite and the three cases are spelled out:
 *
 *   no live record for the key
 *       installed with the capability unspent (reinject_pending = 1) when
 *       punt_id is non-zero. A record whose punt_id is 0 is installed with no
 *       capability at all, and no reinjection is ever admitted against it.
 *   live record, same punt_id
 *       an idempotent replay of the same answer. It succeeds and rewrites the
 *       bindings and the expiry, but it carries `reinject_pending` forward
 *       unchanged. The invariant the decision states:
 *
 *         An idempotent FragmentVerdictAdd replay MUST NOT recreate an
 *         already-consumed reinjection capability.
 *
 *       PENDING stays PENDING and CONSUMED stays CONSUMED. Recreating the
 *       capability would hand a second D-43 exemption to a datagram whose
 *       punt has already been answered, which is exactly the "insert another
 *       first fragment into an already decided datagram" that D-43 forbids.
 *   live record, different punt_id
 *       refused (VNET_API_ERROR_VALUE_EXIST). The verdict of a datagram is
 *       decided once; a second punt operation for a key whose record has not
 *       expired means the agent is answering a punt this node no longer has,
 *       so nothing is touched — not the record, and not the lease, because
 *       the refusal happens before the touch of step 3. A record installed by
 *       the dataplane writer has punt_id 0 and is a "different punt_id" like
 *       any other: its datagram was already decided and forwarded.
 *
 * The capability needs no lifetime of its own. It is part of the record, so
 * it expires exactly when the record does, and after that expiry the key is a
 * new datagram again and any punt_id may install it.
 */
int
cilium_srv6_frag_verdict_add (const ip6_address_t *src, const ip6_address_t *dst, u32 frag_id,
			      u8 next_header, u32 sw_if_index, u32 if_incarnation, u32 src_identity,
			      u8 verdict, u64 policy_revision, u64 endpoint_revision,
			      u64 path_revision, u32 path_cache_index, u32 path_generation,
			      u32 timeout_ms, u64 punt_id)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  const cilium_srv6_local_ep_t *ep;
  cilium_srv6_frag_entry_t tmpl;
  u64 key[5];
  u32 endpoint_slot;
  f64 lifetime, now;
  int taken, rv;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (src == NULL || dst == NULL || ip6_address_is_zero (src) || ip6_address_is_zero (dst))
    return VNET_API_ERROR_INVALID_VALUE;

  if (verdict != CILIUM_SRV6_VERDICT_ALLOW && verdict != CILIUM_SRV6_VERDICT_DENY)
    return VNET_API_ERROR_INVALID_VALUE;

  /* The sentinel is what "no published revision" reads as, so it can never be
     the revision a decision was taken under (same rule as
     srv6_program_add_del). */
  if (policy_revision == CILIUM_SRV6_REV_INVALID)
    return VNET_API_ERROR_INVALID_VALUE;

  /* D-31: the endpoint the punt was issued for must still be the one behind
     this sw_if_index, and it must still carry the identity the decision was
     made for. */
  ep = cilium_srv6_local_ep_lookup (hm, cm, sw_if_index);
  if (ep == NULL)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (ep->if_incarnation != if_incarnation)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (ep->identity != src_identity)
    return VNET_API_ERROR_INVALID_VALUE_3;

  /* 02 §3 makes the interface, not the packet, the authority on who sent a
     packet, so a record keyed on an address that is not this endpoint's would
     bind the decision to a source the endpoint cannot legitimately use. */
  if (!ip6_address_is_equal (&ep->ip, src))
    return VNET_API_ERROR_INVALID_VALUE;

  /*
   * 02 §4.3, the same comparison srv6_program_add_del makes: nothing decided
   * under a revision is installed once that revision has moved. The POLICY
   * key is `ep->policy_rev_slot`, because that is the slot the hot path
   * resolves for a packet from this endpoint; the ENDPOINT key is resolved
   * from `dst` exactly as an install resolves it (D-83).
   */
  {
    int endpoint_key_is_absence = 0;

    endpoint_slot = csh_endpoint_rev_resolve (hm, dst, &endpoint_key_is_absence);

    /* D-83 / errata #34 item 153, the same rule srv6_program_add_del applies:
       a positive record depends on the actual destination's endpoint revision,
       so one whose ENDPOINT key resolved to the reserved `::` absence key is
       refused. A later fragment of an ALLOW is forwarded on a path towards a
       destination this node does not publish as an endpoint at all. */
    if (verdict == CILIUM_SRV6_VERDICT_ALLOW && endpoint_key_is_absence)
      {
	hm->n_program_absence_key_installs++;
	return VNET_API_ERROR_INVALID_DST_ADDRESS;
      }
  }

  /* D-85 (00 §2.23), counted apart from the per-key mismatch below for the
     same reason srv6_program_add_del counts it apart: a fragment verdict
     decided by an agent process that no longer holds the revision authority is
     not a lost race, and the retval the caller sees is the same one the
     per-key mismatch produces. The DENY exclusion is inside the helper. */
  if (cilium_srv6_revision_is_stale_incarnation (hm, policy_revision) ||
      cilium_srv6_revision_is_stale_incarnation (hm, endpoint_revision) ||
      cilium_srv6_revision_is_stale_incarnation (hm, path_revision))
    {
      hm->n_stale_incarnation_quotes++;
      return VNET_API_ERROR_INVALID_VALUE_4;
    }

  if (!cilium_srv6_revisions_match (hm, ep->policy_rev_slot, policy_revision, endpoint_slot,
				    endpoint_revision, path_cache_index, path_revision))
    return VNET_API_ERROR_INVALID_VALUE_4;

  if (verdict == CILIUM_SRV6_VERDICT_ALLOW)
    {
      /* 01 §3.1: a later fragment is forwarded on this handle and on nothing
	 else, so an ALLOW without a resolvable path would forward nowhere. */
      if (cilium_srv6_path_get (hm, path_cache_index, path_generation) == NULL)
	return VNET_API_ERROR_NO_SUCH_ENTRY;
    }
  else
    {
      /* Nothing that could make a DENY record forward may be stored, exactly
	 as srv6_program_add_del does for a DENY entry. */
      path_cache_index = ~0;
      path_generation = 0;
    }

  /*
   * 01 §3.1 bounds the fragment cache by entry count *and* by a timeout. The
   * caller may ask for a shorter lifetime, never a longer one, so a control
   * plane bug or a compromised agent cannot turn a bounded cache into a
   * growing one by pinning records.
   */
  lifetime = (timeout_ms == 0) ? hm->frag_timeout : (f64) timeout_ms * 1e-3;
  if (lifetime > hm->frag_timeout)
    lifetime = hm->frag_timeout;

  cilium_srv6_frag_key (key, src, dst, frag_id, next_header);

  clib_memset (&tmpl, 0, sizeof (tmpl));

  tmpl.src = *src;
  tmpl.dst = *dst;
  tmpl.frag_id = frag_id;
  tmpl.next_header = next_header;
  tmpl.verdict = verdict;

  /* D-20, and the same value set cilium_srv6_frag_record() writes. */
  tmpl.src_identity = ep->identity;
  tmpl.local_context_id = ep->local_context_id;
  tmpl.policy_rev_slot = ep->policy_rev_slot;
  tmpl.endpoint_rev_slot = endpoint_slot;
  tmpl.owner_quota_class = ep->owner_quota_class;
  tmpl.policy_revision = policy_revision;
  tmpl.endpoint_revision = endpoint_revision;
  tmpl.path_revision = path_revision;
  tmpl.path_cache_index = path_cache_index;
  tmpl.path_generation = path_generation;
  /* Issue #90: the capability is armed only when this verdict answers a punt.
     Whether it survives into the installed record is decided below, against
     the record that is already there. */
  tmpl.punt_id = punt_id;
  tmpl.reinject_pending = (punt_id != 0);

  /*
   * The barrier is taken even though csh_frag_install() is already serialised
   * by frag_lock: this is an IF-2 table write, and D-12 requires a structural
   * change to a table the dataplane reads to happen with the workers stopped,
   * so that a packet cannot observe the insert half-applied across the bihash
   * and the age FIFO. Barrier first, then the lock, which is the order
   * srv6_ct_verify uses; no worker can be inside csh_frag_install() holding
   * frag_lock while the barrier is held, because a worker only reaches the
   * barrier check between frames.
   */
  taken = cilium_srv6_barrier_acquire (vm);
  clib_spinlock_lock (&hm->frag_lock);

  now = vlib_time_now (vm);
  tmpl.expires_at = now + lifetime;

  /*
   * Issue #90 reinstall semantics, applied before anything is written and
   * before the lease of step 3 is touched, so that a refusal leaves no trace
   * at all.
   */
  {
    u32 existing;

    if (cilium_srv6_frag_lookup (hm, key, &existing) && existing < hm->frag_capacity &&
	!pool_is_free_index (hm->frags, existing))
      {
	const cilium_srv6_frag_entry_t *f = hm->frags + existing;

	/*
	 * An expired record is not a live one. It has not been reclaimed yet
	 * (csh_frag_gc runs on a timer and cilium_srv6_frag_entry_usable
	 * refuses it on the hot path meanwhile), but its datagram is over, so
	 * the key is available to a new punt again — which is what "record
	 * expiry 後は新 datagram として再利用可能" says.
	 */
	if (f->in_use && f->expires_at > now && f->punt_id != punt_id)
	  {
	    hm->n_frag_punt_id_conflicts++;
	    clib_spinlock_unlock (&hm->frag_lock);
	    cilium_srv6_barrier_release (vm, taken);
	    return VNET_API_ERROR_VALUE_EXIST;
	  }

	/*
	 * Same punt, so this is an idempotent replay of the same answer:
	 *
	 *   An idempotent FragmentVerdictAdd replay MUST NOT recreate an
	 *   already-consumed reinjection capability.
	 *
	 * The capability state is carried forward rather than recomputed from
	 * `punt_id`, which is what makes CONSUMED stay CONSUMED across a
	 * retransmitted message.
	 */
	if (f->in_use && f->expires_at > now)
	  tmpl.reinject_pending = f->reinject_pending;
      }
  }

  if (verdict == CILIUM_SRV6_VERDICT_ALLOW)
    {
      /*
       * Steps 3 and 4 of the fourth policy_lease_touch path (Issue #83). The
       * refresh is the shared operation of 02 §5.4 and not a second copy of
       * its rules: csh_policy_lease_touch() is what applies them, so a slot
       * that has been handed to another identity, the sentinel revision, a
       * revision that is no longer the published one and a lease revision
       * that would move backwards are all refused in the one place that owns
       * the table.
       *
       * Step 4 is not redundant with step 3. A refresh reports that the rules
       * passed; what the hot path reads is the pair {lease_revision,
       * lease_valid_until}, and it is that pair the record's usability
       * depends on. Asking cilium_srv6_policy_lease_valid() the same question
       * cilium-srv6-classify will ask on the next packet is what makes "the
       * entry does not become visible before its exact-revision lease is
       * usable" a checked property rather than an inferred one — a lease
       * length configured to zero, for instance, refreshes successfully and
       * is still not usable.
       *
       * Either failure aborts before csh_frag_install(), so no record is
       * published: the datagram's later fragments drop as
       * DROP_FRAGMENT_UNRESOLVED, which is the fail-closed side. Both are
       * reported as the revision-binding rejection the caller already knows
       * (INVALID_VALUE_4), because both mean the same thing to the agent —
       * this node cannot vouch for {src_identity, policy_revision} right now,
       * so recompile rather than retry.
       */
      if (!csh_policy_lease_touch (hm, ep->policy_rev_slot, ep->identity, policy_revision,
				   now + (f64) hm->allow_lease_ms * 1e-3, 0 /* may_shorten */) ||
	  !cilium_srv6_policy_lease_valid (hm, ep->policy_rev_slot, ep->identity, policy_revision,
					   now))
	{
	  hm->n_frag_lease_rejects++;
	  clib_spinlock_unlock (&hm->frag_lock);
	  cilium_srv6_barrier_release (vm, taken);
	  return VNET_API_ERROR_INVALID_VALUE_4;
	}
    }

  /* 02 §8: every IF-2 message is idempotent, so a re-install of the same key
     overwrites. See the contrast with the dataplane writer documented on
     csh_frag_install(). */
  rv = csh_frag_install (hm, key, &tmpl, 1 /* replace */);

  clib_spinlock_unlock (&hm->frag_lock);
  cilium_srv6_barrier_release (vm, taken);

  return rv;
}

/* 01 §3.1 timeout, 60 s by default. Bounded work per tick. */
static u32
csh_frag_gc (vlib_main_t *vm, f64 now)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  u32 n = 0;

  if (hm->frag_age_head == (u32) ~0)
    return 0;

  clib_spinlock_lock (&hm->frag_lock);

  while (n < CILIUM_SRV6_HEADEND_FRAG_GC_PER_TICK && hm->frag_age_head != (u32) ~0)
    {
      const cilium_srv6_frag_entry_t *f = hm->frags + hm->frag_age_head;

      if (f->expires_at > now)
	break;

      csh_frag_remove (hm, hm->frag_age_head);
      hm->n_frag_gc++;
      n++;
    }

  clib_spinlock_unlock (&hm->frag_lock);

  return n;
}

/* ------------------------------------------------------------------ */
/* configuration (01 §1 outer header parameters)                       */
/* ------------------------------------------------------------------ */

int
cilium_srv6_headend_config_set (const ip6_address_t *node_address, u32 outer_table_id,
				u16 inner_mtu, u8 hop_limit, u8 copy_dscp)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_main_t *vm = vlib_get_main ();
  u32 fib_index;
  int taken;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  /* 01 §1: the outer source address is this node's address and must be
     routable from the Pod for the PTB of 01 §7 to work. */
  if (node_address == NULL || ip6_address_is_zero (node_address) ||
      ip6_address_is_link_local_unicast (node_address))
    return VNET_API_ERROR_INVALID_VALUE;

  if (inner_mtu != 0 && inner_mtu < CILIUM_SRV6_MIN_IPV6_MTU)
    return VNET_API_ERROR_INVALID_VALUE_2;

  if (hop_limit == 0)
    return VNET_API_ERROR_INVALID_VALUE_3;

  fib_index = fib_table_find (FIB_PROTOCOL_IP6, outer_table_id);
  if (fib_index == (u32) ~0)
    return VNET_API_ERROR_NO_SUCH_FIB;

  taken = cilium_srv6_barrier_acquire (vm);

  hm->node_address = *node_address;
  hm->outer_table_id = outer_table_id;
  hm->outer_fib_index = fib_index;
  hm->inner_mtu = inner_mtu ? inner_mtu : CILIUM_SRV6_INNER_MTU_DEFAULT;
  hm->hop_limit = hop_limit;
  hm->copy_dscp = copy_dscp ? 1 : 0;

  CLIB_MEMORY_STORE_BARRIER ();
  hm->configured = 1;

  cilium_srv6_barrier_release (vm, taken);

  return 0;
}

/* ------------------------------------------------------------------ */
/* hook registration (C10 conntrack, PMTUD)                            */
/* ------------------------------------------------------------------ */

void
cilium_srv6_ct_lookup_register (cilium_srv6_ct_lookup_fn fn)
{
  vlib_main_t *vm = vlib_get_main ();
  int taken = cilium_srv6_barrier_acquire (vm);

  cilium_srv6_ct_lookup_hook = fn;

  cilium_srv6_barrier_release (vm, taken);

  CSH_LOG_NOTICE ("headend conntrack lookup hook %s", fn ? "registered" : "cleared");
}

void
cilium_srv6_ct_egress_register (cilium_srv6_ct_egress_fn fn)
{
  vlib_main_t *vm = vlib_get_main ();
  int taken = cilium_srv6_barrier_acquire (vm);

  cilium_srv6_ct_egress_hook = fn;

  cilium_srv6_barrier_release (vm, taken);

  CSH_LOG_NOTICE ("headend conntrack egress hook %s", fn ? "registered" : "cleared");
}

void
cilium_srv6_ptb_send_register (cilium_srv6_ptb_send_fn fn)
{
  vlib_main_t *vm = vlib_get_main ();
  int taken = cilium_srv6_barrier_acquire (vm);

  cilium_srv6_ptb_send_hook = fn;

  cilium_srv6_barrier_release (vm, taken);

  CSH_LOG_NOTICE ("headend ICMPv6 PTB hook %s", fn ? "registered" : "cleared");
}

/* ------------------------------------------------------------------ */
/* housekeeping process                                                */
/* ------------------------------------------------------------------ */

static uword
cilium_srv6_headend_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  while (1)
    {
      f64 now;

      vlib_process_wait_for_event_or_clock (vm, CILIUM_SRV6_HEADEND_TICK_INTERVAL);
      (void) vlib_process_get_events (vm, 0);

      now = vlib_time_now (vm);

      csh_path_reclaim (vm, now);
      csh_frag_gc (vm, now);
      cilium_srv6_punt_expire_tokens (vm, now);
    }

  return 0;
}

VLIB_REGISTER_NODE (cilium_srv6_headend_process_node, static) = {
  .function = cilium_srv6_headend_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "cilium-srv6-headend-process",
  .process_log2_n_stack_bytes = 16,
};

/* ------------------------------------------------------------------ */
/* startup configuration                                               */
/* ------------------------------------------------------------------ */

static clib_error_t *
cilium_srv6_headend_config (vlib_main_t *vm, unformat_input_t *input)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  u32 v32;
  f64 v;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "program-capacity %u", &v32) && v32 > 0)
	hm->program_capacity = v32;
      else if (unformat (input, "path-capacity %u", &v32) && v32 > 0)
	hm->path_capacity = v32;
      else if (unformat (input, "fragment-capacity %u", &v32) && v32 > 0)
	hm->frag_capacity = v32;
      else if (unformat (input, "fragment-timeout %f", &v) && v > 0.0)
	hm->frag_timeout = v;
      else if (unformat (input, "policy-revision-capacity %u", &v32) && v32 > 0)
	hm->policy_rev_capacity = v32;
      else if (unformat (input, "endpoint-revision-capacity %u", &v32) && v32 > 0)
	hm->endpoint_rev_capacity = v32;
      else if (unformat (input, "allow-lease-ms %u", &v32) && v32 > 0)
	hm->allow_lease_ms = v32;
      else if (unformat (input, "grace-period %f", &v) && v > 0.0)
	hm->grace_period = v;
      else if (unformat (input, "punt-capacity %u", &v32) && v32 > 0)
	hm->punt_q[CILIUM_SRV6_PUNT_Q_COMPILE].capacity = v32;
      else if (unformat (input, "punt-reauth-capacity %u", &v32) && v32 > 0)
	hm->punt_q[CILIUM_SRV6_PUNT_Q_REAUTH].capacity = v32;
      else if (unformat (input, "punt-fragment-capacity %u", &v32) && v32 > 0)
	hm->punt_q[CILIUM_SRV6_PUNT_Q_FRAGMENT].capacity = v32;
      else if (unformat (input, "punt-owner-quota %u", &v32) && v32 > 0)
	{
	  int i;
	  for (i = 0; i < CILIUM_SRV6_PUNT_N_Q; i++)
	    hm->punt_q[i].owner_quota = v32;
	}
      else if (unformat (input, "punt-identity-quota %u", &v32) && v32 > 0)
	{
	  int i;
	  for (i = 0; i < CILIUM_SRV6_PUNT_N_Q; i++)
	    hm->punt_q[i].identity_quota = v32;
	}
      else if (unformat (input, "punt-token-timeout %f", &v) && v > 0.0)
	hm->punt_token_timeout = v;
      else
	return clib_error_return (0, "unknown input `%U'", format_unformat_error, input);
    }

  return 0;
}

VLIB_CONFIG_FUNCTION (cilium_srv6_headend_config, "cilium-srv6-headend");

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

/*
 * D-36: the flow entropy seed is a node-local secret. A cluster-wide constant
 * would let an attacker compute a victim's Flow Label from its 5-tuple, which
 * is one of the inputs the RecentTx correlation of 02 §9 checks.
 *
 * The same draw serves the punt_id boot nonce of Issue #90, which needs
 * uniqueness across restarts rather than secrecy; `purpose` says which one is
 * being drawn so that the fallback is reported accurately.
 */
static u64
csh_random_seed (vlib_main_t *vm, const char *purpose)
{
  u64 seed = 0;
  FILE *f = fopen ("/dev/urandom", "rb");

  if (f != NULL)
    {
      size_t n = fread (&seed, 1, sizeof (seed), f);
      fclose (f);
      if (n == sizeof (seed) && seed != 0)
	return seed;
    }

  /*
   * Fallback. This is weaker than /dev/urandom and is logged as such, but it
   * is still node-local and not derivable from another node's state.
   */
  seed = clib_cpu_time_now () ^ ((u64) (uword) vm << 17);
  CSH_LOG_ERR ("could not read /dev/urandom: %s is derived from local clock "
	       "state instead",
	       purpose);

  return seed | 1;
}

static clib_error_t *
cilium_srv6_headend_init (vlib_main_t *vm)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  int i;

  clib_memset (hm, 0, sizeof (*hm));

  cilium_srv6_headend_log_class = vlib_log_register_class ("cilium-srv6", "headend");

  hm->program_capacity = CILIUM_SRV6_PROGRAM_CAPACITY_DEFAULT;
  hm->path_capacity = CILIUM_SRV6_PATH_CAPACITY_DEFAULT;
  hm->frag_capacity = CILIUM_SRV6_FRAG_CAPACITY_DEFAULT;
  hm->frag_timeout = CILIUM_SRV6_FRAG_TIMEOUT_DEFAULT;
  hm->policy_rev_capacity = CILIUM_SRV6_POLICY_REV_CAPACITY_DEFAULT;
  hm->endpoint_rev_capacity = CILIUM_SRV6_ENDPOINT_REV_CAPACITY_DEFAULT;
  hm->allow_lease_ms = CILIUM_SRV6_ALLOW_LEASE_DEFAULT_MS;
  hm->grace_period = CILIUM_SRV6_HEADEND_GRACE_PERIOD_DEFAULT;
  hm->punt_token_timeout = CILIUM_SRV6_PUNT_TOKEN_TIMEOUT_DEFAULT;
  hm->inner_mtu = CILIUM_SRV6_INNER_MTU_DEFAULT;
  hm->hop_limit = CILIUM_SRV6_HOP_LIMIT_DEFAULT;
  hm->copy_dscp = 1;
  hm->outer_fib_index = ~0;

  hm->punt_q[CILIUM_SRV6_PUNT_Q_COMPILE].capacity = CILIUM_SRV6_PUNT_CAPACITY_DEFAULT;
  hm->punt_q[CILIUM_SRV6_PUNT_Q_REAUTH].capacity = CILIUM_SRV6_PUNT_REAUTH_CAPACITY_DEFAULT;
  hm->punt_q[CILIUM_SRV6_PUNT_Q_FRAGMENT].capacity = CILIUM_SRV6_PUNT_FRAGMENT_CAPACITY_DEFAULT;

  for (i = 0; i < CILIUM_SRV6_PUNT_N_Q; i++)
    {
      hm->punt_q[i].owner_quota = CILIUM_SRV6_PUNT_OWNER_QUOTA_DEFAULT;
      hm->punt_q[i].identity_quota = CILIUM_SRV6_PUNT_IDENTITY_QUOTA_DEFAULT;
    }

  hm->prog_age_head[0] = hm->prog_age_head[1] = ~0;
  hm->prog_age_tail[0] = hm->prog_age_tail[1] = ~0;
  hm->frag_age_head = hm->frag_age_tail = ~0;

  hm->flow_hash_seed = csh_random_seed (vm, "the flow entropy seed (D-36)");

  /*
   * Issue #90: the boot half of the punt operation identity space. Drawn the
   * same way as the flow entropy seed for convenience only — unlike that one
   * it is not a secret and does not have to be unpredictable (see the note on
   * cilium_srv6_punt_meta_t.punt_id). What it has to be is different from the
   * value the previous run of this process used, so that a punt_id issued
   * before a restart cannot be mistaken for one issued after it, which the
   * clock-derived fallback also gives.
   */
  hm->punt_id_nonce = csh_random_seed (vm, "the punt operation identity nonce (#90)");
  hm->punt_id_seq = 0;

  hm->classify_node_index = cilium_srv6_classify_node.index;
  hm->process_node_index = cilium_srv6_headend_process_node.index;

  return 0;
}

VLIB_INIT_FUNCTION (cilium_srv6_headend_init) = {
  .runs_after = VLIB_INITS ("vnet_feature_init", "vnet_interface_init", "fib_module_init"),
};

/*
 * 02 §9 / 03 §9: the pools are reserved once and never grown, so the hot path
 * performs no allocation and the pool base pointers are stable for lock-free
 * readers. This runs at main-loop-enter because the capacities come from the
 * startup configuration, which VLIB applies after the init functions.
 */
static clib_error_t *
cilium_srv6_headend_main_loop_enter (vlib_main_t *vm)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  cilium_srv6_policy_rev_t *sentinel;
  cilium_srv6_endpoint_rev_t *ep_sentinel;
  u32 nbuckets;

  if (hm->initialised)
    return 0;

  hm->program_negative_capacity =
    clib_max (1, hm->program_capacity / 100 * CILIUM_SRV6_PROGRAM_NEGATIVE_PERCENT);

  pool_init_fixed (hm->programs, hm->program_capacity);
  pool_init_fixed (hm->paths, hm->path_capacity);
  pool_init_fixed (hm->path_mtus, hm->path_capacity);
  pool_init_fixed (hm->frags, hm->frag_capacity);
  pool_init_fixed (hm->policy_rev, hm->policy_rev_capacity);
  pool_init_fixed (hm->endpoint_rev, hm->endpoint_rev_capacity);

  /* Slot 0 is the permanent sentinel (see CSH_POLICY_REV_SENTINEL). */
  pool_get_zero (hm->policy_rev, sentinel);
  ASSERT (sentinel == hm->policy_rev);
  sentinel->identity = ~0;
  sentinel->refcount = ~0;
  sentinel->policy_revision = CILIUM_SRV6_REV_INVALID;
  sentinel->lease_revision = CILIUM_SRV6_REV_INVALID;
  sentinel->lease_valid_until = 0.0;

  /* Slot 0 of the ENDPOINT table is the same kind of permanent sentinel
     (CSH_ENDPOINT_REV_SENTINEL): it is never in the by-destination index, so
     nothing resolves to it, and it reads as the ~0 sentinel for a holder that
     still names it. */
  pool_get_zero (hm->endpoint_rev, ep_sentinel);
  ASSERT (ep_sentinel == hm->endpoint_rev);
  ep_sentinel->refcount = ~0;
  ep_sentinel->present = 0;
  ep_sentinel->revision = CILIUM_SRV6_REV_INVALID;
  ep_sentinel->hwm = CILIUM_SRV6_REV_INVALID;

  /* D-83 PATH keys, dense by PathCache index. Zero is
     CILIUM_SRV6_REV_ABSENT, i.e. "this index has no published revision",
     which is the fail-closed starting state. */
  vec_validate (hm->path_revs, hm->path_capacity - 1);

  hm->prog_owner_count = hash_create (0, sizeof (uword));
  hm->prog_identity_count = hash_create (0, sizeof (uword));
  hm->frag_owner_count = hash_create (0, sizeof (uword));
  hm->frag_identity_count = hash_create (0, sizeof (uword));
  hm->policy_rev_by_identity = hash_create (0, sizeof (uword));

  nbuckets = 1 << clib_max (6, max_log2 (hm->endpoint_rev_capacity) - 2);
  clib_bihash_init_16_8 (&hm->endpoint_rev_by_dst, "cilium-srv6-endpoint-rev", nbuckets,
			 (uword) hm->endpoint_rev_capacity * 96);

  /* PathCache staging transaction (D-61). All main-thread state: no worker
     reads any of it, so a staged entry cannot reach the dataplane before the
     commit publishes it. */
  hm->path_spec_index = hash_create (0, sizeof (uword));
  hm->path_staged_by_client = hash_create (0, sizeof (uword));
  hm->path_staged_by_spec = hash_create (0, sizeof (uword));
  vec_validate (hm->path_claimed, hm->path_capacity - 1);

  vec_alloc (hm->path_pending, hm->path_capacity);

  clib_spinlock_init (&hm->frag_lock);
  clib_spinlock_init (&hm->punt_lock);

  nbuckets = 1 << clib_max (6, max_log2 (hm->program_capacity) - 2);
  clib_bihash_init_24_8 (&hm->program_table, "cilium-srv6-program", nbuckets,
			 (uword) hm->program_capacity * 128);

  nbuckets = 1 << clib_max (6, max_log2 (hm->frag_capacity) - 2);
  clib_bihash_init_40_8 (&hm->frag_table, "cilium-srv6-fragment", nbuckets,
			 (uword) hm->frag_capacity * 160);

  nbuckets = 1 << clib_max (6, max_log2 (hm->path_capacity) - 2);
  clib_bihash_init_8_8 (&hm->path_mtu_table, "cilium-srv6-path-mtu", nbuckets,
			(uword) hm->path_capacity * 128);

  cilium_srv6_punt_init (vm);

  hm->initialised = 1;

  CSH_LOG_NOTICE ("headend ready: ProgramCache %u entries (negative budget %u), "
		  "PathCache %u, FragmentVerdictCache %u (timeout %.0f s), "
		  "punt queues %u/%u/%u",
		  hm->program_capacity, hm->program_negative_capacity, hm->path_capacity,
		  hm->frag_capacity, hm->frag_timeout,
		  hm->punt_q[CILIUM_SRV6_PUNT_Q_COMPILE].capacity,
		  hm->punt_q[CILIUM_SRV6_PUNT_Q_REAUTH].capacity,
		  hm->punt_q[CILIUM_SRV6_PUNT_Q_FRAGMENT].capacity);

  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (cilium_srv6_headend_main_loop_enter);
