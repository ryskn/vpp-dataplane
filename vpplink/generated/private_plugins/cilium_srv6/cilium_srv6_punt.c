/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — headend punt / slow path (C7, IF-3).
 *
 * design/detail/02-headend-dataplane.md §5 (punt path and its rules)
 * design/detail/00-overview.md §2 (D-27, D-38, D-42, D-43), §4.1 (IF-3
 *   permission boundary and the one-shot reinject token)
 *
 * What lives here is the part of IF-3 that has to be inside VPP:
 *
 *   admission   the bounded queues of 02 §5.2 with the D-42 owner -> identity
 *               hierarchy, so that one namespace (or one route flap) cannot
 *               occupy the slow path. Refusal is DROP_SLOWPATH_OVERFLOW; the
 *               packet is never forwarded around the miss, which is what
 *               keeps the design fail-closed.
 *   token       a one-shot opaque value issued per punt and bound to the
 *               receiving interface lifetime. 00 §4.1: "IF-3 の reinject は
 *               punt 時に発行した一回性 opaque token と packet metadata を
 *               結び付け、任意 metadata だけの注入を受け付けない".
 *   punt_id     the identity of the punt operation (Issue #90). Unlike the
 *               token it is not consumed here: it travels on to
 *               srv6_fragment_verdict_add, is stored in the record, and is
 *               what lets cilium-srv6-classify recognise the reinjected first
 *               fragment as the continuation of the punt that produced that
 *               record instead of dropping it under D-43.
 *   reinject    validation and re-entry of the packet the agent sends back
 *               (02 §5.1 step 8).
 *
 * The transport itself — the Unix domain socket of 00 §4.1, its peer
 * credential check and its framing — is deliberately *not* implemented here.
 * It is reached through cilium_srv6_punt_tx_register(), so this file fixes the
 * boundary (metadata layout, token semantics, admission rules) without
 * pulling a socket implementation into the graph-node change. With no
 * transport registered every punt fails closed and is counted separately in
 * punt_no_transport, so the missing half is observable rather than silent.
 */

#include <stdbool.h>
#include <string.h>

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip6_packet.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_headend.h>

static cilium_srv6_punt_tx_fn cilium_srv6_punt_tx_hook;

static vlib_log_class_t cilium_srv6_punt_log_class;

#define CSP_LOG_ERR(...)    vlib_log_err (cilium_srv6_punt_log_class, __VA_ARGS__)
#define CSP_LOG_NOTICE(...) vlib_log_notice (cilium_srv6_punt_log_class, __VA_ARGS__)

/* Composite keys of the per-queue outstanding counters. */
#define CSP_COUNT_KEY(queue, id) ((((u64) (queue)) << 32) | (u64) (id))

/*
 * Issue #90: the punt operation identity space.
 *
 * The decision of 2026-09-01 asks for uniqueness across a restart and
 * explicitly not for unpredictability: the value never reaches an attacker,
 * and the reinject is already authorised by the one-shot token and by the
 * D-27 socket. {boot nonce, monotonic counter} gives that with no per-punt
 * randomness.
 *
 *   within one run   the counter is strictly increasing and the nonce is
 *                    fixed, so `nonce + seq` never repeats. 2^64 punts is not
 *                    a reachable number, so there is no wrap to reason about.
 *   across runs      the nonce displaces the whole sequence. Two runs collide
 *                    only where nonce2 - nonce1 happens to equal a difference
 *                    of two counter values, which for a 64-bit nonce and a
 *                    realistically bounded counter does not happen.
 *
 * What the construction deliberately does not do is derive the value from the
 * packet or from the fragment key: the decision forbids inferring "same key,
 * therefore same punt", and a derived value would make exactly that inference
 * true by construction.
 *
 * Called with punt_lock held, so the increment needs no atomics. The zero
 * value is skipped because it is the "no punt operation" value of a
 * FragmentVerdictCache record written by the dataplane.
 */
static u64
csp_punt_id_next_locked (cilium_srv6_headend_main_t *hm)
{
  u64 id;

  hm->punt_id_seq++;
  id = hm->punt_id_nonce + hm->punt_id_seq;
  if (PREDICT_FALSE (id == 0))
    {
      hm->punt_id_seq++;
      id = hm->punt_id_nonce + hm->punt_id_seq;
    }
  return id;
}

u64
cilium_srv6_punt_id_next (void)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  u64 id;

  clib_spinlock_lock (&hm->punt_lock);
  id = csp_punt_id_next_locked (hm);
  clib_spinlock_unlock (&hm->punt_lock);

  return id;
}

void
cilium_srv6_punt_tx_register (cilium_srv6_punt_tx_fn fn)
{
  vlib_main_t *vm = vlib_get_main ();
  int taken = cilium_srv6_barrier_acquire (vm);

  cilium_srv6_punt_tx_hook = fn;

  cilium_srv6_barrier_release (vm, taken);

  CSP_LOG_NOTICE ("IF-3 punt transport %s", fn ? "registered" : "cleared");
}

int
cilium_srv6_punt_transport_registered (void)
{
  return cilium_srv6_punt_tx_hook != 0;
}

/* ------------------------------------------------------------------ */
/* outstanding-punt accounting (02 §5.2, D-42)                         */
/* ------------------------------------------------------------------ */

/* punt_lock held. */
static uword
csp_count_get (uword *h, u64 key)
{
  uword *p = hash_get (h, (uword) key);

  return p ? p[0] : 0;
}

/* punt_lock held. */
static void
csp_count_add (uword **h, u64 key, int delta)
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

/*
 * Release the resources one token holds. punt_lock held.
 *
 * DEVIATION (02 §5.2 "weighted fair scheduling"): the design describes the
 * punt path as a queue that is drained with weighted fair scheduling. This
 * implementation hands the packet to the transport immediately — the same
 * shape VPP's own punt socket has — so there is no queue to schedule and the
 * bound is on *outstanding* punts, i.e. punts whose token has not been
 * redeemed or expired yet. Fairness is therefore enforced entirely at
 * admission by the hierarchical quota, which is the property D-42 is after:
 * one owner, and one identity inside it, cannot occupy more than its share of
 * the slow path. Adding a real queue would also mean holding packet buffers
 * across the barrier, which the fixed-pool/no-allocation rule of 02 §9 does
 * not allow.
 */
static void
csp_token_release (cilium_srv6_headend_main_t *hm, cilium_srv6_punt_token_t *t)
{
  cilium_srv6_punt_queue_state_t *q;

  if (!t->in_use)
    return;

  q = hm->punt_q + t->queue;

  if (q->n_outstanding > 0)
    q->n_outstanding--;

  csp_count_add (&hm->punt_owner_count, CSP_COUNT_KEY (t->queue, t->owner_quota_class), -1);
  csp_count_add (&hm->punt_identity_count, CSP_COUNT_KEY (t->queue, t->src_identity), -1);

  t->in_use = 0;

  /*
   * The nonce is bumped on release, not on issue, so a token is one-shot:
   * once redeemed (or expired) the same value can never validate again, and
   * the slot has to be re-issued before it means anything.
   */
  t->nonce++;
  if (t->nonce == 0)
    t->nonce = 1;
}

/* ------------------------------------------------------------------ */
/* punt admission (02 §5.2)                                            */
/* ------------------------------------------------------------------ */

/*
 * One packet of 02 §5.1. Returns 1 if the packet was handed to the agent.
 *
 * Called from a worker, so every mutation of the token store and of the
 * per-owner / per-identity counters happens under punt_lock. Nothing here
 * allocates: the token pool is fixed size and the transport hook copies what
 * it needs out of the buffer.
 */
int
cilium_srv6_punt_one (vlib_main_t *vm, vlib_buffer_t *b, u8 queue, u8 reason)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_headend_meta_t *meta = cilium_srv6_headend_meta (b);
  /* The Fragment header's Next Header lives in the second opaque area
     because the first one is full; cilium-srv6-classify writes both from the
     same bounded parse. */
  const cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b);
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  cilium_srv6_punt_tx_fn tx = cilium_srv6_punt_tx_hook;
  cilium_srv6_punt_queue_state_t *q;
  cilium_srv6_punt_token_t *t;
  cilium_srv6_punt_meta_t wire;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  u32 slot;
  u64 owner_key, identity_key;
  int sent;

  if (PREDICT_FALSE (queue >= CILIUM_SRV6_PUNT_N_Q || !hm->initialised))
    return 0;

  q = hm->punt_q + queue;

  clib_spinlock_lock (&hm->punt_lock);

  /* 02 §5.2: the global bound comes first; "fail-closed を保つため queue
     溢れで bypass しない". */
  if (q->n_outstanding >= q->capacity)
    {
      q->n_drop_global++;
      goto refuse;
    }

  /*
   * D-42: the owner(namespace) budget is the outer bound and the identity
   * budget the inner one. Checking the owner first is what makes the identity
   * budget useless as an amplifier — a tenant that mints new identities still
   * runs into its owner budget.
   */
  owner_key = CSP_COUNT_KEY (queue, meta->owner_quota_class);
  if (csp_count_get (hm->punt_owner_count, owner_key) >= q->owner_quota)
    {
      q->n_drop_owner++;
      goto refuse;
    }

  identity_key = CSP_COUNT_KEY (queue, meta->src_identity);
  if (csp_count_get (hm->punt_identity_count, identity_key) >= q->identity_quota)
    {
      q->n_drop_identity++;
      goto refuse;
    }

  if (pool_free_elts (hm->punt_tokens) == 0)
    {
      q->n_drop_no_token++;
      goto refuse;
    }

  pool_get (hm->punt_tokens, t);
  slot = (u32) (t - hm->punt_tokens);

  if (t->nonce == 0)
    t->nonce = 1;

  t->in_use = 1;
  t->queue = queue;
  t->owner_quota_class = meta->owner_quota_class;
  t->src_identity = meta->src_identity;
  t->rx_sw_if_index = sw_if_index;
  t->rx_if_incarnation =
    (sw_if_index < vec_len (cm->ifs)) ? cm->ifs[sw_if_index].incarnation : (u32) ~0;
  t->expires_at = vlib_time_now (vm) + hm->punt_token_timeout;
  /* Issue #90: one identity per punt operation, recorded with the token so
     that the reinject's echo can be checked against it. */
  t->punt_id = csp_punt_id_next_locked (hm);

  q->n_outstanding++;
  csp_count_add (&hm->punt_owner_count, owner_key, +1);
  csp_count_add (&hm->punt_identity_count, identity_key, +1);

  /* IF-3 metadata (02 §5.1 "packet 全体 + meta"). */
  clib_memset (&wire, 0, sizeof (wire));
  wire.version = CILIUM_SRV6_PUNT_META_VERSION;
  wire.length = sizeof (wire);
  wire.token = ((u64) slot << 32) | (u64) t->nonce;
  wire.reason = reason;
  wire.queue = queue;
  wire.src_identity = meta->src_identity;
  wire.rx_sw_if_index = sw_if_index;
  wire.rx_if_incarnation = t->rx_if_incarnation;
  wire.local_context_id = meta->local_context_id;
  wire.owner_quota_class = meta->owner_quota_class;
  wire.packet_length = (u32) vlib_buffer_length_in_chain (vm, b);
  wire.frag_id = meta->frag_id;
  wire.l4_discriminator = meta->l4_discriminator;
  wire.proto = meta->proto;
  wire.frag_kind = meta->flags;
  /*
   * 01 §3.1: the FragmentVerdictCache key component is the Fragment header's
   * Next Header, not the upper layer protocol. The agent cannot re-derive it
   * — it deliberately does not re-parse the packet — so it is carried here.
   * It is already what cilium-srv6-classify keyed its own lookup on, so the
   * entry the agent installs and the lookup the hot path performs use the
   * same value even when a per-fragment extension header follows.
   */
  wire.frag_next_header = pm->frag_next_header;
  /*
   * Issue #90. The agent echoes this in srv6_fragment_verdict_add and in the
   * reinject; the FragmentVerdictCache record it installs is armed with it,
   * and only the reinject that carries it back may spend the record's one-shot
   * reinjection capability. Every punt carries one — the field describes the
   * punt operation, not the queue — even though only the fragment queue has a
   * record to arm today.
   */
  wire.punt_id = t->punt_id;

  clib_spinlock_unlock (&hm->punt_lock);

  sent = (tx != 0) ? tx (vm, b, &wire) : 0;

  if (PREDICT_TRUE (sent))
    {
      q->n_punted++;
      return 1;
    }

  /* The transport refused (or there is none): give the quota straight back
     rather than letting an unreachable agent drain the queue. */
  clib_spinlock_lock (&hm->punt_lock);
  csp_token_release (hm, t);
  pool_put_index (hm->punt_tokens, slot);
  if (tx == 0)
    q->n_drop_no_transport++;
  else
    q->n_drop_global++;
  clib_spinlock_unlock (&hm->punt_lock);

  return 0;

refuse:
  clib_spinlock_unlock (&hm->punt_lock);
  return 0;
}

/* ------------------------------------------------------------------ */
/* reinject (02 §5.1 step 8, 00 §4.1)                                  */
/* ------------------------------------------------------------------ */

/*
 * Validate a token and consume it. Returns 0 and fills *out on success.
 */
static int
csp_token_redeem (cilium_srv6_headend_main_t *hm, u64 token, cilium_srv6_punt_token_t *out)
{
  cilium_srv6_punt_token_t *t;
  u32 slot = (u32) (token >> 32);
  u32 nonce = (u32) token;
  int rv = VNET_API_ERROR_INVALID_VALUE;

  clib_spinlock_lock (&hm->punt_lock);

  if (slot >= hm->punt_token_capacity || pool_is_free_index (hm->punt_tokens, slot))
    goto done;

  t = hm->punt_tokens + slot;

  /* One-shot: an already released slot has a different nonce. */
  if (!t->in_use || t->nonce != nonce)
    goto done;

  *out = *t;

  csp_token_release (hm, t);
  pool_put_index (hm->punt_tokens, slot);
  rv = 0;

done:
  clib_spinlock_unlock (&hm->punt_lock);
  return rv;
}

/*
 * 02 §5.1 step 8. The packet re-enters at cilium-srv6-classify rather than at
 * cilium-srv6-program on purpose:
 *
 *  - the identity, the source address check and the L4 discriminator are
 *    recomputed from the bytes, so agent-supplied metadata can never decide
 *    how a packet is classified (00 §4.1 "任意 metadata だけの注入を
 *    受け付けない");
 *  - the hot path revision checks run again, which is exactly what step 8
 *    asks for ("再度 hot-path revision 検査").
 *
 * The token supplies the two things that cannot be recovered from the packet:
 * which interface lifetime it arrived on, and — since Issue #90 — which punt
 * operation this is the continuation of. If that interface is gone, or has
 * been replaced (incarnation moved, D-31), the reinject is refused.
 *
 * The echoed `punt_id` is checked against the one the token was issued with
 * rather than believed. It is not an authorisation (the token is), but taking
 * it on trust would let a compromised agent mark a packet as the continuation
 * of a punt other than the one it redeemed, and the FragmentVerdictCache
 * capability of Issue #90 is keyed on exactly that value. Checking it here
 * means cilium-srv6-classify can treat the marking as dataplane-issued.
 */
int
cilium_srv6_punt_reinject (u64 token, u64 punt_id, const u8 *data, u32 len)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  vlib_main_t *vm = vlib_get_main ();
  cilium_srv6_punt_token_t t;
  vlib_buffer_t *b;
  vlib_frame_t *f;
  u32 *to_next;
  u32 bi;
  int taken;
  int rv;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (data == NULL || len < sizeof (ip6_header_t))
    return VNET_API_ERROR_INVALID_VALUE_2;

  /* 00 §4.1: bound every declared length before it is used. A reinject that
     does not fit one buffer is refused rather than chained together here. */
  if (len > vlib_buffer_get_default_data_size (vm))
    return VNET_API_ERROR_INVALID_VALUE_2;

  rv = csp_token_redeem (hm, token, &t);
  if (rv != 0)
    {
      hm->punt_q[CILIUM_SRV6_PUNT_Q_COMPILE].n_reinject_rejected++;
      return rv;
    }

  /*
   * Issue #90: the echoed punt operation identity must be the one this token
   * was issued with. The token is already consumed at this point, so a wrong
   * echo costs the packet and nothing else — which is the fail-closed
   * direction, and the agent has no reason to send one.
   */
  if (punt_id != t.punt_id)
    {
      hm->punt_q[t.queue].n_reinject_rejected++;
      hm->n_reinject_punt_id_mismatch++;
      return VNET_API_ERROR_INVALID_VALUE_2;
    }

  /* D-31: the interface lifetime the punt was issued on must still be live. */
  if (t.rx_sw_if_index >= vec_len (cm->ifs) || !cm->ifs[t.rx_sw_if_index].valid ||
      cm->ifs[t.rx_sw_if_index].incarnation != t.rx_if_incarnation)
    {
      hm->punt_q[t.queue].n_reinject_rejected++;
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
    }

  if (vlib_buffer_alloc (vm, &bi, 1) != 1)
    {
      hm->punt_q[t.queue].n_reinject_rejected++;
      return VNET_API_ERROR_UNSPECIFIED;
    }

  b = vlib_get_buffer (vm, bi);
  clib_memcpy_fast (b->data, data, len);
  b->current_data = 0;
  b->current_length = (u16) len;
  /*
   * Issue #90: CILIUM_SRV6_BUFFER_F_REINJECT is what tells
   * cilium-srv6-classify that this first fragment is the continuation of a
   * punt rather than a second reception from the network — the distinction
   * the D-43 clarification of Issue #90 turns on. It is set here and nowhere
   * else, and a buffer that carried a packet in from an interface cannot have
   * it: the allocator clears the AVAIL flags on every allocation and no
   * receive path sets them.
   */
  b->flags = VNET_BUFFER_F_LOCALLY_ORIGINATED | CILIUM_SRV6_BUFFER_F_REINJECT;
  b->total_length_not_including_first_buffer = 0;

  vnet_buffer (b)->sw_if_index[VLIB_RX] = t.rx_sw_if_index;
  vnet_buffer (b)->sw_if_index[VLIB_TX] = ~0;

  /* Consumed by cilium-srv6-classify before it writes its own path metadata
     over the same scratch area; see cilium_srv6_reinject_meta_t. Both values
     come from the token this reinject redeemed, so neither is agent input. */
  cilium_srv6_reinject_meta (b)->punt_id = t.punt_id;
  cilium_srv6_reinject_meta (b)->punt_queue = t.queue;

  /* Enqueueing a frame from the main thread requires the workers to be
     stopped, exactly as for a table update. */
  taken = cilium_srv6_barrier_acquire (vm);

  f = vlib_get_frame_to_node (vm, hm->classify_node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, hm->classify_node_index, f);

  cilium_srv6_barrier_release (vm, taken);

  hm->punt_q[t.queue].n_reinjected++;

  return 0;
}

/*
 * A token that is never redeemed would hold its share of the queue for ever,
 * so an agent that stops answering releases the slow path by timeout instead
 * of wedging it (02 §5.2 keeps the queue bounded in every failure mode).
 */
void
cilium_srv6_punt_expire_tokens (vlib_main_t *vm, f64 now)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  u32 slot;

  if (!hm->initialised)
    return;

  clib_spinlock_lock (&hm->punt_lock);

  /* Iterated by index rather than with pool_foreach: the loop frees pool
     elements as it goes, and the fixed pool makes the index walk exact. */
  for (slot = 0; slot < hm->punt_token_capacity; slot++)
    {
      cilium_srv6_punt_token_t *t;

      if (pool_is_free_index (hm->punt_tokens, slot))
	continue;

      t = hm->punt_tokens + slot;

      if (!t->in_use || t->expires_at > now)
	continue;

      hm->punt_q[t->queue].n_expired++;
      csp_token_release (hm, t);
      pool_put_index (hm->punt_tokens, slot);
    }

  clib_spinlock_unlock (&hm->punt_lock);
}

/* ------------------------------------------------------------------ */
/* init                                                                */
/* ------------------------------------------------------------------ */

void
cilium_srv6_punt_init (vlib_main_t *vm)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  u32 capacity = 0;
  int i;

  cilium_srv6_punt_log_class = vlib_log_register_class ("cilium-srv6", "punt");

  /* One token slot per admissible outstanding punt, across every queue. */
  for (i = 0; i < CILIUM_SRV6_PUNT_N_Q; i++)
    capacity += hm->punt_q[i].capacity;

  hm->punt_token_capacity = capacity;

  pool_init_fixed (hm->punt_tokens, capacity);

  hm->punt_owner_count = hash_create (0, sizeof (uword));
  hm->punt_identity_count = hash_create (0, sizeof (uword));
}
