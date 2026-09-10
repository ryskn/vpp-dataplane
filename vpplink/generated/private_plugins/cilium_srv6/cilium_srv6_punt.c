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
 *   release     the DENY half of the same protocol (02 §5.6.3): the agent
 *               hands the token back with a 06 §2 drop reason instead of a
 *               packet, and the slot is freed immediately rather than at the
 *               token timeout.
 *
 * The transport — the Unix domain socket of 00 §4.1, its framing and its
 * reconnection — lives in cilium_srv6_punt_transport.c and reaches this file
 * through cilium_srv6_punt_tx_register(). The split is the thread boundary of
 * 00 §2.18.7: what runs here runs on a worker and does no socket I/O, and the
 * transport owner is the only thread that connects, writes, reads and
 * reconnects. With no transport registered, or with one that is not
 * connected, every punt fails closed and is counted in punt_no_transport, so
 * a missing agent is observable rather than silent.
 *
 * Threading. Everything in this file that touches the token store, the quota
 * counters or the punt_id sequence runs under `hm->punt_lock`, from any
 * worker. The two exceptions are stated where they are:
 *
 *   - `q->n_punted` is incremented outside the lock (the transport has to be
 *     called with the lock released) and is therefore an atomic;
 *   - cilium_srv6_punt_reinject() and cilium_srv6_punt_release() are main
 *     thread only, because the first enqueues a frame to a graph node.
 */

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlib/threads.h>
#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip6_packet.h>
#include <vppinfra/atomics.h>
#include <vppinfra/random_isaac.h>

#include <cilium_srv6/cilium_srv6_guard.h>
#include <cilium_srv6/cilium_srv6_headend.h>
#include <cilium_srv6/cilium_srv6_punt_wire.h>
#include <cilium_srv6/cilium_srv6.api_enum.h>

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
   * One-shot (D-76 §2.18.4): the lookup entry goes first and the bytes are
   * wiped, so the value that was on the wire resolves to nothing from this
   * moment on. Redeeming, releasing and expiring all come through here, so
   * there is one place where a token stops being a capability.
   *
   * The key the hash holds is `t->token` itself, so it must be unset while
   * the bytes are still the ones it was inserted under.
   */
  hash_unset_mem (hm->punt_token_index, t->token);
  clib_memset (t->token, 0, sizeof (t->token));
}

/*
 * Draw a fresh 16-byte token into `t` and index it. punt_lock held.
 *
 * The value is opaque: nothing about the slot, the queue or the packet is
 * derivable from it (D-76 §2.18.4). The all-zero value is rejected because
 * the wire reserves it — it is what a peer that can write on the socket but
 * has never seen a punt would send — and a collision with a live token is
 * rejected because two live tokens with the same bytes would make redemption
 * ambiguous. Both are re-drawn; both are astronomically unlikely, and the
 * bounded retry means a broken entropy source fails the punt rather than
 * looping in a worker.
 *
 * Returns 1 on success.
 */
static int
csp_token_draw_locked (cilium_srv6_headend_main_t *hm, cilium_srv6_punt_token_t *t)
{
  int attempt;

  for (attempt = 0; attempt < 4; attempt++)
    {
      const u8 *r = clib_random_buffer_get_data (&hm->punt_rng, CILIUM_SRV6_IF3_TOKEN_LEN);

      clib_memcpy_fast (t->token, r, CILIUM_SRV6_IF3_TOKEN_LEN);

      if (cilium_srv6_if3_token_is_zero (t->token))
	continue;
      if (hash_get_mem (hm->punt_token_index, t->token) != 0)
	continue;

      hash_set_mem (hm->punt_token_index, t->token, (uword) (t - hm->punt_tokens));
      return 1;
    }

  clib_memset (t->token, 0, sizeof (t->token));
  return 0;
}

/* ------------------------------------------------------------------ */
/* punt admission (02 §5.2)                                            */
/* ------------------------------------------------------------------ */

/*
 * Build the plugin-internal punt handoff (D-76, `00` §2.18.2).
 *
 * Every value here was produced by the headend graph, not by a second parse:
 *
 *   src_identity, l4_discriminator, proto,
 *   frag_id, the fragment kind          cilium-srv6-classify (02 §3), through
 *                                       cilium_srv6_headend_meta_t
 *   sport, dport, frag_next_header      the same bounded parse, through
 *                                       cilium_srv6_path_meta_t
 *   rx_sw_if_index, rx_if_incarnation,
 *   token, punt_id                      the admission decision above
 *
 * The two addresses are the only values read from the packet, and they are
 * read the way every other headend stage reads them — the fixed `src_address`
 * and `dst_address` fields of the outermost IPv6 header at
 * vlib_buffer_get_current(), the same header cilium-srv6-classify validated
 * and cilium-srv6-program keyed its ProgramCache lookup on. That is a
 * fixed-offset field read, not a parse: there is no header chain to walk, no
 * length to trust and therefore no second interpretation of the packet for
 * the agent's key to disagree with, which is what `00` §2.18.2 is protecting.
 * They are not carried in the buffer metadata for a mundane reason: both vnet
 * opaque scratch areas are full (24 of 24 bytes, and 20 of 24), and 32 bytes
 * of address do not fit either.
 *
 * The fragment kind comes from the classifier's own classification rather
 * than being inferred from `frag_id != 0`: Identification 0 and Next Header 0
 * are both legitimate on a real fragment, so an inference would report NONE
 * for an atomic fragment and the agent would drop the frame as
 * self-contradictory (02 §5.6.5).
 *
 * Returns 0 if the packet is too short to hold an IPv6 header, which
 * cilium-srv6-classify already rejects as DROP_MALFORMED_INNER; the check is
 * repeated because this function dereferences the header.
 */
static int
csp_meta_build (vlib_main_t *vm, vlib_buffer_t *b, const cilium_srv6_punt_token_t *t, u8 queue,
		u8 reason, cilium_srv6_punt_meta_t *m)
{
  const cilium_srv6_headend_meta_t *meta = cilium_srv6_headend_meta (b);
  const cilium_srv6_path_meta_t *pm = cilium_srv6_path_meta (b);
  const ip6_header_t *ip;

  if (PREDICT_FALSE (b->current_length < sizeof (ip6_header_t)))
    return 0;

  ip = (const ip6_header_t *) vlib_buffer_get_current (b);

  clib_memset (m, 0, sizeof (m[0]));

  /* ---- what travels (02 §5.6.2) ---- */

  clib_memcpy_fast (m->w.token, t->token, CILIUM_SRV6_IF3_TOKEN_LEN);
  /* The punt queue is the opcode; there is no separate `queue` field on the
     wire, so the queue and the reason cannot disagree there (02 §5.6.1). */
  m->w.opcode = (u8) (CILIUM_SRV6_IF3_OP_PUNT_COMPILE + queue);
  m->w.cause = reason;
  m->w.proto = meta->proto;
  m->w.frag_kind = cilium_srv6_meta_frag_kind (meta->flags);
  m->w.frag_next_header = pm->frag_next_header;
  clib_memcpy_fast (m->w.src_ip, ip->src_address.as_u8, 16);
  clib_memcpy_fast (m->w.dst_ip, ip->dst_address.as_u8, 16);
  m->w.l4_discriminator = meta->l4_discriminator;
  m->w.src_port = pm->sport;
  m->w.dst_port = pm->dport;
  m->w.src_identity = meta->src_identity;
  m->w.rx_sw_if_index = t->rx_sw_if_index;
  m->w.rx_if_incarnation = t->rx_if_incarnation;
  /*
   * `cilium_srv6_hparse_t.frag_id` is the Identification exactly as it sits
   * in the packet, i.e. in network order. The wire field is a big-endian u32
   * of the *value*, so the conversion happens once, here, and the serializer
   * stays a plain "write this number big endian".
   */
  m->w.fragment_id = clib_net_to_host_u32 (meta->frag_id);
  m->w.punt_id = t->punt_id;

  /* ---- plugin internal (02 §5.6.8) ---- */

  m->owner_quota_class = meta->owner_quota_class;
  m->local_context_id = meta->local_context_id;
  m->queue = queue;
  m->packet_length = (u32) vlib_buffer_length_in_chain (vm, b);

  return 1;
}

/*
 * One packet of 02 §5.1. Returns 1 if the packet was handed to the agent.
 *
 * Called from a worker, so every mutation of the token store and of the
 * per-owner / per-identity counters happens under punt_lock. Nothing here
 * allocates: the token pool is fixed size and the transport hook copies what
 * it needs out of the buffer before returning (00 §2.18.7 — the hook is
 * forbidden from doing socket I/O, so "copies and enqueues" is all it does).
 */
int
cilium_srv6_punt_one (vlib_main_t *vm, vlib_buffer_t *b, u8 queue, u8 reason)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  const cilium_srv6_headend_meta_t *meta = cilium_srv6_headend_meta (b);
  const cilium_srv6_main_t *cm = &cilium_srv6_main;
  cilium_srv6_punt_tx_fn tx = cilium_srv6_punt_tx_hook;
  cilium_srv6_punt_queue_state_t *q;
  cilium_srv6_punt_token_t *t;
  cilium_srv6_punt_meta_t handoff;
  u32 sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  u32 slot;
  u64 owner_key, identity_key;
  cilium_srv6_punt_tx_result_t sent;

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

  if (!csp_token_draw_locked (hm, t))
    {
      /* The entropy source failed or the index is inconsistent. Fail closed:
	 a punt with no capability could never be answered. */
      pool_put_index (hm->punt_tokens, slot);
      q->n_drop_no_token++;
      goto refuse;
    }

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

  if (!csp_meta_build (vm, b, t, queue, reason, &handoff))
    {
      csp_token_release (hm, t);
      pool_put_index (hm->punt_tokens, slot);
      q->n_drop_global++;
      goto refuse;
    }

  clib_spinlock_unlock (&hm->punt_lock);

  sent = (tx != 0) ? tx (vm, b, &handoff) : CILIUM_SRV6_PUNT_TX_NO_TRANSPORT;

  if (PREDICT_TRUE (sent == CILIUM_SRV6_PUNT_TX_SENT))
    {
      /*
       * Outside punt_lock, and reachable from every worker at once. It used
       * to be a plain `q->n_punted++`, which is a read-modify-write race that
       * silently under-counts the one number an operator uses to tell "the
       * slow path is working" from "the slow path is not being reached"
       * (errata #34 item 152). The rest of this structure is written under
       * the lock; this one field is not, so it is atomic.
       */
      clib_atomic_fetch_add (&q->n_punted, 1);
      return 1;
    }

  /* The transport refused (or there is none): give the quota straight back
     rather than letting an unreachable agent drain the queue. */
  clib_spinlock_lock (&hm->punt_lock);
  csp_token_release (hm, t);
  pool_put_index (hm->punt_tokens, slot);
  if (sent == CILIUM_SRV6_PUNT_TX_QUEUE_FULL)
    q->n_drop_ring_full++;
  else
    q->n_drop_no_transport++;
  clib_spinlock_unlock (&hm->punt_lock);

  return 0;

refuse:
  clib_spinlock_unlock (&hm->punt_lock);
  return 0;
}

/* ------------------------------------------------------------------ */
/* reinject and release (02 §5.1 step 8, §5.6.3, 00 §4.1)              */
/* ------------------------------------------------------------------ */

/*
 * Validate a 16-byte token and consume it. Returns 0 and fills *out on
 * success.
 *
 * The token is opaque (D-76 §2.18.4), so the slot is recovered from the
 * index rather than decoded out of the value: guessing a slot number is not
 * the same as guessing a token. The lookup lives in this process's memory
 * only, which is what makes a token issued by a previous plugin instance
 * resolve to nothing (D-72).
 *
 * One-shot is enforced by csp_token_release(), which removes the index entry
 * and wipes the bytes: a second presentation of the same value finds nothing.
 */
static int
csp_token_redeem (cilium_srv6_headend_main_t *hm, const u8 *token, cilium_srv6_punt_token_t *out)
{
  cilium_srv6_punt_token_t *t;
  uword *p;
  u32 slot;
  int rv = VNET_API_ERROR_INVALID_VALUE;

  if (token == NULL || cilium_srv6_if3_token_is_zero (token))
    return rv;

  clib_spinlock_lock (&hm->punt_lock);

  p = hash_get_mem (hm->punt_token_index, token);
  if (p == NULL)
    goto done;

  slot = (u32) p[0];
  if (slot >= hm->punt_token_capacity || pool_is_free_index (hm->punt_tokens, slot))
    goto done;

  t = hm->punt_tokens + slot;

  if (!t->in_use)
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
 * The 06 §2 reason a release names, as a cilium-srv6-punt error counter.
 * `06` §1 forbids an unclassified drop counter, so every release is charged
 * to exactly one reason and the mapping is the wire's (02 §5.6.3, the subset
 * of 06 §2 that pkg/srv6ec/compiler/reason.go can produce).
 */
static u32
csp_release_error_index (u8 drop_reason)
{
  switch (drop_reason)
    {
    case CILIUM_SRV6_IF3_DROP_POLICY_DENIED:
      return CILIUM_SRV6_PUNT_ERROR_RELEASE_POLICY_DENIED;
    case CILIUM_SRV6_IF3_DROP_SLOWPATH_OVERFLOW:
      return CILIUM_SRV6_PUNT_ERROR_RELEASE_SLOWPATH_OVERFLOW;
    case CILIUM_SRV6_IF3_DROP_NO_REMOTE_ENDPOINT:
      return CILIUM_SRV6_PUNT_ERROR_RELEASE_NO_REMOTE_ENDPOINT;
    case CILIUM_SRV6_IF3_DROP_IDENTITY_UNRESOLVED:
      return CILIUM_SRV6_PUNT_ERROR_RELEASE_IDENTITY_UNRESOLVED;
    default:
      return CILIUM_SRV6_PUNT_ERROR_RELEASE_FRAGMENT_UNRESOLVED;
    }
}

/*
 * 02 §5.6.3 / 00 §2.18.6: the agent DENYed the punt, so the token — and with
 * it the D-42 quota slot it holds — comes back immediately with a 06 §2 drop
 * reason instead of at the punt token timeout. Without this path a burst of
 * DENY starves the slow path of tenants that are behaving correctly, because
 * every DENYed punt holds its slot for the full timeout.
 *
 * There is no packet to drop here: cilium-srv6-punt freed the buffer when the
 * transport accepted the frame. What the drop reason attributes is the
 * datagram the agent decided about, which is why it is counted on the
 * cilium-srv6-punt node rather than being invented as a new counter space.
 *
 * An unknown or already consumed token changes no dataplane state: it is
 * counted by the caller and refused here.
 */
int
cilium_srv6_punt_release (const u8 *token, u8 drop_reason)
{
  cilium_srv6_headend_main_t *hm = &cilium_srv6_headend_main;
  vlib_main_t *vm = vlib_get_main ();
  cilium_srv6_punt_token_t t;
  int rv;

  if (!hm->initialised)
    return VNET_API_ERROR_INIT_FAILED;

  if (drop_reason == CILIUM_SRV6_IF3_DROP_NONE || drop_reason >= CILIUM_SRV6_IF3_N_DROP_REASON)
    return VNET_API_ERROR_INVALID_VALUE_2;

  rv = csp_token_redeem (hm, token, &t);
  if (rv != 0)
    return rv;

  hm->punt_q[t.queue].n_released++;

  vlib_node_increment_counter (vm, cilium_srv6_punt_node.index,
			       csp_release_error_index (drop_reason), 1);

  return 0;
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
cilium_srv6_punt_reinject (const u8 *token, u64 punt_id, const u8 *data, u32 len)
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

/*
 * Seed the token generator.
 *
 * clib_random_buffer_init() derives both ISAAC contexts from a single uword,
 * which would put the whole token stream behind 64 bits of seed. The contexts
 * are seeded here directly instead, with 2 x ISAAC_SIZE words read from
 * /dev/urandom, so the state is drawn at full width and no part of it is a
 * function of a value an observer could reconstruct.
 *
 * The fallback mixes the cycle counter, the wall clock and the process
 * identity. It is not unpredictable and is logged as a deployment fault, the
 * same way csg_draw_instance_id() reports it: a VPP container in which
 * /dev/urandom is unreadable is worth seeing. It is not a correctness
 * failure, because unpredictability is defence in depth here — the reinject
 * is authenticated by the D-27 socket's peer credentials, and D-76 §2.18.4
 * says so explicitly.
 */
static void
csp_rng_init (cilium_srv6_headend_main_t *hm)
{
  uword seed[2][ISAAC_SIZE];
  FILE *f = fopen ("/dev/urandom", "rb");
  int have_entropy = 0;
  uword i, j;

  if (f != NULL)
    {
      size_t n = fread (seed, 1, sizeof (seed), f);
      fclose (f);
      have_entropy = (n == sizeof (seed));
    }

  if (!have_entropy)
    {
      u64 mix[2];

      mix[0] = clib_cpu_time_now () ^ (u64) unix_time_now_nsec ();
      mix[1] = ((u64) getpid () << 32) ^ (u64) (uword) hm;
      for (i = 0; i < ARRAY_LEN (seed); i++)
	for (j = 0; j < ISAAC_SIZE; j++)
	  seed[i][j] = (uword) (mix[i] + j * 0x9e3779b97f4a7c15ULL);

      CSP_LOG_ERR ("could not read /dev/urandom: IF-3 punt tokens are seeded "
		   "from local clock and process state instead. They stay "
		   "one-shot and lifetime-bounded, but they are predictable to "
		   "an observer who can reconstruct that state");
    }

  clib_memset (&hm->punt_rng, 0, sizeof (hm->punt_rng));
  for (i = 0; i < ARRAY_LEN (hm->punt_rng.ctx); i++)
    isaac_init (&hm->punt_rng.ctx[i], seed[i]);

  clib_memset (seed, 0, sizeof (seed));
}

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
  /*
   * D-76 §2.18.4: the token -> slot map. The key is the 16 token bytes, and
   * the memory those bytes live in is the token slot itself, which is stable
   * because the pool is fixed size (pool_init_fixed above never reallocates).
   * hash_set_mem stores the pointer rather than a copy, so the entry has to
   * be removed while the bytes still hold the value it was inserted under —
   * which is what csp_token_release() does, before wiping them.
   */
  hm->punt_token_index = hash_create_mem (0, CILIUM_SRV6_IF3_TOKEN_LEN, sizeof (uword));

  csp_rng_init (hm);
}
