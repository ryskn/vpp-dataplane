/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — SR domain node address set: bounded capacity
 * and atomic set replacement (D-32, D-90, errata #34 items 197 and 205).
 *
 * # What the set decides
 *
 * SR_DOMAIN_NODE_SET is the first check of cilium-end-cilium (03 §3) and the
 * PTB reporter check of the PMTUD node (D-36 (b)): an outer source address
 * that is not in it drops as DROP_UNTRUSTED_SOURCE. In Stage 2 it is the
 * source authority of the destination dataplane, so the set the workers read
 * is an authority statement, not a cache.
 *
 * # D-90
 *
 *   The SR domain set is all-or-nothing. A partially published set is an
 *   incomplete publication of authority. The plugin table has a configurable
 *   bounded capacity. The agent publishes the complete authoritative set by
 *   atomic set replacement - old authoritative set -> build / stage the
 *   complete replacement -> validate capacity -> atomic commit -> new
 *   authoritative set - or publishes nothing. Sequential ADD with rollback is
 *   not acceptable, and Stage 2 forbids partial visibility.
 *
 * # The mechanism: a staged transaction over two preallocated buffers
 *
 * The plugin holds two buffers of `capacity` prefixes each, both allocated
 * once at main-loop-enter (03 §9: no hot path allocation):
 *
 *   active  - the set the workers read. Only cilium_srv6_sr_domain_txn_install
 *             writes it, and the caller holds the worker barrier around that
 *             call.
 *   staged  - the replacement under construction. No worker ever reads it:
 *             cilium_srv6_sr_domain_set_contains is only ever called on the
 *             active set.
 *
 * begin / put / abort touch the staged buffer only. commit validates the
 * staged buffer as a whole (it is the transaction the caller names, it holds
 * exactly the number of prefixes the caller says it staged, and that number
 * fits the capacity) and only then exchanges the two buffers. The exchange is
 * three stores - the prefixes pointer and the count of the active set, and the
 * pointer of the staged set - and it happens inside one worker barrier
 * section, so a worker observes the previous complete set before the barrier
 * and the new complete set after it. There is no instant at which a set with
 * some of the new prefixes and some of the old ones is reachable, and there is
 * no instant at which a worker can read a slot that is being written, because
 * the slots of the active buffer are never written in place.
 *
 * Why this and not a generation-tagged shadow table: a generation tag would
 * have to be compared per packet (or per prefix) to hide the entries of the
 * next generation, which puts the transaction state on the hot path. The
 * double buffer keeps the hot path exactly what it was - one bounded linear
 * scan of pre-masked prefixes - and puts the whole transaction on the
 * control plane. It is the same shape as the PathCache staging transaction
 * (srv6_path_txn_*, D-61), minus the handle reservation the PathCache needs.
 *
 * Failure semantics: every failure before a successful commit leaves the
 * active set exactly as it was, because nothing but the install writes it. An
 * abort, a commit refused at validation, an agent that disconnects or crashes
 * between begin and commit - all leave the previous complete set fully in
 * force. An abandoned staging buffer stays open until it is aborted by its
 * exact txn_id; the open txn_id is readable through srv6_sr_domain_status_get
 * so that a restarted agent can do that without a wildcard abort. A plugin
 * restart loses both buffers and starts from the empty set, which is the
 * fail-closed state (every packet drops) and is repaired by the D-72 step [1]
 * republication.
 *
 * Kept out of cilium_srv6_endcilium.c, and free of vlib, vec and the barrier,
 * so that the whole decision is a pure function of the two buffers and can be
 * executed on the host by vpp/plugins/cilium_srv6/test/srdomain.
 *
 * Design references:
 *   design/detail/00-overview.md D-32, D-90, §2.15.10
 *   design/detail/03-destination-dataplane.md §3, §7
 */

#ifndef __included_cilium_srv6_srdomain_rules_h__
#define __included_cilium_srv6_srdomain_rules_h__

#include <vppinfra/clib.h>
#include <vppinfra/byte_order.h>
#include <vnet/ip/ip6_packet.h>

/*
 * Capacity of the set (D-90). `sr-domain-capacity <n>` in the `cilium-srv6`
 * startup stanza sets it; the value itself is left to the performance
 * evaluation. The default is the bound the plugin had before D-90, so a
 * deployment that does not configure it keeps the per-packet cost it had.
 * The upper bound keeps the value bounded: the hot path scans the published
 * prefixes linearly, and both buffers are allocated at this size.
 */
#define CILIUM_SRV6_SR_DOMAIN_CAPACITY_DEFAULT 16
#define CILIUM_SRV6_SR_DOMAIN_CAPACITY_MAX     4096

/*
 * One SR domain prefix, pre-masked for the hot path comparison, in the same
 * form the guard uses for SRV6_BLOCK.
 */
typedef struct
{
  u64 addr[2];
  u64 mask[2];
  u8 len;
  u8 pad[7];
} cilium_srv6_sr_domain_prefix_t;

/*
 * One buffer of the set. `prefixes` has `capacity` slots; the first `n` are
 * the set.
 */
typedef struct
{
  cilium_srv6_sr_domain_prefix_t *prefixes;
  u32 n;
  u32 capacity;
} cilium_srv6_sr_domain_set_t;

/*
 * The control-plane half: the staged buffer and the transaction identities.
 *
 * txn_id is assigned by the agent and is an operation identity, not a
 * sequence number, exactly as for srv6_path_txn_*: the plugin recognises the
 * transaction it holds open (open_txn_id) and the one that committed last
 * (committed_txn_id, so that a lost commit reply can be retried), and infers
 * nothing else from the value. 0 is the reserved "no transaction".
 */
typedef struct
{
  cilium_srv6_sr_domain_set_t staged;
  u64 open_txn_id;
  u64 committed_txn_id;
  u64 n_commits;
} cilium_srv6_sr_domain_txn_t;

typedef enum
{
  CILIUM_SRV6_SR_DOMAIN_OK = 0,
  /* commit: txn_id is the transaction that committed last and the active set
     is the one it installed. Success that changes nothing. */
  CILIUM_SRV6_SR_DOMAIN_OK_REPLAY,
  /* txn_id is 0, the reserved "no transaction". */
  CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_ZERO,
  /* begin: a different transaction is open. */
  CILIUM_SRV6_SR_DOMAIN_REJECT_BUSY,
  /* begin: txn_id is the transaction that committed last, so a commit retry
     could no longer be told apart from a new transaction. */
  CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_REUSED,
  /* put / commit / abort: no transaction is open, or txn_id names a different
     one than the open one. */
  CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN,
  /* put: prefix length above 128. */
  CILIUM_SRV6_SR_DOMAIN_REJECT_PREFIX,
  /* put: prefix length 0 (::/0). One such entry would authorise every outer
     source address, so it is a wildcard, not a member of the set. */
  CILIUM_SRV6_SR_DOMAIN_REJECT_WILDCARD,
  /* put: the staged set is full. commit: the staged set does not fit the
     active buffer (unreachable while both buffers have one capacity). */
  CILIUM_SRV6_SR_DOMAIN_REJECT_CAPACITY,
  /* commit: the staged set does not hold the number of prefixes the caller
     says it staged. A replacement the caller did not finish building is not
     the complete authoritative set, so it is not installed. */
  CILIUM_SRV6_SR_DOMAIN_REJECT_COUNT,
} cilium_srv6_sr_domain_verdict_t;

static_always_inline void
cilium_srv6_sr_domain_prefix_mask (cilium_srv6_sr_domain_prefix_t *p, const ip6_address_t *a,
				   u8 len)
{
  u32 l = len;
  u32 i;

  p->len = len;

  for (i = 0; i < 2; i++)
    {
      u32 bits = 0;

      if (l > i * 64)
	{
	  bits = l - i * 64;
	  if (bits > 64)
	    bits = 64;
	}

      p->mask[i] = bits ? clib_host_to_net_u64 (~(u64) 0 << (64 - bits)) : 0;
      p->addr[i] = a->as_u64[i] & p->mask[i];
    }
}

/*
 * 03 §3 / D-32: outer SA ∈ SR_DOMAIN_NODE_SET. The hot path predicate.
 *
 * Bounded linear scan over pre-masked prefixes. An empty set returns 0, so a
 * node that has not been told its SR domain drops every packet that reaches
 * the local SID as DROP_UNTRUSTED_SOURCE. Only ever called on the active set.
 */
static_always_inline int
cilium_srv6_sr_domain_set_contains (const cilium_srv6_sr_domain_set_t *s, const ip6_address_t *a)
{
  u32 i;
  u32 n = s->n;

  if (PREDICT_FALSE (n > s->capacity))
    n = s->capacity;

  for (i = 0; i < n; i++)
    {
      const cilium_srv6_sr_domain_prefix_t *p = s->prefixes + i;
      u64 d0 = (a->as_u64[0] ^ p->addr[0]) & p->mask[0];
      u64 d1 = (a->as_u64[1] ^ p->addr[1]) & p->mask[1];

      if ((d0 | d1) == 0)
	return 1;
    }

  return 0;
}

/* Index of an identical (same length, same masked address) prefix, or -1. */
static_always_inline int
cilium_srv6_sr_domain_set_find (const cilium_srv6_sr_domain_set_t *s,
				const cilium_srv6_sr_domain_prefix_t *probe)
{
  u32 i;

  for (i = 0; i < s->n && i < s->capacity; i++)
    {
      const cilium_srv6_sr_domain_prefix_t *p = s->prefixes + i;

      if (p->len == probe->len && p->addr[0] == probe->addr[0] && p->addr[1] == probe->addr[1])
	return (int) i;
    }

  return -1;
}

/*
 * Written out rather than delegated to clib_memset so that this header keeps
 * depending on nothing but the integer types and ip6_address_t, which is what
 * lets test/srdomain compile it with no VPP tree at all.
 */
static_always_inline void
cilium_srv6_sr_domain_prefix_zero (cilium_srv6_sr_domain_prefix_t *p)
{
  u32 i;

  p->addr[0] = p->addr[1] = 0;
  p->mask[0] = p->mask[1] = 0;
  p->len = 0;
  for (i = 0; i < sizeof (p->pad); i++)
    p->pad[i] = 0;
}

/* Control plane only: at most CILIUM_SRV6_SR_DOMAIN_CAPACITY_MAX slots. */
static_always_inline void
cilium_srv6_sr_domain_staged_clear (cilium_srv6_sr_domain_txn_t *t)
{
  u32 i;

  if (t->staged.prefixes != 0)
    for (i = 0; i < t->staged.capacity; i++)
      cilium_srv6_sr_domain_prefix_zero (t->staged.prefixes + i);
  t->staged.n = 0;
}

/*
 * srv6_sr_domain_txn_begin. A repeated begin for the transaction that is
 * already open keeps its staging buffer, so a lost reply costs nothing.
 */
static_always_inline cilium_srv6_sr_domain_verdict_t
cilium_srv6_sr_domain_txn_begin (cilium_srv6_sr_domain_txn_t *t, u64 txn_id)
{
  if (txn_id == 0)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_ZERO;

  if (t->open_txn_id == txn_id)
    return CILIUM_SRV6_SR_DOMAIN_OK;

  if (t->open_txn_id != 0)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_BUSY;

  if (txn_id == t->committed_txn_id)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_REUSED;

  cilium_srv6_sr_domain_staged_clear (t);
  t->open_txn_id = txn_id;

  return CILIUM_SRV6_SR_DOMAIN_OK;
}

/*
 * srv6_sr_domain_txn_put: stage one prefix. A prefix of length 0 (::/0) is
 * refused (REJECT_WILDCARD). Staging an identical prefix twice
 * is an idempotent success, which is what makes a lost reply retryable.
 * Every rejection leaves the staged buffer as it was; none of them closes the
 * transaction.
 */
static_always_inline cilium_srv6_sr_domain_verdict_t
cilium_srv6_sr_domain_txn_put (cilium_srv6_sr_domain_txn_t *t, u64 txn_id, const ip6_address_t *a,
			       u32 len)
{
  cilium_srv6_sr_domain_prefix_t probe;

  if (txn_id == 0)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_ZERO;

  if (t->open_txn_id == 0 || t->open_txn_id != txn_id)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN;

  if (len > 128)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_PREFIX;

  /* D-90: no wildcard. ::/0 would make the source authority check accept
     every source with a single put. */
  if (len == 0)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_WILDCARD;

  cilium_srv6_sr_domain_prefix_zero (&probe);
  cilium_srv6_sr_domain_prefix_mask (&probe, a, (u8) len);

  if (cilium_srv6_sr_domain_set_find (&t->staged, &probe) >= 0)
    return CILIUM_SRV6_SR_DOMAIN_OK;

  if (t->staged.n >= t->staged.capacity)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_CAPACITY;

  t->staged.prefixes[t->staged.n] = probe;
  t->staged.n++;

  return CILIUM_SRV6_SR_DOMAIN_OK;
}

/*
 * srv6_sr_domain_txn_commit, validation half. Decides whether the staged set
 * may replace the active one; changes nothing.
 *
 * OK means the caller now calls cilium_srv6_sr_domain_txn_install under the
 * worker barrier. OK_REPLAY means the commit already happened (a lost reply)
 * and nothing is to be done. Every REJECT_* leaves both buffers and the
 * transaction as they were, so the caller can abort it.
 */
static_always_inline cilium_srv6_sr_domain_verdict_t
cilium_srv6_sr_domain_txn_commit_check (const cilium_srv6_sr_domain_txn_t *t,
					const cilium_srv6_sr_domain_set_t *active, u64 txn_id,
					u32 n_prefixes)
{
  if (txn_id == 0)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_ZERO;

  if (t->open_txn_id == 0)
    {
      if (txn_id != t->committed_txn_id)
	return CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN;
      /* Nothing but a commit writes the active set, so while no transaction
	 is open after txn_id committed, the active set is the one it
	 installed. */
      if (n_prefixes != active->n)
	return CILIUM_SRV6_SR_DOMAIN_REJECT_COUNT;
      return CILIUM_SRV6_SR_DOMAIN_OK_REPLAY;
    }

  if (t->open_txn_id != txn_id)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN;

  if (t->staged.n != n_prefixes)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_COUNT;

  if (t->staged.n > t->staged.capacity || t->staged.n > active->capacity ||
      t->staged.capacity != active->capacity)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_CAPACITY;

  return CILIUM_SRV6_SR_DOMAIN_OK;
}

/*
 * srv6_sr_domain_txn_commit, install half. MUST be called only after
 * cilium_srv6_sr_domain_txn_commit_check returned OK, and with the worker
 * barrier held: it is the one place the active set changes.
 *
 * The staged buffer becomes the active one and the previous active buffer
 * becomes the (logically empty) staging buffer. No slot of either buffer is
 * written here, so the only stores a worker could observe are the pointer and
 * the count of the active set, and under the barrier no worker observes
 * anything.
 */
static_always_inline void
cilium_srv6_sr_domain_txn_install (cilium_srv6_sr_domain_txn_t *t,
				   cilium_srv6_sr_domain_set_t *active)
{
  cilium_srv6_sr_domain_prefix_t *previous = active->prefixes;

  active->prefixes = t->staged.prefixes;
  active->n = t->staged.n;

  t->staged.prefixes = previous;
  t->staged.n = 0;

  t->committed_txn_id = t->open_txn_id;
  t->open_txn_id = 0;
  t->n_commits++;
}

/*
 * srv6_sr_domain_txn_abort: discard the staged set. Exact: txn_id must be the
 * open transaction. There is no wildcard form; a restarted agent reads the
 * open txn_id with srv6_sr_domain_status_get and aborts that one.
 */
static_always_inline cilium_srv6_sr_domain_verdict_t
cilium_srv6_sr_domain_txn_abort (cilium_srv6_sr_domain_txn_t *t, u64 txn_id)
{
  if (txn_id == 0)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_ZERO;

  if (t->open_txn_id == 0 || t->open_txn_id != txn_id)
    return CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN;

  cilium_srv6_sr_domain_staged_clear (t);
  t->open_txn_id = 0;

  return CILIUM_SRV6_SR_DOMAIN_OK;
}

#endif /* __included_cilium_srv6_srdomain_rules_h__ */
