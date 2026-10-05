/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Host-side check of the SR domain node address set rules
 * (cilium_srv6_srdomain_rules.h) — D-90, errata #34 item 205.
 *
 * What this file is for
 *
 *   D-90 makes the SR domain set all-or-nothing: the set the workers read is
 *   replaced only as a whole, by a staged transaction, and a replacement that
 *   does not fit the configured capacity is never installed. In Stage 2 the
 *   set is the source authority of cilium-end-cilium, so a partially replaced
 *   set is an incomplete publication of authority, not a degraded one.
 *
 *   Every decision of that transaction - begin, put, the whole-set validation
 *   of a commit, the install, the abort - and the hot path predicate itself
 *   are pure functions of the two buffers, so they are executed here the way
 *   the D-88 rules are executed in ../localep: compiled against the
 *   byte-level stubs of ../fuzz/stub, with no vlib, no vnet and no plugin
 *   state.
 *
 *   The property that matters most is checked by reading the predicate, not
 *   the buffers: at every step of a staging, cilium_srv6_sr_domain_set_contains
 *   on the active set answers exactly what it answered before the transaction
 *   began, and after the install it answers exactly the new set.
 *
 * What it cannot check
 *
 *   That cilium_srv6_sr_domain_publish_commit() holds the worker barrier
 *   around cilium_srv6_sr_domain_txn_install(), that the nodes only ever call
 *   the predicate on em->sr_domain, and that the retvals are the ones
 *   cilium_srv6.api documents. Those are in cilium_srv6_endcilium.c,
 *   cilium_srv6_endcilium_node.c and cilium_srv6_pmtud.c, which need vlib;
 *   they are named here so a reviewer can check them by name. The agent side
 *   is pinned against a fake dataplane in pkg/srv6ec/cell/srdomain_test.go.
 */

#include <stdio.h>
#include <string.h>

#include <cilium_srv6/cilium_srv6_srdomain_rules.h>

static int failures;
static int checks;

static void
expect (const char *what, int got, int want)
{
  checks++;

  if (got != want)
    {
      fprintf (stderr, "FAIL %s: got %d, want %d\n", what, got, want);
      failures++;
      return;
    }

  printf ("ok   %s\n", what);
}

#define CAP_MAX 8

/* The two buffers, as cilium_srv6_endcilium_main_loop_enter allocates them. */
static cilium_srv6_sr_domain_prefix_t buf_a[CAP_MAX];
static cilium_srv6_sr_domain_prefix_t buf_b[CAP_MAX];

static cilium_srv6_sr_domain_set_t active;
static cilium_srv6_sr_domain_txn_t txn;

static void
reset (u32 capacity)
{
  memset (buf_a, 0, sizeof (buf_a));
  memset (buf_b, 0, sizeof (buf_b));
  memset (&active, 0, sizeof (active));
  memset (&txn, 0, sizeof (txn));

  active.prefixes = buf_a;
  active.capacity = capacity;
  txn.staged.prefixes = buf_b;
  txn.staged.capacity = capacity;
}

/* fc00:2200::<host> */
static ip6_address_t
node (u8 host)
{
  ip6_address_t a;

  memset (&a, 0, sizeof (a));
  a.as_u8[0] = 0xfc;
  a.as_u8[2] = 0x22;
  a.as_u8[15] = host;
  return a;
}

static int
contains (u8 host)
{
  ip6_address_t a = node (host);

  return cilium_srv6_sr_domain_set_contains (&active, &a);
}

static int
put (u64 id, u8 host)
{
  ip6_address_t a = node (host);

  return cilium_srv6_sr_domain_txn_put (&txn, id, &a, 128);
}

/* begin + put every host + commit, the way a successful publication runs. */
static void
publish (u64 id, const u8 *hosts, u32 n)
{
  u32 i;

  expect ("publish: begin", cilium_srv6_sr_domain_txn_begin (&txn, id), CILIUM_SRV6_SR_DOMAIN_OK);
  for (i = 0; i < n; i++)
    expect ("publish: put", put (id, hosts[i]), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("publish: commit validates",
	  cilium_srv6_sr_domain_txn_commit_check (&txn, &active, id, n), CILIUM_SRV6_SR_DOMAIN_OK);
  cilium_srv6_sr_domain_txn_install (&txn, &active);
}

/*
 * The predicate answers for hosts 1..15: a bitmask of which ones are in the
 * active set. Used to compare "what a worker would see" before and after.
 */
static u32
visible (void)
{
  u32 m = 0;
  u8 h;

  for (h = 1; h < 16; h++)
    if (contains (h))
      m |= 1u << h;
  return m;
}

static void
check_empty_set_matches_nothing (void)
{
  reset (4);
  expect ("an empty set matches nothing (fail-closed before the first commit)", visible (), 0);
}

static void
check_commit_swaps_atomically (void)
{
  static const u8 old_set[] = { 1, 2 };
  static const u8 new_set[] = { 2, 3, 4 };
  u32 before;

  reset (4);
  publish (10, old_set, 2);
  before = visible ();
  expect ("the first commit installs exactly the staged set", before, (1u << 1) | (1u << 2));

  expect ("begin of the replacement", cilium_srv6_sr_domain_txn_begin (&txn, 11),
	  CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("put 2", put (11, new_set[0]), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("put 3", put (11, new_set[1]), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("put 4", put (11, new_set[2]), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("a fully staged replacement is still invisible", visible (), (int) before);

  expect ("the commit validates", cilium_srv6_sr_domain_txn_commit_check (&txn, &active, 11, 3),
	  CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("validation alone changes nothing", visible (), (int) before);

  cilium_srv6_sr_domain_txn_install (&txn, &active);
  expect ("after the install the predicate answers exactly the new set", visible (),
	  (1u << 2) | (1u << 3) | (1u << 4));
  expect ("the departed node is no longer trusted", contains (1), 0);
  expect ("active count", active.n, 3);
  expect ("the transaction is closed", txn.open_txn_id == 0, 1);
  expect ("the committed identity is recorded", txn.committed_txn_id == 11, 1);
  expect ("the staging buffer starts empty", txn.staged.n, 0);
  expect ("the two buffers are never the same memory", active.prefixes != txn.staged.prefixes, 1);
  expect ("the active buffer is the one that was staged", active.prefixes == buf_a, 1);
}

static void
check_partial_stage_never_visible (void)
{
  static const u8 old_set[] = { 5 };
  u32 before;
  u8 h;

  reset (CAP_MAX);
  publish (20, old_set, 1);
  before = visible ();

  expect ("begin", cilium_srv6_sr_domain_txn_begin (&txn, 21), CILIUM_SRV6_SR_DOMAIN_OK);
  for (h = 6; h < 6 + 6; h++)
    {
      expect ("put", put (21, h), CILIUM_SRV6_SR_DOMAIN_OK);
      expect ("after every put the worker-visible set is the previous complete one", visible (),
	      (int) before);
    }
}

static void
check_abort_keeps_old_set (void)
{
  static const u8 old_set[] = { 1, 2 };
  u32 before;

  reset (4);
  publish (30, old_set, 2);
  before = visible ();

  expect ("begin", cilium_srv6_sr_domain_txn_begin (&txn, 31), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("put", put (31, 9), CILIUM_SRV6_SR_DOMAIN_OK);

  expect ("there is no wildcard abort", cilium_srv6_sr_domain_txn_abort (&txn, 0),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_ZERO);
  expect ("an abort of another transaction is refused", cilium_srv6_sr_domain_txn_abort (&txn, 99),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN);
  expect ("a refused abort leaves the transaction open", txn.open_txn_id == 31, 1);

  expect ("the exact abort", cilium_srv6_sr_domain_txn_abort (&txn, 31), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("the abort leaves the old set fully in force", visible (), (int) before);
  expect ("the staged prefix never became visible", contains (9), 0);
  expect ("the transaction is closed", txn.open_txn_id == 0, 1);
  expect ("the staging buffer is empty", txn.staged.n, 0);
  expect ("a second abort finds nothing", cilium_srv6_sr_domain_txn_abort (&txn, 31),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN);
  expect ("a commit of the aborted transaction is refused",
	  cilium_srv6_sr_domain_txn_commit_check (&txn, &active, 31, 1),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN);
}

static void
check_capacity_refused (void)
{
  static const u8 old_set[] = { 1 };
  u32 before;

  reset (2);
  publish (40, old_set, 1);
  before = visible ();

  expect ("begin", cilium_srv6_sr_domain_txn_begin (&txn, 41), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("put 1 of 3", put (41, 2), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("put 2 of 3", put (41, 3), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("put 3 of 3 exceeds the capacity", put (41, 4), CILIUM_SRV6_SR_DOMAIN_REJECT_CAPACITY);
  expect ("nothing is truncated into the staged set", txn.staged.n, 2);
  expect ("a commit of the 3-prefix set the caller built is refused",
	  cilium_srv6_sr_domain_txn_commit_check (&txn, &active, 41, 3),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_COUNT);
  expect ("the refused commit leaves the old set in force", visible (), (int) before);
  expect ("the refused commit leaves the transaction open", txn.open_txn_id == 41, 1);
  expect ("abort", cilium_srv6_sr_domain_txn_abort (&txn, 41), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("the old set is still in force", visible (), (int) before);

  /* A full set can still be replaced by another full set: the replacement is
     staged off to the side, so no intermediate state needs a third slot. */
  {
    static const u8 full[] = { 7, 8 };

    publish (42, full, 2);
    expect ("a full set replaced by another full set", visible (), (1u << 7) | (1u << 8));
  }
}

static void
check_count_mismatch (void)
{
  static const u8 old_set[] = { 1 };
  u32 before;

  reset (4);
  publish (50, old_set, 1);
  before = visible ();

  expect ("begin", cilium_srv6_sr_domain_txn_begin (&txn, 51), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("put", put (51, 2), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("put", put (51, 3), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("a commit naming a different count than was staged is refused",
	  cilium_srv6_sr_domain_txn_commit_check (&txn, &active, 51, 3),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_COUNT);
  expect ("and changes nothing", visible (), (int) before);
  expect ("a commit of another transaction is refused",
	  cilium_srv6_sr_domain_txn_commit_check (&txn, &active, 52, 2),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN);
  expect ("a commit with txn_id 0 is refused",
	  cilium_srv6_sr_domain_txn_commit_check (&txn, &active, 0, 2),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_ZERO);
}

static void
check_commit_replay (void)
{
  static const u8 set[] = { 1, 2 };

  reset (4);
  publish (60, set, 2);

  expect ("re-sending the last commit is a success that changes nothing",
	  cilium_srv6_sr_domain_txn_commit_check (&txn, &active, 60, 2),
	  CILIUM_SRV6_SR_DOMAIN_OK_REPLAY);
  expect ("a replay with another count is refused",
	  cilium_srv6_sr_domain_txn_commit_check (&txn, &active, 60, 3),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_COUNT);
  expect ("a commit of an unknown transaction is refused",
	  cilium_srv6_sr_domain_txn_commit_check (&txn, &active, 61, 2),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN);
}

static void
check_begin_rules (void)
{
  static const u8 set[] = { 1 };

  reset (4);
  expect ("txn_id 0 is reserved", cilium_srv6_sr_domain_txn_begin (&txn, 0),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_ZERO);
  expect ("begin", cilium_srv6_sr_domain_txn_begin (&txn, 70), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("put", put (70, 3), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("a repeated begin is idempotent", cilium_srv6_sr_domain_txn_begin (&txn, 70),
	  CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("and keeps the staged set", txn.staged.n, 1);
  expect ("another begin while one is open is refused", cilium_srv6_sr_domain_txn_begin (&txn, 71),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_BUSY);
  expect ("abort", cilium_srv6_sr_domain_txn_abort (&txn, 70), CILIUM_SRV6_SR_DOMAIN_OK);

  publish (72, set, 1);
  expect ("the identity that committed last cannot be reused",
	  cilium_srv6_sr_domain_txn_begin (&txn, 72), CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_REUSED);
  expect ("a new begin clears a stale staging buffer", cilium_srv6_sr_domain_txn_begin (&txn, 73),
	  CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("the staging buffer is empty at begin", txn.staged.n, 0);
}

static void
check_put_rules (void)
{
  ip6_address_t a = node (1);
  ip6_address_t b = node (1);

  reset (4);
  expect ("put without a transaction", put (80, 1), CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN);
  expect ("begin", cilium_srv6_sr_domain_txn_begin (&txn, 80), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("put naming another transaction", put (81, 1), CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN);
  expect ("put with txn_id 0", put (0, 1), CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_ZERO);
  expect ("prefix length above 128", cilium_srv6_sr_domain_txn_put (&txn, 80, &a, 129),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_PREFIX);
  expect ("put", put (80, 1), CILIUM_SRV6_SR_DOMAIN_OK);

  /* D-90: ::/0 is a wildcard, not a member. It is refused, and the refusal
     leaves the transaction open with its staged set unchanged. */
  expect ("prefix length 0 (::/0) is refused", cilium_srv6_sr_domain_txn_put (&txn, 80, &a, 0),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_WILDCARD);
  expect ("the refused wildcard leaves the transaction open", txn.open_txn_id == 80, 1);
  expect ("the refused wildcard is not staged", txn.staged.n, 1);
  expect ("the transaction still commits the set staged before it",
	  cilium_srv6_sr_domain_txn_commit_check (&txn, &active, 80, 1), CILIUM_SRV6_SR_DOMAIN_OK);

  expect ("an identical put is idempotent", put (80, 1), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("and stages it once", txn.staged.n, 1);

  /* Host bits are masked before the comparison, so two spellings of one
     prefix are one entry. */
  a.as_u8[15] = 0x11;
  b.as_u8[15] = 0x22;
  expect ("put /64", cilium_srv6_sr_domain_txn_put (&txn, 80, &a, 64), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("the same /64 with other host bits", cilium_srv6_sr_domain_txn_put (&txn, 80, &b, 64),
	  CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("is one staged entry", txn.staged.n, 2);
}

static void
check_wildcard_never_staged (void)
{
  static const u8 old_set[] = { 1 };
  ip6_address_t any;
  u32 before;

  memset (&any, 0, sizeof (any));
  reset (4);
  publish (110, old_set, 1);
  before = visible ();

  expect ("begin", cilium_srv6_sr_domain_txn_begin (&txn, 111), CILIUM_SRV6_SR_DOMAIN_OK);
  expect ("::/0 is refused", cilium_srv6_sr_domain_txn_put (&txn, 111, &any, 0),
	  CILIUM_SRV6_SR_DOMAIN_REJECT_WILDCARD);
  expect ("nothing is staged", txn.staged.n, 0);
  expect ("the transaction stays open", txn.open_txn_id == 111, 1);
  expect ("the active set is unchanged", visible (), (int) before);
  expect ("an address outside the set is still untrusted", contains (9), 0);
}

static void
check_empty_replacement (void)
{
  static const u8 set[] = { 1, 2 };

  reset (4);
  publish (90, set, 2);
  publish (91, set, 0);
  expect ("an empty replacement is a legitimate publication", visible (), 0);
  expect ("active count", active.n, 0);
}

static void
check_buffers_alternate (void)
{
  static const u8 one[] = { 1 };
  static const u8 two[] = { 2 };
  cilium_srv6_sr_domain_prefix_t *first;

  reset (4);
  publish (100, one, 1);
  first = active.prefixes;
  publish (101, two, 1);
  expect ("each commit installs the other buffer", active.prefixes != first, 1);
  expect ("the previous active buffer becomes the staging buffer", txn.staged.prefixes == first, 1);
  expect ("only the new set is visible", visible (), 1u << 2);
}

static void
check_verdicts_distinct (void)
{
  int v[] = {
    CILIUM_SRV6_SR_DOMAIN_OK_REPLAY,
    CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_ZERO,
    CILIUM_SRV6_SR_DOMAIN_REJECT_BUSY,
    CILIUM_SRV6_SR_DOMAIN_REJECT_TXN_REUSED,
    CILIUM_SRV6_SR_DOMAIN_REJECT_NO_TXN,
    CILIUM_SRV6_SR_DOMAIN_REJECT_PREFIX,
    CILIUM_SRV6_SR_DOMAIN_REJECT_WILDCARD,
    CILIUM_SRV6_SR_DOMAIN_REJECT_CAPACITY,
    CILIUM_SRV6_SR_DOMAIN_REJECT_COUNT,
  };
  unsigned i, j;

  for (i = 0; i < sizeof (v) / sizeof (v[0]); i++)
    {
      expect ("a verdict other than OK is never the OK value", v[i] != CILIUM_SRV6_SR_DOMAIN_OK, 1);

      for (j = i + 1; j < sizeof (v) / sizeof (v[0]); j++)
	expect ("two verdicts are never the same value", v[i] != v[j], 1);
    }
}

int
main (void)
{
  check_empty_set_matches_nothing ();
  check_commit_swaps_atomically ();
  check_partial_stage_never_visible ();
  check_abort_keeps_old_set ();
  check_capacity_refused ();
  check_count_mismatch ();
  check_commit_replay ();
  check_begin_rules ();
  check_put_rules ();
  check_wildcard_never_staged ();
  check_empty_replacement ();
  check_buffers_alternate ();
  check_verdicts_distinct ();

  printf ("\n%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
