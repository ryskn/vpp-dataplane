/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Host-side check of the D-85 agent revision incarnation fence
 * (cilium_srv6_revision.h) — Issue #21 Stage 0 run 13, errata #34 item 176.
 *
 * What this file is for
 *
 *   Run 13 observed four cached ALLOW LOCAL_DELIVER programs displayed as
 *   STALE + (NO VALID LEASE) right after an agent-only restart (incarnation
 *   2 -> 3, plugin instance unchanged) while a Pod A -> Pod B ping still ran
 *   4/4 with no punt and no recompile. The question that observation raises is
 *   not "does one compare work" but "does *every* judgement that can forward a
 *   packet ask the same question, and is that the question the CLI answers?".
 *
 *   The three judgements are:
 *
 *     cilium-srv6-program   ProgramCache hit          cilium_srv6_revisions_match
 *     cilium-srv6-classify  fragment verdict bypass   cilium_srv6_revisions_match
 *     cilium-srv6-ct        reply bypass (D-47 br. 1) verified_revision vs the
 *                                                     published revision
 *
 *   plus the D-51 lease, which gates the first and the third. All of them now
 *   reach cilium_srv6_revision_matches() / cilium_srv6_revision_is_current(),
 *   and so does the CLI, which is what makes "STALE in `show cilium srv6
 *   program-cache`" and "punt on the packet path" one decision rather than two
 *   implementations of one rule.
 *
 *   The predicates are pure functions of (quoted revision, published revision,
 *   current incarnation), so they are checked here the way the IF-3 serializer
 *   is checked in ../wire: compiled against the byte-level stubs of
 *   ../fuzz/stub, with no vlib, no vnet and no plugin state. If the fence ever
 *   needs a table, this build breaks, and that break is the signal.
 *
 * What it cannot check
 *
 *   That each graph node calls the predicate. That is a property of
 *   cilium_srv6_program_node.c, cilium_srv6_ct.c and
 *   cilium_srv6_local_deliver_node.c, which do need vlib; the call sites are
 *   listed above so a reviewer can check them by name.
 */

#include <stdio.h>

#include <cilium_srv6/cilium_srv6_revision.h>

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

/* A revision as the agent composes it (00 §2.23.1). */
static u64
rev (u32 incarnation, u32 local_sequence)
{
  return ((u64) incarnation << 32) | (u64) local_sequence;
}

/* ------------------------------------------------------------------ */
/* the layout itself                                                   */
/* ------------------------------------------------------------------ */

static void
test_layout (void)
{
  expect ("the incarnation is the high 32 bits", CILIUM_SRV6_REV_INCARNATION (rev (3, 7)) == 3, 1);
  expect ("the sequence does not leak into the incarnation",
	  CILIUM_SRV6_REV_INCARNATION (rev (3, 0xffffffff)) == 3, 1);
  expect ("absence has incarnation 0", CILIUM_SRV6_REV_INCARNATION (CILIUM_SRV6_REV_ABSENT) == 0,
	  1);
  expect ("the sentinel has the reserved incarnation",
	  CILIUM_SRV6_REV_INCARNATION (CILIUM_SRV6_REV_INVALID) == 0xffffffff, 1);
}

/* ------------------------------------------------------------------ */
/* the fence                                                           */
/* ------------------------------------------------------------------ */

static void
test_fence (void)
{
  /* The run 13 case: the agent restarted, the plugin advanced 2 -> 3, and the
     entry still quotes what incarnation 2 published. */
  expect ("a quotation from the previous incarnation is not current",
	  cilium_srv6_revision_is_current (rev (2, 5), 3), 0);

  expect ("a quotation from the current incarnation is current",
	  cilium_srv6_revision_is_current (rev (3, 5), 3), 1);

  /* A publish from a *lower* incarnation is refused by the control plane, so
     this direction should not arise on an entry; the fence refuses it anyway,
     because "not this process" is the property, not "older than this
     process". */
  expect ("a quotation from a later incarnation is not current",
	  cilium_srv6_revision_is_current (rev (4, 5), 3), 0);

  /* The two reserved values are not quotations of any process. */
  expect ("absence is not a current quotation",
	  cilium_srv6_revision_is_current (CILIUM_SRV6_REV_ABSENT, 3), 0);
  expect ("the sentinel is not a current quotation",
	  cilium_srv6_revision_is_current (CILIUM_SRV6_REV_INVALID, 3), 0);

  /* §2.23.7: incarnation 0 is never claimed by an agent, so nothing an agent
     published is ever fenced against it. It is checked here because a plugin
     that has accepted no publish yet holds 0, and in that state it must admit
     nothing rather than admit absence. */
  expect ("nothing published is current while the plugin has accepted no incarnation",
	  cilium_srv6_revision_is_current (rev (1, 1), 0), 0);
}

/* ------------------------------------------------------------------ */
/* fence + per-key equality, the predicate every forwarding path uses  */
/* ------------------------------------------------------------------ */

static void
test_matches (void)
{
  /* The ordinary allow: same process, and the key still publishes it. */
  expect ("a current quotation of the published revision matches",
	  cilium_srv6_revision_matches (rev (3, 9), rev (3, 9), 3), 1);

  /* D-17: the key's content moved. Recompile fixes it. */
  expect ("a current quotation of a superseded revision does not match",
	  cilium_srv6_revision_matches (rev (3, 9), rev (3, 10), 3), 0);

  /*
   * The case errata #34 item 176 is about, and the one the per-key rule alone
   * cannot catch: the new agent process never republished this key — because
   * it does not know it exists — so the slot still holds exactly what the
   * entry quotes. Equality passes; the fence must not.
   *
   * Remove the fence from cilium_srv6_revision_matches() and this is the check
   * that fails.
   */
  expect ("a quotation from a previous incarnation does not match a slot that still holds it",
	  cilium_srv6_revision_matches (rev (2, 9), rev (2, 9), 3), 0);

  /* An unknown or reassigned slot reports the sentinel; the equality then
     fails on its own, and the fence refuses the sentinel as a quotation. */
  expect ("an unknown key does not match",
	  cilium_srv6_revision_matches (rev (3, 9), CILIUM_SRV6_REV_INVALID, 3), 0);
  expect ("a withdrawn key does not match",
	  cilium_srv6_revision_matches (rev (3, 9), CILIUM_SRV6_REV_ABSENT, 3), 0);
  expect ("the sentinel never matches itself",
	  cilium_srv6_revision_matches (CILIUM_SRV6_REV_INVALID, CILIUM_SRV6_REV_INVALID, 3), 0);

  /*
   * An UNVERIFIED conntrack entry (03 §6, D-19 / D-45) holds the sentinel as
   * its verified_revision. The reply bypass of 02 §7.2 asks this predicate, so
   * an UNVERIFIED entry can never take it, whatever the slot reads.
   */
  expect ("an UNVERIFIED conntrack entry never takes the reply bypass",
	  cilium_srv6_revision_matches (CILIUM_SRV6_REV_INVALID, rev (3, 9), 3), 0);
}

/* ------------------------------------------------------------------ */
/* the two composite rules, spelled out as the nodes apply them        */
/* ------------------------------------------------------------------ */

/*
 * cilium_srv6_revisions_match(), with the three table reads replaced by their
 * values. Kept in the test rather than called from the header because the
 * header needs vlib for the table reads; the shape is what is checked.
 */
static int
program_hit_usable (u32 incarnation, u64 quoted_policy, u64 published_policy, u64 quoted_endpoint,
		    u64 published_endpoint, u64 quoted_path, u64 published_path)
{
  if (!cilium_srv6_revision_matches (quoted_policy, published_policy, incarnation))
    return 0;

  if (!cilium_srv6_revision_matches (quoted_endpoint, published_endpoint, incarnation))
    return 0;

  if (quoted_path == CILIUM_SRV6_REV_ABSENT)
    return 1;

  return cilium_srv6_revision_matches (quoted_path, published_path, incarnation);
}

static void
test_program_hit (void)
{
  expect (
    "an entry of this incarnation whose three keys are unchanged forwards",
    program_hit_usable (3, rev (3, 1), rev (3, 1), rev (3, 2), rev (3, 2), rev (3, 3), rev (3, 3)),
    1);

  /*
   * Run 13's four cached ALLOW LOCAL_DELIVER entries: every one of the three
   * keys still reads what the entry quotes, because the restarted agent
   * republished none of them. Only the fence stales them — and it must, for
   * ENCAP and LOCAL_DELIVER alike, because the action is not an input to this
   * decision (D-80).
   */
  expect (
    "an entry of the previous incarnation is stale even with all three keys unchanged",
    program_hit_usable (3, rev (2, 1), rev (2, 1), rev (2, 2), rev (2, 2), rev (2, 3), rev (2, 3)),
    0);

  /* A DENY quotes 0 for the path: no path dependency, so it is neither
     key-checked nor incarnation-checked (D-83). The rest of the entry still
     is. */
  expect ("a DENY of this incarnation is usable with an absent path dependency",
	  program_hit_usable (3, rev (3, 1), rev (3, 1), rev (3, 2), rev (3, 2),
			      CILIUM_SRV6_REV_ABSENT, CILIUM_SRV6_REV_ABSENT),
	  1);
  expect ("a DENY of the previous incarnation is still stale",
	  program_hit_usable (3, rev (2, 1), rev (2, 1), rev (2, 2), rev (2, 2),
			      CILIUM_SRV6_REV_ABSENT, CILIUM_SRV6_REV_ABSENT),
	  0);

  /* A path retired under a live entry stales it without touching policy. */
  expect (
    "a path revision that moved stales the entry",
    program_hit_usable (3, rev (3, 1), rev (3, 1), rev (3, 2), rev (3, 2), rev (3, 3), rev (3, 4)),
    0);
}

/*
 * cilium_srv6_policy_lease_valid(), same treatment: the slot's three fields
 * are passed in. D-51 conditions 1 (slot ownership) and 4 (deadline) are plain
 * comparisons of values this test has no opinion about; conditions 2 and 3 are
 * the ones item 176 is about.
 */
static int
lease_usable (u32 incarnation, u64 quoted_revision, u64 lease_revision, int slot_owned,
	      int before_deadline)
{
  if (!slot_owned)
    return 0;

  if (quoted_revision == CILIUM_SRV6_REV_INVALID || lease_revision != quoted_revision)
    return 0;

  if (!cilium_srv6_revision_is_current (quoted_revision, incarnation))
    return 0;

  return before_deadline;
}

static void
test_lease (void)
{
  expect ("a lease granted for this revision by the live process is usable",
	  lease_usable (3, rev (3, 9), rev (3, 9), 1, 1), 1);

  expect ("a lease granted for another revision is not usable",
	  lease_usable (3, rev (3, 9), rev (3, 8), 1, 1), 0);

  expect ("an expired lease is not usable", lease_usable (3, rev (3, 9), rev (3, 9), 1, 0), 0);

  /*
   * The liveness half of item 176. The previous agent process pushed this
   * lease, it was granted for exactly the revision the entry quotes, and its
   * deadline has not passed — a lease deadline is tens of seconds and a Pod
   * restart is faster than that. D-51 says a lease is a proof that a policy
   * watcher is alive; the watcher that made this statement is gone, so the
   * proof is void the moment the plugin accepts the successor's incarnation,
   * not when the deadline runs out.
   */
  expect ("an unexpired lease from the previous incarnation is not usable",
	  lease_usable (3, rev (2, 9), rev (2, 9), 1, 1), 0);

  expect ("a slot that belongs to another identity is not usable",
	  lease_usable (3, rev (3, 9), rev (3, 9), 0, 1), 0);
}

int
main (void)
{
  test_layout ();
  test_fence ();
  test_matches ();
  test_program_hit ();
  test_lease ();

  printf ("\n%d checks, %d failures\n", checks, failures);
  return failures ? 1 : 0;
}
