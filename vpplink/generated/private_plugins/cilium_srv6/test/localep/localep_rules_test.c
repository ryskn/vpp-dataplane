/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Host-side check of the LocalEndpointTable attachment identity rules
 * (cilium_srv6_localep_rules.h) — Issue #21 Stage 0 run 17 OP-17-1,
 * errata #34 item 200.
 *
 * What this file is for
 *
 *   Run 17 observed, after a VPP restart, the Pod interface lifecycle service
 *   recreating four TUNs in a different order: the attachments behind
 *   sw_if_index 8 and 10 swapped. The agent reinstalled both endpoints from
 *   the (sw_if_index, if_incarnation) handles it had kept from before the
 *   restart, and the plugin accepted both writes — the D-31 fence compares the
 *   incarnation against the *live* interface, and a restarted plugin restarts
 *   the counter both halves of the handle are drawn from, so both stale
 *   handles were live. Same-node forwarding stayed at 0% (the packets failed
 *   closed at cilium-srv6-classify with DROP_SRC_IP_MISMATCH) until the agent
 *   was restarted.
 *
 *   Item 200 makes the endpoint write name the CNI attachment it is for, and
 *   the plugin accept it only when its own binding table (D-68) holds exactly
 *   that (attachment_id, sw_if_index, if_incarnation). The decision is a pure
 *   function of the wire fields and of what the binding table holds, so it is
 *   checked here the way the D-85 fence is checked in ../hotpath and the
 *   classify scope in ../classify-scope: compiled against the byte-level stubs
 *   of ../fuzz/stub, with no vlib, no vnet and no plugin state.
 *
 * What it cannot check
 *
 *   That the handler calls it, that the binding it passes is the live one, and
 *   that the retvals are the ones cilium_srv6.api documents. Those are
 *   cilium_srv6_local_ep_add_del() and csh_local_ep_verdict_to_api_error() in
 *   cilium_srv6_headend.c, both of which need vlib; they are named here so a
 *   reviewer can check them by name. The agent side of the same rules is
 *   pinned against a fake dataplane in pkg/srv6ec/reconciler, so a divergence
 *   between the two is a test failure rather than a silent difference.
 */

#include <stdio.h>
#include <string.h>

#include <cilium_srv6/cilium_srv6_localep_rules.h>

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

/* One binding, as the D-68 table holds it. */
static cilium_srv6_localep_binding_t
bound (const char *id, u32 if_incarnation)
{
  cilium_srv6_localep_binding_t b = { 0 };

  b.present = 1;
  b.attachment_id = (const u8 *) id;
  b.id_len = (u32) strlen (id);
  b.if_incarnation = if_incarnation;
  return b;
}

static cilium_srv6_localep_binding_t
unbound (void)
{
  cilium_srv6_localep_binding_t b = { 0 };
  return b;
}

static cilium_srv6_localep_verdict_t
add (const char *id, u32 if_incarnation, cilium_srv6_localep_binding_t b)
{
  return cilium_srv6_localep_decide_add ((const u8 *) id, (u32) strlen (id), if_incarnation, b);
}

static cilium_srv6_localep_entry_t
installed_for (const char *id)
{
  cilium_srv6_localep_entry_t e = { 0 };

  e.present = 1;
  e.attachment_id = (const u8 *) id;
  e.id_len = (u32) strlen (id);
  return e;
}

static cilium_srv6_localep_verdict_t
del (const char *id, cilium_srv6_localep_entry_t e)
{
  return cilium_srv6_localep_decide_del ((const u8 *) id, (u32) strlen (id), e);
}

/* The two attachments of run 17, as the binding table held them after the
   restart: the lifecycle service recreated them in the other order. */
#define ATT_A "c0ffee0000000000000000000000000000000000000000000000000000000001:eth0"
#define ATT_B "c0ffee0000000000000000000000000000000000000000000000000000000002:eth0"

static void
check_the_run_17_shape (void)
{
  /*
   * The stale write: the agent kept attachment A's handle (8, 9) from before
   * the restart, and after it sw_if_index 8 belongs to attachment B. The
   * handle is live — the D-31 fence cannot see anything wrong with it — and
   * the binding table is the only authority that can.
   */
  expect ("a stale handle whose interface now belongs to another attachment is refused",
	  add (ATT_A, 9, bound (ATT_B, 9)), CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT);

  /*
   * The same write once the agent has re-resolved the attachment against the
   * binding table (errata #34 item 199): A is behind sw_if_index 10 now, and
   * the write that names 10 is the one that is accepted.
   */
  expect ("the re-resolved handle is accepted", add (ATT_A, 11, bound (ATT_A, 11)),
	  CILIUM_SRV6_LOCALEP_ACCEPT);

  /*
   * And the write the other endpoint makes for the interface it really is
   * behind is unaffected by A's stale attempt: a refusal changes nothing.
   */
  expect ("the attachment that owns the interface installs on it",
	  add (ATT_B, 9, bound (ATT_B, 9)), CILIUM_SRV6_LOCALEP_ACCEPT);
}

static void
check_the_binding_must_exist (void)
{
  /*
   * D-68 has no second authority: an interface no attachment claims is an
   * interface no endpoint may be installed on. This is also the D-72 ordering
   * check — bindings are reconstructed before any LocalEndpoint is installed,
   * so an ADD that arrives before its binding is an ADD from a writer that did
   * not wait.
   */
  expect ("an interface with no binding takes no endpoint", add (ATT_A, 9, unbound ()),
	  CILIUM_SRV6_LOCALEP_REJECT_NO_BINDING);
}

static void
check_the_incarnation_of_the_binding (void)
{
  /*
   * The binding names an interface *lifetime*, so a binding published for
   * another incarnation than the one being written does not authorise the
   * write. The binding table's own invariants make this unreachable — a
   * binding is removed by the interface delete callback that frees the index —
   * which is why it is checked: it is a check on those invariants, and a
   * silent acceptance here would be the D-31 fence with a second, weaker copy.
   */
  expect ("a binding published for another incarnation does not authorise the write",
	  add (ATT_A, 12, bound (ATT_A, 11)), CILIUM_SRV6_LOCALEP_REJECT_BINDING_INCARNATION);
}

static void
check_the_identity_is_well_formed (void)
{
  /* An ADD must name an attachment; there is no unnamed local endpoint. */
  expect ("an empty identity is refused on an ADD",
	  cilium_srv6_localep_decide_add ((const u8 *) "", 0, 9, bound (ATT_A, 9)),
	  CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID);

  /* The binding table's character set, not a second copy of it. */
  expect ("an identity with a space is refused", add ("a b", 9, bound ("a b", 9)),
	  CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID);

  /* The binding table's length bound, not a second copy of it. */
  {
    static u8 too_long[CILIUM_SRV6_ATTACHMENT_ID_MAX + 1];
    cilium_srv6_localep_binding_t b = { 0 };
    u32 i;

    for (i = 0; i < sizeof (too_long); i++)
      too_long[i] = 'a';

    b.present = 1;
    b.attachment_id = too_long;
    b.id_len = (u32) sizeof (too_long);
    b.if_incarnation = 9;

    expect ("an identity longer than the bound is refused, never truncated",
	    cilium_srv6_localep_decide_add (too_long, (u32) sizeof (too_long), 9, b),
	    CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID);
  }
}

static void
check_the_comparison_is_exact (void)
{
  /*
   * The suffix is the whole reason the VPP interface tag (63 usable bytes) was
   * unusable as the binding carrier: two attachments of one Pod differ only in
   * it. A comparison that stopped early would collapse them into one identity
   * and hand one Pod interface the other's endpoint programming.
   */
  expect ("two attachments of one Pod are not the same attachment",
	  add ("cid:eth0", 9, bound ("cid:eth1", 9)), CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT);

  /* A prefix of the bound identity is not the bound identity. */
  expect ("a prefix is not a match", add ("cid", 9, bound ("cid:eth0", 9)),
	  CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT);

  /* And the exact repeat of an accepted write stays accepted: the retry of an
     install whose acknowledgement was lost is idempotent, and item 200 does
     not make it a rejection. */
  expect ("an exact repeat is still accepted", add (ATT_A, 11, bound (ATT_A, 11)),
	  CILIUM_SRV6_LOCALEP_ACCEPT);
}

static void
check_the_delete_identity (void)
{
  /*
   * The stale DELETE: attachment A's endpoint was installed on a handle that
   * now carries attachment B's endpoint. Removing it would be A's teardown
   * deleting B's endpoint, which is the same misdelivery as the ADD, one
   * direction later.
   */
  expect ("a delete from the previous attachment does not remove the new entry",
	  del (ATT_A, installed_for (ATT_B)),
	  CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT_ENTRY);

  /* The ordinary teardown. */
  expect ("an attachment removes its own entry", del (ATT_A, installed_for (ATT_A)),
	  CILIUM_SRV6_LOCALEP_ACCEPT);

  /*
   * The unverified form: the D-70 orphan sweep reads a lifetime out of
   * srv6_local_ep_dump, which does not report an attachment, so it has none to
   * quote. It is not a way around the check above — a stale writer removes the
   * entries it *has* an identity for.
   */
  expect ("an empty identity deletes by lifetime alone",
	  cilium_srv6_localep_decide_del ((const u8 *) "", 0, installed_for (ATT_B)),
	  CILIUM_SRV6_LOCALEP_ACCEPT);

  /* A malformed non-empty identity is not the empty one. */
  expect ("a malformed identity is refused on a DELETE too", del ("a b", installed_for (ATT_A)),
	  CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID);

  /*
   * An entry that carries no identity at all: the caller answers the absence
   * with its own NO_SUCH_ENTRY, so the rules do not invent a second answer for
   * it.
   */
  {
    cilium_srv6_localep_entry_t none = { 0 };

    expect ("a delete against no entry is left to the caller", del (ATT_A, none),
	    CILIUM_SRV6_LOCALEP_ACCEPT);
  }
}

static void
check_nothing_accepts_by_default (void)
{
  /*
   * ACCEPT is the zero value of the enum, which is convenient to compare
   * against and dangerous to reach by accident. Every rejection is therefore
   * non-zero, and this pins that the four ADD rejections and the DELETE one
   * are five distinct values: the handler maps each to its own retval and two
   * that collapsed would make one of them unreportable.
   */
  int v[] = {
    CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID,	    CILIUM_SRV6_LOCALEP_REJECT_NO_BINDING,
    CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT,    CILIUM_SRV6_LOCALEP_REJECT_BINDING_INCARNATION,
    CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT_ENTRY,
  };
  unsigned i, j;

  for (i = 0; i < sizeof (v) / sizeof (v[0]); i++)
    {
      expect ("a rejection is never the accept value", v[i] != CILIUM_SRV6_LOCALEP_ACCEPT, 1);

      for (j = i + 1; j < sizeof (v) / sizeof (v[0]); j++)
	expect ("two rejections are never the same value", v[i] != v[j], 1);
    }
}

int
main (void)
{
  check_the_run_17_shape ();
  check_the_binding_must_exist ();
  check_the_incarnation_of_the_binding ();
  check_the_identity_is_well_formed ();
  check_the_comparison_is_exact ();
  check_the_delete_identity ();
  check_nothing_accepts_by_default ();

  printf ("\n%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
