/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Host-side check of the LocalEndpointTable attachment identity and exact
 * mutation rules (cilium_srv6_localep_rules.h) — Issue #21 Stage 0 run 17
 * OP-17-1, errata #34 items 200 and 202 (D-88).
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
 *   Item 202 (D-88) makes the mutation exact. An ADD installs where nothing
 *   is installed, is an idempotent success where exactly its tuple is
 *   installed, and is a conflict where anything else is - there is no
 *   implicit replace. A DELETE must name the exact installed instance
 *   (attachment, interface lifetime, address, identity, Context, quota
 *   class), and an empty attachment_id is refused. check_add_is_exact and
 *   check_delete_is_exact walk every field of the tuple one at a time.
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

/* The two attachments of run 17, as the binding table held them after the
   restart: the lifecycle service recreated them in the other order. */
#define ATT_A "c0ffee0000000000000000000000000000000000000000000000000000000001:eth0"
#define ATT_B "c0ffee0000000000000000000000000000000000000000000000000000000002:eth0"

/*
 * One semantic tuple (errata #34 item 202, D-88): attachment A's endpoint on
 * the interface lifetime (8, 9), with one identity, one Context, one quota
 * class and one address. Every exact-mutation check below starts from it and
 * changes one field.
 */
static cilium_srv6_localep_tuple_t
tuple_a (void)
{
  cilium_srv6_localep_tuple_t t = { 0 };

  t.attachment_id = (const u8 *) ATT_A;
  t.id_len = (u32) strlen (ATT_A);
  t.sw_if_index = 8;
  t.if_incarnation = 9;
  t.identity = 4242;
  t.local_context_id = 0x01000abc;
  t.owner_quota_class = 3;
  t.ip[0] = 0xfd;
  t.ip[15] = 0x0a;
  return t;
}

static cilium_srv6_localep_entry_t
installed (cilium_srv6_localep_tuple_t t)
{
  cilium_srv6_localep_entry_t e = { 0 };

  e.present = 1;
  e.tuple = t;
  return e;
}

static cilium_srv6_localep_entry_t
nothing_installed (void)
{
  cilium_srv6_localep_entry_t e = { 0 };
  return e;
}

static cilium_srv6_localep_verdict_t
add_exact (cilium_srv6_localep_tuple_t req, cilium_srv6_localep_binding_t b,
	   cilium_srv6_localep_entry_t e)
{
  return cilium_srv6_localep_decide_add_exact (&req, b, e);
}

static cilium_srv6_localep_verdict_t
del (cilium_srv6_localep_tuple_t req, cilium_srv6_localep_entry_t e)
{
  return cilium_srv6_localep_decide_del (&req, e);
}

/* The fields of the semantic tuple, in the order mutate() changes them. */
static const char *const tuple_fields[] = {
  "attachment_id", "sw_if_index",	"if_incarnation", "identity",
  "local_context_id", "owner_quota_class", "ip",
};

#define N_TUPLE_FIELDS (sizeof (tuple_fields) / sizeof (tuple_fields[0]))

/* t with one field changed to another value, and nothing else. */
static cilium_srv6_localep_tuple_t
mutate (cilium_srv6_localep_tuple_t t, unsigned field)
{
  switch (field)
    {
    case 0:
      t.attachment_id = (const u8 *) ATT_B;
      t.id_len = (u32) strlen (ATT_B);
      break;
    case 1:
      t.sw_if_index++;
      break;
    case 2:
      t.if_incarnation++;
      break;
    case 3:
      t.identity++;
      break;
    case 4:
      t.local_context_id++;
      break;
    case 5:
      t.owner_quota_class++;
      break;
    default:
      t.ip[15]++;
      break;
    }
  return t;
}

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
check_add_is_exact (void)
{
  cilium_srv6_localep_tuple_t a = tuple_a ();
  cilium_srv6_localep_binding_t b = bound (ATT_A, 9);
  char copy[sizeof (ATT_A)];
  unsigned f;

  /* State 1 of D-88: nothing is installed, so the ADD installs. */
  expect ("an ADD onto an empty interface installs", add_exact (a, b, nothing_installed ()),
	  CILIUM_SRV6_LOCALEP_ACCEPT);

  /*
   * State 2: exactly this tuple is installed. The retry of an install whose
   * ACK was lost, the restart adoption of errata #34 item 217 and the D-72
   * recovery publication all re-send it, and all three must be a success that
   * writes nothing - not a refusal, and not a second install.
   */
  expect ("an exact replay is an idempotent success", add_exact (a, b, installed (a)),
	  CILIUM_SRV6_LOCALEP_ACCEPT_IDEMPOTENT);

  /* The comparison is of bytes, not of where they are: the installed identity
     is the table's own copy, never the API message's buffer. */
  memcpy (copy, ATT_A, sizeof (copy));
  {
    cilium_srv6_localep_tuple_t stored = a;

    stored.attachment_id = (const u8 *) copy;
    expect ("an exact replay compares the identity's bytes, not its address",
	    add_exact (a, b, installed (stored)), CILIUM_SRV6_LOCALEP_ACCEPT_IDEMPOTENT);
  }

  /*
   * State 3: anything else is installed. One field at a time, so that a field
   * the comparison forgot shows up by name. The attachment case is the
   * binding having moved to A while B's entry is still installed: the binding
   * check passes, and the entry is still not A's to overwrite.
   */
  for (f = 0; f < N_TUPLE_FIELDS; f++)
    {
      char what[128];

      snprintf (what, sizeof (what),
		"an ADD over an entry that differs in %s is a conflict, not a replace",
		tuple_fields[f]);
      expect (what, add_exact (a, b, installed (mutate (a, f))),
	      CILIUM_SRV6_LOCALEP_REJECT_CONFLICT);
    }

  /*
   * The identity change of D-69, which is the replacement D-88 is about: the
   * attachment, the interface and the address stay, the identity and the
   * Context move. It is refused until the old entry has been deleted, and
   * then it is an ordinary install.
   */
  {
    cilium_srv6_localep_tuple_t next = a;

    next.identity = 5151;
    next.local_context_id = 0x01000abd;
    expect ("an identity change on top of the old entry is refused",
	    add_exact (next, b, installed (a)), CILIUM_SRV6_LOCALEP_REJECT_CONFLICT);
    expect ("the identity change after the old entry's DELETE installs",
	    add_exact (next, b, nothing_installed ()), CILIUM_SRV6_LOCALEP_ACCEPT);
  }

  /*
   * An installed entry whose identity the table does not hold equals no
   * request: the table broke its own invariant (every entry has one since
   * item 200), and the fail-closed reading is "something else is installed".
   */
  {
    cilium_srv6_localep_tuple_t anonymous = a;

    anonymous.attachment_id = 0;
    anonymous.id_len = 0;
    expect ("an entry with no recorded attachment is not an exact match",
	    add_exact (a, b, installed (anonymous)), CILIUM_SRV6_LOCALEP_REJECT_CONFLICT);
  }

  /*
   * The binding check runs first, so a replay is not a way to have an entry
   * confirmed whose binding has moved: the exact tuple is installed, and the
   * interface is now bound to B, or to nobody.
   */
  expect ("an exact replay whose binding has moved is refused by the binding",
	  add_exact (a, bound (ATT_B, 9), installed (a)),
	  CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT);
  expect ("an exact replay with no binding is refused by the binding",
	  add_exact (a, unbound (), installed (a)), CILIUM_SRV6_LOCALEP_REJECT_NO_BINDING);
  expect ("an exact replay against a binding of another lifetime is refused",
	  add_exact (a, bound (ATT_A, 8), installed (a)),
	  CILIUM_SRV6_LOCALEP_REJECT_BINDING_INCARNATION);

  /* And the identity is still checked before anything else. */
  {
    cilium_srv6_localep_tuple_t unnamed = a;

    unnamed.attachment_id = (const u8 *) "";
    unnamed.id_len = 0;
    expect ("an ADD with no attachment is refused before the entry is looked at",
	    add_exact (unnamed, b, nothing_installed ()), CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID);
  }
}

static void
check_delete_is_exact (void)
{
  cilium_srv6_localep_tuple_t a = tuple_a ();
  unsigned f;

  /* The ordinary teardown: the DELETE names exactly what is installed. */
  expect ("a DELETE of the exact installed instance removes it", del (a, installed (a)),
	  CILIUM_SRV6_LOCALEP_ACCEPT);

  /*
   * D-88: there is no wildcard DELETE. An empty attachment_id is refused
   * whatever is installed, and by the request check alone, which the plugin
   * runs before it consults the interface.
   */
  {
    cilium_srv6_localep_tuple_t wildcard = a;

    wildcard.attachment_id = (const u8 *) "";
    wildcard.id_len = 0;
    expect ("an empty attachment_id is refused on a DELETE", del (wildcard, installed (a)),
	    CILIUM_SRV6_LOCALEP_REJECT_ID_EMPTY);
    expect ("an empty attachment_id is refused with nothing installed too",
	    del (wildcard, nothing_installed ()), CILIUM_SRV6_LOCALEP_REJECT_ID_EMPTY);
    expect ("an empty attachment_id is refused by the request check alone",
	    cilium_srv6_localep_check_del_request (&wildcard), CILIUM_SRV6_LOCALEP_REJECT_ID_EMPTY);
  }

  /* A malformed non-empty identity is not the empty one. */
  {
    cilium_srv6_localep_tuple_t malformed = a;

    malformed.attachment_id = (const u8 *) "a b";
    malformed.id_len = 3;
    expect ("a malformed identity is refused on a DELETE", del (malformed, installed (a)),
	    CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID);
  }

  /*
   * The pre-D-88 handle-only DELETE: the key and the attachment, every other
   * field zero. No entry can have the unspecified address, so the request
   * names no instance and is refused as malformed rather than answered as an
   * absence a caller would read as "already gone".
   */
  {
    cilium_srv6_localep_tuple_t handle_only = { 0 };

    handle_only.attachment_id = a.attachment_id;
    handle_only.id_len = a.id_len;
    handle_only.sw_if_index = a.sw_if_index;
    handle_only.if_incarnation = a.if_incarnation;
    expect ("a handle-only DELETE is refused", del (handle_only, installed (a)),
	    CILIUM_SRV6_LOCALEP_REJECT_ADDRESS_UNSPECIFIED);
  }

  expect ("a DELETE with nothing installed is an absence", del (a, nothing_installed ()),
	  CILIUM_SRV6_LOCALEP_REJECT_NO_ENTRY);

  /*
   * The stale DELETE with another attachment: A's teardown arrives after the
   * handle was given to B and B installed on it. Removing B's entry would be
   * the run-17 swap one direction later.
   */
  {
    cilium_srv6_localep_tuple_t b_entry = mutate (a, 0);

    expect ("a stale DELETE from another attachment does not remove the new entry",
	    del (a, installed (b_entry)), CILIUM_SRV6_LOCALEP_REJECT_OTHER_INSTANCE);
  }

  /*
   * The stale DELETE of the same attachment: the old identity's DELETE arrives
   * after the D-69 replacement installed the successor. Attachment, handle
   * and address all match, which is why identity and Context are in the
   * match: without them this DELETE would remove the successor.
   */
  {
    cilium_srv6_localep_tuple_t successor = a;

    successor.identity = 5151;
    successor.local_context_id = 0x01000abd;
    expect ("a stale DELETE of a previous identity does not remove the successor",
	    del (a, installed (successor)), CILIUM_SRV6_LOCALEP_REJECT_OTHER_INSTANCE);
  }

  /* Every field, one at a time. */
  for (f = 0; f < N_TUPLE_FIELDS; f++)
    {
      char what[128];

      snprintf (what, sizeof (what),
		"a DELETE that differs from the installed entry in %s removes nothing",
		tuple_fields[f]);
      expect (what, del (mutate (a, f), installed (a)),
	      CILIUM_SRV6_LOCALEP_REJECT_OTHER_INSTANCE);
    }
}

static void
check_nothing_accepts_by_default (void)
{
  /*
   * ACCEPT is the zero value of the enum, which is convenient to compare
   * against and dangerous to reach by accident. Every other verdict is
   * therefore non-zero - ACCEPT_IDEMPOTENT included, which is a success the
   * caller must recognise by name because it must not write - and every pair
   * is distinct, so that no verdict can be mistaken for another one.
   */
  int v[] = {
    CILIUM_SRV6_LOCALEP_ACCEPT_IDEMPOTENT,
    CILIUM_SRV6_LOCALEP_REJECT_ID_INVALID,
    CILIUM_SRV6_LOCALEP_REJECT_NO_BINDING,
    CILIUM_SRV6_LOCALEP_REJECT_OTHER_ATTACHMENT,
    CILIUM_SRV6_LOCALEP_REJECT_BINDING_INCARNATION,
    CILIUM_SRV6_LOCALEP_REJECT_CONFLICT,
    CILIUM_SRV6_LOCALEP_REJECT_ID_EMPTY,
    CILIUM_SRV6_LOCALEP_REJECT_ADDRESS_UNSPECIFIED,
    CILIUM_SRV6_LOCALEP_REJECT_NO_ENTRY,
    CILIUM_SRV6_LOCALEP_REJECT_OTHER_INSTANCE,
  };
  unsigned i, j;

  for (i = 0; i < sizeof (v) / sizeof (v[0]); i++)
    {
      expect ("a verdict other than ACCEPT is never the accept value",
	      v[i] != CILIUM_SRV6_LOCALEP_ACCEPT, 1);

      for (j = i + 1; j < sizeof (v) / sizeof (v[0]); j++)
	expect ("two verdicts are never the same value", v[i] != v[j], 1);
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
  check_add_is_exact ();
  check_delete_is_exact ();
  check_nothing_accepts_by_default ();

  printf ("\n%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
