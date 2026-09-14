/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Host-side check of the POLICY revision key ownership rules
 * (cilium_srv6_policyrev_rules.h) — Issue #21 Stage 0 run 21 OP-21-2,
 * errata #34 item 222.
 *
 * What this file is for
 *
 *   Run 21 lost the published POLICY revision of identity 46532 like this.
 *   The producer's drain installed the LocalEndpointTable entry of 46532
 *   before the recovery attempt's seed publish, so the *entry* created the
 *   PolicyLeaseTable slot (refcount 1, revision 0). The seed publish then
 *   found that slot and wrote the revision into it without taking a reference
 *   of its own. The D-72 replay reinstalled that one entry — the old slot was
 *   unreferenced first and the new one referenced after — the refcount reached
 *   zero, the slot was poisoned and released with the published revision in
 *   it, and the reinstall created a fresh slot at revision 0. Every later
 *   ProgramCache install for 46532 that quoted the published revision was then
 *   refused as a missing key (INVALID_VALUE_4), 387 times, while the agent's
 *   ledger still read the revision as acknowledged. Identity 23889 survived
 *   only because two entries named its slot.
 *
 *   Item 222 gives the publication a reference of its own, named by the
 *   `published` flag, and reorders every same-entry replace so that the new
 *   reference is taken before the old one is returned. The decision half of
 *   that is a pure function of three observations (does the slot exist, does
 *   it hold the publication's reference, is this element a withdraw) and lives
 *   in cilium_srv6_policyrev_rules.h, which is compiled here against the
 *   byte-level stubs of ../fuzz/stub with no vlib, no vnet and no plugin
 *   state, exactly as ../hotpath compiles the D-85 fence.
 *
 * What it cannot check
 *
 *   The pool and the hash the slots really live in, and therefore the exact
 *   statements of csh_policy_rev_slot_ref / csh_policy_rev_slot_unref /
 *   cilium_srv6_policy_revision_publish / cilium_srv6_local_ep_add_del in
 *   cilium_srv6_headend.c, all of which need vlib. What is executed here is
 *   the decision header plus the model below, whose ref / unref / publish /
 *   install helpers are written to mirror those four functions statement for
 *   statement; each names the function it stands for so a reviewer can put
 *   them side by side. A divergence between the model and the handler is not
 *   caught by this test — it is caught by reading them together, which is why
 *   the model is deliberately small enough to read.
 */

#include <stdio.h>
#include <string.h>

#include <cilium_srv6/cilium_srv6_policyrev_rules.h>

static int failures;
static int checks;

static void
expect (const char *what, long long got, long long want)
{
  checks++;

  if (got != want)
    {
      fprintf (stderr, "FAIL %s: got %lld, want %lld\n", what, got, want);
      failures++;
      return;
    }

  printf ("ok   %s\n", what);
}

/* ------------------------------------------------------------------ */
/* A model of the PolicyLeaseTable slot pool                           */
/* ------------------------------------------------------------------ */

/* The three reserved revision values of 02 §4.3, spelt as the plugin spells
   them: 0 = the key does not exist, ~0 = the sentinel. */
#define MODEL_REV_ABSENT  0ull
#define MODEL_REV_INVALID (~0ull)

/* Slot 0 is the sentinel and is never allocated, exactly as
   CSH_POLICY_REV_SENTINEL is never allocated. */
#define MODEL_SENTINEL	  0u
#define MODEL_N_SLOTS	  6u
#define MODEL_NO_IDENTITY (~0u)

typedef struct
{
  u32 identity;
  u32 refcount;
  int published;
  int in_use;
  u64 policy_revision;
  /* Not in the plugin: which creation of a slot this occupancy is. It is what
     lets a test say "the key kept its slot" rather than only "some slot holds
     the key", which is the whole difference between the fixed replace order
     and the one that released the slot and immediately made a new one. */
  u32 create_seq;
} model_slot_t;

typedef struct
{
  model_slot_t slot[MODEL_N_SLOTS];
  u32 n_creates;
} model_t;

static void
model_init (model_t *t)
{
  u32 i;

  memset (t, 0, sizeof (*t));
  for (i = 0; i < MODEL_N_SLOTS; i++)
    t->slot[i].identity = MODEL_NO_IDENTITY;

  /* The sentinel: present, never allocated, and holding the value that fails
     every comparison. */
  t->slot[MODEL_SENTINEL].in_use = 1;
  t->slot[MODEL_SENTINEL].policy_revision = MODEL_REV_INVALID;
}

/* csh_policy_rev_slot_find */
static u32
model_find (const model_t *t, u32 identity)
{
  u32 i;

  for (i = 1; i < MODEL_N_SLOTS; i++)
    if (t->slot[i].in_use && t->slot[i].identity == identity)
      return i;

  return MODEL_SENTINEL;
}

static u32
model_free_slots (const model_t *t)
{
  u32 i, n = 0;

  for (i = 1; i < MODEL_N_SLOTS; i++)
    if (!t->slot[i].in_use)
      n++;

  return n;
}

/* csh_policy_rev_slot_ref */
static u32
model_slot_ref (model_t *t, u32 identity)
{
  u32 slot = model_find (t, identity);
  u32 i;

  if (slot != MODEL_SENTINEL)
    {
      t->slot[slot].refcount++;
      return slot;
    }

  for (i = 1; i < MODEL_N_SLOTS; i++)
    if (!t->slot[i].in_use)
      break;

  if (i == MODEL_N_SLOTS)
    return MODEL_SENTINEL; /* pool exhausted */

  t->slot[i].in_use = 1;
  t->slot[i].identity = identity;
  t->slot[i].refcount = 1;
  t->slot[i].published = 0;
  t->slot[i].policy_revision = MODEL_REV_ABSENT;
  t->slot[i].create_seq = ++t->n_creates;

  return i;
}

/* csh_policy_rev_slot_unref */
static void
model_slot_unref (model_t *t, u32 slot)
{
  model_slot_t *r;

  if (slot == MODEL_SENTINEL || slot >= MODEL_N_SLOTS)
    return;
  if (!t->slot[slot].in_use)
    return;

  r = t->slot + slot;

  if (r->refcount > 0)
    r->refcount--;

  if (r->refcount != 0)
    return;

  /* The ASSERT the release path carries: an entry unref alone can never
     release a published slot. */
  if (!cilium_srv6_policyrev_slot_invariant_ok (r->refcount, r->published))
    {
      fprintf (stderr, "FAIL a published slot reached refcount 0 (identity %u)\n", r->identity);
      failures++;
    }

  /* Poison before release: a reader holding the index must not match a future
     identity's revision. */
  r->policy_revision = MODEL_REV_INVALID;
  r->identity = MODEL_NO_IDENTITY;
  r->published = 0;
  r->in_use = 0;
}

/*
 * cilium_srv6_policy_revision_publish, one element, second loop. The capacity
 * pre-check of the first loop is exercised separately.
 */
static void
model_publish (model_t *t, u32 identity, u64 revision)
{
  u32 slot = model_find (t, identity);
  cilium_srv6_policyrev_action_t action = cilium_srv6_policyrev_publish_action (
    slot != MODEL_SENTINEL, slot != MODEL_SENTINEL && t->slot[slot].published,
    revision == MODEL_REV_ABSENT);

  switch (action)
    {
    case CILIUM_SRV6_POLICYREV_WITHDRAW:
    case CILIUM_SRV6_POLICYREV_WITHDRAW_NOTHING_HELD:
      if (slot != MODEL_SENTINEL)
	{
	  t->slot[slot].policy_revision = MODEL_REV_ABSENT;
	  if (action == CILIUM_SRV6_POLICYREV_WITHDRAW)
	    {
	      t->slot[slot].published = 0;
	      model_slot_unref (t, slot);
	    }
	}
      return;

    case CILIUM_SRV6_POLICYREV_CREATE:
      slot = model_slot_ref (t, identity);
      if (slot == MODEL_SENTINEL)
	return; /* LIMIT_EXCEEDED */
      break;

    case CILIUM_SRV6_POLICYREV_ADOPT:
      t->slot[slot].refcount++;
      break;

    case CILIUM_SRV6_POLICYREV_REPUBLISH:
      break;
    }

  t->slot[slot].published = 1;
  t->slot[slot].policy_revision = revision;
}

/* The first loop's capacity counter, over one whole message. */
static u32
model_publish_capacity_needed (const model_t *t, const u32 *identities, const u64 *revisions, u32 n)
{
  u32 i, n_new = 0;

  for (i = 0; i < n; i++)
    n_new += (u32) cilium_srv6_policyrev_publish_allocates (
      model_find (t, identities[i]) != MODEL_SENTINEL, revisions[i] == MODEL_REV_ABSENT);

  return n_new;
}

/* ------------------------------------------------------------------ */
/* The entries that reference slots                                    */
/* ------------------------------------------------------------------ */

/* One LocalEndpointTable entry, i.e. one (sw_if_index) row. */
typedef struct
{
  int valid;
  u32 identity;
  u32 policy_rev_slot;
} model_entry_t;

/*
 * cilium_srv6_local_ep_add_del(is_add = 1), the replace half. Item 222 (b):
 * the new reference is taken before the old one is returned, so a re-install
 * of the same identity never takes its slot through zero.
 */
static void
model_local_ep_add (model_t *t, model_entry_t *e, u32 identity)
{
  u32 slot = model_slot_ref (t, identity);

  if (e->valid)
    model_slot_unref (t, e->policy_rev_slot);

  e->valid = 1;
  e->identity = identity;
  e->policy_rev_slot = slot;
}

/* The pre-item-222 order, kept so that the regression has a witness: the old
   reference was returned first and the new one taken after. */
static void
model_local_ep_add_unref_first (model_t *t, model_entry_t *e, u32 identity)
{
  if (e->valid)
    model_slot_unref (t, e->policy_rev_slot);

  e->valid = 1;
  e->identity = identity;
  e->policy_rev_slot = model_slot_ref (t, identity);
}

/* cilium_srv6_local_ep_add_del(is_add = 0) */
static void
model_local_ep_del (model_t *t, model_entry_t *e)
{
  if (!e->valid)
    return;

  model_slot_unref (t, e->policy_rev_slot);
  memset (e, 0, sizeof (*e));
}

/*
 * The POLICY half of the srv6_program_add_del acceptance rule (02 §4.3): the
 * quoted key must exist, and the quotation must match it exactly. The three
 * answers are the plugin's three retvals.
 */
typedef enum
{
  MODEL_INSTALL_ACCEPTED = 0,
  MODEL_INSTALL_MISSING_KEY, /* INVALID_VALUE_4, program_missing_key_installs */
  MODEL_INSTALL_STALE,	     /* INVALID_VALUE_3, program_stale_installs */
} model_install_result_t;

static model_install_result_t
model_program_install (const model_t *t, u32 identity, u64 quoted_revision)
{
  u32 slot = model_find (t, identity);
  u64 cur = t->slot[slot].policy_revision; /* slot 0 holds the sentinel */

  if (cur == MODEL_REV_INVALID || cur == MODEL_REV_ABSENT)
    return MODEL_INSTALL_MISSING_KEY;

  if (quoted_revision != cur)
    return MODEL_INSTALL_STALE;

  return MODEL_INSTALL_ACCEPTED;
}

/* ------------------------------------------------------------------ */
/* The checks                                                          */
/* ------------------------------------------------------------------ */

/* The run-21 identities and the revision of api trace 7543. */
#define COREDNS	  46532u
#define APISERVER 23889u
#define SEED_REV  124554051586ull

/*
 * (d)(1) The run-21 sequence, end to end: the entry creates the slot, the
 * publish adopts it, the entry is reinstalled, and an install quoting the
 * published revision is accepted.
 */
static void
check_entry_first_then_publish_then_reinstall (void)
{
  model_t t;
  model_entry_t ep = { 0 };

  model_init (&t);

  /* 12:15:33.265Z — the producer drain installs the entry first. */
  model_local_ep_add (&t, &ep, COREDNS);
  expect ("the entry created the slot", model_find (&t, COREDNS) != MODEL_SENTINEL, 1);
  expect ("a slot the entry created publishes nothing",
	  model_program_install (&t, COREDNS, SEED_REV), MODEL_INSTALL_MISSING_KEY);

  /* 12:15:33.3568Z — the seed publish finds the existing slot. */
  model_publish (&t, COREDNS, SEED_REV);
  expect ("the publication adopted the existing slot", t.slot[model_find (&t, COREDNS)].published,
	  1);
  expect ("the publication and the entry hold one reference each",
	  t.slot[model_find (&t, COREDNS)].refcount, 2);

  /* 12:15:33.358Z — the D-72 replay reinstalls the same entry. */
  model_local_ep_add (&t, &ep, COREDNS);
  expect ("the re-install did not release the key", model_find (&t, COREDNS) != MODEL_SENTINEL, 1);
  expect ("the re-install kept the published revision",
	  (long long) t.slot[model_find (&t, COREDNS)].policy_revision, (long long) SEED_REV);

  /* api trace 8664 — and the install the agent then retries is accepted. */
  expect ("an install quoting the published revision is accepted",
	  model_program_install (&t, COREDNS, SEED_REV), MODEL_INSTALL_ACCEPTED);
  expect ("an install quoting another revision is stale, not missing",
	  model_program_install (&t, COREDNS, SEED_REV + 1), MODEL_INSTALL_STALE);
}

/*
 * The same sequence with the pre-item-222 publish (no publication reference)
 * and the pre-item-222 replace order, so that the regression this test exists
 * for is stated rather than implied. Both halves have to be wrong for the key
 * to be lost, which is why 23889 — two entries — survived.
 */
static void
check_the_run_21_loss_needs_both_halves (void)
{
  model_t t;
  model_entry_t ep = { 0 };
  model_entry_t ep2 = { 0 };
  u32 slot;

  /* Publication takes no reference (the old publish), replace unrefs first
     (the old order): the key is lost. */
  model_init (&t);
  model_local_ep_add (&t, &ep, COREDNS);
  slot = model_find (&t, COREDNS);
  t.slot[slot].policy_revision = SEED_REV; /* the old publish wrote only this */
  model_local_ep_add_unref_first (&t, &ep, COREDNS);
  expect ("without a publication reference, one entry's replace loses the key",
	  model_program_install (&t, COREDNS, SEED_REV), MODEL_INSTALL_MISSING_KEY);
  expect ("and the key comes back as a newly created slot", t.n_creates, 2u);

  /* Same, with a second entry on the identity: 23889's shape. */
  model_init (&t);
  memset (&ep, 0, sizeof (ep));
  model_local_ep_add (&t, &ep, APISERVER);
  model_local_ep_add (&t, &ep2, APISERVER);
  slot = model_find (&t, APISERVER);
  t.slot[slot].policy_revision = SEED_REV;
  model_local_ep_add_unref_first (&t, &ep, APISERVER);
  expect ("a second entry hid the same defect", model_program_install (&t, APISERVER, SEED_REV),
	  MODEL_INSTALL_ACCEPTED);
}

/*
 * (d)(2) A published identity keeps its slot with no entries left. This is the
 * sentence the publish handler already claimed and did not implement.
 */
static void
check_the_publication_keeps_the_slot (void)
{
  model_t t;
  model_entry_t ep = { 0 };

  model_init (&t);

  model_local_ep_add (&t, &ep, COREDNS);
  model_publish (&t, COREDNS, SEED_REV);
  model_local_ep_del (&t, &ep);

  expect ("the slot survives the last entry", model_find (&t, COREDNS) != MODEL_SENTINEL, 1);
  expect ("and so does the published revision",
	  (long long) t.slot[model_find (&t, COREDNS)].policy_revision, (long long) SEED_REV);
  expect ("the publication is the only reference left", t.slot[model_find (&t, COREDNS)].refcount,
	  1u);
  expect ("a later install still finds the key", model_program_install (&t, COREDNS, SEED_REV),
	  MODEL_INSTALL_ACCEPTED);

  /* And a publication with no entry at all behaves the same way. */
  model_init (&t);
  model_publish (&t, APISERVER, SEED_REV);
  expect ("a publication alone keeps a slot", t.slot[model_find (&t, APISERVER)].refcount, 1u);
}

/*
 * (d)(3) A withdraw returns the publication's reference: the slot is released
 * when nothing else names it, and retained while something does.
 */
static void
check_the_withdraw_returns_the_reference (void)
{
  model_t t;
  model_entry_t ep = { 0 };

  /* Nothing else names it: released. */
  model_init (&t);
  model_publish (&t, COREDNS, SEED_REV);
  model_publish (&t, COREDNS, MODEL_REV_ABSENT);
  expect ("a withdraw releases an unreferenced slot", model_find (&t, COREDNS), MODEL_SENTINEL);
  expect ("and the pool got the slot back", model_free_slots (&t), MODEL_N_SLOTS - 1);

  /* An entry still names it: retained, but publishing nothing. */
  model_init (&t);
  model_publish (&t, COREDNS, SEED_REV);
  model_local_ep_add (&t, &ep, COREDNS);
  model_publish (&t, COREDNS, MODEL_REV_ABSENT);
  expect ("a withdraw does not release a slot an entry names",
	  model_find (&t, COREDNS) != MODEL_SENTINEL, 1);
  expect ("the entry is the only reference left", t.slot[model_find (&t, COREDNS)].refcount, 1u);
  expect ("a withdrawn key is a missing key, not a stale one",
	  model_program_install (&t, COREDNS, SEED_REV), MODEL_INSTALL_MISSING_KEY);

  /* The entry goes, and the slot goes with it. */
  model_local_ep_del (&t, &ep);
  expect ("the last entry releases the withdrawn slot", model_find (&t, COREDNS), MODEL_SENTINEL);

  /* A withdraw of an identity that was never published returns nothing. */
  model_init (&t);
  memset (&ep, 0, sizeof (ep));
  model_local_ep_add (&t, &ep, COREDNS);
  model_publish (&t, COREDNS, MODEL_REV_ABSENT);
  expect ("a withdraw of an unpublished slot releases nothing",
	  t.slot[model_find (&t, COREDNS)].refcount, 1u);

  /* A withdrawn identity coming back adopts the slot the entry still holds. */
  model_init (&t);
  memset (&ep, 0, sizeof (ep));
  model_publish (&t, COREDNS, SEED_REV);
  model_local_ep_add (&t, &ep, COREDNS);
  model_publish (&t, COREDNS, MODEL_REV_ABSENT);
  model_publish (&t, COREDNS, SEED_REV + 2);
  expect ("a republished identity retakes the publication reference",
	  t.slot[model_find (&t, COREDNS)].refcount, 2u);
  expect ("and the slot was never recreated", t.n_creates, 1u);
}

/* (d)(4) A second publish of the same identity takes no second reference. */
static void
check_publishing_twice_is_idempotent_on_the_refcount (void)
{
  model_t t;
  model_entry_t ep = { 0 };
  u32 slot;

  model_init (&t);

  model_publish (&t, COREDNS, SEED_REV);
  slot = model_find (&t, COREDNS);
  expect ("one publication, one reference", t.slot[slot].refcount, 1u);

  model_publish (&t, COREDNS, SEED_REV);
  expect ("republishing the same revision takes nothing", t.slot[slot].refcount, 1u);

  model_publish (&t, COREDNS, SEED_REV + 1);
  expect ("advancing the revision takes nothing either", t.slot[slot].refcount, 1u);
  expect ("and the revision advanced", (long long) t.slot[slot].policy_revision,
	  (long long) (SEED_REV + 1));

  /* With an entry on top, the count is exactly two however many publishes
     arrive: one publication, one entry. */
  model_local_ep_add (&t, &ep, COREDNS);
  model_publish (&t, COREDNS, SEED_REV + 2);
  model_publish (&t, COREDNS, SEED_REV + 3);
  expect ("one publication and one entry are two references", t.slot[slot].refcount, 2u);
}

/*
 * (b) again, on its own: a same-identity re-install keeps the slot even for an
 * identity nothing has published yet, which is the state the run-21 order
 * produced and the state the publication reference cannot protect.
 */
static void
check_a_reinstall_never_recreates_the_slot (void)
{
  model_t t;
  model_entry_t ep = { 0 };
  u32 seq;

  model_init (&t);

  model_local_ep_add (&t, &ep, COREDNS);
  seq = t.slot[model_find (&t, COREDNS)].create_seq;

  model_local_ep_add (&t, &ep, COREDNS);
  expect ("an unpublished slot survives a re-install too",
	  t.slot[model_find (&t, COREDNS)].create_seq, seq);
  expect ("no slot was created for the re-install", t.n_creates, 1u);
  expect ("and the entry still holds exactly one reference",
	  t.slot[model_find (&t, COREDNS)].refcount, 1u);

  /* Changing the identity of the entry does release the old slot, which is
     the case the ordering must not prevent. */
  model_local_ep_add (&t, &ep, APISERVER);
  expect ("an identity change releases the slot it left", model_find (&t, COREDNS), MODEL_SENTINEL);
  expect ("and holds the one it moved to", t.slot[model_find (&t, APISERVER)].refcount, 1u);
}

/* (a) The capacity pre-check counts only the slots a message creates. */
static void
check_the_capacity_precheck_counts_creations (void)
{
  model_t t;
  model_entry_t ep = { 0 };
  u32 ids[3] = { COREDNS, APISERVER, 1u };
  u64 revs[3] = { SEED_REV, SEED_REV, SEED_REV };
  u64 withdraws[3] = { MODEL_REV_ABSENT, MODEL_REV_ABSENT, MODEL_REV_ABSENT };

  model_init (&t);

  expect ("a seed of three unknown identities needs three slots",
	  model_publish_capacity_needed (&t, ids, revs, 3), 3u);

  /* The run-21 order: one identity already has a slot, created by its entry.
     Adopting it must not be counted, or a seed would be refused with
     LIMIT_EXCEEDED for capacity it does not use. */
  model_local_ep_add (&t, &ep, COREDNS);
  expect ("adopting an existing slot needs no capacity",
	  model_publish_capacity_needed (&t, ids, revs, 3), 2u);

  expect ("a message of withdraws needs no capacity",
	  model_publish_capacity_needed (&t, ids, withdraws, 3), 0u);
}

/* The five actions are exhaustive over the three observations, and each one
   is distinct: two that collapsed would make one of them unreachable. */
static void
check_the_action_table_is_exhaustive (void)
{
  int slot_exists, published, absent;
  int seen[5] = { 0 };

  for (slot_exists = 0; slot_exists <= 1; slot_exists++)
    for (published = 0; published <= 1; published++)
      for (absent = 0; absent <= 1; absent++)
	{
	  cilium_srv6_policyrev_action_t a =
	    cilium_srv6_policyrev_publish_action (slot_exists, published, absent);

	  expect ("every observation has an action",
		  a <= CILIUM_SRV6_POLICYREV_WITHDRAW_NOTHING_HELD, 1);
	  seen[a] = 1;

	  /* A slot that does not exist cannot hold the publication's
	     reference, whatever the caller passes. */
	  if (!slot_exists)
	    expect ("no slot means no reference to return or reuse",
		    a == (absent ? CILIUM_SRV6_POLICYREV_WITHDRAW_NOTHING_HELD :
				   CILIUM_SRV6_POLICYREV_CREATE),
		    1);
	}

  expect ("CREATE is reachable", seen[CILIUM_SRV6_POLICYREV_CREATE], 1);
  expect ("ADOPT is reachable", seen[CILIUM_SRV6_POLICYREV_ADOPT], 1);
  expect ("REPUBLISH is reachable", seen[CILIUM_SRV6_POLICYREV_REPUBLISH], 1);
  expect ("WITHDRAW is reachable", seen[CILIUM_SRV6_POLICYREV_WITHDRAW], 1);
  expect ("WITHDRAW_NOTHING_HELD is reachable", seen[CILIUM_SRV6_POLICYREV_WITHDRAW_NOTHING_HELD],
	  1);

  /* The invariant the whole rule exists to create. */
  expect ("a published slot at zero references is a violation",
	  cilium_srv6_policyrev_slot_invariant_ok (0, 1), 0);
  expect ("a published slot at one reference is fine",
	  cilium_srv6_policyrev_slot_invariant_ok (1, 1), 1);
  expect ("an unpublished slot at zero references is fine",
	  cilium_srv6_policyrev_slot_invariant_ok (0, 0), 1);
}

int
main (void)
{
  check_entry_first_then_publish_then_reinstall ();
  check_the_run_21_loss_needs_both_halves ();
  check_the_publication_keeps_the_slot ();
  check_the_withdraw_returns_the_reference ();
  check_publishing_twice_is_idempotent_on_the_refcount ();
  check_a_reinstall_never_recreates_the_slot ();
  check_the_capacity_precheck_counts_creations ();
  check_the_action_table_is_exhaustive ();

  printf ("\n%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
