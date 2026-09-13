/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * Host-side check of which interfaces carry cilium-srv6-classify
 * (cilium_srv6_classify_scope.h) — Issue #21 Stage 0 run 16, errata #34
 * item 191.
 *
 * What this file is for
 *
 *   Run 16 observed, during an N5 stall after a VPP restart, tun1..tun4
 *   carrying `ip6-rx-urpf-loose` and `cilium-srv6-guard` and nothing else,
 *   with `show cilium srv6 guard` reporting "11 total, 7 quarantined, 4
 *   untrusted, 0 trusted-fabric" and "guard coverage: COMPLETE". A same-node
 *   Pod-to-Pod ping ran 10/10 with LocalEndpointTable 0, ProgramCache 0
 *   installs, IF-3 0 frames and all 18 drop reasons 0: the packets were
 *   forwarded by the plain IPv6 FIB with no policy evaluation.
 *
 *   The cause was a scope, not a verdict. `cilium-srv6-classify` already
 *   answers DROP_UNKNOWN_SOURCE_EP for a packet whose
 *   (rx_sw_if_index, rx_if_incarnation) has no LocalEndpointTable entry
 *   (02 §3), but the feature was enabled only by srv6_local_ep_add_del, so on
 *   an interface with no endpoint that branch could not run. The scope is now
 *   cilium_srv6_classify_wanted(), which is a pure function of the D-71
 *   Pod-facing declaration, the D-73 classification and whether the interface
 *   has a local endpoint, and which is checked here the way the D-85 fence is
 *   checked in ../hotpath: compiled against the byte-level stubs of
 *   ../fuzz/stub, with no vlib, no vnet and no plugin state.
 *
 *   errata #34 item 195 added the pod_facing term. Item 191 left a residue:
 *   between a VPP restart and the agent's first srv6_acl_interface_set no
 *   interface is classified at all, so a Pod tun reads QUARANTINED and is
 *   indistinguishable from the host TAP — the window was fail-open for as long
 *   as the agent was absent. The D-71 attachment binding is now the
 *   declaration: srv6_if_attachment_add_del(ADD) sets pod_facing and installs
 *   the feature before it acknowledges.
 *
 *   errata #34 item 196 made cilium_srv6_classify_required() — the two
 *   declaration terms without has_local_ep — the plugin's classify coverage
 *   condition, which gates cilium_srv6_guard_context_install_allowed().
 *
 * What it cannot check
 *
 *   That the callers actually call it, and that pod_facing is written and
 *   cleared where this file says it is. Those sites all need vlib and are
 *   named here so a reviewer can check them by name:
 *
 *     cilium_srv6_local_ep_add_del()      has_local_ep changes
 *     cilium_srv6_acl_interface_set()     trust changes
 *     cilium_srv6_guard_mark_pod_facing() pod_facing 0 -> 1, called from
 *                                         cilium_srv6_if_attachment_add_del()
 *                                         on ADD before the ACK
 *     csg_interface_del()                 pod_facing -> 0, the *only* site
 *     cilium_srv6_headend_sw_interface_add_del()
 *                                         retires the feature so a reused
 *                                         sw_if_index cannot inherit it (D-31)
 *
 *   The DELETE side of cilium_srv6_if_attachment_add_del() appears in none of
 *   those lists, and that is item 195's sticky rule: withdrawing a binding does
 *   not take classify off an interface that still exists.
 *
 *   Nor can it check the refusal: when vnet_feature_enable_disable() fails,
 *   cilium_srv6_guard_mark_pod_facing() restores the previous pod_facing value
 *   and cilium_srv6_if_attachment_add_del() returns
 *   VNET_API_ERROR_CANNOT_ENABLE_DISABLE_FEATURE without inserting the binding.
 *   Reaching that path needs a failing feature arc, i.e. vlib and vnet, so it
 *   is a reviewable property of those two functions rather than a check here.
 *   The post-condition the ADD relies on is written out explicitly in
 *   cilium_srv6_guard_mark_pod_facing(): a refresh that returns 0 without
 *   leaving classify_installed set is converted into that same refusal, so the
 *   ACK never means less than "the feature is on the interface".
 */

#include <stdio.h>

#include <cilium_srv6/cilium_srv6_classify_scope.h>

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

static void
check_the_run_16_state (void)
{
  /*
   * The state the fail-open was observed in: the agent's D-73 classification
   * reconciler had committed UNTRUSTED for the four Pod interfaces (step [1]
   * of the D-72 sequence, §2.15.5), and the recovery was stalled at step [2],
   * so no LocalEndpointTable entry existed yet. This is the one case the
   * change is for.
   */
  expect ("a Pod-facing interface with no endpoint is on the headend path",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_UNTRUSTED, 0, 0), 1);

  expect ("a Pod-facing interface with an endpoint is on the headend path",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_UNTRUSTED, 1, 0), 1);
}

static void
check_the_interfaces_that_must_stay_off (void)
{
  /*
   * 03 §1.1 / D-58: the host TAP is a normal interface to VPP and carries the
   * guard, but it never has a LocalEndpointTable entry. D-73 does not classify
   * it UNTRUSTED — that classification comes from a D-68/D-71 Pod attachment
   * binding — so it stays QUARANTINED, and it must stay off the headend path:
   * classify would drop every host-originated and hostNetwork Pod packet,
   * including the agent's own IF-2/IF-3 and BGP sessions.
   */
  expect ("an unclassified interface with no endpoint stays off",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_QUARANTINED, 0, 0), 0);

  /* D-31: a fabric uplink can never be Pod-facing and never has an endpoint. */
  expect ("a fabric uplink stays off",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_TRUSTED_FABRIC, 0, 0), 0);
}

static void
check_the_dead_man_switch_case (void)
{
  /*
   * D-35: the dead-man switch quarantines every interface that is not
   * TRUSTED_FABRIC while retaining existing ACTIVE delivery. A Pod interface
   * that still has an endpoint is therefore QUARANTINED with an endpoint, and
   * it must keep classify: removing it would not stop that Pod's traffic, it
   * would hand it to the plain IPv6 FIB — the same fail-open, produced by the
   * mechanism meant to contain a compromised agent.
   */
  expect ("a quarantined interface that still has an endpoint keeps classify",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_QUARANTINED, 1, 0), 1);

  /*
   * The symmetric case is the pre-191 rule, kept only as a lower bound: an
   * endpoint always implies classify, whatever the classification is. It is
   * what makes the predicate monotone in has_local_ep, so no trust transition
   * can take the feature away from an interface that is delivering.
   */
  expect ("an endpoint alone is enough, whatever the classification",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_TRUSTED_FABRIC, 1, 0), 1);
}


/*
 * errata #34 item 195: the interface lifetime, replayed as a sequence of
 * predicate inputs.
 *
 * The lifecycle sites are named in the file header; what is checkable here is
 * that the predicate gives the right answer in each state those sites produce,
 * and in particular that the two states which used to be fail-open windows are
 * not.
 */
static void
check_the_binding_is_the_declaration (void)
{
  /*
   * The state item 195 is about, and the one item 191 could not reach: VPP has
   * just restarted, the lifecycle writer has recreated the Pod tun and
   * published its D-71 binding, and the agent has not classified anything yet
   * (or is not running at all). The interface reads QUARANTINED, has no
   * endpoint, and is indistinguishable from the host TAP by trust alone.
   */
  expect ("a bound interface is on the headend path before any classification",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_QUARANTINED, 0, 1), 1);

  /*
   * The D-35 dead-man switch quarantines everything that is not
   * TRUSTED_FABRIC. Before 195 that returned a Pod interface with no endpoint
   * to the host-TAP-shaped state above; the declaration survives it because it
   * is not a classification.
   */
  expect ("the dead-man switch does not undeclare a bound interface",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_QUARANTINED, 0, 1), 1);

  /* The steady state, once the agent has converged onto the same fact. */
  expect ("a bound and classified interface is on the headend path",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_UNTRUSTED, 1, 1), 1);
}

static void
check_the_declaration_is_sticky (void)
{
  /*
   * The binding DELETE -> interface destroy window. The lifecycle writer
   * withdraws the binding first and the interface goes away some time later;
   * in between, the interface still exists and a Pod can still put packets on
   * it. `pod_facing` is deliberately not cleared by the DELETE, so the
   * predicate still selects the interface and those packets are still
   * evaluated (and drop as DROP_UNKNOWN_SOURCE_EP once the endpoint is gone)
   * rather than being handed to the plain IPv6 FIB.
   *
   * The DELETE can arrive in any trust state, including QUARANTINED after a
   * dead-man activation, so both are checked.
   */
  expect ("a withdrawn binding keeps the interface on the headend path",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_UNTRUSTED, 0, 1), 1);

  expect ("a withdrawn binding keeps it there while quarantined too",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_QUARANTINED, 0, 1), 1);

  /*
   * The interface delete callback is the only site that clears the bit, and
   * after it the index is a fresh interface with no declaration: a reused
   * sw_if_index must not inherit the previous Pod's status (D-31). The
   * predicate is what makes that state safe to re-enter — a bare index reads
   * exactly like the host TAP again, which is correct, because nothing has
   * said otherwise yet.
   */
  expect ("a reused sw_if_index does not inherit the declaration",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_QUARANTINED, 0, 0), 0);
}

static void
check_the_coverage_term (void)
{
  /*
   * errata #34 item 196: cilium_srv6_classify_required() is the set the
   * plugin's classify coverage counts and that
   * cilium_srv6_guard_context_install_allowed() requires to be fully covered.
   *
   * It is the two declaration terms and not has_local_ep. An endpoint implies
   * the feature (the retention term above), but it must not imply a *coverage
   * obligation*: the obligation has to be derivable from the declaration
   * alone, because 196's whole point is that the obligation exists before any
   * endpoint does — that is the state run 16 was in when it forwarded Pod
   * traffic with LocalEndpointTable 0.
   */
  expect ("a bound interface is a coverage obligation",
	  cilium_srv6_classify_required (CILIUM_SRV6_TRUST_QUARANTINED, 1), 1);

  expect ("an UNTRUSTED interface is a coverage obligation",
	  cilium_srv6_classify_required (CILIUM_SRV6_TRUST_UNTRUSTED, 0), 1);

  expect ("the host TAP is not a coverage obligation",
	  cilium_srv6_classify_required (CILIUM_SRV6_TRUST_QUARANTINED, 0), 0);

  expect ("a fabric uplink is not a coverage obligation",
	  cilium_srv6_classify_required (CILIUM_SRV6_TRUST_TRUSTED_FABRIC, 0), 0);

  /*
   * Everything required is wanted. Without this the coverage counter could
   * demand a feature the refresh would never install, and the node would sit
   * NOT_READY forever with nothing able to fix it.
   */
  {
    u32 trust;
    int pod, ep;

    for (trust = 0; trust < CILIUM_SRV6_TRUST_N; trust++)
      for (pod = 0; pod < 2; pod++)
	for (ep = 0; ep < 2; ep++)
	  {
	    checks++;
	    if (cilium_srv6_classify_required (trust, pod) &&
		!cilium_srv6_classify_wanted (trust, ep, pod))
	      {
		fprintf (stderr, "FAIL required but not wanted at trust %u pod %d ep %d\n", trust,
			 pod, ep);
		failures++;
	      }
	  }
  }

  printf ("ok   every coverage obligation is a feature the refresh installs\n");
}

static void
check_it_is_monotone (void)
{
  /*
   * Neither input can turn the feature off on its own. This is the property
   * the two callers rely on to be able to call the refresh unconditionally
   * from either event without ordering them.
   */
  u32 trust;
  int pod;

  for (trust = 0; trust < CILIUM_SRV6_TRUST_N; trust++)
    for (pod = 0; pod < 2; pod++)
      {
	int without_ep = cilium_srv6_classify_wanted (trust, 0, pod);
	int with_ep = cilium_srv6_classify_wanted (trust, 1, pod);

	if (with_ep < without_ep)
	  {
	    fprintf (stderr, "FAIL monotone in has_local_ep at trust %u pod %d\n", trust, pod);
	    failures++;
	  }
	checks++;
      }

  printf ("ok   the predicate is monotone in has_local_ep\n");

  /* And in pod_facing, which is what makes the sticky bit safe: nothing that
     happens after the binding ADD can take the feature away while the
     interface lives. */
  {
    int ep;

    for (trust = 0; trust < CILIUM_SRV6_TRUST_N; trust++)
      for (ep = 0; ep < 2; ep++)
	{
	  int undeclared = cilium_srv6_classify_wanted (trust, ep, 0);
	  int declared = cilium_srv6_classify_wanted (trust, ep, 1);

	  if (declared < undeclared)
	    {
	      fprintf (stderr, "FAIL monotone in pod_facing at trust %u ep %d\n", trust, ep);
	      failures++;
	    }
	  checks++;
	}
  }

  printf ("ok   the predicate is monotone in pod_facing\n");

  /* QUARANTINED must stay the fail-safe zero value (03 §1.1): a
     zero-initialised trust map entry must not read as Pod-facing. */
  expect ("QUARANTINED is 0", (int) CILIUM_SRV6_TRUST_QUARANTINED, 0);
}

int
main (void)
{
  check_the_run_16_state ();
  check_the_interfaces_that_must_stay_off ();
  check_the_dead_man_switch_case ();
  check_the_binding_is_the_declaration ();
  check_the_declaration_is_sticky ();
  check_the_coverage_term ();
  check_it_is_monotone ();

  printf ("\n%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
