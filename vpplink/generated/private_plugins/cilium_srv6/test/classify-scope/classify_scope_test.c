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
 *   cilium_srv6_classify_wanted(), which is a pure function of the D-73
 *   classification and of whether the interface has a local endpoint, and
 *   which is checked here the way the D-85 fence is checked in ../hotpath:
 *   compiled against the byte-level stubs of ../fuzz/stub, with no vlib, no
 *   vnet and no plugin state.
 *
 * What it cannot check
 *
 *   That the two callers actually call it. Those are
 *   cilium_srv6_local_ep_add_del() and cilium_srv6_acl_interface_set(), both
 *   of which need vlib; they reach it through
 *   cilium_srv6_headend_classify_refresh() and are named here so a reviewer
 *   can check them by name. The same goes for the third site, the interface
 *   delete callback, which retires the feature so a reused sw_if_index cannot
 *   inherit it (D-31).
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
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_UNTRUSTED, 0), 1);

  expect ("a Pod-facing interface with an endpoint is on the headend path",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_UNTRUSTED, 1), 1);
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
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_QUARANTINED, 0), 0);

  /* D-31: a fabric uplink can never be Pod-facing and never has an endpoint. */
  expect ("a fabric uplink stays off",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_TRUSTED_FABRIC, 0), 0);
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
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_QUARANTINED, 1), 1);

  /*
   * The symmetric case is the pre-191 rule, kept only as a lower bound: an
   * endpoint always implies classify, whatever the classification is. It is
   * what makes the predicate monotone in has_local_ep, so no trust transition
   * can take the feature away from an interface that is delivering.
   */
  expect ("an endpoint alone is enough, whatever the classification",
	  cilium_srv6_classify_wanted (CILIUM_SRV6_TRUST_TRUSTED_FABRIC, 1), 1);
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

  for (trust = 0; trust < CILIUM_SRV6_TRUST_N; trust++)
    {
      int without_ep = cilium_srv6_classify_wanted (trust, 0);
      int with_ep = cilium_srv6_classify_wanted (trust, 1);

      if (with_ep < without_ep)
	{
	  fprintf (stderr, "FAIL monotone in has_local_ep at trust %u\n", trust);
	  failures++;
	}
      checks++;
    }

  printf ("ok   the predicate is monotone in has_local_ep\n");

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
  check_it_is_monotone ();

  printf ("\n%d checks, %d failures\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
