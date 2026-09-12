/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cilium Authors
 *
 * SRv6 Endpoint Context v1 — interface trust classification values and the
 * predicate that decides which interfaces carry cilium-srv6-classify.
 *
 * Both live in a vlib-free header for the same reason the bounded header walk
 * does (cilium_srv6_gparse.h): the predicate is a pure function of
 * (trust, "does this interface have a LocalEndpointTable entry"), so it can be
 * checked on the host without vlib, vnet or plugin state
 * (test/classify-scope).
 *
 * Design references:
 *   design/detail/02-headend-dataplane.md §1 (headend graph), §3 (classify)
 *   design/detail/03-destination-dataplane.md §1.1 (trust classes)
 *   design/detail/00-overview.md §2 (D-31, D-35, D-50, D-73, D-80), §2.20.1
 *   errata #34 item 191
 */

#ifndef __included_cilium_srv6_classify_scope_h__
#define __included_cilium_srv6_classify_scope_h__

#include <vppinfra/clib.h>

/*
 * Interface trust classification (03 §1.1, D-31, authority in D-73).
 *
 * QUARANTINED must stay 0: every zero-initialised or not-yet-classified
 * interface has to be fail-safe.
 *
 * UNTRUSTED is the classification D-73 derives from a D-68/D-71 Pod
 * attachment binding, so "trust == UNTRUSTED" is the plugin's only
 * authoritative statement that an interface is Pod-facing in the sense of
 * 02 §3. It is not inferred from the device class: a host TAP and a fabric
 * uplink awaiting classification are both QUARANTINED, not UNTRUSTED.
 */
typedef enum
{
  CILIUM_SRV6_TRUST_QUARANTINED = 0,
  CILIUM_SRV6_TRUST_UNTRUSTED = 1,
  CILIUM_SRV6_TRUST_TRUSTED_FABRIC = 2,
  CILIUM_SRV6_TRUST_N,
} cilium_srv6_trust_t;

/*
 * Which interfaces must carry cilium-srv6-classify (errata #34 item 191).
 *
 * 02 §1 makes the headend graph start at the Pod interface — pod-if -> guard
 * -> classify -> ct -> program — and 02 §3 defines what classify does when
 * the LocalEndpointTable has no entry for (rx_sw_if_index, rx_if_incarnation):
 *
 *     endpoint = LocalEndpointTable[(rx_sw_if_index, rx_if_incarnation)]
 *     if (!endpoint) -> drop (DROP_UNKNOWN_SOURCE_EP)
 *
 * That branch is only reachable if the feature is on the interface. Enabling
 * it from srv6_local_ep_add_del alone made the branch unreachable in exactly
 * the state it describes: a Pod-facing interface with no endpoint kept the
 * guard but not classify, so its packets left the ip6-unicast arc into
 * ip6-lookup and were forwarded by the plain IPv6 FIB with no policy
 * evaluation (Stage 0 run 16, N5 stall after a VPP restart: LocalEndpointTable
 * 0, ProgramCache 0, all drop reasons 0, same-node Pod-to-Pod ping 10/10).
 * 00 §2.20.1 invariant (2) forbids that outcome directly: the packet "MUST
 * traverse the same guard, classify, conntrack and ProgramCache chain a remote
 * destination traverses", and LOCAL_DELIVER "is a compiler/program action,
 * never a bypass to plain VPP forwarding".
 *
 * Hence the two terms:
 *
 *   trust == UNTRUSTED   the interface is Pod-facing on the authority of D-73,
 *                        so 02 §3 applies to it from that moment, endpoint or
 *                        no endpoint. This is the term that closes item 191.
 *
 *   has_local_ep         an interface that still has an endpoint keeps
 *                        classify even when its classification is taken away.
 *                        D-35 requires the dead-man switch to retain existing
 *                        ACTIVE delivery while it quarantines everything that
 *                        is not TRUSTED_FABRIC; dropping classify there would
 *                        not stop that traffic, it would hand it to the plain
 *                        FIB — the same fail-open, triggered by the mechanism
 *                        meant to contain a compromise.
 *
 * Everything else is deliberately excluded. Enabling classify on every
 * non-fabric interface would put it on the host TAP (03 §1.1 / D-58), which
 * has no LocalEndpointTable entry by construction, and would therefore drop
 * all host-originated and hostNetwork Pod traffic — including the agent's own
 * IF-2/IF-3 and BGP sessions.
 */
static inline int
cilium_srv6_classify_wanted (u32 trust, int has_local_ep)
{
  return (trust == CILIUM_SRV6_TRUST_UNTRUSTED) || (has_local_ep != 0);
}

#endif /* __included_cilium_srv6_classify_scope_h__ */
