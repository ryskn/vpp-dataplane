// Package srv6egress integrates the EgressPolicy CRD into calico-vpp-agent.
//
// On each node, the agent watches EgressPolicy resources and reacts when:
//   - A matching pod exists on this node (selector → local pod), AND
//   - The bgp-controller has distributed the corresponding SR Policy
//     (color + endpoint + segment list) via BGP, AND
//   - The agent's SRv6Provider has the resolved SR Policy ready.
//
// The agent then installs an SR steering entry in VPP's PodVRFIndex (table 2)
// for the pod source / destination CIDR pair, pointing at the SR Policy's
// BSID. This is conceptually the same mechanism used by `steerNodeIPViaSID`
// (PR #1028) but driven by an EgressPolicy selector instead of node-to-node
// reachability.
//
// v1alpha1 scope (this skeleton):
//   - Type definitions and Manager state machine
//   - Watcher entrypoint (controller-runtime informer-driven)
//   - VPPInterface seam for SR steering install/remove (production wires this
//     to the existing connectivity.SRv6Provider)
//
// Out of scope for this PR (follow-up wiring):
//   - main() integration in calico-vpp-agent's lifecycle
//   - Correlation with BGP-received SR Policy in SRv6Provider
//
// Design notes: see srv6egress/docs/.
package srv6egress
