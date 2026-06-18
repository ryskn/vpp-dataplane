// Package srv6egress integrates the EgressPolicy CRD into calico-vpp-agent.
// It is opt-in behind the SRv6Enabled + SRv6EgressEnabled feature gates and is
// wired into the agent lifecycle in cmd/calico_vpp_dataplane.go.
//
// A node plays one or both of two roles:
//
// Headend (pod node): the agent watches EgressPolicy resources and steers when
//   - a matching pod exists on this node (selector → local pod), AND
//   - the bgp-controller has distributed the SR Policy and marked the policy
//     Ready with status.srPolicy.bsid populated.
// It then installs an SR steering entry in the pod's per-pod VRF for the pod
// source / destination CIDR pair, pointing at the SR Policy's BSID. This is
// the same mechanism as `steerNodeIPViaSID` (PR #1028) but driven by an
// EgressPolicy selector instead of node-to-node reachability.
//
// Egress gateway / Border Router (endpoint node): when this node is the
// policy's resolved endpoint, GatewayManager provisions the per-tenant data
// path — a dedicated VRF with End.DT6.In decap, per-fib cnat SNAT (pod → VIP),
// and inter-VRF stitch to the upstream VRF — and advertises the tenant SID over
// BGP for cluster reachability. End.DT6.In and per-fib SNAT are private local
// VPP patches (0006/0007), so this path is driven via CLI. The backbone (BR)
// leg — RFC 9252 VIP service routes + Color — is announced by the
// bgp-controller, not by the agent.
//
// Design notes: see srv6egress/docs/.
package srv6egress
