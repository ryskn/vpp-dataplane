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
// Egress gateway (endpoint node): when this node is the policy's resolved
// endpoint, GatewayManager provisions the per-tenant data path — a dedicated
// per-tenant VRF, a stock End.DT6 localsid that decaps the tenant SID into that
// VRF, an inter-VRF default route from the tenant VRF to the shared upstream
// VRF, and (optionally) a shared return aggregate (cluster pod CIDR ->
// lookup-in-table the cluster VRF) — and advertises the tenant SID over BGP for
// cluster reachability. It is NAT-less L3VPN: no VIP and no SNAT; the pod source
// address is preserved end to end. The tenant SID is a classic End.DT6 or, per
// upstream, a uSID (uDT6 via the v2 localsid API). The whole path uses stock
// vpplink calls (no private VPP patches). The shared per-upstream cluster-return
// route is announced once by the bgp-controller, not by the agent.
//
// Design notes: see srv6egress/docs/.
package srv6egress
