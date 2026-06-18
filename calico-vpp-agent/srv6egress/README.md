# calico-vpp-agent/srv6egress

Per-node integration of the `EgressPolicy` CRD with calico-vpp-agent.

This package gives a node two roles, both driven by `EgressPolicy` and both
opt-in behind the `SRv6Enabled` + `SRv6EgressEnabled` feature gates:

- **Headend** (pod node): watch `EgressPolicy`, resolve the selector to local
  pods, and install an SR steering entry per (local pod × destination CIDR) into
  the pod's per-pod VRF, pointing at the resolved SR Policy's BSID.
- **Egress gateway / Border Router** (gateway node): when the node is the
  policy's resolved endpoint, provision the per-tenant gateway data path
  (decap + SNAT, optional backbone stitch) and advertise the tenant SID over BGP.

Both are wired into the agent's main lifecycle in
`calico-vpp-agent/cmd/calico_vpp_dataplane.go` (no longer a skeleton).

## Layout

```
calico-vpp-agent/srv6egress/
├── doc.go          package documentation
├── types.go        VPPInterface seam, SteeringRequest, policyState
├── watcher.go      EgressPolicy CRD watcher (controller-runtime informer)
├── resolver.go     node-scoped pod + namespace cache; selector → local pod IPv6s
├── manager.go      headend coordinator: (pod × dst) install set + reconcile diff
├── gateway.go      GatewayManager: endpoint-side provisioning + VRF allocation
├── gateway_vpp.go  VPPGateway: End.DT6.In + per-fib SNAT + inter-VRF stitch (CLI)
└── gateway_bgp.go  BGPSIDAdvertiser: advertise the tenant SID for cluster reach
```

The CNI server implements `VPPInterface` (it owns the local pod cache → per-pod
`V6VrfID`), so headend steering is scoped to the matched pod's VRF.

## Headend reconcile model

```
EgressPolicy / pod / ns event ─► Watcher / Resolver ─► Manager.ReconcileAll
                                  └─ recompute (local pod × dst CIDR) install set
                                     └─ diff vs previous → InstallSteering / RemoveSteering
```

A policy is steered only after the bgp-controller sets
`status.conditions[type=Ready,status=True]` and populates `status.srPolicy.bsid`
(`manager.go` gates on this). A periodic `ReconcileAll` (30s, driven from
`calico_vpp_dataplane.go`) retries installs that failed because the SR Policy —
distributed asynchronously over BGP — had not yet landed in VPP when the event
fired. Egress errors are isolated (logged and retried, never returned) so a
transient API/watch error cannot tear down the node agent.

## Egress gateway (Border Router) provisioning

Activated only on a node configured with upstream→VRF tables
(`CalicoVppSrv6.EgressUpstreamTables`); idle elsewhere. Per tenant the
`GatewayManager` provisions, in a dedicated VRF (base `EgressVrfBase`,
default 1000):

- a loopback (so IPv6 features attach), with cnat-snat enabled on it,
- `sr localsid <tenantSID> behavior end.dt6.in <loopback>` — decap then
  re-inject into `ip6-input` so the cnat SNAT arc runs on the inner packet,
- per-fib SNAT: pod source → tenant VIP (`fib == rfib ==` tenant VRF),
- inter-VRF routes: tenant default → upstream VRF (forward) and VIP/128 bounce
  (return), stitched via `ip6-lookup-in-table`.

`End.DT6.In` and per-fib cnat SNAT are private local VPP patches (0006 / 0007),
CLI-only in our build, so the gateway path is driven via `RunCli`. The tenant
SID is advertised over BGP (`BGPSIDAdvertiser`) so headend nodes can route the
SR-encapsulated packet to this gateway. The backbone (BR) leg — RFC 9252 VIP
service routes + Color — is announced by the bgp-controller, not here.

## References

- Design: see srv6egress/docs/ (architecture diagrams + testbed runbook)
- Pattern reference: PR projectcalico/vpp-dataplane#1028 (`steerNodeIPViaSID`)
