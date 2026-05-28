# calico-vpp-agent/srv6egress

Per-node integration of the `EgressPolicy` CRD with calico-vpp-agent.

This package watches `EgressPolicy` resources, decides which steering entries
should be installed locally (based on local pod membership and the BGP-side
SR Policy state), and delegates the install/remove to the existing
`connectivity.SRv6Provider` via the `VPPInterface` seam.

## Layout

```
calico-vpp-agent/srv6egress/
├── doc.go         package documentation
├── types.go       VPPInterface, SteeringRequest, policyState
├── manager.go     Manager: per-node coordinator + reconcile diff
├── watcher.go     EgressPolicy CRD watcher (controller-runtime client)
└── README.md      this file
```

## Reconcile model

```
EgressPolicy event ──► Watcher ──► Manager.OnPolicyUpdate
                                   └─ recomputes (pod × dst) install set
                                      └─ diff vs previous → InstallSteering / RemoveSteering
```

A policy is acted on only after `status.conditions[type=Ready,status=True]` is
set by the bgp-controller and `status.srPolicy.bsid` is populated. Until then
the manager defers (`policy not yet Ready; deferring`).

## Wire-up (TODO — next PR)

This skeleton is **not** yet wired into the agent's main lifecycle. To complete
the integration:

1. In `calico-vpp-agent`'s main bootstrap (alongside other watchers), construct:
   ```go
   vpp := newSRv6EgressVPPAdapter(srv6Provider)   // wraps connectivity.SRv6Provider
   mgr := srv6egress.NewManager(log, vpp)
   w, _ := srv6egress.NewWatcher(log, cfg, mgr)
   t.Go(func() error { return w.Watch(t) })
   ```
2. Add a `srv6EgressVPPAdapter` in `calico-vpp-agent/connectivity/srv6_egress_adapter.go`
   that implements `VPPInterface.InstallSteering` / `RemoveSteering` by calling
   `AddSRv6Steering` / `DelSRv6Steering` against `common.PodVRFIndex`, mirroring
   the pattern of `steerNodeIPViaSID` (PR #1028).
3. Plug in the local pod cache (felix/policy uses `WorkloadEndpoint` watches —
   we can reuse that) into `Manager.computeDesiredInstalls`, replacing the
   current `return nil` placeholder.

## References

- Design: ryskn/vpp-dataplane-research#5 §3 / §9
- Pattern reference: PR projectcalico/vpp-dataplane#1028 (`steerNodeIPViaSID`)
