# bgp-controller

Central reconciler for `EgressPolicy` v1alpha1.

## What it does

For each `EgressPolicy` it watches:

1. **Resolve `<color, endpoint>`** to an upstream + segment list using the operator-supplied controller config (`--config`).
2. **Allocate a per-tenant egress VIP** from the named Calico `IPPool` (`spec.egress.egressIPPool`).
3. **Distribute the SR Policy** over BGP (Color Extended Community, RFC 9012 §3.4.2) so the headend (pod node) can install the SR steering.
4. **Update status**: `egressIP` / `activeEndpoint` / `upstream` / `srPolicy.{bsid,color,segmentList}` / `conditions[type=Ready]`.

On delete: withdraws the BGP route, releases the VIP, removes the finalizer.

## Build & run

```sh
go build -o bin/bgp-controller ./srv6egress/cmd/bgp-controller
./bin/bgp-controller \
  --config srv6egress/config/controller/controller-config.example.yaml \
  --metrics-bind-address :8080 \
  --health-probe-bind-address :8081
```

Run with `KUBECONFIG` pointing to the target cluster, or deploy as a Kubernetes `Deployment` (manifest is TBD — see #12 follow-up).

## v1alpha1 stubs (to be replaced)

| Component | v1alpha1 | Production replacement |
|---|---|---|
| VIP allocator | `vipalloc.NewInMemory()` — counter-based synthetic VIPs | Calico IPAM client backed by `IPPool` |
| BGP distributor | `bgp.NewLoggingStub()` — logs only | gobgp client emitting Color Extended Community |

These are TODOs marked at the bottom of `srv6egress/internal/vipalloc/allocator.go` and `srv6egress/internal/bgp/distributor.go`.

## Architecture references

- Design: ryskn/vpp-dataplane-research#5
- Color = intent: [RFC 9256 §2.1](https://www.rfc-editor.org/rfc/rfc9256#section-2.1)
- Color Extended Community mechanism: [RFC 9012 §3.4.2](https://www.rfc-editor.org/rfc/rfc9012)
- Operator-side abstraction necessity (defense): #5 §0.3
