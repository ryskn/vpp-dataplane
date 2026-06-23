# bgp-controller

Central reconciler for the `EgressPolicy` CRD (`srv6egress.ryskn.io/v1`).

## What it does

For each `EgressPolicy` it watches:

1. **Resolve `<color, endpoint>`** to an upstream + segment list using the operator-supplied controller config (`--config`).
2. **Allocate a per-tenant egress VIP** from the named Calico `IPPool` (`spec.egress.egressIPPool`).
3. **Distribute the SR Policy** over BGP. Default encoding is SR Policy SAFI 73 (full segment list in the Tunnel Encapsulation attribute, so the headend installs the policy and steers on its BSID); `--bgp-encoding=color-route` falls back to a colored IPv6 /128 + Color Extended Community (RFC 9012 §3.4.2).
4. **(BR mode, optional)** When the config has a `backbone:` section, also announce the VIP toward the SRv6 backbone as an **RFC 9252 service route** (the gateway's own End SID + the backbone Color Ext-Community) on the per-upstream GW↔PE eBGP session. The announce intent is persisted in `status.backbone` *before* announcing (persist-then-announce), so it is idempotent and survives controller restarts.
5. **Update status**: `egressIP` / `activeEndpoint` / `upstream` / `srPolicy.{bsid,color,segmentList,endpointAddr}` / `backbone.{prefix,endSID,color,upstream,nexthop}` / `conditions[type=Ready, type=BackboneAdvertised]`.

On delete: withdraws the BGP route(s) — including the backbone service route, using the persisted `status.backbone` so withdraw works across restarts — releases the VIP, removes the finalizer. On startup, every VIP already recorded in an `EgressPolicy` status is re-registered into the allocator before reconciling (`RehydrateVIPs`), so a restart never double-allocates.

## Build & run

```sh
go build -o bin/bgp-controller ./srv6egress/cmd/bgp-controller
./bin/bgp-controller \
  --config srv6egress/config/controller/controller-config.example.yaml \
  --metrics-bind-address :8080 \
  --health-probe-bind-address :8081
```

Run with `KUBECONFIG` pointing to the target cluster, or deploy as a Kubernetes `Deployment`.

## Backends

Backends default to **production**; the stubs are an opt-in fallback for bring-up/tests.

| Flag | Default (production) | Fallback |
|---|---|---|
| `--vip-backend` | `calico` — Calico IPAM, allocates from the `IPPool` | `memory` — counter-based synthetic VIPs |
| `--bgp-backend` | `gobgp` — real gRPC to a local gobgp | `stub` — logs the UPDATEs only |
| `--bgp-encoding` | `sr-policy` — SR Policy SAFI 73 | `color-route` — colored /128 + Color Ext-Comm |

The backbone (BR) leg uses one gobgp service distributor per `backbone.peers` entry (the per-VRF gobgp on the egress GW that holds the eBGP session to the PE); it is wired only when `backbone:` is present in the config.

## Architecture references

- Design: see srv6egress/docs/
- Color = intent: [RFC 9256 §2.1](https://www.rfc-editor.org/rfc/rfc9256#section-2.1)
- Color Extended Community mechanism: [RFC 9012 §3.4.2](https://www.rfc-editor.org/rfc/rfc9012)
- BGP services over SRv6 (BR mode): [RFC 9252](https://www.rfc-editor.org/rfc/rfc9252)
