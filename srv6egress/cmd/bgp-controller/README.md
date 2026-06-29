# bgp-controller

Central reconciler for the `EgressPolicy` CRD (`srv6egress.ryskn.io/v1`).

## What it does

It is **NAT-less L3VPN**: no per-tenant VIP is allocated and no SNAT is
configured; the pod source address is preserved end to end.

For each `EgressPolicy` it watches:

1. **Resolve `<color, endpoint>`** to an upstream + segment list using the operator-supplied controller config (`--config`).
2. **Distribute the SR Policy** over BGP. Default encoding is SR Policy SAFI 73 (full segment list in the Tunnel Encapsulation attribute, so the headend installs the policy and steers on its BSID); `--bgp-encoding=color-route` falls back to a colored IPv6 /128 + Color Extended Community (RFC 9012 §3.4.2).
3. **Update status**: `activeEndpoint` / `upstream` / `srPolicy.{bsid,color,segmentList,endpointAddr}` / `conditions[type=Ready]`.

Separately, once at startup (not per policy), when the config has a `backbone:`
section the controller **announces the cluster pod CIDR to each upstream**
(`AdvertiseClusterReturn`) as an RFC 9252 service route (the upstream's End SID
+ SID structure + the backbone Color Ext-Community). This shared per-upstream
*cluster-return* aggregate lets the upstream/backbone route return traffic
(dst = pod IP) back into the cluster SRv6 fabric. It is not tied to any single
policy and is not recorded in policy status.

On delete: withdraws the policy's BGP SR Policy route and removes the finalizer.
(No VIP to release; the per-upstream cluster-return is a startup announce, not a
per-policy one.)

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
| `--bgp-backend` | `gobgp` — real gRPC to a local gobgp | `stub` — logs the UPDATEs only |
| `--bgp-encoding` | `sr-policy` — SR Policy SAFI 73 | `color-route` — colored /128 + Color Ext-Comm |

The backbone leg uses one gobgp service distributor per `backbone.peers` entry
(the per-VRF gobgp on the egress GW that holds the eBGP session to the PE); it is
wired only when `backbone:` is present in the config, and carries the
per-upstream cluster-return announce above.

## Architecture references

- Design: see srv6egress/docs/
- Color = intent: [RFC 9256 §2.1](https://www.rfc-editor.org/rfc/rfc9256#section-2.1)
- Color Extended Community mechanism: [RFC 9012 §3.4.2](https://www.rfc-editor.org/rfc/rfc9012)
- BGP services over SRv6 (backbone return): [RFC 9252](https://www.rfc-editor.org/rfc/rfc9252)
