# srv6egress

EgressPolicy CRD — **BGP-driven SRv6 Egress Path Steering** for Kubernetes on Calico-VPP.

This directory is an experimental add-on to Calico-VPP for declarative,
per-tenant SR-TE egress path selection. Design is documented in the
architecture diagrams, design notes and testbed runbook under srv6egress/docs/.

## What

`EgressPolicy` is a cluster-scoped CRD that lets cluster operators say:

> "Traffic from namespace/pod label X, destined to CIDR Y, should exit via
> egress gateway Z with path intent **color C**."

It is **NAT-less L3VPN**: the pod source address is preserved end to end — no
per-tenant VIP and no SNAT. The egress gateway decaps the tenant SID with a
stock `End.DT6` into a dedicated per-tenant VRF and forwards to the upstream VRF.

Color follows [RFC 9256 §2.1](https://www.rfc-editor.org/rfc/rfc9256#section-2.1):

> *"The color is an unsigned non-zero 32-bit integer value that associates the
> SR Policy with an intent or objective (e.g., low latency)."*

The bgp-controller resolves `<color, endpoint>` to a concrete segment list and
distributes the SR Policy over BGP; the agent on the pod node (headend) installs
the SR steering in VPP, and the agent on the egress gateway provisions the
`End.DT6` decap + inter-VRF L3VPN data path.

### Backbone stitching (Border Router capability)

The single `v1` API delivers two composable capabilities through one EgressPolicy
CRD: cluster egress (SR Policy steering + `End.DT6` L3VPN termination), and
optional **backbone stitching** — the egress gateway bridges the cluster SR
domain to an operator/upstream SRv6 backbone by terminating each tenant into a
per-upstream VRF (routes learned from the upstream peer by vpp-route-sync). The
controller announces the **cluster pod CIDR** to each upstream once at startup
(`AdvertiseClusterReturn`) so return traffic finds its way back into the cluster
SRv6 fabric. It is opt-in via the controller config's `backbone:` section, not a
separate API version or mode.

The per-upstream tenant SID is a classic `End.DT6`, or a **uSID** (`uDT6` via the
v2 localsid API) when that upstream's locator plan is uSID — selectable per
upstream in the controller config.

## Layout

```
srv6egress/
├── apis/v1/                     # Go types + DeepCopy (EgressPolicy)
│   ├── groupversion_info.go
│   ├── types.go
│   └── zz_generated.deepcopy.go
├── cmd/
│   ├── bgp-controller/                # central reconciler (resolve + SR Policy / cluster-return announce)
│   └── vpp-route-sync/                # program upstream-learned routes into the GW's per-VRF FIBs
├── internal/
│   ├── bgp/                           # gobgp distributors: SR Policy SAFI, colored route, RFC 9252 service
│   ├── config/                        # controller config (upstreams, colors, SID mode, backbone)
│   ├── controller/                    # EgressPolicy reconciler (resolve → distribute) + cluster-return
│   └── routesync/                     # vpp-route-sync internals (govpp / vppctl backends)
├── config/
│   ├── crd/bases/                     # CRD manifest
│   ├── rbac/                          # ClusterRoles for controller + agent
│   ├── controller/                    # controller-config example
│   └── routesync/                     # routesync example
├── docs/                              # architecture diagrams, design notes, testbed runbook
├── examples/                          # example EgressPolicy YAML
└── README.md
```

The per-node agent integration lives in `calico-vpp-agent/srv6egress/`.

## Quick install (CRD only)

```sh
kubectl apply -f srv6egress/config/crd/bases/srv6egress.ryskn.io_egresspolicies.yaml
kubectl apply -f srv6egress/config/rbac/role.yaml
kubectl apply -f srv6egress/examples/tenant-a-via-isp-a.yaml
kubectl get egresspolicies   # ← shows Color / Upstream / Endpoint / Ready columns
```

The CRD installs cleanly on its own; a policy object sits with empty status
until the bgp-controller reconciles it and the calico-vpp-agent (with the
`SRv6Enabled` + `SRv6EgressEnabled` feature gates) programs the data path.

## Status

| Component | Status |
|---|---|
| EgressPolicy CRD + schema (v1) | implemented |
| bgp-controller (gobgp SR Policy SAFI 73, default production) | implemented |
| bgp-controller cluster-return announce (per-upstream pod-CIDR, RFC 9252) | implemented (config-gated by `backbone:`) |
| calico-vpp-agent headend steering | implemented (gate: `SRv6EgressEnabled`) |
| calico-vpp-agent egress gateway provisioning (NAT-less `End.DT6` L3VPN, classic + uSID) | implemented (on nodes with upstream→VRF tables) |
| vpp-route-sync (program upstream FIB routes into the GW) | implemented |
| routesync: build SR policies from *received* RFC 9252 service routes | designed, disabled (`serviceBsidBlock` commented out) |
| HA endpoint, dual-stack, PathProfile CRD | future |

The gateway data path uses **only stock vpplink calls** — there are no private
VPP patches. (Earlier VIP/SNAT prototypes relied on local `End.DT6.In` /
per-fib-SNAT patches; the NAT-less L3VPN model removed that dependency.)

## Regenerating the deepcopy

`zz_generated.deepcopy.go` is hand-authored in this bootstrap. To regenerate
with controller-gen once it is installed:

```sh
controller-gen object paths=./srv6egress/apis/v1/...
controller-gen crd paths=./srv6egress/apis/v1/... output:crd:dir=./srv6egress/config/crd/bases
```

## Scope (v1)

- IPv6 single-stack
- Color steering (RFC 9256), color semantics defined by bgp-controller config
- **NAT-less L3VPN**: pod source preserved end to end (no VIP, no SNAT)
- Per-upstream SID encoding: classic `End.DT6` or `uSID` (`uDT6`)
- Single egress endpoint (HA = future work)
- Optional Border Router mode: inter-domain SR-TE bridging to an upstream SRv6
  backbone (controller `backbone:` config), with a shared per-upstream
  cluster-return aggregate

Future work: PathProfile CRD, dual-stack, HA endpoints, and the reverse
routesync direction (installing SR policies from received service routes).
