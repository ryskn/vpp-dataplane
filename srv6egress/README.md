# srv6egress

EgressPolicy CRD — **BGP-driven SRv6 Egress Path Steering** for Kubernetes on Calico-VPP.

This directory is an experimental add-on to Calico-VPP for declarative,
per-tenant SR-TE egress path selection. Design is documented in the
architecture diagrams, design notes and testbed runbook under srv6egress/docs/.

## What

`EgressPolicy` is a cluster-scoped CRD that lets cluster operators say:

> "Traffic from namespace/pod label X, destined to CIDR Y, should exit via
> egress gateway Z with path intent **color C**, SNAT'd to a per-tenant VIP."

Color follows [RFC 9256 §2.1](https://www.rfc-editor.org/rfc/rfc9256#section-2.1):

> *"The color is an unsigned non-zero 32-bit integer value that associates the
> SR Policy with an intent or objective (e.g., low latency)."*

The bgp-controller resolves `<color, endpoint>` to a concrete segment list,
allocates a per-tenant VIP, and distributes the SR Policy over BGP; the agent
on the pod node (headend) installs the SR steering in VPP, and the agent on the
egress gateway provisions the decap + per-tenant SNAT data path.

### Backbone stitching (Border Router capability)

The single `v1` API delivers two composable capabilities through one EgressPolicy
CRD: cluster egress (SR Policy steering + per-tenant VIP SNAT), and optional
**backbone stitching** — the egress gateway additionally stitches the cluster SR
domain to an operator SRv6 backbone (RFC 9252 service routes + RFC 9012 Color),
announced by the controller and recorded in `status.backbone`. It is opt-in via
the controller config's `backbone:` section, not a separate API version or mode.

## Layout

```
srv6egress/
├── apis/v1/                     # Go types + DeepCopy (EgressPolicy, incl. BackboneStatus)
│   ├── groupversion_info.go
│   ├── types.go
│   └── zz_generated.deepcopy.go
├── cmd/
│   ├── bgp-controller/                # central reconciler (VIP alloc + SR Policy / BR announce)
│   └── vpp-route-sync/                # program upstream-learned routes into the GW's per-VRF FIBs
├── internal/
│   ├── bgp/                           # gobgp distributors: SR Policy SAFI, colored route, RFC 9252 service
│   ├── config/                        # controller config (upstreams, colors, backbone)
│   ├── controller/                    # EgressPolicy reconciler
│   ├── poolvalidator/                 # IPPool (allowedUses) validation
│   ├── routesync/                     # vpp-route-sync internals (govpp / vppctl backends)
│   └── vipalloc/                      # VIP allocator (Calico IPAM / in-memory)
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
kubectl get egresspolicies   # ← shows Color / Upstream / EgressIP columns
```

The CRD installs cleanly on its own; a policy object sits with empty status
until the bgp-controller reconciles it and the calico-vpp-agent (with the
`SRv6Enabled` + `SRv6EgressEnabled` feature gates) programs the data path.

## Status

| Component | Status |
|---|---|
| EgressPolicy CRD + schema (v1, incl. `status.backbone`) | implemented |
| bgp-controller (Calico IPAM VIPs + gobgp SR Policy SAFI 73, default production) | implemented |
| bgp-controller BR mode (RFC 9252 service announce, persist-then-announce) | implemented (config-gated by `backbone:`) |
| calico-vpp-agent headend steering | implemented (gate: `SRv6EgressEnabled`) |
| calico-vpp-agent egress gateway / BR provisioning (End.DT6.In + per-fib SNAT) | implemented (on nodes with upstream→VRF tables) |
| vpp-route-sync (program upstream FIB routes into the GW) | implemented |
| routesync: build SR policies from *received* RFC 9252 service routes | designed, disabled (`serviceBsidBlock` commented out) |
| HA endpoint, dual-stack, no-SNAT mode, PathProfile CRD | future |

The gateway data path depends on two private local VPP patches under
`vpplink/generated/patches/`: **0006** (`End.DT6.In`, decap + ip6-input
re-inject) and **0007** (per-fib cnat SNAT).

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
- Per-tenant IPv6 egress VIP allocated from a Calico IPPool (`allowedUses: [Tunnel]`)
- Single egress endpoint (HA = future work)
- SNAT to VIP is mandatory (not a CRD field)
- Optional Border Router mode: inter-domain SR-TE via RFC 9252 service routes
  (controller `backbone:` config)

Future work: PathProfile CRD, no-SNAT mode, dual-stack, HA endpoints, and the
reverse routesync direction (installing SR policies from received service
routes).
