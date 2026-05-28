# srv6egress

EgressPolicy CRD v1alpha1 — **BGP-driven SRv6 Egress Path Steering** for Kubernetes on Calico-VPP.

This directory contains the research add-on to Calico-VPP for declarative,
per-tenant SR-TE egress path selection. Design documented in
[ryskn/vpp-dataplane-research#5](https://github.com/ryskn/vpp-dataplane-research/issues/5).

## What

`EgressPolicy` is a cluster-scoped CRD that lets cluster operators say:

> "Traffic from namespace/pod label X, destined to CIDR Y, should exit via
> egress gateway Z with path intent **color C**, SNAT'd to a per-tenant VIP."

Color follows [RFC 9256 §2.1](https://www.rfc-editor.org/rfc/rfc9256#section-2.1):

> *"The color is an unsigned non-zero 32-bit integer value that associates the
> SR Policy with an intent or objective (e.g., low latency)."*

The bgp-controller resolves `<color, endpoint>` to a concrete segment list and
distributes the SR Policy over BGP; the agent on the pod node (headend)
installs the SR steering in VPP.

## Layout

```
srv6egress/
├── apis/v1alpha1/                     # Go types + DeepCopy
│   ├── doc.go                         # (collapsed into types.go)
│   ├── groupversion_info.go
│   ├── types.go
│   └── zz_generated.deepcopy.go
├── config/
│   ├── crd/bases/                     # CRD manifest
│   │   └── srv6egress.ryskn.io_egresspolicies.yaml
│   └── rbac/                          # ClusterRoles for controller + agent
│       └── role.yaml
├── examples/                          # Example EgressPolicy YAML
│   └── tenant-a-via-isp-a.yaml
└── README.md
```

## Quick install (validation only — no controller/agent yet)

```sh
kubectl apply -f srv6egress/config/crd/bases/srv6egress.ryskn.io_egresspolicies.yaml
kubectl apply -f srv6egress/config/rbac/role.yaml
kubectl apply -f srv6egress/examples/tenant-a-via-isp-a.yaml
kubectl get egresspolicies   # ← shows Color / Upstream / EgressIP columns
```

The CRD installs cleanly without controller/agent; the policy object will sit
with empty status until the controller (Task #28) reconciles it.

## Status

| Component | Issue | Status |
|---|---|---|
| CRD types & schema | #11 | **this PR** |
| bgp-controller VM skeleton | #12 | next |
| calico-vpp-agent EgressPolicy hook | #13 | after #12 |
| Verification environment (sim-ISP, etc.) | #6 - #10 | deferred (needs infra) |
| v1alpha2 PoC (backbone integration) | #14 | optional / future |

## Regenerating the deepcopy

`zz_generated.deepcopy.go` is hand-authored in this bootstrap. To regenerate
with controller-gen once it is installed:

```sh
controller-gen object paths=./srv6egress/apis/v1alpha1/...
controller-gen crd paths=./srv6egress/apis/v1alpha1/... output:crd:dir=./srv6egress/config/crd/bases
```

## Scope (v1alpha1)

- IPv6 single-stack
- Color steering (RFC 9256), color semantics defined by bgp-controller config
- Per-tenant IPv6 egress VIP allocated from a Calico IPPool (`allowedUses: [Tunnel]`)
- Single egress endpoint (HA = future work)
- SNAT to VIP is mandatory (not a CRD field)

Out of scope here (future): PathProfile CRD, no-SNAT mode, dual-stack,
inter-domain SR-TE via RFC 9252 services SAFI (= v1alpha2 backbone
integration).
