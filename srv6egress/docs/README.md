# srv6egress — design docs

Architecture diagrams and design notes for **srv6egress**, an experimental
add-on to Calico-VPP that gives Kubernetes pods *declarative, per-tenant SRv6
egress path steering*.

> This is experimental / academic work, not part of upstream Calico-VPP.

## What it does

`EgressPolicy` (a cluster-scoped CRD) lets operators express, **per tenant /
namespace**, which upstream or backbone path a pod's egress traffic should take
— declared as an SR-TE **color** (RFC 9256), not an explicit SID. The egress
gateway:

1. terminates the cluster SRv6 path (`End.DT6` decap),
2. SNATs the pod source to a **per-tenant VIP** (so tenants are isolated and the
   pod prefix is never exposed upstream), and
3. optionally acts as a **Border Router** that stitches the cluster SR domain to
   an operator SRv6 backbone (RFC 9252 service routes + RFC 9012 Color Extended
   Community), keeping the *intent (color)* continuous end-to-end.

Two orthogonal layers:

- **color (SR-TE)** selects *which path / upstream* to egress through;
- **per-VRF eBGP** resolves *the route within that path* — mirroring a carrier PE.

## Diagrams (open with diagrams.net / draw.io)

| file | what |
|---|---|
| `current-architecture.drawio` | as-built lab data path: headend SR-encap → GW `End.DT6.In` decap + per-tenant SNAT → upstream, with symmetric return |
| `school-lab-architecture.drawio` | minimal testbed: 2 servers + 1 whitebox switch (switch as L2/L3 underlay) |
| `hw-fabric-underlay.drawio` | switch as a hardware L3-ECMP underlay; SRv6 endpoints stay in software (VPP / FRR+kernel) |
| `full-feature-testbed.drawio` | full-feature testbed: 2 tenants × 2 colors × backbone, with the feature→test matrix |
| `two-spine-clos.drawio` | 2-spine CLOS variant (multi-spine ECMP + fabric failover; needs a 2nd switch) |
| `v1alpha2-lo-stitch.drawio` | tenant-VRF × path-VRF stitch model (loopback as the stitch anchor) |

`testbed-runbook.md` is the concrete build runbook for `full-feature-testbed`:
per-tier config (spine SONiC / leaf FRR / egress-GW VPP+gobgp / PE·P
FRR+kernel SRv6), AS + address + SID plan, bring-up order, and the
feature→verification matrix.

`motivation*.pptx` / `motivation_script.md` are background slides on the
problem framing.

## Data-plane note

The egress gateway relies on two local VPP behavior patches under
`vpplink/generated/patches/`:

- **`End.DT6.In`** — decap then re-inject into `ip6-input` on a chosen RX
  interface, so the IPv6 feature arc (cnat SNAT) runs on the decapsulated inner
  packet (the same composition VXLAN decap uses).
- **per-fib cnat SNAT** — makes the cnat SNAT address selectable per FIB, so each
  tenant VRF maps the pod source to its own VIP.

## Standards

RFC 8402 (Segment Routing) · RFC 8986 (SRv6 network programming) ·
RFC 9256 (SR Policy / color) · RFC 9252 (BGP services over SRv6) ·
RFC 9012 (SR Policy SAFI / Color Extended Community) ·
RFC 9087 (BGP egress peer engineering).
