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

1. terminates the cluster SRv6 path (a stock `End.DT6` decap into a dedicated
   per-tenant VRF),
2. forwards **NAT-less (L3VPN)** to the upstream VRF — the pod source address is
   preserved end to end (no VIP, no SNAT); tenants are isolated by VRF, and
3. optionally acts as a **Border Router** that stitches the cluster SR domain to
   an operator SRv6 backbone (RFC 9252 service routes + RFC 9012 Color Extended
   Community), keeping the *intent (color)* continuous end-to-end. A shared
   per-upstream *cluster-return* aggregate carries return traffic back into the
   cluster SRv6 fabric.

Two orthogonal layers:

- **color (SR-TE)** selects *which path / upstream* to egress through;
- **per-VRF eBGP** resolves *the route within that path* — mirroring a carrier PE.

## Diagrams (open with diagrams.net / draw.io)

| file | what |
|---|---|
| `current-architecture.drawio` | as-built lab data path: headend SR-encap → GW stock `End.DT6` decap into per-tenant VRF → NAT-less (L3VPN) forward to upstream, with symmetric return (some diagrams may still show the earlier VIP/SNAT prototype) |
| `school-lab-architecture.drawio` | minimal testbed: 2 servers + 1 whitebox switch (switch as L2/L3 underlay) |
| `hw-fabric-underlay.drawio` | switch as a hardware L3-ECMP underlay; SRv6 endpoints stay in software (VPP / FRR+kernel) |
| `full-feature-testbed.drawio` | full-feature testbed: 2 tenants × 2 colors × backbone, with the feature→test matrix |
| `two-spine-clos.drawio` | 2-spine CLOS variant (multi-spine ECMP + fabric failover; needs a 2nd switch) |
| `backbone-lo-stitch.drawio` | tenant-VRF × path-VRF stitch model (loopback as the stitch anchor) |

`testbed-runbook.md` is the concrete build runbook for `full-feature-testbed`:
per-tier config (spine SONiC / leaf FRR / egress-GW VPP+gobgp / PE·P
FRR+kernel SRv6), AS + address + SID plan, bring-up order, and the
feature→verification matrix.

`motivation*.pptx` / `motivation_script.md` are background slides on the
problem framing.

## Data-plane note

The egress gateway uses **only stock vpplink calls** — no private VPP patches.
Per tenant it installs, in a dedicated per-tenant VRF:

- a stock **`End.DT6`** localsid for the tenant SID — decap straight into the VRF
  FIB (no loopback, no SNAT; the pod source is preserved = L3VPN). Per upstream
  this can instead be a **`uDT6`** uSID via the v2 localsid API.
- an inter-VRF default route from the tenant VRF to the shared **upstream VRF**
  (the routes learned from the upstream peer by `vpp-route-sync`), and
- an optional shared **cluster-return** aggregate in the upstream VRF: the
  cluster pod CIDR → `lookup-in-table` the cluster VRF, so return traffic
  (dst = pod IP) re-enters the cluster SRv6 fabric.

An earlier VIP/SNAT prototype relied on local `End.DT6.In` + per-fib-cnat-SNAT
patches; the NAT-less L3VPN model removed that dependency.

## Standards

RFC 8402 (Segment Routing) · RFC 8986 (SRv6 network programming) ·
RFC 9256 (SR Policy / color) · RFC 9252 (BGP services over SRv6) ·
RFC 9012 (SR Policy SAFI / Color Extended Community) ·
RFC 9087 (BGP egress peer engineering).
