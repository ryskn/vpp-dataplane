# Full-feature testbed — build runbook

Concrete per-tier configuration and bring-up order for the
`full-feature-testbed.drawio` topology: **2 tenants × 2 colors × 2 services**
on **Dell ×2 + DCS201 ×1**.

- tenant-a → color **100** → PE-A → **service-X**
- tenant-b → color **200** → PE-B → **service-Y**

This document is the as-designed reference. Addresses marked *(live)* match the
values already proven on the running GW; the rest are this testbed's plan.

---

## 1. Roles / physical layout

| host | runs | SR role |
|---|---|---|
| **Server-1** (Dell/Proxmox) | k8s cluster (master + worker = headend, Calico-VPP), **egress GW = BR** (VPP + patch 0006/0007), bgp-controller (infra VM), **leaf1** (FRR) | headend SR-encap; GW decap+SNAT+re-encap |
| **Server-2** (Dell/Proxmox) | **PE-A**, **PE-B**, **P** (FRR + Linux kernel seg6local), service-X, service-Y, **leaf2** (FRR) | backbone End / End.DT6 (RFC 9252 L3VPN) |
| **DCS201 / AS5835-54X** | **spine** (SONiC) | none — HW L3 ECMP **underlay** only (no SRv6 endpoint) |

The data-plane *function* split is fixed: spine/leaf only forward outer IPv6
(SID locators) at line rate; SRv6 behaviors run on VPP (GW) and kernel (PE/P).
But **every box is fully user-configured** — SONiC on the spine, FRR on the
leaves, all of it below.

---

## 2. AS plan (RFC 7938 eBGP underlay, private ASNs)

| node | ASN | role in BGP |
|---|---|---|
| spine (DCS201) | **65000** | underlay fabric, ECMP |
| leaf1 (Server-1) | **65001** | underlay leaf |
| leaf2 (Server-2) | **65002** | underlay leaf |
| egress-GW / cluster / bgp-controller | **64512** | cluster iBGP + BR overlay speaker |
| PE-A | **64500** | backbone, color100 |
| PE-B | **64600** | backbone, color200 |
| P | **64550** | backbone transit |

All adjacencies are eBGP (every link crosses an AS boundary) → enable
`bestpath as-path multipath-relax` everywhere ECMP is wanted.

---

## 3. Address plan

### Loopbacks (/128, BGP router-id + session source)

| node | loopback |
|---|---|
| spine | `fd00:ff::1` |
| leaf1 | `fd00:ff::11` |
| leaf2 | `fd00:ff::12` |
| egress-GW (BR) | `fd00:ff::a0` |
| bgp-controller | `fd00:ff::a1` |
| PE-A (Server-2) | `fd00:ff::a` |
| PE-A2 (Server-1, anycast pair) | `fd00:ff::a2` |
| PE-B | `fd00:ff::b` |
| P | `fd00:ff::c` |

> PE-A and PE-A2 are an **anycast pair**: distinct loopbacks/router-ids, but
> they share the same locator `fcbb:0:a::/48`, the same End.DT6 SID
> `fcbb:0:a:1::`, the same VRF/RT, and a co-located service-X instance.

### Fabric P2P links (underlay, /64; two per leaf for ECMP)

| link | prefix | spine side | leaf side |
|---|---|---|---|
| leaf1–spine #1 | `fd00:f1:0::/64` | `…:254` | `…:1` |
| leaf1–spine #2 | `fd00:f1:1::/64` | `…:254` | `…:1` |
| leaf2–spine #1 | `fd00:f2:0::/64` | `…:254` | `…:1` |
| leaf2–spine #2 | `fd00:f2:1::/64` | `…:254` | `…:1` |

### Server-internal links (leaf ↔ VM, /64)

| link | prefix |
|---|---|
| leaf1 ↔ GW / controller | `fd00:l1::/64` |
| leaf1 ↔ PE-A2 (anycast) | `fd00:l1:a2::/64` |
| leaf2 ↔ PE-A | `fd00:l2:a::/64` |
| leaf2 ↔ PE-B | `fd00:l2:b::/64` |
| leaf2 ↔ P | `fd00:l2:c::/64` |

### SID locators (carried in the underlay as plain IPv6 prefixes)

| owner | locator | key SID(s) |
|---|---|---|
| GW | `fcff:0:0:e0::/64` *(live)* | `fcff:0:0:e0:a::` (tenant-a End.DT6.In) · `fcff:0:0:e0:b::` (tenant-b) |
| **PE-A + PE-A2 (anycast)** | `fcbb:0:a::/48` *(advertised from both)* | End.DT6 `fcbb:0:a:1::` (color100 VRF, **anycast SID**) |
| PE-B | `fcbb:0:b::/48` | End.DT6 `fcbb:0:b:1::` (color200 VRF) |
| P | `fcbb:0:c::/48` | End `fcbb:0:c:1::` (transit) |

### Tenant / service / steering

| item | value |
|---|---|
| VIP-a (tenant-a) | `2001:db8:e:0:b91:ca7f:1e60:6840` *(live, Calico IPAM)* |
| VIP-b (tenant-b) | `2001:db8:e::b` *(IPAM-allocated; example)* |
| BSID color100 | `cafe::e0a` *(live)* |
| BSID color200 | `cafe::e0b` |
| service-X (behind PE-A) | `2001:db8:svc-x::/64` |
| service-Y (behind PE-B) | `2001:db8:svc-y::/64` |
| RT color100 | `64512:100` |
| RT color200 | `64512:200` |

---

## 4. The three BGP planes

1. **Underlay fabric (IPv6 unicast, eBGP)** — spine↔leaf1, spine↔leaf2, and
   leaf↔local-VM. Carries **loopbacks + SID locators only**. ECMP here. This is
   what makes every outer SR DA routable hop-by-hop across the DCS201.
2. **BR overlay (IPv6 VPN / RFC 9252 + 9012 Color, multihop eBGP)** —
   bgp-controller(64512) ↔ PE-A(64500) and ↔ PE-B(64600), sourced from
   loopbacks. Carries VIP /128 and service /64 as L3VPN routes with
   **per-color RT** (`64512:100` / `64512:200`) and prefix-SID. The spine/leaf
   do **not** speak this — they only carry its TCP + its SR packets as plain v6.
3. **Cluster iBGP (64512)** — Calico-VPP internal; headend↔GW reachability for
   the cluster SID. Existing Calico mechanism, not re-specified here.

**Stitch (decided):** loopback-anchor (`End.DT6.In` → `loopNNNN` → per-fib SNAT
→ `ip6-lookup-in-table`). Required for the cnat-snat feature arc to run; the
pure inter-VRF route can't SNAT.

**VIP advertise (decided):** per-color RT, each VIP a `/128` NLRI, static import
on PE. Withdraw = delete one NLRI; no PE policy churn; tenant-granular blast
radius.

---

## 5. Per-tier configuration

### 5a. spine — DCS201 / SONiC (AS65000)

SONiC runs FRR in the `bgp` container. Interfaces/IPs via `config`, BGP via
`vtysh`.

```bash
# --- interfaces (L3, no VLAN; underlay is routed) ---
config interface ip add Ethernet0  fd00:f1:0::254/64   # → leaf1 link1
config interface ip add Ethernet1  fd00:f1:1::254/64   # → leaf1 link2
config interface ip add Ethernet2  fd00:f2:0::254/64   # → leaf2 link1
config interface ip add Ethernet3  fd00:f2:1::254/64   # → leaf2 link2
config loopback add Loopback0
config interface ip add Loopback0  fd00:ff::1/128
config save -y
```

```
! vtysh — underlay eBGP, ECMP, L3 only
router bgp 65000
 bgp router-id 10.0.255.1
 no bgp ebgp-requires-policy
 bgp bestpath as-path multipath-relax
 maximum-paths 8
 neighbor LEAF peer-group
 neighbor LEAF remote-as external
 neighbor LEAF capability extended-nexthop
 neighbor LEAF bfd
 neighbor fd00:f1:0::1 peer-group LEAF
 neighbor fd00:f1:1::1 peer-group LEAF
 neighbor fd00:f2:0::1 peer-group LEAF
 neighbor fd00:f2:1::1 peer-group LEAF
 address-family ipv6 unicast
  network fd00:ff::1/128
  neighbor LEAF activate
  ! permit loopbacks + SID locators only; drop everything else
  neighbor LEAF route-map FABRIC-IN  in
  neighbor LEAF route-map FABRIC-OUT out
 exit-address-family
!
ipv6 prefix-list LOCATORS seq 10 permit fcff:0:0:e0::/64 le 128
ipv6 prefix-list LOCATORS seq 20 permit fcbb:0:a::/48  le 64
ipv6 prefix-list LOCATORS seq 30 permit fcbb:0:b::/48  le 64
ipv6 prefix-list LOCATORS seq 40 permit fcbb:0:c::/48  le 64
ipv6 prefix-list LOCATORS seq 50 permit fd00:ff::/64   le 128   ! loopbacks
route-map FABRIC-IN  permit 10
 match ipv6 address prefix-list LOCATORS
route-map FABRIC-OUT permit 10
 match ipv6 address prefix-list LOCATORS
```

The spine never sees a VIP or a service prefix — those live in the overlay VPN.
It only learns/forwards loopbacks + the four SID locators. That `LOCATORS`
prefix-list is the underlay/overlay separation, on the box you own.

### 5b. leaf — FRR (leaf1=65001, leaf2=65002)

Leaf = up-eBGP to spine (2 links → ECMP) + down-eBGP to each local SR VM,
re-advertising locators both ways.

```
! ===== leaf1 (Server-1), AS65001 =====
router bgp 65001
 bgp router-id 10.0.255.11
 no bgp ebgp-requires-policy
 bgp bestpath as-path multipath-relax
 maximum-paths 8
 ! up to spine (2 links)
 neighbor fd00:f1:0::254 remote-as 65000
 neighbor fd00:f1:1::254 remote-as 65000
 neighbor fd00:f1:0::254 bfd
 neighbor fd00:f1:1::254 bfd
 ! down to GW / controller (cluster side advertises GW BR locator)
 neighbor fd00:l1::a0 remote-as 64512
 address-family ipv6 unicast
  network fd00:ff::11/128
  neighbor fd00:f1:0::254 activate
  neighbor fd00:f1:1::254 activate
  neighbor fd00:l1::a0  activate
 exit-address-family
```

```
! ===== leaf2 (Server-2), AS65002 =====
router bgp 65002
 bgp router-id 10.0.255.12
 no bgp ebgp-requires-policy
 bgp bestpath as-path multipath-relax
 maximum-paths 8
 neighbor fd00:f2:0::254 remote-as 65000
 neighbor fd00:f2:1::254 remote-as 65000
 neighbor fd00:f2:0::254 bfd
 neighbor fd00:f2:1::254 bfd
 ! down to backbone SR nodes (each owns a locator)
 neighbor fd00:l2:a::a remote-as 64500   ! PE-A
 neighbor fd00:l2:b::b remote-as 64600   ! PE-B
 neighbor fd00:l2:c::c remote-as 64550   ! P
 address-family ipv6 unicast
  network fd00:ff::12/128
  neighbor fd00:f2:0::254 activate
  neighbor fd00:f2:1::254 activate
  neighbor fd00:l2:a::a activate
  neighbor fd00:l2:b::b activate
  neighbor fd00:l2:c::c activate
 exit-address-family
```

leaf1's south side learns `fcff:0:0:e0::/64` from the cluster/GW BGP (this is the
existing "advertise gateway tenant SID over BGP" path, commit `543bec18`) and
re-advertises it up. leaf2 learns `fcbb:0:a/b/c` from PE-A/PE-B/P.

### 5c. egress-GW = Border Router (Server-1)

Two parts: the **overlay control plane** (bgp-controller, gobgp) and the
**dataplane** (GW VPP, the live restore commands, one instance per tenant).

**Overlay — bgp-controller (gobgp, AS64512), multihop eBGP to both PEs:**

```yaml
# controller-config.yaml (excerpt — see config/controller/controller-config.example.yaml)
backbone:
  localAS: 64512
  routerID: fd00:ff::a1
  peers:
    - name: pe-a
      address: fd00:ff::a       # PE-A loopback (multihop over fabric)
      remoteAS: 64500
      ebgpMultihop: 8
    - name: pe-b
      address: fd00:ff::b
      remoteAS: 64600
      ebgpMultihop: 8
  colorMap:
    100: { rt: "64512:100", vip: "VIP-a", prefixSID: "fcff:0:0:e0:a::" }
    200: { rt: "64512:200", vip: "VIP-b", prefixSID: "fcff:0:0:e0:b::" }
```

Controller advertises each VIP/128 with its color RT + prefix-SID (GW's own SID,
which doubles as the return End.DT6.In SID); it imports service-X/-Y from the PEs
and hands them to routesync to program GW VPP.

**Dataplane — GW VPP, tenant-a (matches the live restore):**

```
create loopback interface instance 1000
set interface ip6 table loop1000 1000
set interface ip address loop1000 fd6e::3e8/64
set interface feature loop1000 cnat-snat-ip6 arc ip6-unicast
sr localsid address fcff:0:0:e0:a:: behavior end.dt6.in loop1000
set cnat snat-policy addr 2001:db8:e:0:b91:ca7f:1e60:6840 fib 16 rfib 16
ip route add ::/0 table 1000 via ip6-lookup-in-table 100
ip route add 2001:db8:e:0:b91:ca7f:1e60:6840/128 table 100 via ip6-lookup-in-table 1000
```

**tenant-b** is the same shape on a second loopback/stitch VRF, sharing the
backbone path VRF (table 100):

```
create loopback interface instance 1001
set interface ip6 table loop1001 1001
set interface ip address loop1001 fd6e::3e9/64
set interface feature loop1001 cnat-snat-ip6 arc ip6-unicast
sr localsid address fcff:0:0:e0:b:: behavior end.dt6.in loop1001
set cnat snat-policy addr <VIP-b> fib <idx-100> rfib <idx-100>
ip route add ::/0 table 1001 via ip6-lookup-in-table 100
ip route add <VIP-b>/128 table 100 via ip6-lookup-in-table 1001
```

> ⚠️ `fib`/`rfib` take a **FIB index, not a table-id** (`show ip6 fib` to read
> the index for table 100; the live value was `16`). Passing a table-id here
> crashes VPP.

The backbone path VRF (table 100) carries the SR-encap routes that routesync
installs from the 9252 service routes:

```
# (programmed by routesync, shown as equivalent CLI)
ip route add 2001:db8:svc-x::/64 table 100 via srv6 encap [fcbb:0:c:1::, fcbb:0:a:1::]  # color100 → P → PE-A
ip route add 2001:db8:svc-y::/64 table 100 via srv6 encap [fcbb:0:c:1::, fcbb:0:b:1::]  # color200 → P → PE-B
```

Destination decides the segment list → color is carried by *which* PE SID the
list ends at. tenant isolation is the per-loopback SNAT; color steering is the
re-encap.

### 5d. PE / P — FRR + Linux kernel SRv6 (Server-2)

**PE-A (AS64500, color100):** underlay up to leaf2; overlay VPN to controller;
one service VRF importing RT `64512:100`.

```
segment-routing
 srv6
  locators
   locator PE_A
    prefix fcbb:0:a::/48 block-len 40 node-len 24 func-bits 16
!
router bgp 64500
 bgp router-id 10.0.255.10
 no bgp ebgp-requires-policy
 neighbor fd00:l2:a::a remote-as 65002          ! underlay up to leaf2
 neighbor fd00:ff::a1  remote-as 64512          ! overlay VPN to controller
 neighbor fd00:ff::a1  ebgp-multihop 8
 neighbor fd00:ff::a1  update-source PE_A_lo
 segment-routing srv6
  locator PE_A
 address-family ipv6 unicast
  network fcbb:0:a::/48                          ! locator into underlay
  network fd00:ff::a/128                          ! loopback
  neighbor fd00:l2:a::a activate
 exit-address-family
 address-family ipv6 vpn
  neighbor fd00:ff::a1 activate
 exit-address-family
!
router bgp 64500 vrf vrf-c100
 address-family ipv6 unicast
  redistribute connected                          ! service-X/64 lives here
  sid vpn export auto                             ! installs End.DT6 fcbb:0:a:1::
  rd vpn export 64500:100
  rt vpn both 64512:100                            ! per-color RT (static import)
 exit-address-family
```

```bash
# service-X attached in the VRF
ip link add vrf-c100 type vrf table 100
ip link set vrf-c100 up
ip link set <svc-x-veth> master vrf-c100
ip -6 addr add 2001:db8:svc-x::1/64 dev <svc-x-veth>
```

**PE-B (AS64600, color200):** identical with `fcbb:0:b::/48`, End.DT6
`fcbb:0:b:1::`, vrf-c200/table 200, RT `64512:200`, service-Y.

**P (AS64550, transit End):** underlay only, plain kernel seg6local.

```bash
ip -6 addr add fd00:ff::c/128 dev lo
ip -6 route add fcbb:0:c:1:: encap seg6local action End dev <up-dev>
```
```
router bgp 64550
 no bgp ebgp-requires-policy
 neighbor fd00:l2:c::c remote-as 65002
 address-family ipv6 unicast
  network fcbb:0:c::/48
  network fd00:ff::c/128
  neighbor fd00:l2:c::c activate
 exit-address-family
```

### 5e. Anycast service-X — PE-A2 on Server-1 (AS64500)

service-X is made **anycast** by standing up a second PE instance (PE-A2) on
Server-1, behind leaf1. PE-A2 is identical to PE-A in everything the data plane
keys on — **same locator `fcbb:0:a::/48`, same End.DT6 SID `fcbb:0:a:1::`, same
`vrf-c100`/RT `64512:100`** — and hosts its own service-X echo instance. Only
its loopback/router-id and its underlay uplink (leaf1, not leaf2) differ.

```
segment-routing
 srv6
  locators
   locator PE_A
    prefix fcbb:0:a::/48 block-len 40 node-len 24 func-bits 16   ! SAME prefix as PE-A
!
router bgp 64500
 bgp router-id 10.0.255.162                  ! distinct router-id
 no bgp ebgp-requires-policy
 neighbor fd00:l1:a2::1 remote-as 65001      ! underlay UP to leaf1 (not leaf2)
 neighbor fd00:ff::a1   remote-as 64512      ! overlay VPN to controller
 neighbor fd00:ff::a1   ebgp-multihop 8
 neighbor fd00:ff::a1   update-source PE_A2_lo
 segment-routing srv6
  locator PE_A
 address-family ipv6 unicast
  network fcbb:0:a::/48                       ! same locator, advertised from Server-1 too
  network fd00:ff::a2/128
  neighbor fd00:l1:a2::1 activate
 exit-address-family
 address-family ipv6 vpn
  neighbor fd00:ff::a1 activate
 exit-address-family
!
router bgp 64500 vrf vrf-c100
 address-family ipv6 unicast
  redistribute connected                      ! service-X/64 (second echo instance)
  sid vpn export auto                          ! installs the SAME anycast End.DT6 fcbb:0:a:1::
  rd vpn export 64500:1002                     ! distinct RD (so both VPN routes survive in BGP)
  rt vpn both 64512:100                         ! same per-color RT
 exit-address-family
```

leaf1 gains one neighbor:

```
! add under leaf1 (AS65001)
 neighbor fd00:l1:a2::a remote-as 64500
 address-family ipv6 unicast
  neighbor fd00:l1:a2::a activate
 exit-address-family
```

**How the anycast resolves (and why the GW is untouched):**

- Both PE-A and PE-A2 inject `fcbb:0:a::/48` into the underlay — from leaf2 and
  leaf1 respectively. The **spine sees two equal-cost paths to `fcbb:0:a::/48`**
  and HW-ECMPs (this is why `multipath-relax` + `maximum-paths` matter).
- The GW still SR-encaps to the single SID `fcbb:0:a:1::`. The **fabric** picks
  the nearest live instance. The GW config in §5c does not change at all.
- **Failover** = withdraw one PE's locator (shut its uplink, or stop FRR): the
  underlay reconverges to the surviving instance in BFD time; the GW never
  notices. This is *fabric-resolved* service resilience.
- The distinct RD keeps both service-X VPN routes visible at the controller (so
  you can see two origins), while the shared anycast SID means it doesn't matter
  which the GW resolves — both lead to `fcbb:0:a:1::`.

> **Variant — overlay (BGP) multipath instead of underlay anycast:** give each
> PE a *distinct* End.DT6 SID (`fcbb:0:a:1::` / `fcbb:0:a2:1::`) and enable
> add-path/`maximum-paths` at the controller→GW VPN session. The GW then installs
> **two** SR-encap paths and flow-hashes between them; failover is BGP-withdraw
> driven and visible at the GW (`show` two SR paths). Use this if you want the
> resilience in the overlay and per-flow split observable on the GW rather than
> in the fabric. The two approaches can also be combined.

> **service-Y stays single-homed** (PE-B only) on purpose, as the contrast: an
> anycast service (X) vs a single-homed one (Y). Making Y anycast too is a
> mechanical mirror (PE-B2 on Server-1, shared `fcbb:0:b::/48` / `fcbb:0:b:1::`).

> **Placement note:** PE-A2 lives on Server-1 (the cluster host) so the *spine*
> ECMPs the anycast locator across two leaves — the full HW-ECMP-of-anycast
> demo. If you'd rather not run a backbone PE on the cluster host, co-locate
> PE-A2 on Server-2 instead: the anycast still works, but the split happens at
> **leaf2** (two down-links) and the spine sees a single path — a weaker but
> simpler ECMP story.

---

## 6. Bring-up order

1. **Cable + interfaces.** Bring up all P2P links; confirm IPv6 link-local +
   configured /64s ping across each physical link.
2. **Underlay BGP.** spine ↔ leaf1/leaf2, then leaf ↔ local VMs. Verify each
   node's loopback + the four SID locators appear on every other node:
   `show bgp ipv6 unicast` / `vtysh -c "show ipv6 route fcbb:0:a::/48"`.
   From GW, `ping fcbb:0:a:1::` and `ping fd00:ff::a` must cross the DCS201.
3. **ECMP check.** From leaf1, `show ipv6 route fd00:ff::12/128` should list two
   next-hops (both spine links). `traceroute`/counters confirm spread.
4. **Backbone SRv6.** On PE-A/PE-A2/PE-B confirm the End.DT6 SID is installed
   (`ip -6 route show | grep seg6local`); on P the End SID. From GW,
   `ping fcbb:0:a:1::` reaches a PE-A instance. On the **spine**,
   `show ipv6 route fcbb:0:a::/48` must list **two** next-hops (via leaf1 and
   leaf2) — that is the anycast locator being ECMP'd.
5. **Overlay VPN.** Start bgp-controller; bring up multihop eBGP to PE-A/PE-B.
   Verify on PE-A: `show bgp ipv6 vpn` shows VIP-a/128 (RT 64512:100) imported
   into vrf-c100; on the controller, service-X/64 imported under color100.
6. **GW dataplane.** Apply the loop1000/loop1001 + End.DT6.In + per-fib SNAT +
   stitch routes; let routesync install the service SR-encap routes in table 100.
7. **Cluster + headend.** Deploy EgressPolicy (tenant-a/color100,
   tenant-b/color200); confirm `Ready=True`, BSID/SR policy installed on the
   worker, steering present (`show sr steering-policies`).
8. **End-to-end.** From a tenant-a pod, `ping 2001:db8:svc-x::1` and a TCP
   fetch; from tenant-b, `service-Y`. Trace both legs (decap→SNAT→fabric→PE→svc
   and the symmetric return).

---

## 7. Verification matrix (what proves each feature)

| feature | how to show it |
|---|---|
| headend SR steering | `show sr steering-policies` on worker; pod→cluster SID encap in trace |
| color path selection | tenant-a hits PE-A/service-X, tenant-b hits PE-B/service-Y (different SR list) |
| End.DT6.In decap | `show trace` on GW: srv6-localsid → ip6-input(loop100X) |
| per-tenant SNAT isolation | trace shows src podIP→VIP-a (tenant-a) vs →VIP-b (tenant-b), distinct VIPs |
| VIP auto-alloc + advertise | Calico IPAM VIP; `show bgp ipv6 vpn` on PE has VIP/128 |
| per-color RT | PE-A imports only `64512:100`, PE-B only `64512:200` |
| BR 9252 + Color continuity | VIP/service carry prefix-SID + color end-to-end |
| HW ECMP underlay | two next-hops on leaf→spine; counters split across links |
| anycast service SID | spine has 2 paths to `fcbb:0:a::/48`; both PE-A/PE-A2 echo counters move; GW config unchanged |
| anycast failover | stop one PE-A instance → underlay reconverges (BFD), pod→service-X flow survives, GW never notices |
| fabric failover | drop one spine↔leaf link → BFD/eBGP reconverge, flow survives |
| path failover | add P1/P2 (anycast `fcbb:0:c::/48`) or eBGP withdraw → reroute |
| dynamic CRUD | create/update/delete EgressPolicy → controller → agent reconcile |
| return symmetry | service→VIP→(un-SNAT)→pod, stateful for ICMP + TCP |

---

## 8. Failover demos (two independent layers)

- **Underlay (fabric):** shut one `leaf↔spine` link. BFD drops the session,
  ECMP/eBGP reconverges onto the surviving link. Long-running pod→service flow
  keeps going. This is DC-fabric-level resilience, distinct from SR.
- **Overlay (SR/path):** withdraw a PE's locator (or use P1/P2 anycast and shut
  one P). The SR path reroutes / the SR Policy falls to a backup candidate-path.
- **Service anycast (§5e):** stop the PE-A instance the flow currently lands on
  (shut its uplink or stop FRR). The anycast locator `fcbb:0:a::/48` reconverges
  to the surviving instance; the pod→service-X flow keeps going with **no GW or
  controller change** — resilience resolved entirely in the fabric/underlay.

All three can be shown in the same environment without reconfig — the point of
the multi-plane design.

> Single-spine caveat: with one DCS201 the *fabric failover* demo is link-level
> (two leaf↔spine links), not spine-node-level. True multi-spine ECMP + spine
> failure needs a 2nd switch — see `two-spine-clos.drawio` (future work).
