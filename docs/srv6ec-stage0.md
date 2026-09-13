# SRv6 Endpoint Context — Stage 0 deployment

This document describes the vpp-dataplane half of the Stage 0 test bed for the
SRv6 Endpoint Context v1 design: what it deploys, how the images are made
reproducible, and what is known to be missing or unresolved.

Stage 0 is defined in Issue #21 and Issue #135 of the Cilium fork. Its purpose
is not throughput and not a demonstration that packets flow. It is to establish
that:

* Cilium keeps CNI, IPAM, endpoint identity and policy authority;
* the Pod's L3 datapath is owned by VPP and by nothing else;
* the exact `(attachment_id, sw_if_index, if_incarnation)` binding is published
  by the component that created the interface, before the CNI ADD succeeds
  (D-71).

Cross-node SRv6 forwarding is explicitly *not* expected in Stage 0 or Stage 1.
The profile runs with `FabricAuthority = none`, and with no interface classified
as `TRUSTED_FABRIC` the guard drops `SRV6_BLOCK`-destined ingress on the uplink.
That is the designed behaviour, not a defect of this deployment.

## 1. Topology

```
  Kubernetes control plane
  Cilium agent (CNI, IPAM, endpoint identity, policy, srv6ec)
        |
        |  CreatePodInterface / DeletePodInterface
        |  unix:/var/run/vpp/podinterface-lifecycle.sock
        v
  +--------------------------- DaemonSet srv6ec-vpp-node ---------------------+
  |                                                                          |
  |  podinterface-lifecycle          vppapi-proxy            vpp              |
  |  (lifecycle authority)           (socat)                 (vpp-manager)    |
  |         |                            |                        |          |
  |         |  IF-2 binary API           |  IF-2 forwarded        | starts    |
  |         |  /var/run/vpp/             |  /var/run/vpp-srv6ec/  | and owns  |
  |         |  vpp-api.sock              |  vpp-api.sock          | VPP       |
  |         v                            v                        v          |
  |  +--------------------------------------------------------------------+  |
  |  |  VPP + cilium_srv6 plugin                                          |  |
  |  |  uplink (virtio)   vpptap0   Pod TUNs                              |  |
  |  +--------------------------------------------------------------------+  |
  +--------------------------------------------------------------------------+
                     ^                             ^
                     |  IF-2, via the proxy socket |  IF-3, plugin connects out
                     |  /var/run/vpp-srv6ec/       |  /run/cilium/srv6ec/
                     |  vpp-api.sock               |  punt.sock
                        Cilium agent (srv6ec)
```

The two directions are not symmetric. On IF-2 the Cilium agent is the client and
connects to a socket inside this DaemonSet — through the proxy socket rather
than VPP's own, for the reason section 4.2 gives. On IF-3 it is the other way
round: the Cilium agent binds `/run/cilium/srv6ec/punt.sock` and the
`cilium_srv6` plugin, inside the `vpp` container, connects out to it. Section
4.1 covers what that costs this manifest.

## 2. Containers

| container | image | entrypoint | what it owns |
|---|---|---|---|
| `vpp` | `calicovpp/vpp` (with `cilium_srv6_plugin.so`) | `/usr/bin/vpp-manager` | the uplink, `vpptap0`, the VPP process, the IF-3 client end |
| `podinterface-lifecycle` | `calicovpp/agent` | `/bin/podinterface-lifecycle` | Pod TUN creation and deletion, the IF-4 attachment binding, the durable lifecycle state |
| `vppapi-proxy` | `calicovpp/agent` | `socat` | the IF-2 socket the Cilium agent connects to |

Not deployed, and deliberately so: `calico-node`, Felix, Typha, the Calico CNI
installer, `calico-vpp-agent`, GoBGP. Issue #135 ruling 3 rejects making
interface creation depend on a second network control plane, so the lifecycle
service is a separate entrypoint rather than a mode of the agent: it never
reaches the Felix configuration barrier and never constructs the Calico v3
client, the BGP server, the Felix server, the connectivity/routing/service
servers, the watchers, or multinet.

### 2.1 What the lifecycle service programs, and what it does not

The pod interface drivers are shared with the Calico CNI backend, but the
*policy* — which steps run, in which order, and which subsystems are touched —
is chosen once, when the server is built, by `podinterface.LifecycleProfile`
against `podinterface.CalicoProfile`. Nothing is inferred at run time from the
pod spec or the interface name.

On a `CreatePodInterface`, in this order (Issue #135 ruling 8):

| step | side |
|---|---|
| per-pod IPv4/IPv6 VRFs, with their default route via the pod VRF | VPP |
| the per-pod loopback, in those VRFs, carrying the container addresses | VPP |
| the TUN, in those VRFs: MTU, admin up, rx mode, unnumbered to the loopback | VPP |
| `accept_ra=0`, `addr_gen_mode=none` (L3 only), addresses (`/128`), device routes, MTU, forwarding sysctls | Pod netns |
| the `/128` route to the TUN inside the pod VRF | VPP |
| strict uRPF: the RPF VRF, its routes, and the uRPF binding on the TUN | VPP |
| the IF-4 `(attachment_id, sw_if_index, if_incarnation)` binding | `cilium_srv6` |

Only then does the RPC reply — the publication barrier of D-71. Any failure
above rolls the whole thing back through the cleanup stack and fails the CNI
ADD; a Pod-side sysctl or a device route that cannot be installed is a failure,
not a warning.

#### The rescan re-applies the Pod namespace side (errata #34 item 211)

When the lifecycle service starts again it reconciles every durably stored pod
spec against a fresh VPP dump (`rescanLifecycleState`). On the branch where the
per-pod VRFs are gone — a VPP restart — the VPP interface is created again, and
the netdev the Pod network namespace then holds is not guaranteed to be the one
it had: `CreateOrAttachTapV2` creates the tun with `TAP_FLAG_PERSIST` and first
tries `TAP_FLAG_ATTACH`, so it either re-attaches to the pre-restart netdev or
creates a new one. A new netdev carries no address, no device route and default
sysctls.

**The rescan therefore runs the same Pod-namespace steps a `CreatePodInterface`
runs, from the stored pod spec** (`addresses`, `routes`, MTU, `accept_ra=0`,
`addr_gen_mode=none`, forwarding sysctls) — the row of the table above that says
"Pod netns", in the same order. Before this, the rescan re-created the VPP
interface and republished the IF-4 binding while the Pod namespace was left with
only the kernel's `fe80::`: every IPv6 Pod lost its address and its routes on
every VPP restart, and nothing above the service could see it, because the Cilium
endpoint reads Ready and the binding table reads correct (Stage 0 run 19b:
`H-1c FAIL fd00::51/128 is not configured in the Pod namespace`,
`ping: connect: Network is unreachable`, `I-6` 6 × SKIP). The same code on the
same path worked in run 18 — the difference is only whether the attach found the
pre-restart netdev, which nothing verifies and which an IPv4 deployment would
never notice.

The steps are **reconciled, not re-applied**, under `LifecycleProfile`: the
addresses and routes the namespace already has are read first, an interface that
already carries exactly the stored configuration is left untouched, a missing
address or device route is added, and a non-link-scope address the stored pod
spec does not name is removed rather than left beside the right one — D-50 makes
the attachment L3-only, so the interface carries exactly the addresses the CNI
decided. Routes that are installed and not stored are left alone: the kernel put
them there. The kernel's link-local address is also left alone; it is present on
a healthy Pod interface too, because VPP brings the host side of the tun up when
it creates it and the address is generated before `addr_gen_mode=none` is
written, which prevents further generation rather than removing what exists. An
observation that cannot be taken is a failure, not an empty observation — acting
on an empty one would delete every address the interface has.

The resulting order on the rescan path is the order of the table above: create
the tun → VPP-side configuration (VRF, MTU, admin up) → the Pod-namespace L3
configuration → VPP-side routing and uRPF → the IF-4 binding ADD, acknowledged
→ the attachment is recorded and the durable state persisted. The D-71 binding
is published only after the Pod side is configured, and a Pod-side failure fails
the reconciliation of that attachment and leaves the service not ready rather
than publishing a binding for an interface that cannot carry traffic.

Errata #34 item 203 — creating the TUN administratively down, publishing the
binding, and only then bringing it up — is **not** done here: `InterfaceAdminUp`
sits inside `DoPodInterfaceConfiguration`, which the memif driver and the Calico
CNI backend also call, so moving it would change paths outside the lifecycle
create and rescan. It would also not close the window it appears to close: VPP
sets the *host* side of the tun up when it creates it
(`vnet_netlink_set_link_state (tif->ifindex, 1)` in VPP's tap plugin),
independently of the VPP-side admin state.

What it deliberately does **not** program, because Cilium owns NAT, policy and
services in this profile and Calico's CNAT is not deployed at all:

| not programmed | why |
|---|---|
| `cnat_snat_policy_add_del_if`: both the SNAT policy and the `CNAT_POLICY_POD` registration | Calico's NAT dataplane. Under `LifecycleProfile` the driver holds a CNAT policy object that has no VPP handle, so the call does not exist to be made — it is not made and then tolerated |
| `cnat_enable_disable_feature`: the NAT feature arcs on the pod interface | same |
| host port CNAT translations | Calico's service dataplane; host ports are out of the v1 scope (Issue #135 ruling 2) |
| redirect-to-host classify tables | Calico punt configuration. This profile never installs it on the ADD side, so the DEL side must not detach it either |
| Calico policy, workload endpoints, BGP or route announcements | there is no Calico control plane here; the pod events the shared code publishes have no subscriber |

Before this was gated, every `CreatePodInterface` on the Stage 0 node failed
with `cnatSnatPolicyAddDelIf … VPPApiError: Feature disabled by configuration
(-30)` (Issue #21, BLOCKER-7). The SNAT enable was already skipped through
`common.NoSNATPolicy`, but the CNAT registration and the feature arcs still ran
unconditionally. The rollback was correct — no interface and no binding leaked —
so the failure was clean, but the ADD never succeeded.

### 2.2 Readiness

The `podinterface-lifecycle` container reports ready on `/readiness` once VPP,
`vpp-manager` and the lifecycle service itself have reported initialized
(`health.PodInterfaceLifecycleComponents`). Felix and the Calico agent are not
in that set: this entrypoint never starts them, and requiring them kept the
probe at 503 for a service that works (errata #34 item 128). The
`calico-vpp-agent` entrypoint keeps its four-component set unchanged.

The lifecycle component reports itself *not* initialized, and the container
reports unhealthy, when the durable lifecycle state cannot be interpreted
exactly (Issue #135 ruling 4). See section 3.

## 3. Sockets, host paths and state

| path | kind | producer | consumer |
|---|---|---|---|
| `/var/run/vpp/vpp-api.sock` | unix socket, VPP-created (0660 in a 0755 dir) | VPP `socksvr` | `podinterface-lifecycle`, `vppapi-proxy` |
| `/var/run/vpp-srv6ec/vpp-api.sock` | unix socket, 0600 in a 0700 dir | `vppapi-proxy` | Cilium agent (IF-2) |
| `/run/cilium/srv6ec/punt.sock` | unix socket, 0600 in a 0700 dir | Cilium agent (IF-3 listener) | the `cilium_srv6` plugin in the `vpp` container |
| `/var/run/vpp/podinterface-lifecycle.sock` | unix socket, gRPC | `podinterface-lifecycle` | Cilium CNI plugin |
| `/var/run/vpp/vppmanagerinfofile` | file | `vpp-manager` | `podinterface-lifecycle` (uplink MTU) |
| `/var/run/vpp/calicovpp_state.v12.json` | file | `podinterface-lifecycle` | itself, across restarts |
| `/var/run/vpp/cli.sock` | unix socket | VPP | `vppctl` / `calivppctl` |

hostPath volumes of the DaemonSet:

| volume | host path | why |
|---|---|---|
| `vpp-rundir` | `/var/run/vpp` | the sockets and the durable lifecycle state above |
| `srv6ec-if2-rundir` | `/var/run/vpp-srv6ec` | the proxied IF-2 socket; a hostPath because the Cilium agent Pod mounts the same directory |
| `cilium-run` | `/run/cilium` | the parent of the IF-3 punt socket the Cilium agent binds, mounted into the `vpp` container only. `DirectoryOrCreate`, and deliberately not the socket's own directory — section 4.1 |
| `vpp-data` | `/var/lib/vpp` | VPP core files |
| `vpp-config` | `/etc/vpp` | generated `startup.conf` / `startup.exec` |
| `netns` | `/run/netns` | Pod network namespaces, mounted `Bidirectional` |
| `devices` / `hostsys` / `lib-firmware` / `host-root` | `/dev`, `/sys`, `/lib/firmware`, `/` | uplink driver binding, as in the Calico profile |

Note on durability: the lifecycle state file lives under `/var/run/vpp`, which
on most distributions is a tmpfs. It therefore survives a container restart and
an agent restart — which is what the D-71 rescan and the E2E 7 case need — but
not a node reboot. A node reboot is a clean dataplane reset in this profile
(VPP's interfaces are gone too), so the two are consistent, but a test that
expects state to survive a reboot is testing something this profile does not
provide.

## 4. The sockets between the Cilium agent and VPP

Two of the interfaces of the design cross the boundary between the Cilium agent
Pod and this DaemonSet, in opposite directions. IF-3 (4.1) is the punt/reinject
transport, where the plugin dials the agent. IF-2 (4.2) is the VPP binary API,
where the agent dials VPP.

### 4.1 The IF-3 punt socket and the `/run/cilium` mount

The `cilium_srv6` plugin is the **client** on IF-3. The Cilium agent binds
`/run/cilium/srv6ec/punt.sock` (`pkg/srv6ec/cell.DefaultPuntSocket`, the default
of `--srv6-punt-socket`), creating the `srv6ec` directory 0700 root and the
socket 0600 root, and authorises every accepted connection by `SO_PEERCRED`
against `--srv6-punt-allowed-uids`. In the Stage 0 profile that list is `[0]`.
The plugin reads the path it dials from its own startup stanza:

```
cilium-srv6 {
    punt-socket /run/cilium/srv6ec/punt.sock
}
```

`cilium-srv6` is the stanza the plugin registers with
`VLIB_CONFIG_FUNCTION (cilium_srv6_config, "cilium-srv6")` in
`cilium_srv6_guard.c`; the value has to equal the agent's
`--srv6-punt-socket`. This kit creates no state for IF-3 and starts no process
for it: the connection is opened by the plugin from inside VPP, it is one-way
client-connect with reconnect (the plugin retries; nothing here supervises it),
and a socket that is not there yet is not an error for this DaemonSet.

**Peer credential.** What the agent authenticates on IF-3 is the UID of the VPP
process itself — not a proxy's, as it is on IF-2. The `vpp` container sets no
`runAsUser`, `vpp-manager/images/ubuntu/Dockerfile` sets no `USER`, and the VPP
startup configuration sets no `unix { uid ... }`, so VPP runs as UID 0 and
matches the `[0]` in `--srv6-punt-allowed-uids`. Adding any of those three would
break IF-3 at accept time, which is why the manifest says so at the
`securityContext`. UID 0 is required twice over, in fact: the socket's
directory is 0700 root, so only root can traverse it to reach the socket at
all, and the peer credential check then decides whether the connection is
served. The directory mode is a layer; the credential check is the authority.

**Which directory is mounted, and why not the obvious one.** The plugin needs
`/run/cilium/srv6ec/punt.sock` to resolve inside the `vpp` container. The
manifest mounts the **parent**, `/run/cilium`, with `type: DirectoryOrCreate`.
The two narrower alternatives were rejected for concrete reasons:

* **`hostPath: /run/cilium/srv6ec`, `type: DirectoryOrCreate`** — the kubelet
  would create that directory 0755 root before the agent ever looks at it. The
  agent's `compiler.secureSocketDir` only chmods a directory *it* created; a
  pre-existing one is left exactly as it is and merely produces a warning, by
  the ruling of Issue #21 decision 6 (errata #34 item 121: the agent must not
  narrow directories it does not own). So the kit would silently downgrade the
  0700 contract of the dedicated runtime directory to 0755 — a change to a
  security property, made invisibly, by a deployment kit. The socket's 0600 mode
  and the peer-credential check would still hold, but the directory layer of
  00 §4.1 would be gone and nothing would fail to announce it.
* **`hostPath: /run/cilium/srv6ec`, `type: Directory`** — correct on mode, wrong
  on ordering. This DaemonSet has to be able to start before the Cilium agent,
  because the agent Pod mounts the IF-2 proxy directory that this DaemonSet's
  `vppapi-proxy` container creates, and it mounts it with `type: Directory`
  (section 7). Requiring here a directory that only exists once the agent has
  run would put the two Pods on either side of each other's precondition.

Mounting the parent avoids both. It does not weaken anything either, because
`/run/cilium` on a Cilium node is already created by the kubelet and not by the
agent: Cilium's own `cilium-run` volume is `hostPath: /var/run/cilium`,
`type: DirectoryOrCreate`, and the daemon's `os.MkdirAll(RunDir,
defaults.RuntimePathRights)` is a no-op on a directory that exists. Whichever of
the two Pods lands on the node first, `/run/cilium` ends up 0755 root. The agent
never changes that parent's mode, deliberately: `secureSocketDir` creates
parents only when they are missing and chmods none of them, which is the same
errata 121 rule seen from the other side. `/run/cilium` and
`/var/run/cilium` (Cilium's `daemon.runPath` default) are the same directory:
`/var/run` is a symlink to `/run` on systemd hosts. The manifest uses the
`/run/cilium` spelling on both sides of the mount so that the container path is
the socket path the plugin is configured with, with no symlink hop.

Two consequences worth stating rather than discovering:

1. **No mount propagation is needed.** The agent creates `srv6ec` as a plain
   subdirectory inside a directory the bind mount already shares, not as a new
   mount point, so it appears in the container as soon as it exists on the host.
   `mountPropagation` would only matter if the agent mounted something there.
2. **The mount is read-write and grants nothing new.** The `vpp` container is
   `privileged` and already mounts the host root at `/host`; `/run/cilium` is
   reachable from there whether or not this volume exists. The volume exists so
   the configured path resolves, not to grant access. The plugin only ever
   `connect(2)`s; it creates nothing under this mount.

**Version coupling.** The `punt-socket` key exists only in a `cilium_srv6`
snapshot that implements the IF-3 transport. An older snapshot's config parser
answers ``unknown input `punt-socket ...'``, which is a `clib_error` from a
`VLIB_CONFIG_FUNCTION` and therefore aborts VPP startup, and the DaemonSet
crash-loops. That is fail-closed and loud, but it means the ConfigMap and the
digest-pinned VPP image have to move together — the pin in
`vpplink/generated/private_plugins/CILIUM_SRV6_SOURCE_COMMIT` is what says
which plugin tree an image was built from.

### 4.2 The IF-2 socket proxy

`pkg/srv6ec/vppapi.VerifySocketPath` in the Cilium fork requires the VPP binary
API socket to be a Unix domain socket owned by an accepted UID, with no access
for group or other, inside a directory with the same ownership rule and mode
`0700`. That is the deployment contract of 00 §4.1 (D-27). VPP creates its
socket mode 0660 in `/var/run/vpp`, which is mode 0755, so the agent refuses it
and no IF-2 connection is established.

`chmod` on VPP's own socket is not a fix. VPP recreates the socket on every
start, and E2E 6 restarts VPP on purpose, so the fix would be undone by the
very test it has to survive.

Stage 0 therefore puts a forwarding proxy in a directory this profile owns
(Issue #21 ruling T-6). Three consequences, all of them intended:

1. The listening socket and its directory are created once, by a container
   whose lifetime is independent of VPP's, so a VPP restart does not change the
   socket the agent is configured with.
2. Killing the `vppapi-proxy` container breaks the IF-2 transport without
   touching VPP. That is exactly the E2E 5 fault: the agent must observe a
   transport reconnect with an unchanged `plugin_instance_id` and an unchanged
   `context_epoch`, as distinct from the E2E 6 fault where the
   `plugin_instance_id` changes.
3. The peer credential the agent reads belongs to `socat`, not to VPP.

Point 3 is a real trust delta and is stated rather than hidden. `transport.go`
already documents that the peer credential proves the UID of the process on the
other end and never that the process is VPP, so the check keeps exactly the
meaning it claims; what changes is that the process at the far end of the
accepted connection is one hop away. Both processes are root in the same Pod on
a test bed, which is why this is acceptable here. It is not an answer to the
production socket-mode question, which is open in Issue #60 section A.

Forwarding bytes is sufficient for the binary API. The adapter the Cilium agent
dials with is govpp's `socketclient`, which carries the whole API as a
length-prefixed message stream over a `SOCK_STREAM` socket and passes no file
descriptors — there is no `SCM_RIGHTS` and no shared-memory segment handshake in
`vendor/go.fd.io/govpp/adapter/socketclient`. A byte-forwarding proxy therefore
preserves the protocol. This does not generalise to VPP API clients that use the
shared-memory transport.

### 4.3 `SRV6_BLOCK` is configured explicitly, and the two sides are gated on equality

The same `cilium-srv6` stanza carries `srv6-block`, the plugin's `SRV6_BLOCK`
(D-60):

```
cilium-srv6 {
    punt-socket /run/cilium/srv6ec/punt.sock
    srv6-block fdbb:bb00::/32
}
```

It is written out rather than left to the plugin's default, because the plugin's
default is a **test** default. `cilium_srv6_guard.h` names the constant
`CILIUM_SRV6_BLOCK_TEST_DEFAULT_*` and the header says why it exists: a plugin
brought up with no startup configuration still needs a block of known extent,
since a zero-length block would make the guard's `dst in SRV6_BLOCK` comparison
match every address and drop everything on every interface. It is not a value a
deployment may use. `show cilium srv6 guard` distinguishes the two cases:

```
SRV6_BLOCK           : fdbb:bb00::/32 (configured)
SRV6_BLOCK           : fdbb:bb00::/32 (TEST DEFAULT, not configured)
```

Stage 0 runs 16 and 17 produced the second line. Nothing failed, because the
Cilium agent's `--srv6-block` happened to carry the same `fdbb:bb00::/32` — the
two sides agreed by coincidence, and a change to either one alone would have
produced a silent disagreement in which the agent allocates and advertises SIDs
out of one block while the guard polices another (errata #34 item 198).

**Single source of truth.** The agent's value and VPP's value live in two
repositories and cannot be read out of one file. The declared source of truth is
the Cilium chart value `srv6EndpointContext.block`
(`test/srv6ec/stage0/values-stage0.yaml`, rendered into the `srv6-block` key of
the `cilium-config` ConfigMap). The `srv6-block` line above is an explicit
parameter of this kit that restates it, with the same Stage 0 default. What
makes the restatement safe is not discipline but a gate: `check-i.sh` in the
Cilium kit asserts, on every run,

* **I-0a** — the running plugin reports `(configured)`, not
  `(TEST DEFAULT, not configured)`;
* **I-0b** — the prefix the plugin reports is exactly the agent's
  `--srv6-block`.

so a divergence between the two repositories is a FAIL of the run that observes
it rather than something that has to be noticed by eye. Write the address in the
canonical lower-case compressed form that VPP's `format_ip6_address` prints,
because that is the form I-0b compares.

From the plugin snapshot that carries errata 198 on, an unconfigured block also
makes `context install` report `BLOCKED`: the readiness predicate that gates
Context and local SID installation requires a configured block, so a node
running without this line forwards plainly and installs no SRv6 state at all.

## 5. Image reproducibility

Issue #135 ruling 6 requires an immutable identity for the VPP image, derived
from three commits, and the digest to be recorded with the test result.

### Tag derivation

`scripts/srv6ec-image-tag.sh` produces

```
vpp-<VPP upstream commit:12>-dp-<vpp-dataplane commit:12>-srv6-<cilium_srv6 commit:12>
```

for example

```
vpp-e84849bcdb70-dp-fbc3b15557e1-srv6-b37d8847c03f
```

The three inputs:

| input | where it is read | why it is authoritative |
|---|---|---|
| VPP upstream commit | the `BASE` default in `vpplink/generated/vpp_clone_current.sh` | it is the commit the build resets the VPP checkout to |
| vpp-dataplane commit | `HEAD` of this repository | it contains the cherry-pick list, the patches, the deb list in `vpp-manager/Makefile` and the Dockerfile — every remaining build input |
| cilium_srv6 commit | `CILIUM_SRV6_SOURCE_COMMIT` in `vpplink/generated/private_plugins/` | `scripts/check-cilium-srv6-sync.sh` proves the vendored tree is byte-for-byte that commit's tree |

No mutable tag is produced. There is no `latest`, no branch tag and nothing a
later build overwrites.

`vpp-manager`'s own `VPP_HASH` is reported alongside the tag but is not the tag.
It hashes the clone script, the patches, the private plugins and the deb lists,
so it is a good cache key for the VPP tarball, but it does not name the
vpp-dataplane commit and it says nothing about which canonical `cilium_srv6`
commit the snapshot came from.

The script refuses to emit a tag when the `BASE` assignment in the clone script
is absent or ambiguous, and it reports a dirty working tree so callers can
refuse to name an image after a commit that does not describe it.

### Refreshing the `cilium_srv6` pin

Two artifacts move together, and forgetting the second one is a run-time
failure, not a build failure:

```
# 1. refresh the snapshot and the pin file
scripts/sync-cilium-srv6.sh <cilium-repo> <commit>

# 2. regenerate the Go bindings from the refreshed .api file
make gen-cilium-srv6-binapi CILIUM_SRV6_VPP_SRC=<vpp>/src

# 3. prove both are in sync
scripts/check-cilium-srv6-sync.sh <cilium-repo>
```

Step 2 exists because the `.api` file is the only input the Go bindings have.
Every message whose definition changed gets a new CRC, and GoVPP's codec
refuses to decode a reply whose CRC is not the one the bindings were generated
for. A refresh that skips step 2 therefore builds and vets cleanly and then
fails at run time: after the refresh to `46b07cb152`, `srv6_acl_details` changed
from `0x437a687c` to `0xea1bcd20`, so `IfIncarnation` in `vpplink/srv6ec_ifbind.go`
could not decode the `srv6_acl_dump` reply, reported `srv6 acl dump reported no
state for if[N]`, and no Pod interface could be created (errata #34 items 160
and 210).

`make gen-cilium-srv6-binapi` regenerates only
`vpplink/generated/bindings/cilium_srv6/`. It needs `python3` and a VPP *source*
tree (for `tools/vppapigen` and for the `memclnt`, `interface_types` and
`ip_types` definitions the plugin imports), not a built VPP, so unlike `make
goapi` it runs on a developer machine including macOS. The generator version is
read from `go.fd.io/govpp` in `go.mod`, so the bindings stay compatible with the
GoVPP runtime the agent links against; override it with
`CILIUM_SRV6_GOVPP_VERSION=` only to reproduce an older file.

Step 3 is what makes the coupling enforceable. `check-cilium-srv6-sync.sh` now
checks two things: the snapshot is byte-for-byte the pinned commit's tree, and
the generated bindings carry the pinned `.api` file's version string and the
same per-message CRC table as the canonical repository's own bindings at that
commit. The second check reads
`pkg/srv6ec/vppapi/binapi/cilium_srv6/cilium_srv6.ba.go` from the Cilium
checkout that is already passed in (override with
`CILIUM_SRV6_BINDINGS_SOURCE_PATH=`), because the `.api` file is identical on
both sides and a CRC is a property of that file rather than of the generator, so
CI needs no Python and no VPP tree to run it.

### CI

`.github/workflows/vpp-image-srv6ec.yml`:

1. **`snapshot-gate` job.** Reads both pin files, derives the canonical
   repository slug from them, checks that repository out, and runs
   `scripts/check-cilium-srv6-sync.sh` and
   `scripts/check-podinterface-proto-sync.sh`. A hand-edited snapshot fails
   here (Issue #135 ruling 7). It is a separate job so the failure arrives in
   seconds rather than after the VPP compile. It then derives the tag.
2. **`build` job.** `make -C vpp-manager vpp-image TAG=<tag>`, push under the
   immutable tag, read back the digest, and write tag, digest and the three
   commits to the job summary and to the `srv6ec-vpp-image-provenance`
   artifact.

Two things CI needs that are not in the repository:

* the secret `CILIUM_PRIVATE_TOKEN`, with read access to the canonical Cilium
  repository. The workflow's own `GITHUB_TOKEN` is scoped to this repository
  and cannot read another one.
* a runner with enough disk. The VPP build compiles the release *and* debug
  packages; a GitHub-hosted `ubuntu-24.04` runner has roughly 14 GB free after
  the standard image, and the free-disk step in the workflow may not be enough.
  `workflow_dispatch` takes a `runner` input so the build can be sent to a
  self-hosted Linux docker host.

### Local build

`scripts/srv6ec-build-vpp-image.sh --cilium-repo <path> [--push]` runs the same
sequence on a Linux docker host. It requires Linux (the VPP build runs in a
container that bind-mounts the build tree and compiles for x86_64), docker,
and on the order of 40 GB of free disk across the build tree and the docker
data root. It refuses a dirty tree unless `--allow-dirty` is passed, in which
case the tag gets a `-dirty` suffix that the deploy helper will not accept.

### Deploying

`scripts/srv6ec-stage0-deploy.sh` takes only digests:

```
scripts/srv6ec-stage0-deploy.sh install \
  --vpp   ghcr.io/ryskn/calicovpp/vpp@sha256:... \
  --agent ghcr.io/ryskn/calicovpp/agent@sha256:...
```

A tag is refused, including an immutable-looking one, because a tag is a name a
registry can repoint and a test result naming a tag does not name the bytes
that were tested. `status` reports the `imageID` from the Pod status rather than
the image from the DaemonSet spec, because on a stalled rollout those differ and
only the first describes the system a result came from.

The manifest's image references are `:REPLACE-ME` placeholders. Applying
`yaml/srv6ec-stage0` directly produces Pods that cannot pull, on purpose.

## 6. Configuration

`yaml/srv6ec-stage0/` is the base. Two components:

| component | effect | cost |
|---|---|---|
| `components/poll-sleep` | adds `poll-sleep-usec 100` to the VPP `unix` stanza | up to 100 us extra forwarding latency on an idle dataplane, and incompatible with multiple VPP workers (rules out TC-603). Needed on the 6-core test bed host (Issue #21 §1); must be off for any latency or throughput measurement |
| `components/uplink-af-xdp` | switches the uplink driver to `af_xdp` | Stage 2 only, and **incomplete**: it changes the driver and nothing else. Hugepages, memory limits, and the securityContext an AF_XDP uplink needs are not addressed |

Values in the ConfigMap that are cluster-specific and have to be checked before
the first apply: `SERVICE_PREFIX` (the kubeadm `serviceSubnet`),
`uplinkInterfaces[0].interfaceName` (the host NIC name, which differs per
cluster), and `srv6-block` in the `cilium-srv6` stanza, which must equal the
Cilium chart's `srv6EndpointContext.block` — see 4.3 for which of the two is the
source of truth and for the gate that catches a divergence.

`components/poll-sleep` restates the whole `CALICOVPP_CONFIG_TEMPLATE`, because
a ConfigMap value is one string and there is no way to patch a line of it. Any
edit to that template in the base has to be repeated there — including the
`cilium-srv6 { punt-socket ...; srv6-block ... }` stanza, without which the
plugin has no IF-3 socket to dial (punted packets are then dropped rather than
resolved) and no configured `SRV6_BLOCK` (4.3).

### Why the uplink stays `virtio` in Stage 0 and Stage 1

The plugin cannot classify a VPP native virtio-pci uplink as `TRUSTED_FABRIC`:
the device class name of the PCI virtio-net driver is also `"virtio"`
(`virtio/device.c:1136`), so the plugin's non-promotable list — written for
tap/tun — covers the VM's real NIC too (errata 114). The ruling on that errata
is that moving `"virtio"` onto the promotable list is forbidden, because it
would widen the trust boundary for the convenience of a test bed. Stage 1 does
not need a fabric interface, so it keeps `virtio`; Stage 2 changes the driver
instead.

## 7. What the Cilium side must provide

Not part of this repository, listed because Stage 0 does not come up without it:

* `--srv6-vpp-api-socket=/var/run/vpp-srv6ec/vpp-api.sock`, and the hostPath
  `/var/run/vpp-srv6ec` mounted into the Cilium agent Pod. Root must be an
  accepted UID, since the proxy runs as root. The chart mounts it with
  `type: Directory` on purpose — a kubelet-created directory would not satisfy
  the 0700 check — which is also why this DaemonSet has to start first.
* the IF-3 punt socket left at its defaults: `--srv6-punt-socket` at
  `/run/cilium/srv6ec/punt.sock` and `--srv6-punt-allowed-uids=0`. The agent
  binds it; the plugin dials it from the `vpp` container as UID 0. If the flag
  is moved, `punt-socket` in `CALICOVPP_CONFIG_TEMPLATE` has to move with it.
  Nothing has to be mounted into the Cilium agent Pod for IF-3 — the socket is
  inside the agent's own runtime directory — and nothing has to be created on
  the host: `/run/cilium/srv6ec` is the agent's to create, at 0700.
* a hostPath for `/var/lib/cilium` so that the srv6ec durable state survives an
  agent restart. The Helm chart mounts only a `subPath` of it, which loses the
  state and makes E2E 6 and E2E 7 unmeasurable (errata 117).
* the CNI NetConf `cniDatapathProvider` pointing at
  `/var/run/vpp/podinterface-lifecycle.sock`.
* `--devices` excluding `vpptap0` and the VPP-owned uplink, so the Cilium base
  datapath does not attach `bpf_host` to interfaces VPP owns (Issue #135 ruling
  5). "No unexpected tc/XDP attachment on `vpptap0`" is an acceptance criterion,
  not a nicety.
* the srv6ec flags are named differently on the two sides: the agent takes
  `--srv6-block`, the operator takes `--srv6-locator-block`.
* the chart value `srv6EndpointContext.block` is the source of truth for
  `SRV6_BLOCK`, and this kit's `cilium-srv6 { srv6-block ... }` restates it
  (4.3). The Cilium kit's `check-i.sh` I-0a/I-0b fail the run if the plugin is
  on its test default or if the two values differ.

## 8. Known pitfalls

1. **The `vpp` container requires a reachable Calico datastore.** See section 9;
   this is the one that stops Stage 0 from starting.
2. **`vmbr0` on the Proxmox host has `multicast_snooping=1`**, which drops IPv6
   ND. Unaddressed at the time of writing (Issue #21 §1).
3. **A rolling update of this DaemonSet restarts VPP** on the node it touches
   and drops that node's Pod datapath for the duration. Expected on a test bed.
4. **`Calico's own SRv6`** (`fcff::/48`, `cafe::/118`) would be a second SRv6
   authority inside the same VPP. This profile does not run `calico-vpp-agent`,
   so it does not arise here; it does arise if the Calico profile is ever
   deployed on the same node.
5. **`SRV6_BLOCK` must not overlap node addresses or any PodCIDR** (D-60). The
   test bed value is `fdbb:bb00::/32`, which is a test-only value, not a
   production default — and it must be written into the `cilium-srv6` stanza
   explicitly rather than left to the plugin's identically-valued test default,
   which no deployment may rely on (4.3, errata #34 item 198).
6. **The `cilium-srv6 { punt-socket ... }` stanza needs a VPP image that knows
   the key.** The plugin's startup config parser rejects an unknown key with a
   `clib_error`, which aborts VPP startup, so pairing this manifest with an
   image built from a `cilium_srv6` snapshot older than the IF-3 transport
   crash-loops the DaemonSet. Check
   `vpplink/generated/private_plugins/CILIUM_SRV6_SOURCE_COMMIT` against the
   image being deployed (section 4.1).
7. **A VPP restart re-creates the Pod-side netdev, and the Pod-side L3
   configuration has to be re-applied with it** (errata #34 item 211). The rescan
   does that from the durable pod spec now; see 2.1. A deployment that keeps its
   own Pod-side configuration outside the pod spec would lose it here, and an
   IPv4-only deployment would not notice the difference because
   `CreateOrAttachTapV2` sometimes re-attaches to a netdev that kept its
   configuration.

## 9. Open items

These are recorded rather than resolved, because resolving them means changing
behaviour outside the scope of a deployment kit.

### 9.1 `vpp-manager` requires the Calico datastore (blocking)

`vpp-manager` calls `updateCalicoNode()` unconditionally before it writes the
vpp-manager info file and reports `Ready`
(`vpp-manager/vpp_runner.go:1135`). That function constructs a Calico v3 client
from the environment, gets the `Node` resource for `NODENAME`, and writes the
node's BGP addresses back. It retries ten times and then returns an error, and
the caller responds with `terminateVpp`.

In a Cilium-primary cluster there is no reason for the Calico datastore to
exist, so VPP would not start. Two ways out, neither of which this kit chooses:

* **A. Keep `vpp-manager` unchanged and provide the datastore.** Install the
  Calico CRDs and ensure a `Node` resource per Kubernetes node, without running
  any Calico control plane component. This is what the manifest's ClusterRole is
  sized for. It stays inside the instruction not to deploy `calico-node`, Felix,
  Typha or the Calico CNI installer, but it does add a Calico-shaped datastore
  dependency to a profile whose entire point is that Cilium is the only control
  plane.
* **B. Make the call conditional in `vpp-manager`.** The BGP address write
  exists so that Calico's BGP can advertise the node; in this profile nothing
  reads it. Skipping it when no Calico datastore is configured is a small
  change, but it is a change to the startup contract of a production component
  and to `vpp-manager`'s externally visible behaviour, so it needs a decision
  rather than an implementation.

Until this is decided, the DaemonSet will not reach `Ready` on a cluster with no
Calico datastore.

### 9.2 ClusterRole width

The manifest copies `calico-vpp-node-role` verbatim, which grants far more than
this profile uses — Calico IPAM create/update/delete among it. Narrowing it
requires knowing what `updateCalicoNode()` and `calicov3cli.NewFromEnv()`
actually touch, which follows from the decision in 9.1.

### 9.3 `socat` in the agent image

The agent image now installs `socat`, for the IF-2 proxy only. It keeps the
profile at two images, which matters on the test bed cluster because it cannot
pull images live and every image has to be imported. It is a package added to an
image for a test bed's benefit, which is worth revisiting if the production
answer to the socket-mode question (Issue #60 section A) makes the proxy
unnecessary.

### 9.4 The build has not been run

Neither the CI workflow nor the local build script has produced an image. The
build needs Linux and tens of gigabytes of disk. The mechanics that could be
checked without building — tag derivation, YAML validity, the manifest rendering
and applying with a client dry-run, the deploy helper's digest enforcement, and
`GOOS=linux` compilation of the lifecycle entrypoint — were checked.
