# VPP private plugins

`vpp_clone_current.sh` copies each directory here into `src/plugins/<name>` of
the VPP source tree it prepares, so that the resulting VPP build contains the
out-of-tree plugins this dataplane needs.

## `cilium_srv6` is a generated snapshot — do not edit it

`cilium_srv6/` is **not** maintained here. Its canonical source is
`vpp/plugins/cilium_srv6` in the Cilium repository (decision 7 of Issue #135,
2026-09-10): the plugin source lives in exactly one place, and this repository
holds a vendored snapshot of it.

- Refresh the snapshot with
  `scripts/sync-cilium-srv6.sh <cilium-repo-path> [<commit-ish>]`. The script
  extracts the tree from the Cilium repository's git object store and rewrites
  the pin file `CILIUM_SRV6_SOURCE_COMMIT`.
- `scripts/check-cilium-srv6-sync.sh <cilium-repo-path>` verifies that the
  snapshot is byte-for-byte identical to the tree of the pinned commit. CI runs
  it, so a hand edited snapshot is a build failure.
- The Go bindings generated from `cilium_srv6.api` live in
  `vpplink/generated/bindings/cilium_srv6/` and are produced by
  `make gen-binapi` (which needs a VPP source tree); they are not edited either.

Neither submodule nor subtree is used: both would make the snapshot look like a
second place where the plugin can be modified.

The pinned commit SHA is the only authority for which version of the canonical
source a snapshot corresponds to. A pull request number is not one, and is not
written down as if it were: a pull request can be rebased, retargeted, closed
and reopened under a different number, and in none of those cases does its
number name a file's contents. The same rule governs the `PodInterfaceLifecycle`
proto snapshot under `calico-vpp-agent/proto/`, which is refreshed by
`scripts/sync-podinterface-proto.sh`, pinned by `PODINTERFACE_PROTO_SOURCE` and
checked by `scripts/check-podinterface-proto-sync.sh`.

The other directories here (`ip_ttl_fixup`, `pbl`) are maintained in this
repository and have no upstream pin.
