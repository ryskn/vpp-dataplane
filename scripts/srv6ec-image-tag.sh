#!/bin/bash
# Copyright (C) 2026 Cilium Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Derive the immutable tag of the SRv6 Endpoint Context VPP image from the
# three commits that determine its contents (Issue #135 ruling 6):
#
#   1. the VPP upstream commit  — BASE in vpplink/generated/vpp_clone_current.sh
#   2. the vpp-dataplane commit — this repository's HEAD (or $2)
#   3. the cilium_srv6 commit   — CILIUM_SRV6_SOURCE_COMMIT in the pin file
#
# Every input of the image is a function of those three:
#   - the cherry-picked VPP changes, the patches and the deb list live in
#     vpp_clone_current.sh, vpplink/generated/patches and vpp-manager/Makefile,
#     all of which are contents of the vpp-dataplane commit;
#   - the vendored plugin tree is byte-for-byte the tree of the pinned
#     cilium_srv6 commit, which scripts/check-cilium-srv6-sync.sh proves;
#   - the Dockerfile is a content of the vpp-dataplane commit.
#
# So the tag names the image contents, and never moves: there is no `latest`,
# no branch tag and no tag that is rewritten by a later build. A rebuild of the
# same three commits either produces the same tag or is a bug in this script.
#
# vpp-manager's own VPP_HASH is *not* the tag. It is a build-input fingerprint
# (it hashes the patches, the private plugins and the deb lists) used to cache
# the VPP tarball, it does not name the vpp-dataplane commit, and it says
# nothing about which canonical cilium_srv6 commit the snapshot came from. It
# is reported alongside the tag so a build can be correlated with its cache.
#
# Usage:
#   scripts/srv6ec-image-tag.sh [--shell|--tag|--github] [<dataplane-commit>]
#
#   --shell   (default) KEY=VALUE lines, suitable for eval or $GITHUB_OUTPUT
#   --tag     the bare tag, nothing else
#   --github  KEY=VALUE lines appended to $GITHUB_OUTPUT if it is set

set -euo pipefail

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPODIR="$(cd "$SCRIPTDIR/.." >/dev/null 2>&1 && pwd)"

CLONE_SCRIPT="$REPODIR/vpplink/generated/vpp_clone_current.sh"
SRV6_PIN_FILE="$REPODIR/vpplink/generated/private_plugins/CILIUM_SRV6_SOURCE_COMMIT"

# Length of each commit in the tag. 12 hex characters is what the rest of this
# repository's tooling abbreviates to, and three of them plus the separators
# stay well inside the 128 character limit on a Docker tag.
SHORT=12

function die() {
	printf "\e[0;31m%s\e[0m\n" "$1" >&2
	exit 1
}

MODE="--shell"
case "${1:-}" in
--shell | --tag | --github)
	MODE="$1"
	shift
	;;
-*)
	die "unknown option $1"
	;;
esac

DATAPLANE_COMMIT="${1:-}"
if [ -z "$DATAPLANE_COMMIT" ]; then
	DATAPLANE_COMMIT="$(git -C "$REPODIR" rev-parse HEAD)"
fi
DATAPLANE_COMMIT="$(git -C "$REPODIR" rev-parse "$DATAPLANE_COMMIT")"

# A dirty tree cannot be named by a commit. Refusing here is the difference
# between "this tag identifies these contents" and "this tag identifies these
# contents plus whatever was uncommitted on the machine that built it".
if [ -n "$(git -C "$REPODIR" status --porcelain)" ]; then
	DATAPLANE_DIRTY=true
else
	DATAPLANE_DIRTY=false
fi

[ -f "$CLONE_SCRIPT" ] || die "missing $CLONE_SCRIPT"
[ -f "$SRV6_PIN_FILE" ] || die "missing $SRV6_PIN_FILE"

# vpp_clone_current.sh cannot be sourced (sourcing it clones VPP), so the
# default of BASE is read out of the assignment. Exactly one match is required:
# zero means the file changed shape, more than one means it is ambiguous which
# commit the build would use, and guessing either way would produce a tag that
# does not name the image.
VPP_BASE_MATCHES="$(grep -oE 'BASE=[^ ]*[0-9a-f]{40}' "$CLONE_SCRIPT" | grep -oE '[0-9a-f]{40}' | sort -u)"
VPP_BASE_COUNT="$(printf '%s' "$VPP_BASE_MATCHES" | grep -c . || true)"
if [ "$VPP_BASE_COUNT" -ne 1 ]; then
	die "expected exactly one VPP BASE commit in $CLONE_SCRIPT, found $VPP_BASE_COUNT"
fi
VPP_UPSTREAM_COMMIT="$VPP_BASE_MATCHES"

# shellcheck disable=SC1090
source "$SRV6_PIN_FILE"
[ -n "${CILIUM_SRV6_SOURCE_COMMIT:-}" ] || die "CILIUM_SRV6_SOURCE_COMMIT is not set in $SRV6_PIN_FILE"
if ! [[ "$CILIUM_SRV6_SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
	die "CILIUM_SRV6_SOURCE_COMMIT is not a full commit sha: $CILIUM_SRV6_SOURCE_COMMIT"
fi

VPP_SHORT="${VPP_UPSTREAM_COMMIT:0:$SHORT}"
DP_SHORT="${DATAPLANE_COMMIT:0:$SHORT}"
SRV6_SHORT="${CILIUM_SRV6_SOURCE_COMMIT:0:$SHORT}"

IMAGE_TAG="vpp-${VPP_SHORT}-dp-${DP_SHORT}-srv6-${SRV6_SHORT}"

VPP_HASH="$(make -s -C "$REPODIR/vpp-manager" vpp-hash 2>/dev/null | sed -n 's/^VPP hash: //p')"

read -r -d '' OUTPUT <<EOF || true
IMAGE_TAG=${IMAGE_TAG}
VPP_UPSTREAM_COMMIT=${VPP_UPSTREAM_COMMIT}
DATAPLANE_COMMIT=${DATAPLANE_COMMIT}
DATAPLANE_DIRTY=${DATAPLANE_DIRTY}
CILIUM_SRV6_SOURCE_COMMIT=${CILIUM_SRV6_SOURCE_COMMIT}
CILIUM_SRV6_SOURCE_REPO=${CILIUM_SRV6_SOURCE_REPO:-}
CILIUM_SRV6_SOURCE_PATH=${CILIUM_SRV6_SOURCE_PATH:-}
VPP_HASH=${VPP_HASH}
EOF

case "$MODE" in
--tag)
	echo "$IMAGE_TAG"
	;;
--shell)
	echo "$OUTPUT"
	;;
--github)
	echo "$OUTPUT"
	if [ -n "${GITHUB_OUTPUT:-}" ]; then
		echo "$OUTPUT" >>"$GITHUB_OUTPUT"
	fi
	;;
esac
