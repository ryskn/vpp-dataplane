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
# Build the SRv6 Endpoint Context VPP image locally and, optionally, push it.
#
# This is the same sequence .github/workflows/vpp-image-srv6ec.yml runs, in a
# form that can be run on any Linux host with docker. It exists because the
# build is heavy (it clones VPP, compiles the release and debug packages and
# produces multi-gigabyte build trees) and is therefore something one wants to
# be able to run on a chosen machine rather than only in CI.
#
# Requirements, none of which this script installs:
#   - Linux. The VPP build runs in a container that bind-mounts the build tree
#     and compiles for x86_64; it does not work on macOS.
#   - docker, git, make, and roughly 40 GB of free disk in $VPP_DIR plus the
#     docker data root. The VPP build tree alone (release + debug) is tens of
#     gigabytes.
#   - a checkout of the canonical Cilium repository containing the pinned
#     cilium_srv6 commit, for the snapshot gate.
#
# Usage:
#   scripts/srv6ec-build-vpp-image.sh --cilium-repo <path> [options]
#
#   --cilium-repo <path>   checkout used by the snapshot gates (required
#                          unless --skip-gate is given)
#   --registry <prefix>    image repository, default ghcr.io/ryskn/calicovpp/vpp
#   --push                 push the built tag and print the pushed digest
#   --skip-gate            do not run the snapshot gates (for a machine that
#                          has no Cilium checkout; the resulting image is then
#                          NOT known to match the pinned plugin source, so do
#                          not deploy it)
#   --allow-dirty          build from a dirty tree. The tag then does not name
#                          the contents, so the image is tagged with a
#                          `-dirty` suffix and refused by the deploy helper.

set -euo pipefail

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPODIR="$(cd "$SCRIPTDIR/.." >/dev/null 2>&1 && pwd)"

IMAGE_REPO="ghcr.io/ryskn/calicovpp/vpp"
CILIUM_REPO=""
DO_PUSH=false
SKIP_GATE=false
ALLOW_DIRTY=false

function die() {
	printf "\e[0;31m%s\e[0m\n" "$1" >&2
	exit 1
}
function info() { printf "\e[0;34m%s\e[0m\n" "$1" >&2; }
function ok() { printf "\e[0;32m%s\e[0m\n" "$1" >&2; }

while [ $# -gt 0 ]; do
	case "$1" in
	--cilium-repo)
		CILIUM_REPO="$2"
		shift 2
		;;
	--registry)
		IMAGE_REPO="$2"
		shift 2
		;;
	--push)
		DO_PUSH=true
		shift
		;;
	--skip-gate)
		SKIP_GATE=true
		shift
		;;
	--allow-dirty)
		ALLOW_DIRTY=true
		shift
		;;
	*)
		die "unknown argument $1"
		;;
	esac
done

[ "$(uname -s)" = "Linux" ] || die "the VPP build needs a Linux docker host, this is $(uname -s)"
command -v docker >/dev/null || die "docker is not on PATH"

if [ "$SKIP_GATE" = false ]; then
	[ -n "$CILIUM_REPO" ] || die "--cilium-repo is required (or pass --skip-gate)"
	info "== snapshot gate: cilium_srv6 =="
	"$SCRIPTDIR/check-cilium-srv6-sync.sh" "$CILIUM_REPO"
	info "== snapshot gate: podinterface.proto =="
	"$SCRIPTDIR/check-podinterface-proto-sync.sh" "$CILIUM_REPO"
else
	info "snapshot gates skipped: this image is not known to match the pinned plugin source"
fi

eval "$("$SCRIPTDIR/srv6ec-image-tag.sh" --shell)"

if [ "${DATAPLANE_DIRTY}" = "true" ]; then
	if [ "$ALLOW_DIRTY" = false ]; then
		die "the working tree is dirty: commit first, or pass --allow-dirty to build an image that no commit names"
	fi
	IMAGE_TAG="${IMAGE_TAG}-dirty"
fi

IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"

info "VPP upstream commit : ${VPP_UPSTREAM_COMMIT}"
info "vpp-dataplane commit: ${DATAPLANE_COMMIT}"
info "cilium_srv6 commit  : ${CILIUM_SRV6_SOURCE_COMMIT}"
info "VPP build hash      : ${VPP_HASH}"
info "image               : ${IMAGE}"

# vpp-manager's `vpp` target produces vpp-${VPP_HASH}.tar and `vpp-image`
# consumes it; the tarball target rebuilds it when it is missing, so a repeated
# build of unchanged VPP inputs skips the compile.
info "== building VPP and the image =="
make -C "$REPODIR/vpp-manager" vpp-image "TAG=${IMAGE_TAG}"

docker tag "calicovpp/vpp:${IMAGE_TAG}" "${IMAGE}"
docker tag "calicovpp/vpp:dbg-${IMAGE_TAG}" "${IMAGE_REPO}:dbg-${IMAGE_TAG}"

if [ "$DO_PUSH" = true ]; then
	info "== pushing =="
	docker push "${IMAGE}"
	docker push "${IMAGE_REPO}:dbg-${IMAGE_TAG}"
	DIGEST="$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${IMAGE}" | grep "^${IMAGE_REPO}@" | head -1)"
	[ -n "$DIGEST" ] || die "pushed ${IMAGE} but docker reports no digest for it"
	ok "pushed ${IMAGE}"
	ok "digest ${DIGEST}"
	echo "$DIGEST"
else
	ok "built ${IMAGE} (not pushed)"
fi
