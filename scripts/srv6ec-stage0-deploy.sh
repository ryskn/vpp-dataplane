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
# Deploy helper for the SRv6 Endpoint Context Stage 0 lifecycle profile.
#
# This is the /calicovpp-deploy loop extended to the vpp container, which that
# skill deliberately leaves at its upstream tag. Issue #135 ruling 6 requires
# the opposite for this profile: the VPP image carries the out-of-tree
# cilium_srv6 plugin, its identity is part of what a test result means, and the
# ruling says no mutable tag.
#
# So every image reference this script installs must be a digest
# (repo@sha256:...). A tag is refused, including an immutable-looking one:
# a tag is a name a registry can repoint, and a test result that names a tag
# does not name the bytes that were tested.
#
# Subcommands:
#   install   --vpp <ref> --agent <ref>   render the manifest with those images
#                                         and apply it
#   set-image --vpp <ref> [--agent <ref>] flip the images of a running DaemonSet
#   status                                what is deployed, per node
#   rollout                               wait for the rolling update
#   diff      --vpp <ref> --agent <ref>   server-side diff of an install
#
# Both --vpp and --agent accept the `digest=` line of the CI provenance
# artifact verbatim.

set -euo pipefail

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPODIR="$(cd "$SCRIPTDIR/.." >/dev/null 2>&1 && pwd)"

KUSTOMIZE_DIR="$REPODIR/yaml/srv6ec-stage0"
NAMESPACE="srv6ec-stage0"
DAEMONSET="srv6ec-vpp-node"

# The exact strings the manifest carries; substituting anything else would
# silently leave a placeholder in the applied object.
VPP_PLACEHOLDER="ghcr.io/ryskn/calicovpp/vpp:REPLACE-ME"
AGENT_PLACEHOLDER="ghcr.io/ryskn/calicovpp/agent:REPLACE-ME"

VPP_IMAGE=""
AGENT_IMAGE=""
ROLLOUT_TIMEOUT="10m"

function die() {
	printf "\e[0;31m%s\e[0m\n" "$1" >&2
	exit 1
}
function info() { printf "\e[0;34m%s\e[0m\n" "$1" >&2; }
function ok() { printf "\e[0;32m%s\e[0m\n" "$1" >&2; }

function usage() {
	sed -n '17,39p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
	exit 1
}

# require_digest enforces the one rule this script exists for.
function require_digest() {
	local what="$1" ref="$2"
	[ -n "$ref" ] || die "--${what} is required"
	if [[ "$ref" != *"@sha256:"* ]]; then
		die "--${what}: refusing '${ref}': deploy by digest (repo@sha256:...), not by tag. The CI job summary and the srv6ec-vpp-image-provenance artifact both give the digest."
	fi
	local digest="${ref##*@sha256:}"
	if ! [[ "$digest" =~ ^[0-9a-f]{64}$ ]]; then
		die "--${what}: '${ref}' does not end in a sha256 digest"
	fi
	# A reference carrying both a tag and a digest resolves by digest, but it
	# reads as if the tag mattered. Refuse the ambiguity.
	local before="${ref%@sha256:*}"
	if [[ "${before##*/}" == *:* ]]; then
		die "--${what}: '${ref}' carries both a tag and a digest; pass the digest form only"
	fi
}

function render() {
	require_digest vpp "$VPP_IMAGE"
	local agent="$AGENT_IMAGE"
	if [ -z "$agent" ]; then
		die "--agent is required for this subcommand"
	fi
	require_digest agent "$agent"

	command -v kubectl >/dev/null || die "kubectl is not on PATH"

	local rendered
	rendered="$(kubectl kustomize "$KUSTOMIZE_DIR")"

	# Substitute, then prove the substitution happened. Counting is the point:
	# a manifest change that renames a placeholder must fail here rather than
	# apply an image that cannot be pulled.
	local vpp_count agent_count
	vpp_count="$(printf '%s\n' "$rendered" | grep -c -F "$VPP_PLACEHOLDER" || true)"
	agent_count="$(printf '%s\n' "$rendered" | grep -c -F "$AGENT_PLACEHOLDER" || true)"
	[ "$vpp_count" -ge 1 ] || die "no '${VPP_PLACEHOLDER}' in the rendered manifest"
	[ "$agent_count" -ge 1 ] || die "no '${AGENT_PLACEHOLDER}' in the rendered manifest"

	rendered="${rendered//$VPP_PLACEHOLDER/$VPP_IMAGE}"
	rendered="${rendered//$AGENT_PLACEHOLDER/$agent}"

	if printf '%s\n' "$rendered" | grep -q 'REPLACE-ME'; then
		die "the rendered manifest still contains a REPLACE-ME image reference"
	fi
	printf '%s\n' "$rendered"
}

function cmd_install() {
	# Render fully before touching the cluster: piping render into kubectl
	# would still run kubectl when render refuses the images, and "no objects
	# passed to apply" is a worse message than the one render prints.
	local manifest
	manifest="$(render)"
	printf '%s\n' "$manifest" | kubectl apply -f -
	ok "applied; images:"
	printf '  vpp   %s\n' "$VPP_IMAGE" >&2
	printf '  agent %s\n' "$AGENT_IMAGE" >&2
	cmd_rollout
}

function cmd_diff() {
	local manifest
	manifest="$(render)"
	# `kubectl diff` exits 1 when there is a difference, which is the normal
	# case here and not an error.
	printf '%s\n' "$manifest" | kubectl diff -f - || true
}

function cmd_set_image() {
	require_digest vpp "$VPP_IMAGE"
	local args=("vpp=${VPP_IMAGE}")
	if [ -n "$AGENT_IMAGE" ]; then
		require_digest agent "$AGENT_IMAGE"
		args+=("podinterface-lifecycle=${AGENT_IMAGE}" "vppapi-proxy=${AGENT_IMAGE}")
	fi

	info "previous images:"
	kubectl -n "$NAMESPACE" get ds "$DAEMONSET" \
		-o jsonpath='{range .spec.template.spec.containers[*]}  {.name}{"\t"}{.image}{"\n"}{end}' >&2

	kubectl -n "$NAMESPACE" set image "ds/${DAEMONSET}" "${args[@]}"
	cmd_rollout
}

function cmd_rollout() {
	# A rolling update of this DaemonSet restarts VPP on the node it touches,
	# which drops that node's Pod datapath for the duration. That is expected
	# on a test bed and is not something to do anywhere else.
	kubectl -n "$NAMESPACE" rollout status "ds/${DAEMONSET}" --timeout="$ROLLOUT_TIMEOUT"
	cmd_status
}

function cmd_status() {
	echo "== DaemonSet =="
	kubectl -n "$NAMESPACE" get ds "$DAEMONSET" \
		-o jsonpath='{range .spec.template.spec.containers[*]}{.name}{"\t"}{.image}{"\n"}{end}'
	echo
	echo "== Pods =="
	kubectl -n "$NAMESPACE" get pods -o wide
	echo
	echo "== running images per node =="
	# .status is what is actually running; .spec is what was asked for. On a
	# stalled rollout they differ, and only the first one describes the system
	# a test result came from.
	kubectl -n "$NAMESPACE" get pods -o json |
		python3 -c '
import json, sys
for pod in json.load(sys.stdin)["items"]:
    node = pod["spec"].get("nodeName", "?")
    for cs in pod["status"].get("containerStatuses", []):
        print(f"{node}\t{cs[\"name\"]}\t{cs.get(\"imageID\", \"\")}")
'
}

[ $# -ge 1 ] || usage
SUBCOMMAND="$1"
shift

while [ $# -gt 0 ]; do
	case "$1" in
	--vpp)
		VPP_IMAGE="$2"
		shift 2
		;;
	--agent)
		AGENT_IMAGE="$2"
		shift 2
		;;
	--namespace)
		NAMESPACE="$2"
		shift 2
		;;
	--kustomize)
		KUSTOMIZE_DIR="$2"
		shift 2
		;;
	--timeout)
		ROLLOUT_TIMEOUT="$2"
		shift 2
		;;
	*)
		die "unknown argument $1"
		;;
	esac
done

case "$SUBCOMMAND" in
install) cmd_install ;;
diff) cmd_diff ;;
set-image) cmd_set_image ;;
rollout) cmd_rollout ;;
status) cmd_status ;;
*) usage ;;
esac
