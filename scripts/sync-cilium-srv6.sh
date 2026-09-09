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
# Refresh the vendored snapshot of the cilium_srv6 VPP plugin.
#
# The canonical source of the plugin is cilium/vpp/plugins/cilium_srv6 in the
# Cilium repository (decision 7 of Issue #135, 2026-09-10).  This repository
# only ever holds a generated snapshot; the snapshot is never hand edited.  A
# single pin file records which canonical commit the snapshot was taken from,
# and scripts/check-cilium-srv6-sync.sh verifies byte-for-byte equality between
# the snapshot and that commit's tree.
#
# Usage:
#   scripts/sync-cilium-srv6.sh <cilium-repo-path> [<commit-ish>]
#
#   <cilium-repo-path>  path to a checkout of the Cilium repository that
#                       contains vpp/plugins/cilium_srv6
#   <commit-ish>        commit to take the snapshot from (default: HEAD of the
#                       given checkout).  The snapshot is extracted from the
#                       git object store, not from the working tree, so an
#                       unclean working tree cannot leak into the snapshot.

set -euo pipefail

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPODIR="$(cd "$SCRIPTDIR/.." >/dev/null 2>&1 && pwd)"

# Path of the plugin inside the Cilium repository.
CILIUM_PLUGIN_PATH="vpp/plugins/cilium_srv6"
# Destination of the snapshot inside this repository.
DEST_DIR="$REPODIR/vpplink/generated/private_plugins/cilium_srv6"
# Pin file recording the canonical commit the snapshot was taken from.
PIN_FILE="$REPODIR/vpplink/generated/private_plugins/CILIUM_SRV6_SOURCE_COMMIT"

function red() { printf "\e[0;31m%s\e[0m\n" "$1" >&2; }
function green() { printf "\e[0;32m%s\e[0m\n" "$1" >&2; }

if [ $# -lt 1 ]; then
	red "usage: $0 <cilium-repo-path> [<commit-ish>]"
	exit 1
fi

CILIUM_DIR="$1"
COMMITISH="${2:-HEAD}"

if [ ! -d "$CILIUM_DIR/.git" ]; then
	red "$CILIUM_DIR is not a git repository"
	exit 1
fi

COMMIT="$(git -C "$CILIUM_DIR" rev-parse "$COMMITISH^{commit}")"

if ! git -C "$CILIUM_DIR" cat-file -e "$COMMIT:$CILIUM_PLUGIN_PATH" 2>/dev/null; then
	red "$CILIUM_PLUGIN_PATH does not exist at $COMMIT in $CILIUM_DIR"
	exit 1
fi

green "Snapshotting $CILIUM_PLUGIN_PATH from $COMMIT"

rm -rf "$DEST_DIR"
mkdir -p "$DEST_DIR"
# git archive writes the tree exactly as recorded in the commit, so the result
# is reproducible and independent of the source working tree.
git -C "$CILIUM_DIR" archive --format=tar "$COMMIT:$CILIUM_PLUGIN_PATH" | tar -x -C "$DEST_DIR"

mkdir -p "$(dirname "$PIN_FILE")"
cat >"$PIN_FILE" <<EOF
# Canonical source of vpplink/generated/private_plugins/cilium_srv6.
#
# Written by scripts/sync-cilium-srv6.sh.  Do not edit by hand and do not edit
# the snapshot: scripts/check-cilium-srv6-sync.sh fails the build when the
# snapshot and this commit's tree differ by a single byte.
CILIUM_SRV6_SOURCE_REPO=https://github.com/ryskn/cilium-private.git
CILIUM_SRV6_SOURCE_PATH=$CILIUM_PLUGIN_PATH
CILIUM_SRV6_SOURCE_COMMIT=$COMMIT
EOF

green "Wrote $PIN_FILE"
green "Snapshot refreshed. Regenerate the binapi bindings with 'make gen-binapi' on a Linux host."
