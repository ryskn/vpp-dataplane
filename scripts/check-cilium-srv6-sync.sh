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
# Verify that the vendored cilium_srv6 snapshot is byte-for-byte identical to
# the tree of the pinned canonical commit (decision 7 of Issue #135).  A hand
# edited snapshot is a CI failure: the only supported way to change it is
# scripts/sync-cilium-srv6.sh.
#
# Usage:
#   scripts/check-cilium-srv6-sync.sh <cilium-repo-path>
#
# The check needs a checkout of the canonical repository that contains the
# pinned commit; CI is expected to clone it (or use a cached clone) and pass
# the path.  Exit status 0 means the snapshot matches the pin.

set -euo pipefail

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPODIR="$(cd "$SCRIPTDIR/.." >/dev/null 2>&1 && pwd)"

DEST_DIR="$REPODIR/vpplink/generated/private_plugins/cilium_srv6"
PIN_FILE="$REPODIR/vpplink/generated/private_plugins/CILIUM_SRV6_SOURCE_COMMIT"

function red() { printf "\e[0;31m%s\e[0m\n" "$1" >&2; }
function green() { printf "\e[0;32m%s\e[0m\n" "$1" >&2; }

if [ $# -lt 1 ]; then
	red "usage: $0 <cilium-repo-path>"
	exit 1
fi

CILIUM_DIR="$1"

if [ ! -f "$PIN_FILE" ]; then
	red "missing pin file $PIN_FILE"
	exit 1
fi

# shellcheck disable=SC1090
source "$PIN_FILE"

if [ -z "${CILIUM_SRV6_SOURCE_COMMIT:-}" ] || [ -z "${CILIUM_SRV6_SOURCE_PATH:-}" ]; then
	red "pin file $PIN_FILE does not define CILIUM_SRV6_SOURCE_COMMIT / CILIUM_SRV6_SOURCE_PATH"
	exit 1
fi

if ! git -C "$CILIUM_DIR" cat-file -e "${CILIUM_SRV6_SOURCE_COMMIT}^{commit}" 2>/dev/null; then
	red "pinned commit $CILIUM_SRV6_SOURCE_COMMIT not found in $CILIUM_DIR"
	exit 1
fi

TMPDIR_="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_"' EXIT

git -C "$CILIUM_DIR" archive --format=tar \
	"${CILIUM_SRV6_SOURCE_COMMIT}:${CILIUM_SRV6_SOURCE_PATH}" | tar -x -C "$TMPDIR_"

if diff -ru "$TMPDIR_" "$DEST_DIR"; then
	green "cilium_srv6 snapshot matches ${CILIUM_SRV6_SOURCE_COMMIT}"
	exit 0
fi

red "cilium_srv6 snapshot differs from pinned commit ${CILIUM_SRV6_SOURCE_COMMIT}"
red "the snapshot is generated: run scripts/sync-cilium-srv6.sh <cilium-repo> <commit>"
exit 1
