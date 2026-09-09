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
# Verify that the vendored PodInterfaceLifecycle proto is byte-for-byte
# identical to the pinned canonical file in the Cilium repository. Same rule as
# scripts/check-cilium-srv6-sync.sh, applied to the proto.
#
# Usage:
#   scripts/check-podinterface-proto-sync.sh <cilium-repo-path>

set -euo pipefail

SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPODIR="$(cd "$SCRIPTDIR/.." >/dev/null 2>&1 && pwd)"

SNAPSHOT="$REPODIR/calico-vpp-agent/proto/podinterface/podinterface.proto"
PIN_FILE="$REPODIR/calico-vpp-agent/proto/PODINTERFACE_PROTO_SOURCE"

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

if [ -z "${PODINTERFACE_PROTO_SOURCE_COMMIT:-}" ]; then
	red "PODINTERFACE_PROTO_SOURCE_COMMIT is not set in $PIN_FILE"
	red "the canonical proto has not been pinned yet, so the snapshot is unverified"
	exit 1
fi

if ! git -C "$CILIUM_DIR" cat-file -e "${PODINTERFACE_PROTO_SOURCE_COMMIT}^{commit}" 2>/dev/null; then
	red "pinned commit $PODINTERFACE_PROTO_SOURCE_COMMIT not found in $CILIUM_DIR"
	exit 1
fi

if ! git -C "$CILIUM_DIR" show \
	"${PODINTERFACE_PROTO_SOURCE_COMMIT}:${PODINTERFACE_PROTO_SOURCE_PATH}" \
	| diff -u - "$SNAPSHOT"; then
	red "podinterface.proto snapshot differs from pinned commit ${PODINTERFACE_PROTO_SOURCE_COMMIT}"
	exit 1
fi

green "podinterface.proto snapshot matches ${PODINTERFACE_PROTO_SOURCE_COMMIT}"
