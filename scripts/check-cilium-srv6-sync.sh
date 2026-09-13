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

if ! diff -ru "$TMPDIR_" "$DEST_DIR"; then
	red "cilium_srv6 snapshot differs from pinned commit ${CILIUM_SRV6_SOURCE_COMMIT}"
	red "the snapshot is generated: run scripts/sync-cilium-srv6.sh <cilium-repo> <commit>"
	exit 1
fi

green "cilium_srv6 snapshot matches ${CILIUM_SRV6_SOURCE_COMMIT}"

# ---------------------------------------------------------------------------
# The generated Go bindings must describe the same .api file as the snapshot.
#
# A snapshot refresh changes cilium_srv6.api, which changes the CRC of every
# message whose definition changed, and the binary API codec rejects a reply
# whose CRC is not the one it was generated for.  Nothing in the byte-for-byte
# snapshot check above notices that, so a refresh that forgets to regenerate
# ships bindings that cannot decode the plugin's replies at run time (errata
# #34 items 160 and 210: srv6_acl_dump replies became undecodable, so the
# lifecycle service could not read if_incarnation and no Pod interface could be
# created).  Compare the two here instead.
#
# The comparison uses the Cilium fork's own generated bindings at the pinned
# commit as the reference: the .api file is byte-identical, so the CRCs must be
# identical too, and reading them needs no vppapigen, no Python and no VPP
# source tree in CI.  Generator versions may differ between the two
# repositories; the CRC is a property of the .api file, not of the generator.
# ---------------------------------------------------------------------------

CILIUM_SRV6_BINDINGS_SOURCE_PATH="${CILIUM_SRV6_BINDINGS_SOURCE_PATH:-pkg/srv6ec/vppapi/binapi/cilium_srv6/cilium_srv6.ba.go}"
BINDINGS_FILE="$REPODIR/vpplink/generated/bindings/cilium_srv6/cilium_srv6.ba.go"
REGEN_CMD="make gen-cilium-srv6-binapi CILIUM_SRV6_VPP_SRC=<vpp>/src"

if [ ! -f "$BINDINGS_FILE" ]; then
	red "missing generated bindings $BINDINGS_FILE"
	red "regenerate them: $REGEN_CMD"
	exit 1
fi

# "option version = "1.9.0";" in the .api, "APIVersion = "1.9.0"" in the bindings.
API_VERSION="$(sed -nE 's/^[[:space:]]*option[[:space:]]+version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
	"$DEST_DIR/cilium_srv6.api" | head -1)"
BINDINGS_VERSION="$(sed -nE 's/^[[:space:]]*APIVersion[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' \
	"$BINDINGS_FILE" | head -1)"

if [ -z "$API_VERSION" ] || [ -z "$BINDINGS_VERSION" ]; then
	red "cannot read the API version from the snapshot (.api) or from the bindings"
	exit 1
fi

if [ "$API_VERSION" != "$BINDINGS_VERSION" ]; then
	red "cilium_srv6 bindings are generated from API version $BINDINGS_VERSION, the snapshot is $API_VERSION"
	red "regenerate them: $REGEN_CMD"
	exit 1
fi

if ! git -C "$CILIUM_DIR" cat-file -e \
	"${CILIUM_SRV6_SOURCE_COMMIT}:${CILIUM_SRV6_BINDINGS_SOURCE_PATH}" 2>/dev/null; then
	red "$CILIUM_SRV6_BINDINGS_SOURCE_PATH does not exist at ${CILIUM_SRV6_SOURCE_COMMIT} in $CILIUM_DIR"
	red "set CILIUM_SRV6_BINDINGS_SOURCE_PATH to the canonical repository's generated bindings"
	exit 1
fi

git -C "$CILIUM_DIR" show \
	"${CILIUM_SRV6_SOURCE_COMMIT}:${CILIUM_SRV6_BINDINGS_SOURCE_PATH}" >"$TMPDIR_/reference.ba.go"

# One "<message> <crc>" line per message, plus the file-level version CRC.
function crc_table() {
	sed -nE 's|^func \(\*([A-Za-z0-9_]+)\) GetCrcString\(\) string[[:space:]]*\{ return "([0-9a-f]+)".*|\1 \2|p' "$1" |
		sort
	sed -nE 's|^[[:space:]]*VersionCrc[[:space:]]*=[[:space:]]*(0x[0-9a-fA-F]+).*|VersionCrc \1|p' "$1"
}

crc_table "$TMPDIR_/reference.ba.go" >"$TMPDIR_/reference.crc"
crc_table "$BINDINGS_FILE" >"$TMPDIR_/bindings.crc"

if [ ! -s "$TMPDIR_/reference.crc" ]; then
	red "no message CRCs found in ${CILIUM_SRV6_BINDINGS_SOURCE_PATH} at ${CILIUM_SRV6_SOURCE_COMMIT}"
	exit 1
fi

if ! diff -u --label "pinned ${CILIUM_SRV6_SOURCE_COMMIT}" --label "vpplink/generated/bindings" \
	"$TMPDIR_/reference.crc" "$TMPDIR_/bindings.crc"; then
	red "cilium_srv6 bindings do not match the message CRCs of the pinned .api file"
	red "the codec rejects every reply whose CRC changed; regenerate the bindings:"
	red "  $REGEN_CMD"
	exit 1
fi

green "cilium_srv6 bindings match the .api of ${CILIUM_SRV6_SOURCE_COMMIT} (API version $API_VERSION)"
exit 0
