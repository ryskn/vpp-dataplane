// Copyright (C) 2026 Cilium Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vpplink

import (
	"fmt"
	"io"

	cilium_srv6 "github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/cilium_srv6"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
)

// IF-4 binding writer (SRv6 Endpoint Context v1, D-71).
//
// The cilium_srv6 plugin owns a table that maps a CNI attachment identity to
// exactly one live VPP InterfaceHandle:
//
//	attachment_id              -> exactly one live (sw_if_index, if_incarnation)
//	(sw_if_index, incarnation) -> at most one attachment_id
//
// This file is the writer side of that table (00 §2.12.6-§2.12.9; table rules
// in 02 §8.1).  It deliberately contains no identity translation: the caller
// creates the interface and therefore already knows both identities, and the
// writer only commits the pair it was given.  Reconstructing an attachment ID
// from an interface name, deriving sw_if_index from a Linux ifindex, hashing or
// truncating an attachment ID, re-resolving a stale handle onto the current one
// and implicitly replacing a conflicting binding are all forbidden
// (00 §2.12.7).

// AttachmentIDMaxLen is the largest attachment_id the cilium_srv6 plugin
// accepts (02 §8.1 rule 1).  It bounds the heap allocation of one API message;
// it is not a CNI-side limit, and an attachment ID longer than this is
// rejected rather than truncated.
const AttachmentIDMaxLen = 255

// IfIncarnation reads the current interface incarnation of swIfIndex from the
// cilium_srv6 plugin (D-31).  The incarnation distinguishes successive
// interfaces that happen to reuse the same sw_if_index, and it is the second
// half of the InterfaceHandle a binding is published against.
//
// srv6_acl_dump filtered by one sw_if_index returns exactly one details message
// for a live interface.  An empty dump is a failure, not "incarnation 0": the
// interface is unknown to the plugin, so no handle can be published for it.
func (v *VppLink) IfIncarnation(swIfIndex uint32) (uint32, error) {
	client := cilium_srv6.NewServiceClient(v.GetConnection())

	stream, err := client.Srv6ACLDump(v.GetContext(), &cilium_srv6.Srv6ACLDump{
		SwIfIndex: interface_types.InterfaceIndex(swIfIndex),
	})
	if err != nil {
		return 0, fmt.Errorf("failed to dump srv6 acl state for if[%d]: %w", swIfIndex, err)
	}

	found := false
	var incarnation uint32
	for {
		response, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("failed to dump srv6 acl state for if[%d]: %w", swIfIndex, err)
		}
		if uint32(response.SwIfIndex) != swIfIndex {
			// The plugin filters server-side; ignore anything else rather
			// than picking a handle that was not asked for.
			continue
		}
		if found && incarnation != response.IfIncarnation {
			return 0, fmt.Errorf("srv6 acl dump reported several incarnations for if[%d]", swIfIndex)
		}
		incarnation = response.IfIncarnation
		found = true
	}
	if !found {
		return 0, fmt.Errorf("srv6 acl dump reported no state for if[%d]", swIfIndex)
	}
	return incarnation, nil
}

// IfAttachmentAdd publishes the binding attachmentID -> (swIfIndex,
// ifIncarnation).  Re-sending the exact same tuple is idempotent; a request
// that agrees with an existing binding on only one side is rejected by the
// plugin and surfaces here as an error (02 §8.1 rules 4 and 5).
func (v *VppLink) IfAttachmentAdd(attachmentID string, swIfIndex uint32, ifIncarnation uint32) error {
	return v.ifAttachmentAddDel(attachmentID, swIfIndex, ifIncarnation, true)
}

// IfAttachmentDel withdraws the binding for the exact tuple (attachmentID,
// swIfIndex, ifIncarnation).  The plugin deletes on exact match only, so a
// delete that was in flight across an interface replacement cannot remove the
// new incarnation's binding (02 §8.1 rule 6).
func (v *VppLink) IfAttachmentDel(attachmentID string, swIfIndex uint32, ifIncarnation uint32) error {
	return v.ifAttachmentAddDel(attachmentID, swIfIndex, ifIncarnation, false)
}

func (v *VppLink) ifAttachmentAddDel(attachmentID string, swIfIndex uint32, ifIncarnation uint32, isAdd bool) error {
	if err := ValidateAttachmentID(attachmentID); err != nil {
		return err
	}
	client := cilium_srv6.NewServiceClient(v.GetConnection())

	_, err := client.Srv6IfAttachmentAddDel(v.GetContext(), &cilium_srv6.Srv6IfAttachmentAddDel{
		SwIfIndex:     interface_types.InterfaceIndex(swIfIndex),
		IfIncarnation: ifIncarnation,
		IsAdd:         isAdd,
		AttachmentID:  attachmentID,
	})
	if err != nil {
		return fmt.Errorf("failed to %s srv6 if attachment %q -> if[%d] incarnation %d: %w",
			map[bool]string{true: "add", false: "delete"}[isAdd],
			attachmentID, swIfIndex, ifIncarnation, err)
	}
	return nil
}

// ValidateAttachmentID enforces the wire constraint of 02 §8.1 rule 1:
// 1..AttachmentIDMaxLen bytes of printable ASCII (0x21..0x7e).  An attachment
// ID outside that range is rejected; it is never truncated, because a truncated
// identity is a different identity.
func ValidateAttachmentID(attachmentID string) error {
	if len(attachmentID) == 0 {
		return fmt.Errorf("attachment id is empty")
	}
	if len(attachmentID) > AttachmentIDMaxLen {
		return fmt.Errorf("attachment id is %d bytes, more than the %d byte limit",
			len(attachmentID), AttachmentIDMaxLen)
	}
	for i := 0; i < len(attachmentID); i++ {
		if attachmentID[i] < 0x21 || attachmentID[i] > 0x7e {
			return fmt.Errorf("attachment id contains a non printable ASCII byte 0x%02x at offset %d",
				attachmentID[i], i)
		}
	}
	return nil
}
