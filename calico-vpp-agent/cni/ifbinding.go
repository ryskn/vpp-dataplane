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

package cni

import (
	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// IfBindingWriter is the IF-4 binding writer this server publishes through.
//
// It is the whole of the server's dependency on the cilium_srv6 plugin, and it
// is satisfied by *vpplink.VppLink. Keeping it an interface is what lets the
// publication and revocation rules of D-71 be exercised without a live VPP.
type IfBindingWriter interface {
	// IfIncarnation returns the current incarnation of swIfIndex, or an error
	// when the interface is unknown to the plugin. "Unknown" is an error and
	// never incarnation 0: a handle that cannot be read cannot be published.
	IfIncarnation(swIfIndex uint32) (uint32, error)
	// IfAttachmentAdd publishes attachmentID -> (swIfIndex, ifIncarnation).
	IfAttachmentAdd(attachmentID string, swIfIndex uint32, ifIncarnation uint32) error
	// IfAttachmentDel withdraws the exact tuple.
	IfAttachmentDel(attachmentID string, swIfIndex uint32, ifIncarnation uint32) error
}

// publishIfAttachment performs steps 2 to 4 of the D-71 ADD sequence
// (00 §2.12.6) for a pod interface that has just been created:
//
//  1. VPP interface create                    (done by the caller)
//  2. read the current if_incarnation
//  3. srv6_if_attachment_add_del(ADD, attachmentID, handle)
//  4. ADD ACK                                 (this function returning nil)
//  5. expose the CNI attachment as successful (done by the caller)
//
// The publication happens while the caller still holds the cleanup stack of the
// interface creation, so a failure here rolls the interface back and the CNI
// ADD fails (completion criteria 1 and 3 of 00 §2.12.9). Nothing is pushed onto
// the stack before the ADD succeeds, so a failed publication never schedules a
// withdrawal of a binding that was not written.
//
// Re-publishing the exact same tuple is an idempotent replay and is allowed
// (02 §8.1 rule 4); the plugin rejects any write that agrees on only one side.
func (s *Server) publishIfAttachment(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack) error {
	if s.ifBinding == nil {
		return nil
	}
	if podSpec.AttachmentID == "" {
		// Reaching here without an attachment identity would mean the identity
		// has to be reconstructed from the interface, which is exactly what
		// 00 §2.12.7 prohibition 1 forbids. Fail instead.
		return errors.Errorf("pod %s has no CNI attachment identity to publish", podSpec.Key())
	}
	swIfIndex := podSpec.TunTapSwIfIndex
	if swIfIndex == vpplink.InvalidID {
		return errors.Errorf("pod %s has no VPP interface to publish a binding for", podSpec.Key())
	}

	ifIncarnation, err := s.ifBinding.IfIncarnation(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "cannot read the incarnation of if[%d] for pod %s", swIfIndex, podSpec.Key())
	}

	published := &model.PublishedIfAttachment{
		AttachmentID:  podSpec.AttachmentID,
		SwIfIndex:     swIfIndex,
		IfIncarnation: ifIncarnation,
	}
	err = s.ifBinding.IfAttachmentAdd(published.AttachmentID, published.SwIfIndex, published.IfIncarnation)
	if err != nil {
		return errors.Wrapf(err, "cannot publish the CNI attachment binding for pod %s", podSpec.Key())
	}
	s.log.Infof("pod(add) published IF-4 binding %s", published)

	podSpec.PublishedIfAttachment = published
	if stack != nil {
		stack.Push(s.ifBinding.IfAttachmentDel,
			published.AttachmentID, published.SwIfIndex, published.IfIncarnation)
	}
	return nil
}

// revokeIfAttachment withdraws the binding this pod spec published, using the
// exact tuple that was written (00 §2.12.7 prohibition 4, 02 §8.1 rule 6).
//
// It is best effort: a failed revocation must not stop the destruction of the
// interface, because the plugin's interface-delete callback removes the binding
// anyway (02 §8.1 rule 7) and keeping the interface alive to retry would be an
// availability failure with no safety benefit (00 §2.12.7).
//
// When nothing was published, nothing is guessed: there is no tuple to delete,
// and the callback is the safety net (Issue #135 ruling 5).
func (s *Server) revokeIfAttachment(podSpec *model.LocalPodSpec) {
	if s.ifBinding == nil {
		return
	}
	published := podSpec.PublishedIfAttachment
	if published == nil {
		s.log.Infof("pod(del) no published IF-4 binding for %s, leaving it to the interface delete callback",
			podSpec.Key())
		return
	}
	err := s.ifBinding.IfAttachmentDel(published.AttachmentID, published.SwIfIndex, published.IfIncarnation)
	if err != nil {
		s.log.WithError(err).Warnf("pod(del) could not withdraw IF-4 binding %s, continuing with the interface destruction",
			published)
	} else {
		s.log.Infof("pod(del) withdrew IF-4 binding %s", published)
	}
	podSpec.PublishedIfAttachment = nil
}

// storedHandleStillLive reports whether the interface handle recorded in this
// pod spec is still the live one.
//
// It is the check that keeps the "the VRFs are already there, so the pod is
// already set up" shortcut honest: the stored sw_if_index may since have been
// freed and handed to a different interface, and the incarnation is what
// distinguishes the two (D-31). A mismatch is never repaired by re-resolving
// the binding onto whatever handle is current now (00 §2.12.7 prohibition 4);
// the caller fails.
func (s *Server) storedHandleStillLive(podSpec *model.LocalPodSpec) (bool, error) {
	published := podSpec.PublishedIfAttachment
	if published == nil {
		return false, nil
	}
	if podSpec.TunTapSwIfIndex != published.SwIfIndex {
		return false, nil
	}
	ifIncarnation, err := s.ifBinding.IfIncarnation(published.SwIfIndex)
	if err != nil {
		return false, err
	}
	return ifIncarnation == published.IfIncarnation, nil
}

// rescanDecision is what to do with one durably stored pod spec when the
// lifecycle service starts up again while VPP kept running (Issue #135
// ruling 4).
type rescanDecision int

const (
	// rescanReplay: the stored attachment identity and the stored handle are
	// both still valid, so the binding ADD may be replayed as the exact same
	// tuple, which the plugin treats as idempotent (02 §8.1 rule 4).
	rescanReplay rescanDecision = iota
	// rescanNewLifecycle: the interface this state described is gone, so the
	// old binding no longer means anything. The old tuple is withdrawn and a
	// new interface lifecycle is started, which publishes a new binding under
	// the normal ADD contract (00 §2.12.8).
	rescanNewLifecycle
	// rescanFailClosed: ownership cannot be established exactly. Nothing is
	// guessed and nothing is discarded; the service refuses to become ready.
	rescanFailClosed
)

func (d rescanDecision) String() string {
	switch d {
	case rescanReplay:
		return "replay"
	case rescanNewLifecycle:
		return "new-lifecycle"
	default:
		return "fail-closed"
	}
}

// planRescan decides what to do with one stored pod spec.
//
//   - No attachment identity in the durable state means the identity would have
//     to be reconstructed to publish anything, so it fails closed.
//   - A live handle that still matches the published incarnation is the same
//     interface lifetime: replay.
//   - vppStateLost is true when VPP no longer has the per-pod VRFs, i.e. the
//     interface this state described does not exist any more. Then the old
//     lifetime is cleaned up and a new one is created.
//   - Anything else (VPP kept our VRFs but the handle moved) is contradictory
//     and fails closed rather than re-resolving the binding.
func planRescan(hasAttachmentID bool, vppStateLost bool, handleStillLive bool) rescanDecision {
	if !hasAttachmentID {
		return rescanFailClosed
	}
	if vppStateLost {
		return rescanNewLifecycle
	}
	if handleStillLive {
		return rescanReplay
	}
	return rescanFailClosed
}

// teardownPlan says which of the three independent teardown operations of
// Issue #135 ruling 6 have to run for one DelVppInterface call.
//
// The three operations are independent on purpose: only the namespace-side
// cleanup needs the Pod network namespace to still exist, so a namespace that
// is already gone must not prevent the binding from being withdrawn or the VPP
// interface from being destroyed.
type teardownPlan struct {
	// RevokeBinding withdraws the published IF-4 binding (operation 1).
	RevokeBinding bool
	// DeleteVppInterfaces destroys the VPP-side interfaces (operation 2).
	DeleteVppInterfaces bool
	// CleanupNetns removes the Pod-side configuration (operation 3).
	CleanupNetns bool
}

// planTeardown builds the plan. netnsPresent gates operation 3 and nothing
// else; vppStateStillOwned says whether the VPP state recorded for this pod is
// still provably ours, which is what operation 2 needs so that it cannot
// destroy an interface that reused the stored sw_if_index.
func planTeardown(hasPublishedBinding bool, netnsPresent bool, vppStateStillOwned bool) teardownPlan {
	return teardownPlan{
		RevokeBinding:       hasPublishedBinding,
		DeleteVppInterfaces: vppStateStillOwned,
		CleanupNetns:        netnsPresent,
	}
}
