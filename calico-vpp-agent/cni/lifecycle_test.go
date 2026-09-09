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
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	podinterfacepb "github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/proto/podinterface"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// fakeIfBindingWriter records every IF-4 operation and lets a test decide what
// the plugin answers. It stands in for the cilium_srv6 plugin, which is the
// only part of the binding contract that needs a live VPP.
type fakeIfBindingWriter struct {
	// incarnations answers IfIncarnation. A missing sw_if_index reproduces an
	// srv6_acl_dump that returns no details for it, which is a failure and not
	// "incarnation 0".
	incarnations map[uint32]uint32
	// addErr, when set, fails every IfAttachmentAdd.
	addErr error
	// delErr, when set, fails every IfAttachmentDel.
	delErr error

	calls []string
	// bindings holds the tuples currently published, so that a replay of the
	// exact same tuple can be told from a second, different write.
	bindings map[string]model.PublishedIfAttachment
}

func newFakeIfBindingWriter() *fakeIfBindingWriter {
	return &fakeIfBindingWriter{
		incarnations: make(map[uint32]uint32),
		bindings:     make(map[string]model.PublishedIfAttachment),
	}
}

func (f *fakeIfBindingWriter) IfIncarnation(swIfIndex uint32) (uint32, error) {
	f.calls = append(f.calls, fmt.Sprintf("incarnation(%d)", swIfIndex))
	incarnation, ok := f.incarnations[swIfIndex]
	if !ok {
		return 0, errors.Errorf("srv6 acl dump reported no state for if[%d]", swIfIndex)
	}
	return incarnation, nil
}

func (f *fakeIfBindingWriter) IfAttachmentAdd(attachmentID string, swIfIndex uint32, ifIncarnation uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("add(%s,%d,%d)", attachmentID, swIfIndex, ifIncarnation))
	if f.addErr != nil {
		return f.addErr
	}
	tuple := model.PublishedIfAttachment{
		AttachmentID: attachmentID, SwIfIndex: swIfIndex, IfIncarnation: ifIncarnation,
	}
	if existing, ok := f.bindings[attachmentID]; ok && !existing.Equals(&tuple) {
		// 02 §8.1 rule 5: agreeing on only one side is rejected, never
		// implicitly replaced.
		return errors.Errorf("conflicting binding for %s", attachmentID)
	}
	f.bindings[attachmentID] = tuple
	return nil
}

func (f *fakeIfBindingWriter) IfAttachmentDel(attachmentID string, swIfIndex uint32, ifIncarnation uint32) error {
	f.calls = append(f.calls, fmt.Sprintf("del(%s,%d,%d)", attachmentID, swIfIndex, ifIncarnation))
	if f.delErr != nil {
		return f.delErr
	}
	tuple := model.PublishedIfAttachment{
		AttachmentID: attachmentID, SwIfIndex: swIfIndex, IfIncarnation: ifIncarnation,
	}
	if existing, ok := f.bindings[attachmentID]; ok && existing.Equals(&tuple) {
		delete(f.bindings, attachmentID)
	}
	return nil
}

func testLifecycleServer(writer IfBindingWriter) *Server {
	log := logrus.New()
	log.SetOutput(&strings.Builder{})
	isL3 := true
	config.GetCalicoVppInterfaces().DefaultPodIfSpec = &config.InterfaceSpec{
		NumRxQueues: 1, NumTxQueues: 1, RxQueueSize: 1024, TxQueueSize: 1024, IsL3: &isL3,
	}
	return &Server{
		log:                  logrus.NewEntry(log),
		podInterfaceMap:      make(map[string]model.LocalPodSpec),
		lifecycleProfile:     true,
		ifBinding:            writer,
		primaryInterfaceName: DefaultPrimaryInterfaceName,
	}
}

func validCreateRequest() *podinterfacepb.CreatePodInterfaceRequest {
	return &podinterfacepb.CreatePodInterfaceRequest{
		AttachmentId: strings.Repeat("a", 64) + ":eth0",
		Netns:        "/proc/1234/ns/net",
		Ifname:       "eth0",
		Addresses:    []string{"fd00::1/128"},
		Routes:       []string{"::/0"},
		Mtu:          1500,
	}
}

func statusCode(t *testing.T, err error) codes.Code {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got none")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected a gRPC status, got %v", err)
	}
	return st.Code()
}

// --- request validation -----------------------------------------------------

func TestPodSpecFromCreateRequestKeepsTheAttachmentIdentityVerbatim(t *testing.T) {
	s := testLifecycleServer(newFakeIfBindingWriter())
	request := validCreateRequest()

	podSpec, err := s.podSpecFromCreateRequest(request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if podSpec.AttachmentID != request.AttachmentId {
		t.Fatalf("attachment identity was altered: got %q, want %q",
			podSpec.AttachmentID, request.AttachmentId)
	}
	if podSpec.NetnsName != request.Netns || podSpec.InterfaceName != request.Ifname {
		t.Fatalf("netns/ifname were altered: %q %q", podSpec.NetnsName, podSpec.InterfaceName)
	}
	if podSpec.Mtu != int(request.Mtu) {
		t.Fatalf("mtu %d, want %d", podSpec.Mtu, request.Mtu)
	}
	if len(podSpec.ContainerIPs) != 1 || podSpec.ContainerIPs[0].String() != "fd00::1" {
		t.Fatalf("addresses were not carried over: %v", podSpec.ContainerIPs)
	}
	if len(podSpec.Routes) != 1 || podSpec.Routes[0].String() != "::/0" {
		t.Fatalf("routes were not carried over: %v", podSpec.Routes)
	}
	if podSpec.EnableMemif || podSpec.EnableVCL ||
		podSpec.PortFilteredIfType != model.VppIfTypeUnknown ||
		podSpec.NetworkName != "" {
		t.Fatalf("the pod spec left the v1 supported profile: %+v", podSpec.PodAnnotations)
	}
}

func TestPodSpecFromCreateRequestRejectsInvalidAttachmentIdentities(t *testing.T) {
	s := testLifecycleServer(newFakeIfBindingWriter())

	// 256 bytes: one over the limit of 02 §8.1 rule 1. It must be rejected and
	// never truncated to fit, because a truncated identity is a different
	// identity.
	tooLong := strings.Repeat("a", 256-len(":eth0")) + ":eth0"
	if len(tooLong) != 256 {
		t.Fatalf("test setup: attachment id is %d bytes", len(tooLong))
	}

	for name, attachmentID := range map[string]string{
		"empty":         "",
		"too long":      tooLong,
		"space":         "container id:eth0",
		"tab":           "container\tid:eth0",
		"non ascii":     "cöntainer:eth0",
		"control byte":  "container\x01:eth0",
		"no ifname":     "containerid",
		"wrong ifname":  "containerid:eth1",
		"del character": "container\x7f:eth0",
	} {
		t.Run(name, func(t *testing.T) {
			request := validCreateRequest()
			request.AttachmentId = attachmentID
			podSpec, err := s.podSpecFromCreateRequest(request)
			if code := statusCode(t, err); code != codes.InvalidArgument {
				t.Fatalf("got status %s, want InvalidArgument", code)
			}
			if podSpec != nil {
				t.Fatalf("a rejected request produced a pod spec: %+v", podSpec)
			}
		})
	}

	// The largest accepted identity is exactly 255 bytes.
	atLimit := strings.Repeat("a", 255-len(":eth0")) + ":eth0"
	request := validCreateRequest()
	request.AttachmentId = atLimit
	podSpec, err := s.podSpecFromCreateRequest(request)
	if err != nil {
		t.Fatalf("a 255 byte attachment id was rejected: %v", err)
	}
	if podSpec.AttachmentID != atLimit {
		t.Fatalf("the 255 byte attachment id was altered")
	}
}

func TestPodSpecFromCreateRequestRejectsOutOfScopeAttachments(t *testing.T) {
	s := testLifecycleServer(newFakeIfBindingWriter())

	t.Run("secondary attachment", func(t *testing.T) {
		request := validCreateRequest()
		request.Ifname = "eth1"
		request.AttachmentId = strings.Repeat("a", 64) + ":eth1"
		if code := statusCode(t, mustFail(s, request)); code != codes.InvalidArgument {
			t.Fatalf("got status %s, want InvalidArgument", code)
		}
	})

	t.Run("memif / port based load balancing", func(t *testing.T) {
		request := validCreateRequest()
		request.Ifname = "memif0"
		request.AttachmentId = strings.Repeat("a", 64) + ":memif0"
		if code := statusCode(t, mustFail(s, request)); code != codes.InvalidArgument {
			t.Fatalf("got status %s, want InvalidArgument", code)
		}
	})

	t.Run("ipv4 address", func(t *testing.T) {
		request := validCreateRequest()
		request.Addresses = []string{"10.0.0.1/32"}
		if code := statusCode(t, mustFail(s, request)); code != codes.InvalidArgument {
			t.Fatalf("got status %s, want InvalidArgument", code)
		}
	})

	t.Run("non host address", func(t *testing.T) {
		request := validCreateRequest()
		request.Addresses = []string{"fd00::1/64"}
		if code := statusCode(t, mustFail(s, request)); code != codes.InvalidArgument {
			t.Fatalf("got status %s, want InvalidArgument", code)
		}
	})

	t.Run("no address", func(t *testing.T) {
		request := validCreateRequest()
		request.Addresses = nil
		if code := statusCode(t, mustFail(s, request)); code != codes.InvalidArgument {
			t.Fatalf("got status %s, want InvalidArgument", code)
		}
	})

	t.Run("no netns", func(t *testing.T) {
		request := validCreateRequest()
		request.Netns = ""
		if code := statusCode(t, mustFail(s, request)); code != codes.InvalidArgument {
			t.Fatalf("got status %s, want InvalidArgument", code)
		}
	})
}

func mustFail(s *Server, request *podinterfacepb.CreatePodInterfaceRequest) error {
	_, err := s.podSpecFromCreateRequest(request)
	return err
}

// --- binding publication ----------------------------------------------------

func publishablePodSpec() *model.LocalPodSpec {
	podSpec := &model.LocalPodSpec{
		InterfaceName:      "eth0",
		NetnsName:          "/proc/1234/ns/net",
		AttachmentID:       "container:eth0",
		LocalPodSpecStatus: *model.NewLocalPodSpecStatus(),
	}
	podSpec.TunTapSwIfIndex = 7
	return podSpec
}

func TestPublishIfAttachmentPublishesTheCurrentHandle(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[7] = 3
	s := testLifecycleServer(writer)
	podSpec := publishablePodSpec()
	stack := &vpplink.CleanupStack{}

	if err := s.publishIfAttachment(podSpec, stack); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"incarnation(7)", "add(container:eth0,7,3)"}
	if got := strings.Join(writer.calls, " "); got != strings.Join(want, " ") {
		t.Fatalf("call sequence %q, want %q", got, strings.Join(want, " "))
	}
	if podSpec.PublishedIfAttachment == nil ||
		podSpec.PublishedIfAttachment.IfIncarnation != 3 ||
		podSpec.PublishedIfAttachment.SwIfIndex != 7 ||
		podSpec.PublishedIfAttachment.AttachmentID != "container:eth0" {
		t.Fatalf("the published tuple was not recorded: %s", podSpec.PublishedIfAttachment)
	}
}

// An srv6_acl_dump that returns no details means the plugin does not know this
// interface. Reading that as incarnation 0 would publish a binding against a
// handle nobody confirmed.
func TestPublishIfAttachmentFailsOnAnEmptyAclDump(t *testing.T) {
	writer := newFakeIfBindingWriter() // no incarnation registered for if[7]
	s := testLifecycleServer(writer)
	podSpec := publishablePodSpec()
	stack := &vpplink.CleanupStack{}

	err := s.publishIfAttachment(podSpec, stack)
	if err == nil {
		t.Fatalf("an empty acl dump was accepted")
	}
	for _, call := range writer.calls {
		if strings.HasPrefix(call, "add(") {
			t.Fatalf("a binding was published without a confirmed handle: %v", writer.calls)
		}
	}
	if podSpec.PublishedIfAttachment != nil {
		t.Fatalf("a tuple was recorded although nothing was published")
	}
}

// A failed binding ADD has to roll the interface back and fail the CNI ADD
// (00 §2.12.9 completion criteria 1 and 3). The rollback is the cleanup stack
// AddVppInterface passes in, so the test drives the same stack the production
// path uses.
func TestPublishIfAttachmentFailureRollsTheInterfaceBack(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[7] = 3
	writer.addErr = errors.New("plugin refused the binding")
	s := testLifecycleServer(writer)
	podSpec := publishablePodSpec()

	interfaceDeleted := false
	stack := &vpplink.CleanupStack{}
	stack.Push(func(uint32) error { interfaceDeleted = true; return nil }, uint32(7))

	err := s.publishIfAttachment(podSpec, stack)
	if err == nil {
		t.Fatalf("a refused binding was reported as success")
	}
	if podSpec.PublishedIfAttachment != nil {
		t.Fatalf("a refused binding was recorded as published")
	}

	// This is what AddVppInterface does on its error path.
	stack.Execute()
	if !interfaceDeleted {
		t.Fatalf("the interface was not rolled back after the binding ADD failed")
	}
	// The rollback must not withdraw a binding that was never written.
	for _, call := range writer.calls {
		if strings.HasPrefix(call, "del(") {
			t.Fatalf("the rollback withdrew a binding that was never published: %v", writer.calls)
		}
	}
}

func TestPublishIfAttachmentSchedulesTheWithdrawalOfWhatItWrote(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[7] = 3
	s := testLifecycleServer(writer)
	podSpec := publishablePodSpec()
	stack := &vpplink.CleanupStack{}

	if err := s.publishIfAttachment(podSpec, stack); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	stack.Execute()
	if len(writer.bindings) != 0 {
		t.Fatalf("the rollback left the binding published: %v", writer.bindings)
	}
	last := writer.calls[len(writer.calls)-1]
	if last != "del(container:eth0,7,3)" {
		t.Fatalf("the rollback withdrew %q, want the exact tuple that was written", last)
	}
}

// Re-sending the exact same tuple is the only idempotent case (02 §8.1 rule 4).
func TestPublishIfAttachmentReplayOfTheExactTupleIsIdempotent(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[7] = 3
	s := testLifecycleServer(writer)
	podSpec := publishablePodSpec()

	if err := s.publishIfAttachment(podSpec, nil); err != nil {
		t.Fatalf("first publication failed: %v", err)
	}
	first := *podSpec.PublishedIfAttachment
	if err := s.publishIfAttachment(podSpec, nil); err != nil {
		t.Fatalf("replaying the exact tuple failed: %v", err)
	}
	if !first.Equals(podSpec.PublishedIfAttachment) {
		t.Fatalf("the replay changed the published tuple: %s -> %s", &first, podSpec.PublishedIfAttachment)
	}
	if len(writer.bindings) != 1 {
		t.Fatalf("the replay produced a second binding: %v", writer.bindings)
	}
}

// A publication with no attachment identity would have to reconstruct one,
// which 00 §2.12.7 prohibition 1 forbids.
func TestPublishIfAttachmentRefusesToInventAnIdentity(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[7] = 3
	s := testLifecycleServer(writer)
	podSpec := publishablePodSpec()
	podSpec.AttachmentID = ""

	if err := s.publishIfAttachment(podSpec, nil); err == nil {
		t.Fatalf("a pod spec without an attachment identity was published")
	}
	if len(writer.calls) != 0 {
		t.Fatalf("the plugin was contacted for a pod spec with no identity: %v", writer.calls)
	}
}

// --- binding revocation -----------------------------------------------------

func TestRevokeIfAttachmentWithdrawsTheExactStoredTuple(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[7] = 9 // the live incarnation moved on
	s := testLifecycleServer(writer)
	podSpec := publishablePodSpec()
	podSpec.PublishedIfAttachment = &model.PublishedIfAttachment{
		AttachmentID: "container:eth0", SwIfIndex: 7, IfIncarnation: 3,
	}

	s.revokeIfAttachment(podSpec)

	if len(writer.calls) != 1 || writer.calls[0] != "del(container:eth0,7,3)" {
		t.Fatalf("revocation used %v, want the stored tuple and no fresh resolution", writer.calls)
	}
	if podSpec.PublishedIfAttachment != nil {
		t.Fatalf("the published tuple was not cleared after the withdrawal")
	}
}

func TestRevokeIfAttachmentGuessesNothingWhenNothingWasPublished(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[7] = 3
	s := testLifecycleServer(writer)
	podSpec := publishablePodSpec()

	s.revokeIfAttachment(podSpec)

	if len(writer.calls) != 0 {
		t.Fatalf("a binding was guessed for a pod spec that published none: %v", writer.calls)
	}
}

// A failed withdrawal must not become a reason to keep the interface alive: the
// plugin's interface delete callback removes the binding anyway (02 §8.1
// rule 7), so retrying forever would only cost availability.
func TestRevokeIfAttachmentToleratesAFailedWithdrawal(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.delErr = errors.New("plugin refused the withdrawal")
	s := testLifecycleServer(writer)
	podSpec := publishablePodSpec()
	podSpec.PublishedIfAttachment = &model.PublishedIfAttachment{
		AttachmentID: "container:eth0", SwIfIndex: 7, IfIncarnation: 3,
	}

	s.revokeIfAttachment(podSpec) // must not panic and must not block
	if len(writer.calls) != 1 {
		t.Fatalf("the withdrawal was not attempted: %v", writer.calls)
	}
}

// --- stored handle verification ---------------------------------------------

func TestStoredHandleStillLive(t *testing.T) {
	for name, tc := range map[string]struct {
		incarnations map[uint32]uint32
		published    *model.PublishedIfAttachment
		swIfIndex    uint32
		want         bool
		wantErr      bool
	}{
		"same interface lifetime": {
			incarnations: map[uint32]uint32{7: 3},
			published:    &model.PublishedIfAttachment{AttachmentID: "c:eth0", SwIfIndex: 7, IfIncarnation: 3},
			swIfIndex:    7,
			want:         true,
		},
		"index reused by another interface": {
			incarnations: map[uint32]uint32{7: 4},
			published:    &model.PublishedIfAttachment{AttachmentID: "c:eth0", SwIfIndex: 7, IfIncarnation: 3},
			swIfIndex:    7,
			want:         false,
		},
		"interface gone": {
			incarnations: map[uint32]uint32{},
			published:    &model.PublishedIfAttachment{AttachmentID: "c:eth0", SwIfIndex: 7, IfIncarnation: 3},
			swIfIndex:    7,
			wantErr:      true,
		},
		"nothing published": {
			incarnations: map[uint32]uint32{7: 3},
			published:    nil,
			swIfIndex:    7,
			want:         false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			writer := newFakeIfBindingWriter()
			writer.incarnations = tc.incarnations
			s := testLifecycleServer(writer)
			podSpec := publishablePodSpec()
			podSpec.TunTapSwIfIndex = tc.swIfIndex
			podSpec.PublishedIfAttachment = tc.published

			live, err := s.storedHandleStillLive(podSpec)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if live != tc.want {
				t.Fatalf("got %v, want %v", live, tc.want)
			}
		})
	}
}

// --- teardown decomposition -------------------------------------------------

// Teardown is three independent operations, and only the namespace-side
// cleanup needs the Pod netns (Issue #135 ruling 6). A netns that is already
// gone must still withdraw the binding and destroy the VPP interface.
func TestPlanTeardownDoesNotLetAMissingNetnsSkipTheFirstTwoOperations(t *testing.T) {
	plan := planTeardown(true /* hasPublishedBinding */, false /* netnsPresent */, true /* vppStateStillOwned */)
	if !plan.RevokeBinding {
		t.Fatalf("a missing netns skipped the binding withdrawal")
	}
	if !plan.DeleteVppInterfaces {
		t.Fatalf("a missing netns skipped the VPP interface destruction")
	}
	if plan.CleanupNetns {
		t.Fatalf("the namespace-side cleanup was planned without a netns")
	}
}

// The plan above is only worth anything if DelVppInterface follows it. This
// drives the real function with a netns that does not exist and asserts that
// the binding was already withdrawn by the time it reaches VPP: before the
// decomposition, a missing netns returned early and neither the withdrawal nor
// the interface destruction happened at all.
//
// The call cannot get past v4v6VrfsExistInVPP without a live VPP, so the VPP
// interaction is what ends it; everything asserted here happens strictly
// before that point.
func TestDelVppInterfaceWithdrawsTheBindingBeforeReachingVPP(t *testing.T) {
	writer := newFakeIfBindingWriter()
	s := testLifecycleServer(writer)
	podSpec := publishablePodSpec()
	podSpec.NetnsName = "/proc/does-not-exist/ns/net"
	podSpec.PublishedIfAttachment = &model.PublishedIfAttachment{
		AttachmentID: "container:eth0", SwIfIndex: 7, IfIncarnation: 3,
	}

	defer func() {
		// s.vpp is nil, so the VPP-side teardown cannot run here.
		_ = recover()
		if len(writer.calls) == 0 {
			t.Errorf("a missing netns skipped the binding withdrawal entirely")
			return
		}
		if writer.calls[0] != "del(container:eth0,7,3)" {
			t.Errorf("the first teardown operation was %q, want the withdrawal of the exact stored tuple",
				writer.calls[0])
		}
	}()

	s.DelVppInterface(podSpec)
}

func TestPlanTeardown(t *testing.T) {
	full := planTeardown(true, true, true)
	if !full.RevokeBinding || !full.DeleteVppInterfaces || !full.CleanupNetns {
		t.Fatalf("the complete teardown is incomplete: %+v", full)
	}
	// Nothing published: there is no exact tuple to withdraw, and the interface
	// delete callback is the safety net.
	noBinding := planTeardown(false, true, true)
	if noBinding.RevokeBinding {
		t.Fatalf("a withdrawal was planned for a pod that published nothing")
	}
	// The recorded handle is not provably ours any more: destroying it could
	// tear down another Pod's interface.
	notOurs := planTeardown(true, true, false)
	if notOurs.DeleteVppInterfaces {
		t.Fatalf("an unprovable handle was scheduled for destruction")
	}
}

// --- restart reconciliation --------------------------------------------------

func TestPlanRescan(t *testing.T) {
	for name, tc := range map[string]struct {
		hasAttachmentID bool
		vppStateLost    bool
		handleStillLive bool
		want            rescanDecision
	}{
		"same tuple still live": {true, false, true, rescanReplay},
		"vpp lost its state":    {true, true, false, rescanNewLifecycle},
		"handle moved under us": {true, false, false, rescanFailClosed},
		"no stored identity":    {false, false, true, rescanFailClosed},
		"no identity and no vpp state": {
			hasAttachmentID: false, vppStateLost: true, handleStillLive: false, want: rescanFailClosed,
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := planRescan(tc.hasAttachmentID, tc.vppStateLost, tc.handleStillLive)
			if got != tc.want {
				t.Fatalf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// --- the publication barrier at the service boundary ------------------------

func testLifecycleService(t *testing.T, writer IfBindingWriter) (*Server, *lifecycleService) {
	t.Helper()
	s := testLifecycleServer(writer)
	s.stateFilename = filepath.Join(t.TempDir(), "calicovpp_state.json")
	return s, &lifecycleService{server: s}
}

// CreatePodInterface must not reply until the binding ADD was acknowledged
// (00 §2.12.6). A creation step that produced an interface but published no
// binding therefore has to fail the RPC, not return a handle: replying first
// and publishing afterwards is exactly the asynchronous write the contract
// forbids.
func TestCreatePodInterfaceRefusesToReplyWithoutAPublishedBinding(t *testing.T) {
	writer := newFakeIfBindingWriter()
	s, service := testLifecycleService(t, writer)
	s.createVppInterfaceFn = func(podSpec *model.LocalPodSpec, doHostSideConf bool) (uint32, error) {
		// The interface exists, but nothing was published for it.
		podSpec.TunTapSwIfIndex = 7
		return 7, nil
	}

	reply, err := service.CreatePodInterface(context.Background(), validCreateRequest())
	if err == nil {
		t.Fatalf("the service replied %v although no binding was published", reply)
	}
	if code := statusCode(t, err); code != codes.Internal {
		t.Fatalf("got status %s, want Internal", code)
	}
}

func TestCreatePodInterfaceRepliesWithThePublishedHandle(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[7] = 3
	s, service := testLifecycleService(t, writer)
	s.createVppInterfaceFn = func(podSpec *model.LocalPodSpec, doHostSideConf bool) (uint32, error) {
		podSpec.TunTapSwIfIndex = 7
		stack := &vpplink.CleanupStack{}
		if err := s.publishIfAttachment(podSpec, stack); err != nil {
			return vpplink.InvalidID, err
		}
		return 7, nil
	}

	request := validCreateRequest()
	reply, err := service.CreatePodInterface(context.Background(), request)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reply.SwIfIndex != 7 || reply.IfIncarnation != 3 {
		t.Fatalf("reply carried (%d, %d), want the published handle (7, 3)", reply.SwIfIndex, reply.IfIncarnation)
	}
	stored, ok := s.podInterfaceMap[model.LocalPodSpecKey(request.Netns, request.Ifname)]
	if !ok {
		t.Fatalf("the attachment was not recorded")
	}
	if stored.AttachmentID != request.AttachmentId {
		t.Fatalf("the stored identity is %q, want %q", stored.AttachmentID, request.AttachmentId)
	}
}

// A failing interface creation must surface as an error, never as a reply.
func TestCreatePodInterfaceFailsWhenTheInterfaceCannotBeCreated(t *testing.T) {
	writer := newFakeIfBindingWriter()
	s, service := testLifecycleService(t, writer)
	s.createVppInterfaceFn = func(podSpec *model.LocalPodSpec, doHostSideConf bool) (uint32, error) {
		return vpplink.InvalidID, errors.New("binding ADD refused")
	}

	if _, err := service.CreatePodInterface(context.Background(), validCreateRequest()); err == nil {
		t.Fatalf("a failed creation was reported as success")
	}
	if len(s.podInterfaceMap) != 0 {
		t.Fatalf("a failed creation left durable state behind: %v", s.podInterfaceMap)
	}
}

// The service refuses to serve while durable ownership is unresolved
// (Issue #135 ruling 4).
func TestCreatePodInterfaceRefusesWhileNotReady(t *testing.T) {
	writer := newFakeIfBindingWriter()
	s, service := testLifecycleService(t, writer)
	s.notReadyReason = "incompatible durable lifecycle state"

	_, err := service.CreatePodInterface(context.Background(), validCreateRequest())
	if code := statusCode(t, err); code != codes.FailedPrecondition {
		t.Fatalf("got status %s, want FailedPrecondition", code)
	}
}

func TestDeletePodInterfaceReportsAnUnknownAttachmentAsNotFound(t *testing.T) {
	writer := newFakeIfBindingWriter()
	_, service := testLifecycleService(t, writer)

	_, err := service.DeletePodInterface(context.Background(), &podinterfacepb.DeletePodInterfaceRequest{
		AttachmentId: "container:eth0",
		Netns:        "/proc/1234/ns/net",
		Ifname:       "eth0",
	})
	if code := statusCode(t, err); code != codes.NotFound {
		t.Fatalf("got status %s, want NotFound", code)
	}
}

func TestDeletePodInterfaceTearsTheStoredAttachmentDown(t *testing.T) {
	writer := newFakeIfBindingWriter()
	s, service := testLifecycleService(t, writer)
	key := model.LocalPodSpecKey("/proc/1234/ns/net", "eth0")
	s.podInterfaceMap[key] = model.LocalPodSpec{
		InterfaceName: "eth0",
		NetnsName:     "/proc/1234/ns/net",
		AttachmentID:  "container:eth0",
	}
	torndown := ""
	s.delVppInterfaceFn = func(podSpec *model.LocalPodSpec) { torndown = podSpec.AttachmentID }

	if _, err := service.DeletePodInterface(context.Background(), &podinterfacepb.DeletePodInterfaceRequest{
		AttachmentId: "container:eth0",
		Netns:        "/proc/1234/ns/net",
		Ifname:       "eth0",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if torndown != "container:eth0" {
		t.Fatalf("teardown ran for %q", torndown)
	}
	if _, ok := s.podInterfaceMap[key]; ok {
		t.Fatalf("the attachment is still recorded after the delete")
	}
}

// Deleting an interface under a different identity than the one that was
// published would withdraw a binding the request does not own.
func TestDeletePodInterfaceRefusesAMismatchedIdentity(t *testing.T) {
	writer := newFakeIfBindingWriter()
	s, service := testLifecycleService(t, writer)
	key := model.LocalPodSpecKey("/proc/1234/ns/net", "eth0")
	s.podInterfaceMap[key] = model.LocalPodSpec{
		InterfaceName: "eth0",
		NetnsName:     "/proc/1234/ns/net",
		AttachmentID:  "container-a:eth0",
	}
	s.delVppInterfaceFn = func(podSpec *model.LocalPodSpec) {
		t.Fatalf("teardown ran for a mismatched identity")
	}

	_, err := service.DeletePodInterface(context.Background(), &podinterfacepb.DeletePodInterfaceRequest{
		AttachmentId: "container-b:eth0",
		Netns:        "/proc/1234/ns/net",
		Ifname:       "eth0",
	})
	if code := statusCode(t, err); code != codes.NotFound {
		t.Fatalf("got status %s, want NotFound", code)
	}
	if _, ok := s.podInterfaceMap[key]; !ok {
		t.Fatalf("a refused delete dropped the stored attachment")
	}
}

// --- restart reconciliation, end to end over the durable state ---------------

func TestRescanLifecycleStateKeepsIncompatibleStateAndRefusesToServe(t *testing.T) {
	dir := t.TempDir()
	oldPath := filepath.Join(dir, fmt.Sprintf("calicovpp_state.v%d.json", config.CniServerStateFileVersion-1))
	if err := os.WriteFile(oldPath, []byte(`{"version":1,"podSpecs":{}}`), 0600); err != nil {
		t.Fatalf("cannot write the old state: %v", err)
	}

	writer := newFakeIfBindingWriter()
	s := testLifecycleServer(writer)
	s.stateFilename = filepath.Join(dir, fmt.Sprintf("calicovpp_state.v%d.json", config.CniServerStateFileVersion))

	s.rescanLifecycleState()

	if s.LifecycleNotReadyReason() == "" {
		t.Fatalf("an incompatible durable state left the service ready")
	}
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("the incompatible state file was discarded: %v", err)
	}
}

func TestRescanLifecycleStateFailsClosedWithoutAStoredIdentity(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, fmt.Sprintf("calicovpp_state.v%d.json", config.CniServerStateFileVersion))
	state := model.NewCniServerState(map[string]model.LocalPodSpec{
		"netns:/proc/1/ns/net,if:eth0": {
			InterfaceName: "eth0",
			NetnsName:     "/proc/1/ns/net",
			// No AttachmentID: the identity that was published is unknown.
		},
	})
	if err := model.PersistCniServerState(state, path); err != nil {
		t.Fatalf("cannot write the state: %v", err)
	}

	writer := newFakeIfBindingWriter()
	s := testLifecycleServer(writer)
	s.stateFilename = path
	// The VRF lookup would need a live VPP; short-circuit it, since the
	// decision under test is taken from the absence of the identity.
	s.createVppInterfaceFn = func(podSpec *model.LocalPodSpec, doHostSideConf bool) (uint32, error) {
		t.Fatalf("an interface was created for a pod spec with no attachment identity")
		return vpplink.InvalidID, nil
	}

	func() {
		// v4v6VrfsExistInVPP needs a live VPP and ends the call; the decision
		// this test asserts on is taken from the state alone, so run it and
		// look at what was recorded.
		defer func() { _ = recover() }()
		s.rescanLifecycleState()
	}()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("the state file was discarded: %v", err)
	}
}

// --- explicit dependencies --------------------------------------------------

// The lifecycle profile has no Calico IPAM authority behind it. That is stated
// by constructing NoSNATPolicy, not by leaving the dependency nil: a nil
// dependency and an authority that decided no address needs SNAT would
// otherwise be the same value (Issue #135 pre-merge item 1).
func TestNewLifecycleServerConstructsAnExplicitSNATPolicy(t *testing.T) {
	log := logrus.New()
	log.SetOutput(&strings.Builder{})
	s := NewLifecycleServer(nil /* vpp */, newFakeIfBindingWriter(), logrus.NewEntry(log))

	if s.snatPolicy == nil {
		t.Fatalf("the lifecycle server was built without an SNAT policy")
	}
	if _, ok := s.snatPolicy.(common.NoSNATPolicy); !ok {
		t.Fatalf("the lifecycle server's SNAT policy is %T, want common.NoSNATPolicy", s.snatPolicy)
	}
	if s.snatPolicy.NeedsSNAT(&net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(128, 128)}) {
		t.Fatalf("NoSNATPolicy asked for SNAT")
	}
}

// --- the primary attachment is the only supported one -----------------------

// v1 serves the Pod's primary attachment and refuses everything else, at the
// RPC boundary, before anything is created. A secondary attachment is neither
// ignored nor folded into the primary one: either would break the invariant
// that one CNI attachment identity names exactly one interface (D-68).
func TestCreatePodInterfaceRejectsEveryNonPrimaryInterfaceName(t *testing.T) {
	for _, ifname := range []string{
		"eth1",   // the multinet secondary attachment
		"net1",   // its other spelling
		"eth2",   //
		"memif0", // the second interface of a port-based-load-balancing pod
		"eth0x",  // not a prefix match
		"eth",    // not a prefix match the other way round
		"ETH0",   // not case insensitive
		" eth0",  // not trimmed
		"eth0 ",  //
	} {
		t.Run(ifname, func(t *testing.T) {
			writer := newFakeIfBindingWriter()
			s := testLifecycleServer(writer)
			realized := false
			s.realizePodInterfacesFn = func(*model.LocalPodSpec, *vpplink.CleanupStack, bool) (uint32, bool, error) {
				realized = true
				return vpplink.InvalidID, false, nil
			}

			request := validCreateRequest()
			request.Ifname = ifname
			request.AttachmentId = strings.Repeat("a", 64) + ":" + ifname

			reply, err := (&lifecycleService{server: s}).CreatePodInterface(context.Background(), request)

			if err == nil {
				t.Fatalf("interface %q was accepted: %v", ifname, reply)
			}
			if code := statusCode(t, err); code != codes.InvalidArgument {
				t.Fatalf("interface %q was refused with %s, want InvalidArgument", ifname, code)
			}
			if realized {
				t.Fatalf("interface %q was refused only after an interface had been created for it", ifname)
			}
			if len(s.podInterfaceMap) != 0 {
				t.Fatalf("a refused attachment was recorded: %v", s.podInterfaceMap)
			}
			if len(writer.bindings) != 0 {
				t.Fatalf("a refused attachment published a binding: %v", writer.bindings)
			}
			if len(writer.calls) != 0 {
				t.Fatalf("a refused attachment reached the plugin: %v", writer.calls)
			}
		})
	}
}

// The delete side answers the same question the create side does, and answers
// it before it looks at its stored state (Issue #135 merge condition 2).
//
// An unsupported interface name and an attachment that is already gone are two
// different answers: NOT_FOUND is what the CNI DEL turns into an idempotent
// success, so answering an unsupported request out of the map would make "this
// service does not serve eth1" indistinguishable from "eth1 was already
// deleted", and a caller that is attaching secondary interfaces would never
// learn that they are unsupported.
//
// Each name is refused in both states the stored map can be in, and the two
// states catch different mistakes:
//
//   - "absent" is the case the ordering is about. Nothing is stored under the
//     key, so a validation placed after the lookup answers NOT_FOUND — the very
//     conflation this test exists to prevent — while the validation placed
//     before it answers INVALID_ARGUMENT.
//   - "stored" is the case a missing validation shows up in: the lookup hits,
//     and without the check the attachment would be torn down and dropped.
func TestDeletePodInterfaceRejectsEveryNonPrimaryInterfaceName(t *testing.T) {
	for _, ifname := range []string{
		"eth1",   // the multinet secondary attachment
		"net1",   // its other spelling
		"memif0", // the second interface of a port-based-load-balancing pod
		"eth0x",  // not a prefix match
		"eth",    // not a prefix match the other way round
		"ETH0",   // not case insensitive
		" eth0",  // not trimmed
		"eth0 ",  //
	} {
		for _, stored := range []bool{false, true} {
			name := ifname + "/absent"
			if stored {
				name = ifname + "/stored"
			}
			t.Run(name, func(t *testing.T) {
				writer := newFakeIfBindingWriter()
				s, service := testLifecycleService(t, writer)
				netns := "/proc/1234/ns/net"
				attachmentID := "container:" + ifname
				key := model.LocalPodSpecKey(netns, ifname)
				if stored {
					s.podInterfaceMap[key] = model.LocalPodSpec{
						InterfaceName: ifname,
						NetnsName:     netns,
						AttachmentID:  attachmentID,
					}
				}
				s.delVppInterfaceFn = func(*model.LocalPodSpec) {
					t.Fatalf("teardown ran for the unsupported interface %q", ifname)
				}

				_, err := service.DeletePodInterface(context.Background(), &podinterfacepb.DeletePodInterfaceRequest{
					AttachmentId: attachmentID,
					Netns:        netns,
					Ifname:       ifname,
				})

				if code := statusCode(t, err); code != codes.InvalidArgument {
					t.Fatalf("deleting %q was refused with %s, want InvalidArgument", ifname, code)
				}
				if _, ok := s.podInterfaceMap[key]; ok != stored {
					t.Fatalf("a refused delete changed the stored attachment (stored=%t)", stored)
				}
				if len(writer.calls) != 0 {
					t.Fatalf("a refused delete reached the plugin: %v", writer.calls)
				}
			})
		}
	}
}

// The supported name with nothing stored for it stays NOT_FOUND, which is what
// the CNI DEL treats as an idempotent success. Only the unsupported name became
// a contract violation; deleting the primary attachment twice did not.
func TestDeletePodInterfaceReportsAnAbsentPrimaryAttachmentAsNotFound(t *testing.T) {
	writer := newFakeIfBindingWriter()
	s, service := testLifecycleService(t, writer)
	s.delVppInterfaceFn = func(*model.LocalPodSpec) {
		t.Fatalf("teardown ran for an attachment that is not stored")
	}

	_, err := service.DeletePodInterface(context.Background(), &podinterfacepb.DeletePodInterfaceRequest{
		AttachmentId: "container:" + DefaultPrimaryInterfaceName,
		Netns:        "/proc/1234/ns/net",
		Ifname:       DefaultPrimaryInterfaceName,
	})

	if code := statusCode(t, err); code != codes.NotFound {
		t.Fatalf("deleting an absent %s was refused with %s, want NotFound",
			DefaultPrimaryInterfaceName, code)
	}
	if len(writer.calls) != 0 {
		t.Fatalf("a delete of an unknown attachment reached the plugin: %v", writer.calls)
	}
}

// The name that is served is the one the server was configured with, and the
// constant is that configuration's value rather than a rule of its own.
func TestTheSupportedPrimaryInterfaceNameIsTheConfiguredOne(t *testing.T) {
	if DefaultPrimaryInterfaceName != "eth0" {
		t.Fatalf("the default primary interface name is %q, want eth0", DefaultPrimaryInterfaceName)
	}

	s := testLifecycleServer(newFakeIfBindingWriter())
	if err := s.validatePrimaryInterfaceName(DefaultPrimaryInterfaceName); err != nil {
		t.Fatalf("the configured primary interface name was refused: %v", err)
	}

	// Reconfiguring which name is primary moves the whole rule with it: the
	// old name stops being served, and the new one starts.
	s.SetPrimaryInterfaceName("eth9")
	if err := s.validatePrimaryInterfaceName("eth9"); err != nil {
		t.Fatalf("the reconfigured primary interface name was refused: %v", err)
	}
	if err := s.validatePrimaryInterfaceName("eth0"); err == nil {
		t.Fatalf("eth0 is still served after the primary interface name was changed")
	}
}

// The refusal says which name is served, so an operator can tell a
// misconfiguration from an unsupported feature.
func TestTheRefusalNamesTheSupportedAttachment(t *testing.T) {
	s := testLifecycleServer(newFakeIfBindingWriter())
	err := s.validatePrimaryInterfaceName("eth1")
	if err == nil {
		t.Fatalf("eth1 was accepted")
	}
	message := status.Convert(err).Message()
	if !strings.Contains(message, "eth0") || !strings.Contains(message, "eth1") {
		t.Fatalf("the refusal is %q, want it to name both the supported and the requested interface", message)
	}
}
