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
	"io"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/podinterface"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// A Pod-side device route that cannot be installed means different things to
// the two profiles, and the difference is a policy decision rather than a
// property of the code that installs routes (Issue #135 merge condition 1):
//
//	LifecycleProfile: error -> cleanup stack -> no binding published -> CNI ADD failure
//	CalicoProfile:    logged, and the ADD continues
//
// The tests below run the real AddVppInterface, the real cleanup stack, the
// real binding publication and the real per-profile route step. Only two things
// are replaced: the part of the ADD that needs a live VPP (the seam
// realizePodInterfacesFn, as in publication_barrier_test.go) and the netlink
// route writer, which has no Pod netns to write into here.
//
// The two tests differ in exactly one input, the driver's profile, so what
// differs in the outcome is attributable to the profile and to nothing else.

const (
	routeFailureSwIfIndex   = uint32(11)
	routeFailureIncarnation = uint32(5)
	routeFailureLinkIndex   = 42
	routeFailureAttachment  = "container:eth0"
)

// routeFailurePodSpec is a v1 lifecycle pod spec with one device route, which
// is the route the netlink writer below refuses.
func routeFailurePodSpec() *model.LocalPodSpec {
	isL3 := true
	_, defaultRoute, err := net.ParseCIDR("::/0")
	if err != nil {
		panic(err)
	}
	return &model.LocalPodSpec{
		InterfaceName: barrierTestInterfaceName,
		NetnsName:     hostNetnsPath,
		AttachmentID:  routeFailureAttachment,
		ContainerIPs:  []net.IP{net.ParseIP("fd00::1")},
		Routes:        []net.IPNet{*defaultRoute},
		PodAnnotations: model.PodAnnotations{
			IfSpec:        lifecycleIfSpec(isL3),
			PBLMemifSpec:  lifecycleIfSpec(isL3),
			DefaultIfType: model.VppIfTypeTunTap,
		},
		LocalPodSpecStatus: *model.NewLocalPodSpecStatus(),
	}
}

// routeFailureTestServer builds a server whose Pod-side route step is the real
// one of profile, run against a netlink writer that fails every route with
// routeErr. rollbacks counts how many times the interface the fake dataplane
// "created" was rolled back, that is, how many times the cleanup stack ran.
func routeFailureTestServer(
	t *testing.T,
	writer *fakeIfBindingWriter,
	profile podinterface.PodInterfaceProfile,
	routeErr error,
) (s *Server, rollbacks *int, routeAttempts *int) {
	t.Helper()
	s = testLifecycleServer(writer)
	s.availableBuffers = 1 << 30
	s.stateFilename = filepath.Join(t.TempDir(), "cni-server-state")
	s.vrfsExistInVppFn = func(*model.LocalPodSpec) bool { return false }

	log := logrus.New()
	log.SetOutput(io.Discard)
	// The driver is the real one; only its profile differs between the tests.
	// It is given no VppLink because nothing it does here reaches VPP.
	s.tuntapDriver = podinterface.NewTunTapPodInterfaceDriver(
		nil /* vpp */, logrus.NewEntry(log), common.NoSNATPolicy{}, profile)

	rolledBack := 0
	rollbacks = &rolledBack
	attempts := 0
	routeAttempts = &attempts

	s.realizePodInterfacesFn = func(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, doHostSideConf bool) (uint32, bool, error) {
		podSpec.TunTapSwIfIndex = routeFailureSwIfIndex
		// What the real drivers push: undoing the interface they just created.
		// Counting it is how the test observes the rollback.
		stack.Push(func(uint32) error { rolledBack++; return nil }, routeFailureSwIfIndex)

		hasv4, hasv6 := podSpec.Hasv46()
		failingRouteAdd := func(*netlink.Route) error {
			attempts++
			return routeErr
		}
		if err := s.tuntapDriver.AddPodRoutes(
			failingRouteAdd, routeFailureLinkIndex, podSpec, routeFailureSwIfIndex, hasv4, hasv6,
		); err != nil {
			// The Pod-side configuration is part of interface creation, so its
			// failure is the interface creation failing.
			return vpplink.InvalidID, false, err
		}
		return vpplink.InvalidID, false, nil
	}
	return s, rollbacks, routeAttempts
}

// The lifecycle service owns the L3 realization of the attachment, so it must
// not answer a CNI ADD with success while it knows a device route it was told
// to install is missing. The failure fails the ADD, the cleanup stack rolls the
// interface back, and no binding is published: the attachment never becomes
// visible to anything.
func TestLifecycleProfileFailsTheAddWhenAPodRouteCannotBeInstalled(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[routeFailureSwIfIndex] = routeFailureIncarnation
	routeErr := errors.New("network is unreachable")
	s, rollbacks, attempts := routeFailureTestServer(t, writer, podinterface.LifecycleProfile, routeErr)
	podSpec := routeFailurePodSpec()

	swIfIndex, err := s.AddVppInterface(podSpec, false /* doHostSideConf */)

	if err == nil {
		t.Fatalf("AddVppInterface reported success although a device route could not be installed")
	}
	if !strings.Contains(err.Error(), routeErr.Error()) {
		t.Fatalf("the ADD failed with %v, which does not report the route failure", err)
	}
	if swIfIndex != vpplink.InvalidID {
		t.Fatalf("AddVppInterface returned interface %d after a failed route, want InvalidID", swIfIndex)
	}
	if *attempts != 1 {
		t.Fatalf("the route was attempted %d times, want exactly 1", *attempts)
	}
	if *rollbacks != 1 {
		t.Fatalf("the interface was rolled back %d times after the failed route, want exactly 1", *rollbacks)
	}
	if podSpec.PublishedIfAttachment != nil {
		t.Fatalf("an incomplete attachment recorded a published binding: %s", podSpec.PublishedIfAttachment)
	}
	if len(writer.bindings) != 0 {
		t.Fatalf("an incomplete attachment left a binding in the plugin's table: %v", writer.bindings)
	}
	// The route step runs before the publication barrier, so the plugin is
	// never asked to publish anything for this attachment at all.
	if len(writer.calls) != 0 {
		t.Fatalf("an incomplete attachment reached the plugin: %v", writer.calls)
	}
}

// The Calico CNI backend keeps the behaviour it has always had: a route that
// cannot be installed is logged, and the ADD continues to completion. Only the
// profile differs from the test above; the failing route, the pod spec and the
// rest of the ADD are the same.
func TestCalicoProfileStillOnlyLogsAPodRouteThatCannotBeInstalled(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[routeFailureSwIfIndex] = routeFailureIncarnation
	routeErr := errors.New("network is unreachable")
	s, rollbacks, attempts := routeFailureTestServer(t, writer, podinterface.CalicoProfile, routeErr)
	podSpec := routeFailurePodSpec()

	swIfIndex, err := s.AddVppInterface(podSpec, false /* doHostSideConf */)

	if err != nil {
		t.Fatalf("the Calico profile turned a failed device route into a failed ADD: %v", err)
	}
	if swIfIndex != routeFailureSwIfIndex {
		t.Fatalf("AddVppInterface returned interface %d, want %d", swIfIndex, routeFailureSwIfIndex)
	}
	if *attempts != 1 {
		t.Fatalf("the route was attempted %d times, want exactly 1", *attempts)
	}
	if *rollbacks != 0 {
		t.Fatalf("the Calico profile rolled the interface back %d times after a failed device route", *rollbacks)
	}
	// The ADD ran to its end, which is what "the failure was only logged"
	// means here: everything downstream of the route step still happened.
	if podSpec.PublishedIfAttachment == nil {
		t.Fatalf("the ADD did not run to completion")
	}
}
