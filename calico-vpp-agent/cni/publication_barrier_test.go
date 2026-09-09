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
	"go/ast"
	"go/parser"
	"go/token"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"google.golang.org/grpc/codes"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// The publication barrier of 00 §2.12.6 is a property of where the binding is
// published inside AddVppInterface:
//
//	the binding ADD must be the last thing that happens before the interface
//	is reported as created, and it must happen while the cleanup stack that
//	rolls the interface back is still in scope.
//
// AddVppInterface cannot be executed without a live VPP, so no behavioural test
// in this package can observe that placement. These tests read the source
// instead. They are narrow on purpose: they exist because the two ways of
// breaking the barrier — publishing after the function returns, and publishing
// without the cleanup stack — are both invisible to every other test here, and
// both are what the contract singles out as forbidden ("CNI ADD 成功を返した後の
// 非同期 binding 書込みは禁止", completion criteria 1 and 3 of §2.12.9).
func parseNetworkVpp(t *testing.T) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "network_vpp.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("cannot parse network_vpp.go: %v", err)
	}
	return fset, file
}

func findFunc(t *testing.T, file *ast.File, name string) *ast.FuncDecl {
	t.Helper()
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == name {
			return fn
		}
	}
	t.Fatalf("cannot find %s in network_vpp.go", name)
	return nil
}

// callsPublish reports whether the expression is a call to publishIfAttachment,
// and with how many arguments.
func callsPublish(expr ast.Expr) (bool, int) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return false, 0
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "publishIfAttachment" {
		return false, 0
	}
	return true, len(call.Args)
}

func TestAddVppInterfacePublishesBeforeReportingSuccess(t *testing.T) {
	_, file := parseNetworkVpp(t)
	fn := findFunc(t, file, "AddVppInterface")

	publishIndex := -1
	publishArgs := 0
	successReturnIndex := -1

	for i, stmt := range fn.Body.List {
		switch s := stmt.(type) {
		case *ast.AssignStmt:
			if len(s.Rhs) == 1 {
				if ok, args := callsPublish(s.Rhs[0]); ok {
					publishIndex = i
					publishArgs = args
				}
			}
		case *ast.ReturnStmt:
			// The success return is the one that hands back the interface
			// index; the failure path returns vpplink.InvalidID.
			if len(s.Results) == 2 {
				if sel, ok := s.Results[0].(*ast.SelectorExpr); ok && sel.Sel.Name == "TunTapSwIfIndex" {
					successReturnIndex = i
				}
			}
		}
	}

	if publishIndex < 0 {
		t.Fatalf("AddVppInterface does not publish the binding on its success path: " +
			"the interface would be reported as created before, or without, the binding ADD being acknowledged")
	}
	if successReturnIndex < 0 {
		t.Fatalf("cannot find the success return of AddVppInterface")
	}
	if publishIndex >= successReturnIndex {
		t.Fatalf("AddVppInterface publishes the binding at statement %d, after its success return at %d",
			publishIndex, successReturnIndex)
	}
	// Exactly one statement may sit between them: the error check that jumps to
	// the rollback. Anything else would run after the binding was published but
	// before the interface is reported, which the fixed ADD order does not have.
	if gap := successReturnIndex - publishIndex; gap != 2 {
		t.Fatalf("%d statements sit between the binding publication and the success return, want exactly 1 (the error check)",
			gap-1)
	}
	if publishArgs != 2 {
		t.Fatalf("the binding publication is called with %d arguments, want 2: "+
			"without the cleanup stack, a failed binding ADD cannot roll the interface back",
			publishArgs)
	}
}

// A binding written after the caller was told the interface exists is exactly
// the asynchronous write 00 §2.12.6 forbids.
func TestBindingIsNeverPublishedAsynchronously(t *testing.T) {
	fset, file := parseNetworkVpp(t)
	ast.Inspect(file, func(n ast.Node) bool {
		goStmt, ok := n.(*ast.GoStmt)
		if !ok {
			return true
		}
		ast.Inspect(goStmt, func(inner ast.Node) bool {
			if expr, ok := inner.(ast.Expr); ok {
				if publishes, _ := callsPublish(expr); publishes {
					t.Errorf("%s: the binding is published from a goroutine; "+
						"the ADD ACK is the publication barrier and cannot be asynchronous",
						fset.Position(inner.Pos()))
				}
			}
			return true
		})
		return true
	})
}

// --- the barrier at run time ------------------------------------------------
//
// The tests above read the source. The ones below run AddVppInterface.
//
// What needs a live VPP is the dataplane realization — the per-pod VRFs, the
// interfaces and their routing — and that is the one step the seam
// realizePodInterfacesFn replaces. Everything the barrier is about stays real:
// the cleanup stack AddVppInterface owns, the binding publication against the
// fake plugin, the error path that runs the stack, and the values the function
// returns. So a barrier that is moved, made asynchronous, or left without its
// rollback is observed here, not merely read.

// barrierTestServer builds a lifecycle server whose dataplane realization is
// faked. rollbacks counts how many times the interface the fake "created" was
// rolled back, i.e. how many times the cleanup stack was executed.
func barrierTestServer(t *testing.T, writer *fakeIfBindingWriter) (s *Server, rollbacks *int) {
	t.Helper()
	s = testLifecycleServer(writer)
	s.availableBuffers = 1 << 30
	s.stateFilename = filepath.Join(t.TempDir(), "cni-server-state")
	// Nothing of this pod is in VPP yet, so the ADD takes the creation path
	// rather than the idempotent replay path.
	s.vrfsExistInVppFn = func(*model.LocalPodSpec) bool { return false }

	rolledBack := 0
	rollbacks = &rolledBack
	s.realizePodInterfacesFn = func(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, doHostSideConf bool) (uint32, bool, error) {
		podSpec.TunTapSwIfIndex = barrierTestSwIfIndex
		// This is what the real drivers push: undoing the interface they just
		// created. Counting it is how the test sees the rollback happen.
		stack.Push(func(uint32) error { rolledBack++; return nil }, uint32(barrierTestSwIfIndex))
		return vpplink.InvalidID, false, nil
	}
	return s, rollbacks
}

const (
	barrierTestSwIfIndex     = uint32(7)
	barrierTestIncarnation   = uint32(3)
	barrierTestAttachmentID  = "container:eth0"
	barrierTestInterfaceName = "eth0"
)

// hostNetnsPath is a network namespace that exists for the duration of the
// test: AddVppInterface refuses to do anything for a netns that is gone, and
// the barrier is downstream of that check.
const hostNetnsPath = "/proc/self/ns/net"

func barrierTestPodSpec() *model.LocalPodSpec {
	isL3 := true
	podSpec := &model.LocalPodSpec{
		InterfaceName: barrierTestInterfaceName,
		NetnsName:     hostNetnsPath,
		AttachmentID:  barrierTestAttachmentID,
		ContainerIPs:  []net.IP{net.ParseIP("fd00::1")},
		PodAnnotations: model.PodAnnotations{
			IfSpec:        lifecycleIfSpec(isL3),
			PBLMemifSpec:  lifecycleIfSpec(isL3),
			DefaultIfType: model.VppIfTypeTunTap,
		},
		LocalPodSpecStatus: *model.NewLocalPodSpecStatus(),
	}
	return podSpec
}

// A refused binding ADD is a failed CNI ADD, and the interface that was created
// for it does not survive: completion criteria 1 and 3 of 00 §2.12.9.
func TestAddVppInterfaceFailsAndRollsBackWhenTheBindingIsRefused(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[barrierTestSwIfIndex] = barrierTestIncarnation
	writer.addErr = errors.New("plugin refused the binding")
	s, rollbacks := barrierTestServer(t, writer)
	podSpec := barrierTestPodSpec()

	swIfIndex, err := s.AddVppInterface(podSpec, false /* doHostSideConf */)

	if err == nil {
		t.Fatalf("AddVppInterface reported success although the binding ADD was refused")
	}
	if swIfIndex != vpplink.InvalidID {
		t.Fatalf("AddVppInterface returned interface %d after a refused binding, want InvalidID", swIfIndex)
	}
	if *rollbacks != 1 {
		t.Fatalf("the interface was rolled back %d times after the refused binding, want exactly 1", *rollbacks)
	}
	if podSpec.PublishedIfAttachment != nil {
		t.Fatalf("a refused binding was recorded as published: %s", podSpec.PublishedIfAttachment)
	}
	if len(writer.bindings) != 0 {
		t.Fatalf("a refused binding was left in the plugin's table: %v", writer.bindings)
	}
	// The rollback must not withdraw a binding that was never written.
	for _, call := range writer.calls {
		if strings.HasPrefix(call, "del(") {
			t.Fatalf("the rollback withdrew a binding that was never published: %v", writer.calls)
		}
	}
}

// The same run, with the plugin accepting: the interface is reported only after
// the ADD was acknowledged, and nothing is rolled back.
func TestAddVppInterfaceReportsTheInterfaceOnlyAfterTheBindingIsAcknowledged(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[barrierTestSwIfIndex] = barrierTestIncarnation
	s, rollbacks := barrierTestServer(t, writer)
	podSpec := barrierTestPodSpec()

	swIfIndex, err := s.AddVppInterface(podSpec, false /* doHostSideConf */)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if swIfIndex != barrierTestSwIfIndex {
		t.Fatalf("AddVppInterface returned interface %d, want %d", swIfIndex, barrierTestSwIfIndex)
	}
	if *rollbacks != 0 {
		t.Fatalf("a successful ADD rolled the interface back %d times", *rollbacks)
	}
	if podSpec.PublishedIfAttachment == nil {
		t.Fatalf("AddVppInterface reported the interface without publishing a binding")
	}
	// The binding must already be in the plugin's table when AddVppInterface
	// returns: an ADD acknowledged later would be the asynchronous write the
	// contract forbids.
	want := "add(" + barrierTestAttachmentID + ",7,3)"
	if len(writer.calls) == 0 || writer.calls[len(writer.calls)-1] != want {
		t.Fatalf("the last plugin call at the moment of the reply was %v, want %s ending it", writer.calls, want)
	}
	if _, ok := writer.bindings[barrierTestAttachmentID]; !ok {
		t.Fatalf("the binding was not published by the time AddVppInterface returned: %v", writer.bindings)
	}
}

// The barrier is what the RPC reply means, so a refused binding must not
// produce a CreatePodInterface reply. This runs the real AddVppInterface
// underneath: the gRPC layer is not allowed to turn a rolled back interface
// into a successful CNI ADD.
func TestCreatePodInterfaceReturnsNoReplyWhenTheBindingIsRefused(t *testing.T) {
	writer := newFakeIfBindingWriter()
	writer.incarnations[barrierTestSwIfIndex] = barrierTestIncarnation
	writer.addErr = errors.New("plugin refused the binding")
	s, rollbacks := barrierTestServer(t, writer)

	request := validCreateRequest()
	request.Netns = hostNetnsPath
	request.AttachmentId = barrierTestAttachmentID

	reply, err := (&lifecycleService{server: s}).CreatePodInterface(context.Background(), request)

	if err == nil {
		t.Fatalf("CreatePodInterface replied although the binding ADD was refused: %v", reply)
	}
	if reply != nil {
		t.Fatalf("CreatePodInterface returned a reply together with an error: %v", reply)
	}
	if code := statusCode(t, err); code != codes.Internal {
		t.Fatalf("CreatePodInterface failed with %s, want Internal", code)
	}
	if *rollbacks != 1 {
		t.Fatalf("the interface was rolled back %d times, want exactly 1", *rollbacks)
	}
	if len(s.podInterfaceMap) != 0 {
		t.Fatalf("a failed ADD left the attachment in the pod interface map: %v", s.podInterfaceMap)
	}
	if len(writer.bindings) != 0 {
		t.Fatalf("a failed ADD left a binding published: %v", writer.bindings)
	}
}
