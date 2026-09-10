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

package health

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/sirupsen/logrus"
)

func testHealthServer(required []string) *HealthServer {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return NewHealthServer(logrus.NewEntry(log), 0, required)
}

// readinessCode is what a kubelet probe would see.
func readinessCode(hs *HealthServer) int {
	recorder := httptest.NewRecorder()
	hs.readinessHandler(recorder, httptest.NewRequest(http.MethodGet, "/readiness", nil))
	return recorder.Code
}

// The Calico entrypoint keeps the four components it has always required.
// Nothing here weakens it: it is not ready until Felix and the agent have both
// reported in.
func TestCalicoAgentReadinessRequiresFelixAndTheAgent(t *testing.T) {
	hs := testHealthServer(CalicoAgentComponents())

	for _, component := range []string{ComponentVPP, ComponentVPPManager, ComponentFelix} {
		hs.SetComponentStatus(component, true, "")
		if hs.GetStatus().Ready {
			t.Fatalf("the Calico agent reported ready after %s alone", component)
		}
		if code := readinessCode(hs); code != http.StatusServiceUnavailable {
			t.Fatalf("/readiness answered %d after %s alone, want 503", code, component)
		}
	}

	hs.SetComponentStatus(ComponentAgent, true, "")
	if !hs.GetStatus().Ready {
		t.Fatalf("the Calico agent did not report ready with all four components initialized")
	}
	if code := readinessCode(hs); code != http.StatusOK {
		t.Fatalf("/readiness answered %d with all four components initialized, want 200", code)
	}
}

// A component that reports itself uninitialized again takes readiness away,
// which is what the lifecycle service does when its durable state cannot be
// interpreted (Issue #135 ruling 4).
func TestReadinessIsWithdrawnWhenAComponentReportsUninitialized(t *testing.T) {
	hs := testHealthServer(PodInterfaceLifecycleComponents())
	for _, component := range PodInterfaceLifecycleComponents() {
		hs.SetComponentStatus(component, true, "")
	}
	if !hs.GetStatus().Ready {
		t.Fatalf("the lifecycle service did not report ready with its components initialized")
	}

	hs.SetComponentStatus(ComponentPodInterfaceLifecycle, false, "state cannot be interpreted")
	if hs.GetStatus().Ready {
		t.Fatalf("readiness survived the lifecycle service reporting itself uninitialized")
	}
}

// The lifecycle entrypoint reports ready once VPP, vpp-manager and the
// lifecycle service itself have reported in. It must not wait for Felix or for
// the Calico agent: it never starts them, so requiring them kept /readiness at
// 503 for a fully functional service (errata #34 item 128).
func TestPodInterfaceLifecycleReadinessDoesNotWaitForCalico(t *testing.T) {
	hs := testHealthServer(PodInterfaceLifecycleComponents())

	hs.SetComponentStatus(ComponentVPP, true, "VPP connection established")
	hs.SetComponentStatus(ComponentVPPManager, true, "VPP Manager ready")
	if hs.GetStatus().Ready {
		t.Fatalf("the lifecycle service reported ready before the lifecycle component did")
	}

	hs.SetComponentStatus(ComponentPodInterfaceLifecycle, true, "pod interface lifecycle service ready")
	if !hs.GetStatus().Ready {
		t.Fatalf("the lifecycle service did not report ready with VPP, vpp-manager and itself initialized")
	}
	if code := readinessCode(hs); code != http.StatusOK {
		t.Fatalf("/readiness answered %d, want 200", code)
	}

	status := hs.GetStatus()
	if _, reported := status.Components[ComponentFelix]; reported {
		t.Fatalf("the lifecycle entrypoint reported a Felix component")
	}
	if _, reported := status.Components[ComponentAgent]; reported {
		t.Fatalf("the lifecycle entrypoint reported a Calico agent component")
	}
}

// The two sets are what the two entrypoints ask for, and they are not the same
// set.
func TestTheTwoRequiredComponentSets(t *testing.T) {
	requireSet(t, "calico-vpp-agent", CalicoAgentComponents(),
		ComponentVPP, ComponentVPPManager, ComponentFelix, ComponentAgent)
	requireSet(t, "podinterface-lifecycle", PodInterfaceLifecycleComponents(),
		ComponentVPP, ComponentVPPManager, ComponentPodInterfaceLifecycle)
}

func requireSet(t *testing.T, name string, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("the %s required component set is %v, want %v", name, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the %s required component set is %v, want %v", name, got, want)
		}
	}
}

// A health server with no required component set would answer 200 for a process
// that has initialized nothing. Building one is a construction failure rather
// than a readiness policy.
func TestAHealthServerRequiresAComponentSet(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("a health server with no required components was accepted")
		}
	}()
	testHealthServer(nil)
}

// The caller's slice is not the server's: mutating it afterwards must not
// change what readiness is about.
func TestTheRequiredComponentSetIsCopied(t *testing.T) {
	required := PodInterfaceLifecycleComponents()
	hs := testHealthServer(required)
	required[0] = ComponentFelix

	for _, component := range PodInterfaceLifecycleComponents() {
		hs.SetComponentStatus(component, true, "")
	}
	if !hs.GetStatus().Ready {
		t.Fatalf("the server followed the caller's later mutation of the component set")
	}
}
