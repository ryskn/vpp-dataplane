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

package model

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectcalico/vpp-dataplane/v3/config"
)

func stateFileName(dir string, version int) string {
	return filepath.Join(dir, fmt.Sprintf("calicovpp_state.v%d.json", version))
}

func writeStateFile(t *testing.T, path string, version int, podSpecs map[string]LocalPodSpec) {
	t.Helper()
	if podSpecs == nil {
		podSpecs = make(map[string]LocalPodSpec)
	}
	data, err := json.Marshal(&CniServerState{Version: version, PodSpecs: podSpecs})
	if err != nil {
		t.Fatalf("cannot encode state: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("cannot write state: %v", err)
	}
}

func TestLoadLifecycleStateReadsTheCurrentVersion(t *testing.T) {
	dir := t.TempDir()
	path := stateFileName(dir, config.CniServerStateFileVersion)
	writeStateFile(t, path, config.CniServerStateFileVersion, map[string]LocalPodSpec{
		"netns:/proc/1/ns/net,if:eth0": {
			InterfaceName: "eth0",
			NetnsName:     "/proc/1/ns/net",
			AttachmentID:  "container:eth0",
			LocalPodSpecStatus: LocalPodSpecStatus{
				TunTapSwIfIndex: 7,
				PublishedIfAttachment: &PublishedIfAttachment{
					AttachmentID: "container:eth0", SwIfIndex: 7, IfIncarnation: 3,
				},
			},
		},
	})

	state, err := LoadLifecycleState(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	podSpec, ok := state.PodSpecs["netns:/proc/1/ns/net,if:eth0"]
	if !ok {
		t.Fatalf("the stored pod spec was not loaded")
	}
	if podSpec.AttachmentID != "container:eth0" {
		t.Fatalf("the attachment identity did not survive the round trip: %q", podSpec.AttachmentID)
	}
	if podSpec.PublishedIfAttachment == nil ||
		podSpec.PublishedIfAttachment.IfIncarnation != 3 ||
		podSpec.PublishedIfAttachment.SwIfIndex != 7 {
		t.Fatalf("the published tuple did not survive the round trip: %s", podSpec.PublishedIfAttachment)
	}
}

func TestLoadLifecycleStateOnAnEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	state, err := LoadLifecycleState(stateFileName(dir, config.CniServerStateFileVersion))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(state.PodSpecs) != 0 {
		t.Fatalf("expected no pod specs, got %d", len(state.PodSpecs))
	}
}

// An incompatible state must fail closed and, crucially, must not be deleted:
// the VPP interfaces it describes may still exist, and forgetting the control
// plane's view of them turns them into orphans nothing owns (Issue #135
// ruling 4).
func TestLoadLifecycleStateKeepsAnIncompatibleStateFile(t *testing.T) {
	oldVersion := config.CniServerStateFileVersion - 1

	t.Run("foreign version file in the same directory", func(t *testing.T) {
		dir := t.TempDir()
		oldPath := stateFileName(dir, oldVersion)
		writeStateFile(t, oldPath, oldVersion, nil)

		_, err := LoadLifecycleState(stateFileName(dir, config.CniServerStateFileVersion))
		var incompatible *IncompatibleStateError
		if !asIncompatible(err, &incompatible) {
			t.Fatalf("got %v, want an IncompatibleStateError", err)
		}
		if incompatible.Version != oldVersion {
			t.Fatalf("reported version %d, want %d", incompatible.Version, oldVersion)
		}
		if _, statErr := os.Stat(oldPath); statErr != nil {
			t.Fatalf("the incompatible state file was removed: %v", statErr)
		}
	})

	t.Run("version mismatch inside the file", func(t *testing.T) {
		dir := t.TempDir()
		path := stateFileName(dir, config.CniServerStateFileVersion)
		writeStateFile(t, path, oldVersion, nil)

		_, err := LoadLifecycleState(path)
		var incompatible *IncompatibleStateError
		if !asIncompatible(err, &incompatible) {
			t.Fatalf("got %v, want an IncompatibleStateError", err)
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("the incompatible state file was removed: %v", statErr)
		}
	})

	t.Run("undecodable file", func(t *testing.T) {
		dir := t.TempDir()
		path := stateFileName(dir, config.CniServerStateFileVersion)
		if err := os.WriteFile(path, []byte("{not json"), 0600); err != nil {
			t.Fatalf("cannot write state: %v", err)
		}

		_, err := LoadLifecycleState(path)
		var incompatible *IncompatibleStateError
		if !asIncompatible(err, &incompatible) {
			t.Fatalf("got %v, want an IncompatibleStateError", err)
		}
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("the undecodable state file was removed: %v", statErr)
		}
	})
}

// Version 11 and earlier have no AttachmentID, so the identity that was
// published for their interfaces is simply not in the state. Declaring them
// migratable would mean guessing it.
func TestNoStateFileVersionIsDeclaredMigratable(t *testing.T) {
	if len(migratableStateFileVersions) != 0 {
		t.Fatalf("migratable versions %v are declared, but no exact migration is implemented",
			migratableVersionList())
	}
}

func asIncompatible(err error, target **IncompatibleStateError) bool {
	if err == nil {
		return false
	}
	incompatible, ok := err.(*IncompatibleStateError)
	if !ok {
		return false
	}
	*target = incompatible
	return true
}
