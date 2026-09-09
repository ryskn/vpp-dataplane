// Copyright (C) 2025 Cisco Systems Inc.
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
	"regexp"
	"sort"
	"strconv"

	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/v3/config"
)

type CniServerState struct {
	Version  int                     `json:"version"`
	PodSpecs map[string]LocalPodSpec `json:"podSpecs"`
}

func NewCniServerState(podSpecs map[string]LocalPodSpec) *CniServerState {
	return &CniServerState{
		Version:  config.CniServerStateFileVersion,
		PodSpecs: podSpecs,
	}
}

func PersistCniServerState(state *CniServerState, fname string) (err error) {
	tmpFile := fmt.Sprintf("%s~", fname)
	data, err := json.Marshal(state)
	if err != nil {
		return errors.Wrap(err, "Error encoding pod data")
	}
	err = os.WriteFile(tmpFile, data, 0200)
	if err != nil {
		return errors.Wrapf(err, "Error writing file %s", tmpFile)
	}
	err = os.Rename(tmpFile, fname)
	if err != nil {
		return errors.Wrapf(err, "Error moving file %s", tmpFile)
	}
	return nil
}

func LoadCniServerState(fname string) (*CniServerState, error) {
	state := NewCniServerState(make(map[string]LocalPodSpec))
	data, err := os.ReadFile(fname)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		} else {
			return state, errors.Wrapf(err, "Error reading file %s", fname)
		}
	}
	err = json.Unmarshal(data, state)
	if err != nil {
		return state, errors.Wrapf(err, "Error unmarshaling json state")
	}
	if state.Version != config.CniServerStateFileVersion {
		// When adding new versions, we need to keep loading old versions or some pods
		// will remain disconnected forever after an upgrade
		return state, fmt.Errorf("unsupported save file version: %d", state.Version)
	}
	return state, nil
}

// IncompatibleStateError reports durable lifecycle state that exists on disk
// but cannot be interpreted by this build.
//
// It exists so that the caller can distinguish it from "no state": an
// incompatible state file must never be discarded, because the VPP interfaces
// it describes may still exist and deleting the file would leave them as
// orphans that nothing owns (Issue #135 ruling 4):
//
//	An incompatible durable lifecycle state MUST NOT be silently discarded
//	while its VPP interfaces may still exist. If exact ownership cannot be
//	recovered, the lifecycle service must fail closed and require an explicit
//	dataplane reset.
type IncompatibleStateError struct {
	// Filename is the state file that could not be used.
	Filename string
	// Version is the version found in the file, or the version encoded in its
	// name for a foreign file this build never reads. It is 0 when the file
	// could not be parsed at all.
	Version int
	// Reason explains what made the state unusable.
	Reason string
}

func (e *IncompatibleStateError) Error() string {
	return fmt.Sprintf("incompatible durable lifecycle state %s (version %d): %s; "+
		"the file is kept, an explicit dataplane reset is required",
		e.Filename, e.Version, e.Reason)
}

// migratableStateFileVersions lists the older state file versions this build
// can migrate exactly.
//
// It is deliberately empty. Version 11 and earlier have no AttachmentID field,
// so the exact CNI attachment identity that was published for their interfaces
// is not in the state at all, and reconstructing it would mean guessing it from
// an interface name — the reconstruction 00 §2.12.7 prohibition 1 forbids. Such
// a state is therefore not migratable and must fail closed (Issue #135
// ruling 4).
var migratableStateFileVersions = map[int]bool{}

var stateFileVersionRe = regexp.MustCompile(`^calicovpp_state\.v(\d+)\.json$`)

// LoadLifecycleState loads the durable state of the Pod interface lifecycle
// service, applying the fail-closed rules of Issue #135 ruling 4.
//
// The state file name embeds its version, so a state written by another build
// lives at a different path and would otherwise simply not be seen. Both cases
// are therefore checked: the file for this version, and any state file for a
// different version sitting in the same directory. Either way, nothing is
// deleted: an unreadable or foreign state is reported as an
// *IncompatibleStateError and the caller fails closed.
func LoadLifecycleState(fname string) (*CniServerState, error) {
	dir := filepath.Dir(fname)
	foreign, err := findForeignStateFiles(dir, config.CniServerStateFileVersion)
	if err != nil {
		// Not being able to list the directory is not evidence that no foreign
		// state exists, so it is treated as fail-closed too.
		return nil, &IncompatibleStateError{
			Filename: dir,
			Reason:   fmt.Sprintf("cannot list durable state directory: %v", err),
		}
	}
	if len(foreign) > 0 {
		return nil, &IncompatibleStateError{
			Filename: foreign[0].filename,
			Version:  foreign[0].version,
			Reason: fmt.Sprintf("state written by version %d, which this build cannot migrate "+
				"(migratable versions: %v)", foreign[0].version, migratableVersionList()),
		}
	}

	data, err := os.ReadFile(fname)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return NewCniServerState(make(map[string]LocalPodSpec)), nil
		}
		return nil, &IncompatibleStateError{
			Filename: fname,
			Reason:   fmt.Sprintf("cannot read state file: %v", err),
		}
	}

	state := NewCniServerState(make(map[string]LocalPodSpec))
	if err := json.Unmarshal(data, state); err != nil {
		return nil, &IncompatibleStateError{
			Filename: fname,
			Reason:   fmt.Sprintf("cannot decode state file: %v", err),
		}
	}
	if state.Version != config.CniServerStateFileVersion {
		return nil, &IncompatibleStateError{
			Filename: fname,
			Version:  state.Version,
			Reason: fmt.Sprintf("state declares version %d but is stored under version %d",
				state.Version, config.CniServerStateFileVersion),
		}
	}
	return state, nil
}

type foreignStateFile struct {
	filename string
	version  int
}

// findForeignStateFiles returns the state files in dir that were written by a
// version other than currentVersion, oldest version first.
func findForeignStateFiles(dir string, currentVersion int) ([]foreignStateFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	found := make([]foreignStateFile, 0)
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		m := stateFileVersionRe.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		version, err := strconv.Atoi(m[1])
		if err != nil || version == currentVersion || migratableStateFileVersions[version] {
			continue
		}
		found = append(found, foreignStateFile{
			filename: filepath.Join(dir, entry.Name()),
			version:  version,
		})
	}
	sort.Slice(found, func(i, j int) bool { return found[i].version < found[j].version })
	return found, nil
}

func migratableVersionList() []int {
	versions := make([]int, 0, len(migratableStateFileVersions))
	for v := range migratableStateFileVersions {
		versions = append(versions, v)
	}
	sort.Ints(versions)
	return versions
}
