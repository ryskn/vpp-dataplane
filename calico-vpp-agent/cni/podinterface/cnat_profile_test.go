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

package podinterface

import (
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// recordingCnat is a cnatDataplane that records what was asked of it instead of
// asking VPP. It is how "this profile makes no CNAT call" is observed rather
// than asserted.
type recordingCnat struct{ calls []string }

func (r *recordingCnat) EnableDisableCnatSNAT(swIfIndex uint32, isIP6 bool, isEnable bool) error {
	r.calls = append(r.calls, fmt.Sprintf("EnableDisableCnatSNAT(%d,ip6=%t,enable=%t)", swIfIndex, isIP6, isEnable))
	return nil
}

func (r *recordingCnat) RegisterPodInterface(swIfIndex uint32) error {
	r.calls = append(r.calls, fmt.Sprintf("RegisterPodInterface(%d)", swIfIndex))
	return nil
}

func (r *recordingCnat) RemovePodInterface(swIfIndex uint32) error {
	r.calls = append(r.calls, fmt.Sprintf("RemovePodInterface(%d)", swIfIndex))
	return nil
}

func (r *recordingCnat) CnatEnableFeatures(swIfIndex uint32) error {
	r.calls = append(r.calls, fmt.Sprintf("CnatEnableFeatures(%d)", swIfIndex))
	return nil
}

// masqueradingSNATPolicy answers yes for every prefix, which is what an IP pool
// with masquerading enabled makes the Felix authority answer.
type masqueradingSNATPolicy struct{}

func (masqueradingSNATPolicy) NeedsSNAT(*net.IPNet) bool { return true }

func cnatTestLog() *logrus.Entry {
	log := logrus.New()
	log.SetOutput(io.Discard)
	return logrus.NewEntry(log)
}

func cnatTestPodSpec() *model.LocalPodSpec {
	return &model.LocalPodSpec{
		ContainerIPs: []net.IP{net.ParseIP("fd00::1"), net.ParseIP("10.0.0.1")},
	}
}

func requireCalls(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("CNAT calls are %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("CNAT calls are %v, want %v", got, want)
		}
	}
}

const cnatTestSwIfIndex = uint32(7)

// The lifecycle profile programs no CNAT at all.
//
// This is what BLOCKER-7 was: cnat_snat_policy_add_del_if answered "Feature
// disabled by configuration" (-30) on the Stage 0 node, because that profile
// does not deploy Calico's CNAT configuration — Cilium owns NAT, policy and
// services there (Issue #135 ruling 3). The repair is that the call is not
// made, not that its failure is tolerated.
func TestLifecycleProfileMakesNoCnatCall(t *testing.T) {
	recorder := &recordingCnat{}
	// A masquerading policy is used on purpose: even an authority that asks for
	// SNAT must not produce a CNAT call under this profile.
	nat := newPodIfNatConfiguration(LifecycleProfile, recorder, masqueradingSNATPolicy{})

	stack := vpplink.NewCleanupStack()
	if err := nat.configure(cnatTestLog(), cnatTestPodSpec(), stack, cnatTestSwIfIndex); err != nil {
		t.Fatalf("the lifecycle profile failed the NAT configuration: %v", err)
	}
	nat.unconfigure(cnatTestLog(), cnatTestSwIfIndex)

	requireCalls(t, recorder.calls)

	// Nothing was programmed, so nothing was pushed onto the cleanup stack:
	// running it must not reach the dataplane either.
	stack.Execute()
	requireCalls(t, recorder.calls)
}

// The Calico profile keeps the sequence it has always issued: SNAT per family
// where the IP pool authority asks for it, then the pod interface registration,
// then the NAT feature arcs.
func TestCalicoProfileStillConfiguresCnat(t *testing.T) {
	recorder := &recordingCnat{}
	nat := newPodIfNatConfiguration(CalicoProfile, recorder, masqueradingSNATPolicy{})

	stack := vpplink.NewCleanupStack()
	if err := nat.configure(cnatTestLog(), cnatTestPodSpec(), stack, cnatTestSwIfIndex); err != nil {
		t.Fatalf("the Calico profile failed the NAT configuration: %v", err)
	}

	requireCalls(t, recorder.calls,
		"EnableDisableCnatSNAT(7,ip6=false,enable=true)",
		"EnableDisableCnatSNAT(7,ip6=true,enable=true)",
		"RegisterPodInterface(7)",
		"CnatEnableFeatures(7)",
	)

	// And what it programmed is what a failed ADD rolls back, in reverse.
	recorder.calls = nil
	stack.Execute()
	requireCalls(t, recorder.calls,
		"RemovePodInterface(7)",
		"EnableDisableCnatSNAT(7,ip6=true,enable=false)",
		"EnableDisableCnatSNAT(7,ip6=false,enable=false)",
	)

	recorder.calls = nil
	nat.unconfigure(cnatTestLog(), cnatTestSwIfIndex)
	requireCalls(t, recorder.calls,
		"RemovePodInterface(7)",
		"EnableDisableCnatSNAT(7,ip6=false,enable=false)",
		"EnableDisableCnatSNAT(7,ip6=true,enable=false)",
	)
}

// An SNAT authority that answers no produces no SNAT call, but the Calico
// profile still registers the interface with CNAT: the two are separate
// decisions, and only the profile removes the second one.
func TestCalicoProfileWithoutSnatStillRegistersThePodInterface(t *testing.T) {
	recorder := &recordingCnat{}
	nat := newPodIfNatConfiguration(CalicoProfile, recorder, common.NoSNATPolicy{})

	stack := vpplink.NewCleanupStack()
	if err := nat.configure(cnatTestLog(), cnatTestPodSpec(), stack, cnatTestSwIfIndex); err != nil {
		t.Fatalf("the Calico profile failed the NAT configuration: %v", err)
	}
	requireCalls(t, recorder.calls,
		"RegisterPodInterface(7)",
		"CnatEnableFeatures(7)",
	)
}

// Every driver that configures CNAT — not the tun driver alone — takes its
// profile from the entry point that built it, and the lifecycle profile gives
// each of them a policy that holds no VPP handle at all.
//
// The drivers are built with a nil VppLink, so this is not only a claim about a
// type: any CNAT call these drivers made would dereference it and panic.
func TestEveryDriverTakesTheCnatPolicyFromItsProfile(t *testing.T) {
	entry := cnatTestLog()

	for _, tc := range []struct {
		name  string
		build func(profile PodInterfaceProfile) *PodInterfaceDriverData
	}{
		{
			name: "tun",
			build: func(p PodInterfaceProfile) *PodInterfaceDriverData {
				return &NewTunTapPodInterfaceDriver(nil, entry, common.NoSNATPolicy{}, p).PodInterfaceDriverData
			},
		},
		{
			name: "loopback",
			build: func(p PodInterfaceProfile) *PodInterfaceDriverData {
				return &NewLoopbackPodInterfaceDriver(nil, entry, common.NoSNATPolicy{}, p).PodInterfaceDriverData
			},
		},
		{
			name: "memif",
			build: func(p PodInterfaceProfile) *PodInterfaceDriverData {
				return &NewMemifPodInterfaceDriver(nil, entry, common.NoSNATPolicy{}, p).PodInterfaceDriverData
			},
		},
		{
			name: "vcl",
			build: func(p PodInterfaceProfile) *PodInterfaceDriverData {
				return &NewVclPodInterfaceDriver(nil, entry, common.NoSNATPolicy{}, p).PodInterfaceDriverData
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			lifecycle := tc.build(LifecycleProfile)
			if lifecycle.profile != LifecycleProfile {
				t.Fatalf("the %s driver built for the lifecycle profile has profile %s", tc.name, lifecycle.profile)
			}
			if _, ok := lifecycle.podIfNat.(noPodIfNat); !ok {
				t.Fatalf("the lifecycle %s driver has CNAT policy %T, want noPodIfNat", tc.name, lifecycle.podIfNat)
			}
			// No VPP call, so a nil VppLink is never dereferenced.
			stack := vpplink.NewCleanupStack()
			if err := lifecycle.DoPodIfNatConfiguration(cnatTestPodSpec(), stack, cnatTestSwIfIndex); err != nil {
				t.Fatalf("the lifecycle %s driver failed the NAT configuration: %v", tc.name, err)
			}
			lifecycle.UndoPodIfNatConfiguration(cnatTestSwIfIndex)
			stack.Execute()

			calico := tc.build(CalicoProfile)
			if calico.profile != CalicoProfile {
				t.Fatalf("the %s driver built for the Calico profile has profile %s", tc.name, calico.profile)
			}
			nat, ok := calico.podIfNat.(calicoPodIfNat)
			if !ok {
				t.Fatalf("the Calico %s driver has CNAT policy %T, want calicoPodIfNat", tc.name, calico.podIfNat)
			}
			if nat.snatPolicy == nil {
				t.Fatalf("the Calico %s driver has no SNAT authority behind its CNAT policy", tc.name)
			}
		})
	}
}

// A driver cannot be built without an SNAT authority, in either profile: the
// omission is a construction failure and never a silent "no SNAT" answer
// (Issue #135 pre-merge item 1).
func TestADriverStillRequiresAnSnatAuthority(t *testing.T) {
	for _, profile := range []PodInterfaceProfile{CalicoProfile, LifecycleProfile} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("building a %s driver without an SNAT authority was accepted", profile)
				}
			}()
			NewTunTapPodInterfaceDriver(nil, cnatTestLog(), nil, profile)
		}()
	}
}
