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
	"net"
	"testing"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
)

// masqueradingSNATPolicy answers yes for every prefix, which is what an IP pool
// with masquerading enabled makes the Felix authority answer.
type masqueradingSNATPolicy struct{ calls int }

func (p *masqueradingSNATPolicy) NeedsSNAT(*net.IPNet) bool {
	p.calls++
	return true
}

func snatTestPodSpec() *LocalPodSpec {
	return &LocalPodSpec{
		ContainerIPs: []net.IP{net.ParseIP("fd00::1"), net.ParseIP("10.0.0.1")},
	}
}

// NoSNATPolicy is a decision, and it is the decision the Pod interface
// lifecycle profile injects: no IP pool authority exists, so no address is
// masqueraded (Issue #135 pre-merge item 1).
func TestNoSNATPolicyAnswersNo(t *testing.T) {
	podSpec := snatTestPodSpec()
	for _, isIP6 := range []bool{true, false} {
		if podSpec.NeedsSnat(common.NoSNATPolicy{}, isIP6) {
			t.Fatalf("NoSNATPolicy asked for SNAT (isIP6=%t)", isIP6)
		}
	}
}

// The policy is consulted per address family, so the answer for one family is
// not the answer for the other.
func TestNeedsSnatConsultsThePolicyPerFamily(t *testing.T) {
	podSpec := snatTestPodSpec()

	policy := &masqueradingSNATPolicy{}
	if !podSpec.NeedsSnat(policy, true /* isIP6 */) {
		t.Fatalf("the IPv6 address was not offered to the policy")
	}
	if policy.calls != 1 {
		t.Fatalf("the policy was consulted %d times for one IPv6 address, want 1", policy.calls)
	}

	policy = &masqueradingSNATPolicy{}
	if !podSpec.NeedsSnat(policy, false /* isIP6 */) {
		t.Fatalf("the IPv4 address was not offered to the policy")
	}
	if policy.calls != 1 {
		t.Fatalf("the policy was consulted %d times for one IPv4 address, want 1", policy.calls)
	}
}

// A missing policy is a server that was built without deciding. It must not be
// indistinguishable from a policy that decided no address needs SNAT, which is
// exactly what the previous nil branch made it (Issue #135 pre-merge item 1).
func TestNeedsSnatRefusesAMissingPolicy(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("a nil SNAT policy was silently answered as \"no SNAT\"")
		}
	}()
	_ = snatTestPodSpec().NeedsSnat(nil, true)
}
