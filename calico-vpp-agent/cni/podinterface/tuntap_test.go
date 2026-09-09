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
	"io"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
)

func testTunTapDriver() *TunTapPodInterfaceDriver {
	log := logrus.New()
	log.SetOutput(&strings.Builder{})
	driver := &TunTapPodInterfaceDriver{}
	driver.log = logrus.NewEntry(log)
	driver.Name = "tun"
	return driver
}

// D-50 makes the Pod attachment L3-only, so the interface must carry exactly
// the addresses the CNI decided. accept_ra=0 and addr_gen_mode=none are what
// keep the kernel from adding its own, which makes them part of the interface
// creation transaction rather than a best-effort nicety: a failing sysctl has
// to fail the ADD so the interface is rolled back (Issue #135 ruling 8).
func TestSuppressIPv6AutoconfigurationFailsTheAddOnASysctlFailure(t *testing.T) {
	driver := testTunTapDriver()
	podSpec := &model.LocalPodSpec{InterfaceName: "eth0"}

	for _, failing := range []string{"accept_ra", "addr_gen_mode"} {
		t.Run(failing, func(t *testing.T) {
			original := writeProcSys
			defer func() { writeProcSys = original }()

			written := make(map[string]string)
			writeProcSys = func(path, value string) error {
				if strings.HasSuffix(path, failing) {
					return errors.New("read-only file system")
				}
				written[path] = value
				return nil
			}

			err := driver.suppressIPv6Autoconfiguration(podSpec)
			if err == nil {
				t.Fatalf("a failing %s sysctl was not reported as an error", failing)
			}
			if !strings.Contains(err.Error(), failing) {
				t.Fatalf("the error does not name the sysctl that failed: %v", err)
			}
		})
	}
}

func TestSuppressIPv6AutoconfigurationWritesBothSysctls(t *testing.T) {
	driver := testTunTapDriver()
	podSpec := &model.LocalPodSpec{InterfaceName: "eth0"}

	original := writeProcSys
	defer func() { writeProcSys = original }()

	written := make(map[string]string)
	writeProcSys = func(path, value string) error {
		written[path] = value
		return nil
	}

	if err := driver.suppressIPv6Autoconfiguration(podSpec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := written["/proc/sys/net/ipv6/conf/eth0/accept_ra"]; got != "0" {
		t.Fatalf("accept_ra was set to %q, want \"0\"", got)
	}
	// 1 is IN6_ADDR_GEN_MODE_NONE.
	if got := written["/proc/sys/net/ipv6/conf/eth0/addr_gen_mode"]; got != "1" {
		t.Fatalf("addr_gen_mode was set to %q, want \"1\" (none)", got)
	}
}

// The MTU computation must work without a Felix configuration: the Pod
// interface lifecycle profile has no Felix behind it.
func TestComputePodMtuWithoutFelixConfig(t *testing.T) {
	common.VppManagerInfo = &config.VppManagerInfo{}
	config.GetCalicoVppFeatureGates().IPSecEnabled = &config.False
	driver := testTunTapDriver()
	if got := driver.computePodMtu(1400, nil, false, false); got != 1400 {
		t.Fatalf("requested MTU 1400 became %d", got)
	}
	if got := driver.computePodMtu(0, nil, false, false); got <= 0 {
		t.Fatalf("an unspecified MTU produced %d", got)
	}
}

// --- Pod-side configuration policy per profile ------------------------------
//
// The two profiles share the code that performs each step and not the policy
// that orders them (Issue #135 pre-merge item 4). These tests pin both
// policies, so that a change to one is visible as a change to that one.

func stepNames(steps []namespaceSideStep) []string {
	names := make([]string, 0, len(steps))
	for _, step := range steps {
		names = append(names, string(step))
	}
	return names
}

func requireSteps(t *testing.T, got []namespaceSideStep, want ...string) {
	t.Helper()
	names := stepNames(got)
	if len(names) != len(want) {
		t.Fatalf("steps are %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("steps are %v, want %v", names, want)
		}
	}
}

// The lifecycle profile follows the fixed ADD order of Issue #135 ruling 8:
// suppression before any address exists, addresses before the routes that point
// at them, and the MTU last.
func TestLifecycleProfileConfiguresThePodSideInTheFixedAddOrder(t *testing.T) {
	requireSteps(t, namespaceSideSteps(LifecycleProfile, true /* hasv6 */, true /* isL3 */),
		"enable-ipv6", "suppress-ipv6-autoconf", "addresses", "routes", "mtu", "container-sysctls")
}

// An L2 pod interface keeps its link-local address: neighbour discovery needs
// it, so the suppression step does not apply there.
func TestLifecycleProfileDoesNotSuppressAddressGenerationOnAnL2Interface(t *testing.T) {
	requireSteps(t, namespaceSideSteps(LifecycleProfile, true /* hasv6 */, false /* isL3 */),
		"enable-ipv6", "addresses", "routes", "mtu", "container-sysctls")
}

// Without IPv6 there is nothing to enable and nothing to suppress.
func TestLifecycleProfileWithoutIPv6(t *testing.T) {
	requireSteps(t, namespaceSideSteps(LifecycleProfile, false /* hasv6 */, true /* isL3 */),
		"addresses", "routes", "mtu", "container-sysctls")
}

// The Calico CNI backend keeps exactly the Pod-side configuration it applied
// before this contract existed: routes before addresses, no suppression of the
// kernel's IPv6 autoconfiguration, and no MTU step of its own. Tightening it is
// a change to Calico and belongs to a change made for Calico's reasons.
func TestCalicoProfileKeepsItsExistingPodSideConfiguration(t *testing.T) {
	requireSteps(t, namespaceSideSteps(CalicoProfile, true /* hasv6 */, true /* isL3 */),
		"enable-ipv6", "routes", "addresses", "container-sysctls")
	requireSteps(t, namespaceSideSteps(CalicoProfile, true /* hasv6 */, false /* isL3 */),
		"enable-ipv6", "routes", "addresses", "container-sysctls")
	requireSteps(t, namespaceSideSteps(CalicoProfile, false /* hasv6 */, true /* isL3 */),
		"routes", "addresses", "container-sysctls")
}

// The suppression is a lifecycle-profile step, and it is not reachable from the
// Calico profile under any pod spec: that is the whole point of separating the
// policies rather than the code.
func TestSuppressionIsUnreachableFromTheCalicoProfile(t *testing.T) {
	for _, hasv6 := range []bool{true, false} {
		for _, isL3 := range []bool{true, false} {
			for _, step := range namespaceSideSteps(CalicoProfile, hasv6, isL3) {
				if step == stepSuppressIPv6Autoconf || step == stepMtu {
					t.Fatalf("the Calico profile runs %q (hasv6=%t isL3=%t)", step, hasv6, isL3)
				}
			}
		}
	}
}

// The profile is what the entry point chose, and nothing else. A driver built
// for Calico stays a Calico driver whatever pod spec it is handed.
func TestTheProfileComesFromTheConstructor(t *testing.T) {
	log := logrus.New()
	log.SetOutput(io.Discard)
	entry := logrus.NewEntry(log)

	calico := NewTunTapPodInterfaceDriver(nil, entry, common.NoSNATPolicy{}, CalicoProfile)
	if calico.profile != CalicoProfile {
		t.Fatalf("the Calico driver has profile %s", calico.profile)
	}
	lifecycle := NewTunTapPodInterfaceDriver(nil, entry, common.NoSNATPolicy{}, LifecycleProfile)
	if lifecycle.profile != LifecycleProfile {
		t.Fatalf("the lifecycle driver has profile %s", lifecycle.profile)
	}
}
