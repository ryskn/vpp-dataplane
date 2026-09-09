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
