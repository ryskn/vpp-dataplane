// Copyright (C) 2021 Cisco Systems Inc.
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

package config

import (
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

func TestCommonConfig(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "common config tests")
}

func network(address string) *net.IPNet {
	_, n, _ := net.ParseCIDR(address)
	return n
}

type SomeType struct {
	A int
}

type SomeValidableType struct {
	A int
}

func (typ *SomeValidableType) Validate() error {
	typ.A = 1234
	return nil
}

var _ = Describe("Test Common Config", func() {
	It("Test Routes Sorting", func() {

		var (
			gw               = net.ParseIP("192.168.2.1")
			net0             = network("192.168.2.1/32")
			net2             = network("192.168.3.0/24")
			net3             = network("10.8.0.0/16")
			deflt *net.IPNet = nil
		)

		// LinkIndex is the target position of the route in sorted order
		var routesLists = [][]netlink.Route{
			{
				netlink.Route{LinkIndex: 3, Dst: deflt, Gw: gw},
				netlink.Route{LinkIndex: 1, Dst: net2, Gw: gw},
				netlink.Route{LinkIndex: 2, Dst: net3, Gw: gw},
				netlink.Route{LinkIndex: 0, Dst: net0, Gw: nil},
			},
		}

		for _, rl := range routesLists {
			c := LinuxInterfaceState{routes: rl}
			c.sortRoutes()
			for i, r := range c.routes {
				Expect(r.LinkIndex).To(Equal(i), "Link %d should be at index %d", r.LinkIndex, i)
			}
		}
	})

	It("Test Routes Sorting", func() {
		SomeParsedVar := JSONEnvVar("SOMEVAR", &SomeType{})
		Expect(os.Setenv("SOMEVAR", "{\"A\":1}")).ToNot(HaveOccurred())
		Expect(ParseEnvVars("SOMEVAR")).To(BeEmpty())
		Expect((*SomeParsedVar).A).To(Equal(1))

		SomeValidableParsedVar := JSONEnvVar("SOMEVAR2", &SomeValidableType{})
		Expect(ParseEnvVars("SOMEVAR2")).To(BeEmpty())
		Expect((*SomeValidableParsedVar).A).To(Equal(1234))

		_ = RequiredStringEnvVar("SOMEVAR3")
		Expect(os.Unsetenv("SOMEVAR3")).ToNot(HaveOccurred())
		errs := ParseEnvVars("SOMEVAR3")
		Expect(len(errs)).To(Equal(1))
		Expect(errs[0]).To(HaveOccurred())

	})

	It("Test Deployment Profile parsing", func() {
		defer func() {
			Expect(os.Unsetenv(DeploymentProfileEnvVarName)).ToNot(HaveOccurred())
			Expect(ParseEnvVars(DeploymentProfileEnvVarName)).To(BeEmpty())
		}()

		/* unset defaults to the calico profile, preserving the existing behaviour */
		Expect(os.Unsetenv(DeploymentProfileEnvVarName)).ToNot(HaveOccurred())
		Expect(ParseEnvVars(DeploymentProfileEnvVarName)).To(BeEmpty())
		Expect(GetDeploymentProfile()).To(Equal(DeploymentProfileCalico))
		Expect(GetDeploymentProfile().UsesCalicoDatastore()).To(BeTrue())

		Expect(os.Setenv(DeploymentProfileEnvVarName, "calico")).ToNot(HaveOccurred())
		Expect(ParseEnvVars(DeploymentProfileEnvVarName)).To(BeEmpty())
		Expect(GetDeploymentProfile()).To(Equal(DeploymentProfileCalico))
		Expect(GetDeploymentProfile().UsesCalicoDatastore()).To(BeTrue())

		Expect(os.Setenv(DeploymentProfileEnvVarName, "external")).ToNot(HaveOccurred())
		Expect(ParseEnvVars(DeploymentProfileEnvVarName)).To(BeEmpty())
		Expect(GetDeploymentProfile()).To(Equal(DeploymentProfileExternal))
		Expect(GetDeploymentProfile().UsesCalicoDatastore()).To(BeFalse())

		/* an unknown value is a configuration error, never a fallback */
		for _, unknown := range []string{"cilium", "Calico", "EXTERNAL", "none", "auto"} {
			Expect(os.Setenv(DeploymentProfileEnvVarName, unknown)).ToNot(HaveOccurred())
			errs := ParseEnvVars(DeploymentProfileEnvVarName)
			Expect(len(errs)).To(Equal(1), "value %s should not be a valid profile", unknown)
			Expect(errs[0]).To(HaveOccurred())
		}
	})
})
