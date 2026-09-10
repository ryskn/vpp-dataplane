// Copyright (C) 2026 Cisco Systems Inc.
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

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pkg/errors"
	calicov3cli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/config"
)

/* setDeploymentProfile sets the deployment profile through the regular
 * environment parsing path, and restores the default when the test ends. */
func setDeploymentProfile(t *testing.T, profile string) {
	t.Helper()
	if err := os.Setenv(config.DeploymentProfileEnvVarName, profile); err != nil {
		t.Fatalf("cannot set %s: %v", config.DeploymentProfileEnvVarName, err)
	}
	if errs := config.ParseEnvVars(config.DeploymentProfileEnvVarName); len(errs) != 0 {
		t.Fatalf("cannot parse %s=%s: %v", config.DeploymentProfileEnvVarName, profile, errs)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv(config.DeploymentProfileEnvVarName); err != nil {
			t.Fatalf("cannot unset %s: %v", config.DeploymentProfileEnvVarName, err)
		}
		if errs := config.ParseEnvVars(config.DeploymentProfileEnvVarName); len(errs) != 0 {
			t.Fatalf("cannot restore %s: %v", config.DeploymentProfileEnvVarName, errs)
		}
	})
}

/* countingCalicoClientFactory replaces the only constructor of a Calico
 * datastore client, and counts how many times it was called. */
func countingCalicoClientFactory(t *testing.T, calls *int) {
	t.Helper()
	previous := newCalicoClient
	newCalicoClient = func() (calicov3cli.Interface, error) {
		*calls++
		return nil, errors.New("no calico datastore in this test")
	}
	t.Cleanup(func() { newCalicoClient = previous })
}

func TestMain(m *testing.M) {
	/* vpp_runner.go logs through the package level logger, which main()
	 * normally creates. */
	log = logrus.New()
	log.SetOutput(os.Stderr)
	os.Exit(m.Run())
}

/* In the external profile no Calico client may be constructed: readiness must
 * not depend on a Calico node resource being reachable. */
func TestUpdateNodeAddressesExternalProfileDoesNotUseCalico(t *testing.T) {
	setDeploymentProfile(t, string(config.DeploymentProfileExternal))
	calls := 0
	countingCalicoClientFactory(t, &calls)

	runner := &VppRunner{}
	err := runner.updateNodeAddresses(&config.LinuxInterfaceState{})
	if err != nil {
		t.Fatalf("updateNodeAddresses should succeed without a Calico datastore, got %v", err)
	}
	if calls != 0 {
		t.Fatalf("a Calico client was constructed %d times in the external profile", calls)
	}
}

/* In the calico profile the existing behaviour is unchanged: the Calico client
 * is constructed, and a failure to reach the datastore is an error (which the
 * caller turns into terminateVpp). */
func TestUpdateNodeAddressesCalicoProfileUsesCalico(t *testing.T) {
	setDeploymentProfile(t, string(config.DeploymentProfileCalico))
	calls := 0
	countingCalicoClientFactory(t, &calls)

	runner := &VppRunner{}
	err := runner.updateNodeAddresses(&config.LinuxInterfaceState{})
	if err == nil {
		t.Fatal("updateNodeAddresses should report the Calico client error in the calico profile")
	}
	if calls != 1 {
		t.Fatalf("expected exactly one Calico client construction, got %d", calls)
	}
}

/* The default (unset environment) profile is calico, so an existing deployment
 * that does not set the variable keeps updating the Calico node. */
func TestDefaultProfileIsCalico(t *testing.T) {
	if err := os.Unsetenv(config.DeploymentProfileEnvVarName); err != nil {
		t.Fatalf("cannot unset %s: %v", config.DeploymentProfileEnvVarName, err)
	}
	if errs := config.ParseEnvVars(config.DeploymentProfileEnvVarName); len(errs) != 0 {
		t.Fatalf("cannot parse an unset %s: %v", config.DeploymentProfileEnvVarName, errs)
	}
	if !config.GetDeploymentProfile().UsesCalicoDatastore() {
		t.Fatalf("default profile %s should use the Calico datastore", config.GetDeploymentProfile())
	}

	calls := 0
	countingCalicoClientFactory(t, &calls)
	runner := &VppRunner{}
	if err := runner.updateNodeAddresses(&config.LinuxInterfaceState{}); err == nil {
		t.Fatal("updateNodeAddresses should report the Calico client error in the default profile")
	}
	if calls != 1 {
		t.Fatalf("expected exactly one Calico client construction, got %d", calls)
	}
}

/* The gating above is only meaningful if newCalicoClient stays the single
 * constructor of a Calico datastore client in this package: a direct call to
 * calicov3cli.NewFromEnv() elsewhere would bypass the profile gate. */
func TestCalicoClientIsOnlyConstructedThroughTheSeam(t *testing.T) {
	sources, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("cannot list the package sources: %v", err)
	}
	found := make(map[string]int)
	for _, source := range sources {
		if strings.HasSuffix(source, "_test.go") {
			continue
		}
		content, err := os.ReadFile(source)
		if err != nil {
			t.Fatalf("cannot read %s: %v", source, err)
		}
		count := strings.Count(string(content), "calicov3cli.NewFromEnv")
		if count != 0 {
			found[source] = count
		}
	}
	if len(found) != 1 || found["vpp_runner.go"] != 1 {
		t.Fatalf("calicov3cli.NewFromEnv must appear exactly once, in the "+
			"newCalicoClient definition in vpp_runner.go, found %v", found)
	}
}

/* An unknown profile is a configuration error: it never falls back to a
 * profile, and it is never inferred from whether the Calico API answers. */
func TestUnknownProfileIsAnError(t *testing.T) {
	if err := os.Setenv(config.DeploymentProfileEnvVarName, "cilium"); err != nil {
		t.Fatalf("cannot set %s: %v", config.DeploymentProfileEnvVarName, err)
	}
	t.Cleanup(func() {
		if err := os.Unsetenv(config.DeploymentProfileEnvVarName); err != nil {
			t.Fatalf("cannot unset %s: %v", config.DeploymentProfileEnvVarName, err)
		}
		if errs := config.ParseEnvVars(config.DeploymentProfileEnvVarName); len(errs) != 0 {
			t.Fatalf("cannot restore %s: %v", config.DeploymentProfileEnvVarName, errs)
		}
	})
	if errs := config.ParseEnvVars(config.DeploymentProfileEnvVarName); len(errs) == 0 {
		t.Fatal("an unknown deployment profile should be rejected")
	}
}
