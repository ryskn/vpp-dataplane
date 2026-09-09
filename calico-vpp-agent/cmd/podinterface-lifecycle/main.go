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

// Command podinterface-lifecycle runs the VPP Pod interface lifecycle service.
//
// It is a second entrypoint next to calico-vpp-agent rather than a mode of it,
// because the two have different authorities behind them (Issue #135 ruling 3).
// The agent is a Calico dataplane: it waits for Felix configuration and a node
// BGP spec before it does anything, and Calico owns IPAM, workload endpoints
// and routing. This service owns only the VPP Pod interface lifecycle; the CNI
// that calls it owns attachment identity, IPAM and endpoint lifecycle. Making
// interface creation wait for a second network control plane it does not use
// would be exactly the coupling the ruling rejects, so this entrypoint never
// reaches the Felix configuration barrier at all.
//
// What it starts:
//   - the health server, so readiness can be reported;
//   - the VPP API connection, and the wait for vpp-manager to have finished
//     configuring the uplinks (the pod MTU computation reads them);
//   - the PodInterfaceLifecycle gRPC service.
//
// What it deliberately does not start: the Calico v3 and Kubernetes API
// clients, the BGP server, the Felix server and its plugin, the connectivity,
// routing and service servers, the network and prefix watchers, and multinet.
// No pubsub subscriber is registered either: the pod events the CNI server
// publishes have no consumer in this profile.
package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/health"
	"github.com/projectcalico/vpp-dataplane/v3/config"
)

const componentPodInterfaceLifecycle = "podinterface-lifecycle"

var (
	t   tomb.Tomb
	log *logrus.Logger
)

func goRun(f func(t *tomb.Tomb) error) {
	if t.Alive() {
		t.Go(func() error {
			err := f(&t)
			if err != nil {
				log.Warnf("Tomb function errored with %s", err)
			}
			return err
		})
	}
}

func main() {
	log = logrus.New()

	if err := config.LoadConfig(log); err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	if err := common.WritePidToFile(); err != nil {
		log.Fatalf("Error writing pidfile: %v", err)
	}

	healthServer := health.NewHealthServer(
		log.WithFields(logrus.Fields{"component": "health"}),
		*config.GetCalicoVppInitialConfig().HealthCheckPort,
	)
	goRun(healthServer.ServeHealth)

	vpp, err := common.CreateVppLink(config.VppAPISocket, log.WithFields(logrus.Fields{"component": "vpp-api"}))
	if err != nil {
		log.Fatalf("Cannot create VPP client: %v", err)
	}
	healthServer.SetComponentStatus(health.ComponentVPP, true, "VPP connection established")

	// vpp-manager owns the uplinks and vpptap0; wait for it to have finished,
	// as the agent does, because the pod MTU is derived from the uplink MTUs.
	common.VppManagerInfo, err = common.WaitForVppManager()
	if err != nil {
		log.Fatalf("Vpp Manager not started: %v", err)
	}
	healthServer.SetComponentStatus(health.ComponentVPPManager, true, "VPP Manager ready")

	// The pod interface code publishes events unconditionally; the pubsub has
	// to exist for that, but nothing subscribes to it in this profile.
	common.ThePubSub = common.NewPubSub(log.WithFields(logrus.Fields{"component": "pubsub"}))

	// vpp is both the dataplane and the IF-4 binding writer: the component that
	// creates the interface is the one that publishes its binding (D-71).
	lifecycleServer := cni.NewLifecycleServer(vpp, vpp,
		log.WithFields(logrus.Fields{"component": componentPodInterfaceLifecycle}))

	goRun(lifecycleServer.ServeLifecycle)

	// Readiness follows the durable state reconciliation: a state whose exact
	// ownership could not be recovered leaves the service unready and requires
	// an explicit dataplane reset (Issue #135 ruling 4).
	goRun(func(t *tomb.Tomb) error {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		ready := false
		for {
			select {
			case <-t.Dying():
				return nil
			case <-ticker.C:
				reason := lifecycleServer.LifecycleNotReadyReason()
				switch {
				case reason != "" && ready:
					ready = false
					healthServer.SetComponentStatus(componentPodInterfaceLifecycle, false, reason)
					healthServer.MarkAsUnhealthy(reason)
				case reason != "" && !ready:
					healthServer.SetComponentStatus(componentPodInterfaceLifecycle, false, reason)
					healthServer.MarkAsUnhealthy(reason)
				case reason == "" && !ready:
					ready = true
					healthServer.SetComponentStatus(componentPodInterfaceLifecycle, true,
						"pod interface lifecycle service ready")
					healthServer.MarkAsHealthy("pod interface lifecycle service ready")
				}
			}
		}
	})

	log.Infof("Pod interface lifecycle service started")

	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGUSR1)

	select {
	case sig := <-sigChan:
		switch sig {
		case os.Interrupt, syscall.SIGTERM:
			log.Infof("SIG received, exiting")
			t.Kill(errors.Errorf("Caught INT signal"))
		case syscall.SIGUSR1:
			// vpp-manager pokes us with USR1 if VPP terminates
			log.Warnf("Vpp stopped, exiting...")
			t.Kill(errors.Errorf("Caught signal USR1"))
		}
	case <-t.Dying():
		log.Errorf("tomb Dying %s", t.Err())
	}

	go func() {
		time.Sleep(*config.CalicoVppGracefulShutdownTimeout)
		panic("Graceful shutdown took too long")
	}()
	log.Infof("Tomb exited with %v", t.Wait())
}
