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

package cni

import (
	gerrors "errors"
	"net"
	"os"
	"syscall"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/podinterface"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	podinterfacepb "github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/proto/podinterface"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// DefaultPrimaryInterfaceName is the Pod interface name the lifecycle profile
// supports in v1.
//
// Only the primary attachment of a Pod is in scope: a secondary (multinet)
// attachment would need the Cilium endpoint model to treat it as an
// independent endpoint, which is not established, and folding an unsupported
// secondary attachment into the primary one is explicitly forbidden
// (Issue #135 ruling 3 of the 7-point set).
const DefaultPrimaryInterfaceName = "eth0"

// NewLifecycleServer builds a Pod interface lifecycle service: the VPP
// interface lifecycle authority for an external CNI.
//
// The Calico dependencies of NewCNIServer are not constructed here rather than
// stubbed (Issue #135 ruling 3). There is no Felix IPAM authority, so the pod
// specs this server builds have no IP pool behind them and never take the SNAT
// path; there is no node BGP spec, so nothing resolves a host address for host
// ports; and no pubsub handler is registered, because there is no Calico
// control plane subscribing to pod events. Cilium remains the Kubernetes, CNI,
// IPAM and endpoint authority; this server is only the interface lifecycle
// authority.
func NewLifecycleServer(vpp *vpplink.VppLink, ifBinding IfBindingWriter, log *logrus.Entry) *Server {
	server := &Server{
		vpp: vpp,
		log: log,

		// felixServerIpam is deliberately left nil: see above.
		felixServerIpam: nil,

		grpcServer:      grpc.NewServer(),
		podInterfaceMap: make(map[string]model.LocalPodSpec),
		dsrVIPs:         make(map[string]*dsrVIPState),
		dsrDesired:      make(map[string]*common.DSRService),

		tuntapDriver:   podinterface.NewTunTapPodInterfaceDriver(vpp, log, nil),
		memifDriver:    podinterface.NewMemifPodInterfaceDriver(vpp, log, nil),
		vclDriver:      podinterface.NewVclPodInterfaceDriver(vpp, log, nil),
		loopbackDriver: podinterface.NewLoopbackPodInterfaceDriver(vpp, log, nil),

		cniEventChan:         make(chan common.CalicoVppEvent, common.ChanSize),
		cniMultinetEventChan: make(chan common.CalicoVppEvent, common.ChanSize),

		lifecycleProfile:     true,
		ifBinding:            ifBinding,
		primaryInterfaceName: DefaultPrimaryInterfaceName,
	}
	return server
}

// SetPrimaryInterfaceName overrides the supported primary Pod interface name.
func (s *Server) SetPrimaryInterfaceName(name string) {
	s.primaryInterfaceName = name
}

// LifecycleNotReadyReason returns the reason the lifecycle service refuses to
// serve, or the empty string when it is ready.
//
// It is non-empty when durable ownership could not be established exactly. The
// service then stays unready until an explicit dataplane reset, because the
// alternative — discarding state whose VPP interfaces may still exist — leaves
// orphaned interfaces that nothing owns (Issue #135 ruling 4).
func (s *Server) LifecycleNotReadyReason() string {
	s.lock.Lock()
	defer s.lock.Unlock()
	return s.notReadyReason
}

func (s *Server) markNotReady(reason string) {
	if s.notReadyReason == "" {
		s.notReadyReason = reason
	}
	s.log.Errorf("Pod interface lifecycle service is not ready: %s", reason)
}

// rescanLifecycleState reconciles the durable lifecycle state against VPP after
// a restart of this process (Issue #135 ruling 4).
//
// This is a stateful continuation from the durable authority, not a re-publish:
// for every stored attachment the current handle is verified against a fresh
// dump, and the outcome is one of three, decided by planRescan:
//
//   - the exact same tuple is still live: replay the binding ADD, which the
//     plugin treats as idempotent;
//   - the interface is gone: withdraw the old tuple and create a new interface
//     lifecycle, which publishes a new binding under the normal ADD contract;
//   - ownership cannot be established exactly: fail closed. Nothing is guessed,
//     and nothing is deleted from the durable state.
func (s *Server) rescanLifecycleState() {
	cniServerState, err := model.LoadLifecycleState(config.CniServerStateFilename)
	if err != nil {
		s.lock.Lock()
		defer s.lock.Unlock()
		// The state file is kept on purpose. Removing it would forget the
		// control plane's view while the VPP interfaces it describes may still
		// exist.
		s.markNotReady(err.Error())
		return
	}

	s.log.Infof("RescanState: reconciling %d stored pod interfaces", len(cniServerState.PodSpecs))
	s.lock.Lock()
	defer s.lock.Unlock()

	for key, podSpec := range cniServerState.PodSpecs {
		podSpecCopy := podSpec.Copy()

		if podSpecCopy.AttachmentID == "" {
			// Without the attachment identity the binding could only be
			// re-published by reconstructing it, which 00 §2.12.7 prohibition 1
			// forbids. Keep the entry so the state is not silently discarded
			// and refuse to serve.
			s.podInterfaceMap[key] = podSpecCopy
			s.markNotReady(errors.Errorf(
				"stored pod interface %s has no CNI attachment identity; exact ownership cannot be recovered",
				key).Error())
			continue
		}

		_, err := s.AddVppInterface(&podSpecCopy, false /* doHostSideConf */)
		switch err.(type) {
		case PodNSNotFoundErr:
			// The Pod is gone. Its binding and its VPP interface are not: run
			// the teardown, which needs neither the netns nor a subsequent CNI
			// DEL (Issue #135 ruling 6), and drop the entry.
			s.log.Infof("pod(rescan) netns of %s is gone, tearing its interface down", podSpecCopy.String())
			s.DelVppInterface(&podSpecCopy)
		case nil:
			s.log.Infof("pod(rescan) restored podSpec=%s binding=%s",
				podSpecCopy.String(), podSpecCopy.PublishedIfAttachment)
			s.podInterfaceMap[key] = podSpecCopy
		default:
			// Keep the entry: the interface it describes may exist, so this
			// state must not be discarded.
			s.podInterfaceMap[key] = podSpecCopy
			s.markNotReady(errors.Wrapf(err, "cannot reconcile stored pod interface %s", key).Error())
		}
	}

	if err := model.PersistCniServerState(
		model.NewCniServerState(s.podInterfaceMap),
		config.CniServerStateFilename,
	); err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}
}

// ServeLifecycle runs the PodInterfaceLifecycle gRPC service.
//
// Unlike ServeCNI it registers no Calico CNI backend, installs no
// redirect-to-host rules and waits for no network definitions: those are
// Calico control plane features, and the lifecycle profile has no Calico
// control plane behind it.
func (s *Server) ServeLifecycle(t *tomb.Tomb) error {
	err := syscall.Unlink(config.PodInterfaceLifecycleSocket)
	if err != nil && !gerrors.Is(err, os.ErrNotExist) {
		s.log.Warnf("unable to unlink the pod interface lifecycle socket: %+v", err)
	}

	socketListener, err := net.Listen("unix", config.PodInterfaceLifecycleSocket)
	if err != nil {
		return errors.Wrapf(err, "failed to listen on %s", config.PodInterfaceLifecycleSocket)
	}

	podinterfacepb.RegisterPodInterfaceLifecycleServer(s.grpcServer, &lifecycleService{server: s})

	s.rescanState()

	s.log.Infof("Serve() PodInterfaceLifecycle on %s", config.PodInterfaceLifecycleSocket)

	go func() {
		err := s.grpcServer.Serve(socketListener)
		if err != nil {
			s.log.Fatalf("GrpcServer Server returned %s", err)
		}
	}()

	<-t.Dying()
	s.log.Infof("Pod interface lifecycle server asked to exit")

	s.grpcServer.GracefulStop()
	return syscall.Unlink(config.PodInterfaceLifecycleSocket)
}
