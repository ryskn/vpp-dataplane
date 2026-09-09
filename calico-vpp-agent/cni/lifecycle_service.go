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
	"context"
	"net"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	podinterfacepb "github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/proto/podinterface"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// lifecycleService implements the PodInterfaceLifecycle contract on top of the
// interface lifecycle machinery of Server.
//
// It is deliberately thin: it validates the request, converts it into a
// LocalPodSpec without going through the Calico AddRequest, and lets
// AddVppInterface / DelVppInterface enforce the D-71 ordering. Failures are
// gRPC statuses, so the caller can distinguish a rejected request from a
// dataplane failure and, for DELETE, an unknown attachment from a failed one.
type lifecycleService struct {
	podinterfacepb.UnimplementedPodInterfaceLifecycleServer
	server *Server
}

// CreatePodInterface creates the Pod-facing VPP interface for one CNI
// attachment and publishes its IF-4 binding before replying.
//
// The reply is the publication barrier of 00 §2.12.6: it is produced only after
// the binding ADD was acknowledged, so a caller that waits for it cannot expose
// an attachment whose identity is not yet published against the current
// InterfaceHandle. A failure anywhere in the sequence rolls the interface back
// and is reported as an error, never as a partially successful reply.
func (l *lifecycleService) CreatePodInterface(
	ctx context.Context,
	request *podinterfacepb.CreatePodInterfaceRequest,
) (*podinterfacepb.CreatePodInterfaceReply, error) {
	s := l.server

	if reason := s.LifecycleNotReadyReason(); reason != "" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"pod interface lifecycle service is not ready: %s", reason)
	}

	podSpec, err := s.podSpecFromCreateRequest(request)
	if err != nil {
		return nil, err
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	s.log.Infof("pod(add) attachment=%s spec=%s", podSpec.AttachmentID, podSpec.String())

	if existing, ok := s.podInterfaceMap[podSpec.Key()]; ok {
		if existing.AttachmentID != podSpec.AttachmentID {
			// The same netns and interface name under a different attachment
			// identity is a conflict, not an update. Silently rebinding it
			// would be the implicit replacement 00 §2.12.7 prohibition 5
			// forbids.
			return nil, status.Errorf(codes.AlreadyExists,
				"interface %s is already attached as %q, refusing to rebind it to %q",
				podSpec.Key(), existing.AttachmentID, podSpec.AttachmentID)
		}
		// Same attachment: continue from the stored state, so that a retry
		// replays the exact tuple that was published rather than creating a
		// second lifetime.
		existingCopy := existing.Copy()
		podSpec = &existingCopy
	}

	swIfIndex, err := s.createVppInterface(podSpec, true /* doHostSideConf */)
	if err != nil {
		s.log.Errorf("Interface add failed %s : %v", podSpec.String(), err)
		return nil, status.Errorf(codes.Internal, "cannot create the pod interface: %v", err)
	}
	if podSpec.PublishedIfAttachment == nil {
		// Unreachable while a binding writer is configured, because
		// AddVppInterface publishes before returning. Refuse rather than reply
		// without a published binding.
		return nil, status.Errorf(codes.Internal,
			"pod interface %s was created but no binding was published", podSpec.Key())
	}

	s.podInterfaceMap[podSpec.Key()] = *podSpec
	if err := model.PersistCniServerState(
		model.NewCniServerState(s.podInterfaceMap),
		s.stateFilename,
	); err != nil {
		// The interface exists and its binding is published; losing the
		// durable record would make the next restart unable to name the exact
		// tuple it must withdraw, so this is a failure, not a warning.
		s.log.Errorf("CNI state persist errored %v", err)
		s.delVppInterface(podSpec)
		delete(s.podInterfaceMap, podSpec.Key())
		return nil, status.Errorf(codes.Internal, "cannot persist the pod interface state: %v", err)
	}

	s.log.Infof("pod(add) Done attachment=%s swIfIndex=%d binding=%s",
		podSpec.AttachmentID, swIfIndex, podSpec.PublishedIfAttachment)

	return &podinterfacepb.CreatePodInterfaceReply{
		SwIfIndex:     podSpec.PublishedIfAttachment.SwIfIndex,
		IfIncarnation: podSpec.PublishedIfAttachment.IfIncarnation,
	}, nil
}

// DeletePodInterface tears one attachment down.
//
// An attachment this service does not know is reported as NOT_FOUND rather than
// as a success, so the caller decides whether a missing attachment is an
// idempotent DEL or a real inconsistency. Nothing is reconstructed for an
// unknown attachment: without a stored tuple there is nothing exact to
// withdraw, and the plugin's interface delete callback is the safety net
// (Issue #135 ruling 5).
func (l *lifecycleService) DeletePodInterface(
	ctx context.Context,
	request *podinterfacepb.DeletePodInterfaceRequest,
) (*podinterfacepb.DeletePodInterfaceReply, error) {
	s := l.server

	if err := vpplink.ValidateAttachmentID(request.GetAttachmentId()); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid attachment_id: %v", err)
	}
	if request.GetNetns() == "" {
		return nil, status.Error(codes.InvalidArgument, "netns is required")
	}
	if request.GetIfname() == "" {
		return nil, status.Error(codes.InvalidArgument, "ifname is required")
	}

	key := model.LocalPodSpecKey(request.GetNetns(), request.GetIfname())

	s.lock.Lock()
	defer s.lock.Unlock()

	podSpec, ok := s.podInterfaceMap[key]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no pod interface for %s", key)
	}
	if podSpec.AttachmentID != request.GetAttachmentId() {
		// Deleting under a different identity than the one that was published
		// would withdraw a binding this request does not own.
		return nil, status.Errorf(codes.NotFound,
			"pod interface %s is attached as %q, not as %q",
			key, podSpec.AttachmentID, request.GetAttachmentId())
	}

	s.log.Infof("pod(del) attachment=%s spec=%s", podSpec.AttachmentID, podSpec.String())
	s.delVppInterface(&podSpec)

	delete(s.podInterfaceMap, key)
	if err := model.PersistCniServerState(
		model.NewCniServerState(s.podInterfaceMap),
		s.stateFilename,
	); err != nil {
		s.log.Errorf("CNI state persist errored %v", err)
	}

	s.log.Infof("pod(del) Done attachment=%s", request.GetAttachmentId())
	return &podinterfacepb.DeletePodInterfaceReply{}, nil
}

// podSpecFromCreateRequest converts a CreatePodInterface request into a
// LocalPodSpec.
//
// It builds the pod spec directly instead of going through the Calico
// AddRequest: the Calico request carries workload identifiers, annotations,
// host ports and dataplane options that have no meaning here, and translating
// into it would make Calico's data model part of this contract.
//
// Everything outside the v1 supported profile is rejected rather than
// approximated (Issue #135 ruling 2): port-based load balancing, memif,
// multinet and secondary attachments are out of scope, and an attachment that
// asks for them is refused instead of being folded into the primary one.
func (s *Server) podSpecFromCreateRequest(
	request *podinterfacepb.CreatePodInterfaceRequest,
) (*model.LocalPodSpec, error) {
	attachmentID := request.GetAttachmentId()
	// The attachment identity is stored and published verbatim: it is never
	// truncated to fit, because a truncated identity is a different identity
	// (02 §8.1 rule 1, 00 §2.12.7 prohibition 3).
	if err := vpplink.ValidateAttachmentID(attachmentID); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid attachment_id: %v", err)
	}

	netns := request.GetNetns()
	if netns == "" {
		return nil, status.Error(codes.InvalidArgument, "netns is required")
	}
	ifname := request.GetIfname()
	if ifname == "" {
		return nil, status.Error(codes.InvalidArgument, "ifname is required")
	}
	if err := s.validatePrimaryInterfaceName(ifname); err != nil {
		return nil, err
	}
	// The attachment identity is of the form <container id>:<ifname>. Requiring
	// the two to agree is a consistency check on what the caller sent; the
	// identity is never derived from the interface name (00 §2.12.7
	// prohibition 1).
	if idx := strings.LastIndex(attachmentID, ":"); idx < 0 || attachmentID[idx+1:] != ifname {
		return nil, status.Errorf(codes.InvalidArgument,
			"attachment_id %q does not name interface %q", attachmentID, ifname)
	}

	if len(request.GetAddresses()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one address is required")
	}

	isL3 := true
	podSpec := &model.LocalPodSpec{
		InterfaceName: ifname,
		NetnsName:     netns,
		AttachmentID:  attachmentID,
		// IP forwarding inside the Pod is not part of this contract; the Pod
		// is an endpoint, not a router.
		AllowIPForwarding: false,
		Routes:            make([]net.IPNet, 0, len(request.GetRoutes())),
		ContainerIPs:      make([]net.IP, 0, len(request.GetAddresses())),
		Mtu:               int(request.GetMtu()),
		HostPorts:         make([]model.HostPortBinding, 0),
		// NetworkName stays empty: multinet is out of scope, and the empty
		// name is what "the default network" means here.
		NetworkName: "",
		PodAnnotations: model.PodAnnotations{
			AllowedSpoofingSources: make([]net.IPNet, 0),
			IfPortConfigs:          make([]model.LocalIfPortConfigs, 0),
			// L3 only: D-50 fixes the Pod attachment to an IP-mode interface.
			IfSpec:        lifecycleIfSpec(isL3),
			PBLMemifSpec:  lifecycleIfSpec(isL3),
			DefaultIfType: model.VppIfTypeTunTap,
			// PortFilteredIfType stays Unknown: no port-based split.
			PortFilteredIfType: model.VppIfTypeUnknown,
			EnableMemif:        false,
			EnableVCL:          false,
		},
		LocalPodSpecStatus: *model.NewLocalPodSpecStatus(),
	}

	for _, addr := range request.GetAddresses() {
		ip, ipNet, err := net.ParseCIDR(addr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "cannot parse address %q: %v", addr, err)
		}
		if ip.To4() != nil {
			return nil, status.Errorf(codes.InvalidArgument,
				"address %q is IPv4; this profile is IPv6 single stack", addr)
		}
		if ones, bits := ipNet.Mask.Size(); ones != bits {
			return nil, status.Errorf(codes.InvalidArgument,
				"address %q is not a host address (/128)", addr)
		}
		podSpec.ContainerIPs = append(podSpec.ContainerIPs, ip)
	}

	for _, routeStr := range request.GetRoutes() {
		_, route, err := net.ParseCIDR(routeStr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "cannot parse route %q: %v", routeStr, err)
		}
		podSpec.Routes = append(podSpec.Routes, *route)
	}

	return podSpec, nil
}

// validatePrimaryInterfaceName rejects every attachment that is not the Pod's
// primary one.
//
// v1 supports the primary attachment and nothing else (Issue #135 ruling 3 of
// the 7-point set): a secondary (multinet) attachment would need the Cilium
// endpoint model to treat it as an independent endpoint, which is not
// established. Being out of scope is expressed as a refusal, not as silence.
// Accepting the request and ignoring the interface name would create an
// interface for eth1 under eth0's identity, and ignoring the request would tell
// the CNI that an attachment it asked for exists when it does not; either way
// one CNI attachment identity would stop naming exactly one interface, which is
// the invariant of D-68.
//
// The comparison is exact. There is no normalisation, no prefix matching and no
// "looks like a primary interface" rule: a name this service was not configured
// for is a name it does not serve. DefaultPrimaryInterfaceName is what the
// lifecycle server is configured with, and SetPrimaryInterfaceName is the only
// way that changes.
func (s *Server) validatePrimaryInterfaceName(ifname string) error {
	if ifname == s.primaryInterfaceName {
		return nil
	}
	if strings.HasPrefix(ifname, "memif") {
		// Reachable only if this service was configured with a memif name as
		// its primary interface. Memif is out of scope regardless: it is the
		// second interface of a port-based-load-balancing attachment, and
		// which of the two owns the attachment is not something a
		// configuration convenience may decide (Issue #135 ruling 2).
		return status.Errorf(codes.InvalidArgument,
			"memif interfaces are out of scope for the pod interface lifecycle service")
	}
	return status.Errorf(codes.InvalidArgument,
		"only the primary attachment %q is supported, got %q: secondary attachments are out of scope, "+
			"and are neither ignored nor folded into the primary one",
		s.primaryInterfaceName, ifname)
}

func lifecycleIfSpec(isL3 bool) config.InterfaceSpec {
	l3 := isL3
	spec := config.InterfaceSpec{
		NumRxQueues: config.GetCalicoVppInterfaces().DefaultPodIfSpec.NumRxQueues,
		NumTxQueues: config.GetCalicoVppInterfaces().DefaultPodIfSpec.NumTxQueues,
		RxQueueSize: vpplink.DefaultIntTo(
			config.GetCalicoVppInterfaces().DefaultPodIfSpec.RxQueueSize,
			vpplink.CalicoVppDefaultQueueSize,
		),
		TxQueueSize: vpplink.DefaultIntTo(
			config.GetCalicoVppInterfaces().DefaultPodIfSpec.TxQueueSize,
			vpplink.CalicoVppDefaultQueueSize,
		),
		IsL3: &l3,
	}
	return spec
}
