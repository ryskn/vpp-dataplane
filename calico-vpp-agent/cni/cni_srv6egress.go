package cni

import (
	"errors"
	"fmt"
	"net"

	govppapi "go.fd.io/govpp/api"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/srv6egress"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// The CNI server implements srv6egress.VPPInterface: it owns the local pod
// cache, so it can scope each EgressPolicy steering to the matched pod's
// per-pod VRF (V6VrfID). Only that pod's traffic to DestPrefix is steered into
// the SR Policy identified by BSID; the SR Policy itself (BSID → segment list)
// is installed independently by the SRv6 connectivity provider from BGP intent.

// InstallSteering implements srv6egress.VPPInterface.
func (s *Server) InstallSteering(req srv6egress.SteeringRequest) error {
	steer, err := s.egressSteer(req)
	if err != nil {
		return err
	}
	return s.vpp.AddSRv6Steering(steer)
}

// RemoveSteering implements srv6egress.VPPInterface. Idempotent at the VPP
// layer; a delete for an absent entry is not treated as fatal by callers.
func (s *Server) RemoveSteering(req srv6egress.SteeringRequest) error {
	steer, err := s.egressSteer(req)
	if err != nil {
		return err
	}
	if err := s.vpp.DelSRv6Steering(steer); err != nil {
		var vppErr govppapi.VPPApiError
		if errors.As(err, &vppErr) && (vppErr == govppapi.NO_SUCH_INNER_FIB || vppErr == govppapi.UNSPECIFIED) {
			return nil
		}
		return err
	}
	return nil
}

// InstallBlackhole implements srv6egress.VPPInterface. It installs a drop route
// for req.DestPrefix in the owning pod's per-pod IPv6 VRF so that, while the SR
// Policy is unavailable, the pod's traffic is dropped (fail-closed) instead of
// leaking out via the node default egress.
func (s *Server) InstallBlackhole(req srv6egress.SteeringRequest) error {
	route, err := s.egressBlackholeRoute(req)
	if err != nil {
		return err
	}
	return s.vpp.RouteAdd(route)
}

// RemoveBlackhole implements srv6egress.VPPInterface. Idempotent: a delete for
// an absent route is logged and treated as success by callers.
func (s *Server) RemoveBlackhole(req srv6egress.SteeringRequest) error {
	route, err := s.egressBlackholeRoute(req)
	if err != nil {
		return err
	}
	if err := s.vpp.RouteDel(route); err != nil {
		s.log.WithError(err).Warnf("cni(egress) del blackhole %s in vrf %d (continuing)", req.DestPrefix, route.Table)
	}
	return nil
}

// egressBlackholeRoute builds the per-pod-VRF drop route for an egress
// SteeringRequest, resolving the owning pod's IPv6 VRF from the local pod cache.
func (s *Server) egressBlackholeRoute(req srv6egress.SteeringRequest) (*types.Route, error) {
	if req.PodIP == nil || req.DestPrefix == nil {
		return nil, fmt.Errorf("egress blackhole: incomplete request %+v", req)
	}
	vrf, ok := s.podV6VrfForIP(req.PodIP)
	if !ok {
		return nil, fmt.Errorf("egress blackhole: no local pod with IP %s", req.PodIP)
	}
	if vrf == vpplink.InvalidID {
		return nil, fmt.Errorf("egress blackhole: pod %s has no v6 VRF yet", req.PodIP)
	}
	return &types.Route{
		Dst:   req.DestPrefix,
		Table: vrf,
		Paths: []types.RoutePath{{IsDrop: true}},
	}, nil
}

// egressSteer builds the SrSteer for an egress SteeringRequest, resolving the
// owning pod's per-pod IPv6 VRF from the local pod cache.
func (s *Server) egressSteer(req srv6egress.SteeringRequest) (*types.SrSteer, error) {
	if req.PodIP == nil || req.DestPrefix == nil || req.BSID == nil {
		return nil, fmt.Errorf("egress steer: incomplete request %+v", req)
	}
	vrf, ok := s.podV6VrfForIP(req.PodIP)
	if !ok {
		return nil, fmt.Errorf("egress steer: no local pod with IP %s", req.PodIP)
	}
	if vrf == vpplink.InvalidID {
		return nil, fmt.Errorf("egress steer: pod %s has no v6 VRF yet", req.PodIP)
	}
	prefix, err := ip_types.ParsePrefix(req.DestPrefix.String())
	if err != nil {
		return nil, fmt.Errorf("egress steer: parse dest %s: %w", req.DestPrefix, err)
	}
	return &types.SrSteer{
		TrafficType: types.SrSteerIPv6,
		FibTable:    vrf,
		Prefix:      prefix,
		// L3 steering selects the FIB by FibTable; SwIfIndex must be ~0 (InvalidID,
		// the API default), not 0 — a 0 makes VPP try to derive the table from
		// interface 0 and reject it ("Invalid sw_if_index"), ignoring FibTable.
		SwIfIndex: vpplink.InvalidID,
		Bsid:      types.ToVppIP6Address(req.BSID),
	}, nil
}

// podV6VrfForIP returns the per-pod IPv6 VRF of the local pod owning ip.
func (s *Server) podV6VrfForIP(ip net.IP) (uint32, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for key := range s.podInterfaceMap {
		spec := s.podInterfaceMap[key]
		for _, cip := range spec.GetContainerIPs() {
			if cip.IP.Equal(ip) {
				return spec.V6VrfID, true
			}
		}
	}
	return 0, false
}
