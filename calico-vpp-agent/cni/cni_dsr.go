package cni

import (
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// dsrVIPState tracks, for a DSR ClusterIP with backend pods local to this node,
// the shared PodVRFIndex delivery route and the set of local pods that currently
// have the VIP programmed (bound on lo + allowed through uRPF), keyed by pod IP.
// boundPods is authoritative for cleanup: a pod stays in it until its VIP
// binding has been successfully removed (or the pod is gone), so per-pod cleanup
// failures are retried on the next reconcile rather than forgotten.
type dsrVIPState struct {
	vip       net.IP
	delivery  *types.Route
	boundPods map[string]bool
}

func (s *Server) handleDSRServiceAdded(svc *common.DSRService) {
	if svc == nil || svc.VIP == nil {
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.dsrDesired[svc.VIP.String()] = svc
	s.reconcileDSRVIPs()
}

func (s *Server) handleDSRServiceDeleted(svc *common.DSRService) {
	if svc == nil || svc.VIP == nil {
		return
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.dsrDesired, svc.VIP.String())
	s.reconcileDSRVIPs()
}

// reconcileDSRVIPs drives installed DSR VIP state toward the desired set,
// retrying failed installs and removals (both the delivery route and per-pod
// bindings). It is invoked on every DSR event, the services server's periodic
// re-publish, and pod add/del — so a transient failure is retried rather than
// recorded as reconciled. Caller holds s.lock.
func (s *Server) reconcileDSRVIPs() {
	for _, svc := range s.dsrDesired {
		s.programDSRVIP(svc)
	}
	for key := range s.dsrVIPs {
		if _, ok := s.dsrDesired[key]; !ok {
			s.teardownDSRVIP(key)
		}
	}
}

// programDSRVIP binds the VIP on this node's local backend pods (so their kernel
// accepts dst==VIP and the reply is sourced from the VIP, allowed through uRPF),
// unbinds pods no longer backing the service (retaining ones whose cleanup
// fails), and reconciles the PodVRFIndex ECMP delivery route. No NAT is
// involved. Caller holds s.lock.
func (s *Server) programDSRVIP(svc *common.DSRService) {
	vipKey := svc.VIP.String()
	prev := s.dsrVIPs[vipKey]
	boundPods := map[string]bool{}
	if prev != nil {
		for ip := range prev.boundPods {
			boundPods[ip] = true
		}
	}

	desiredLocal := map[string]bool{}
	var deliveryPaths []types.RoutePath
	for _, beIP := range svc.Backends {
		podSpec := s.findLocalPodByIP(beIP)
		if podSpec == nil || podSpec.TunTapSwIfIndex == vpplink.InvalidSwIfIndex {
			continue // not a local tun-backed pod
		}
		desiredLocal[beIP.String()] = true
		if err := s.bindVIPInPod(podSpec, svc.VIP, true /* add */); err != nil {
			s.log.Errorf("cni(dsr) bind vip=%s pod=%s: %v", svc.VIP, beIP, err)
		}
		if err := s.dsrRPFRoute(podSpec, svc.VIP, true /* add */); err != nil {
			s.log.Errorf("cni(dsr) rpf add vip=%s pod=%s: %v", svc.VIP, beIP, err)
		}
		boundPods[beIP.String()] = true
		deliveryPaths = append(deliveryPaths, types.RoutePath{
			SwIfIndex: podSpec.TunTapSwIfIndex,
			Gw:        beIP,
		})
	}

	// Unbind pods no longer backing the service; keep ones whose cleanup fails so
	// a departed-but-running pod can't keep answering as / uRPF-spoofing the VIP.
	for ipStr := range boundPods {
		if desiredLocal[ipStr] {
			continue
		}
		if s.cleanupDSRPod(ipStr, svc.VIP) {
			delete(boundPods, ipStr)
		}
	}

	st := &dsrVIPState{vip: svc.VIP, boundPods: boundPods}
	st.delivery = s.updateDeliveryRoute(svc.VIP, prev, deliveryPaths)
	// Drop the entry only once the route is gone AND no pod cleanup is pending.
	if st.delivery == nil && len(boundPods) == 0 {
		delete(s.dsrVIPs, vipKey)
		return
	}
	s.dsrVIPs[vipKey] = st
	s.log.Debugf("cni(dsr) vip=%s local backends=%d bound=%d", svc.VIP, len(desiredLocal), len(boundPods))
}

// teardownDSRVIP removes all DSR state for a VIP no longer desired, retaining
// (for retry on the next reconcile) the delivery route and any pod whose cleanup
// fails. Caller holds s.lock.
func (s *Server) teardownDSRVIP(key string) {
	st := s.dsrVIPs[key]
	if st == nil {
		return
	}
	st.delivery = s.updateDeliveryRoute(st.vip, st, nil /* no paths */)
	for ipStr := range st.boundPods {
		if s.cleanupDSRPod(ipStr, st.vip) {
			delete(st.boundPods, ipStr)
		}
	}
	if st.delivery == nil && len(st.boundPods) == 0 {
		delete(s.dsrVIPs, key)
	}
}

// cleanupDSRPod removes the VIP binding (lo) and uRPF allow from a pod that no
// longer backs the service. Returns true when cleanup is complete — the pod is
// gone (its netns + per-pod RPF VRF auto-cleaned) or both removals succeeded —
// and false when it must be retried.
func (s *Server) cleanupDSRPod(ipStr string, vip net.IP) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return true
	}
	podSpec := s.findLocalPodByIP(ip)
	if podSpec == nil {
		return true // pod gone; netns + per-pod RPF VRF auto-cleaned
	}
	ok := true
	if err := s.bindVIPInPod(podSpec, vip, false /* del */); err != nil {
		s.log.Errorf("cni(dsr) unbind vip=%s pod=%s: %v", vip, ip, err)
		ok = false
	}
	if err := s.dsrRPFRoute(podSpec, vip, false /* del */); err != nil {
		s.log.Errorf("cni(dsr) rpf del vip=%s pod=%s: %v", vip, ip, err)
		ok = false
	}
	return ok
}

// updateDeliveryRoute reconciles the PodVRFIndex delivery route for a VIP to the
// given paths, retaining state on VPP failure so the next reconcile retries:
//   - unchanged paths: keep the existing route (no blackhole churn);
//   - changed paths: delete the old (on failure keep it and retry later), then
//     add the new (on failure return nil so the add is retried);
//   - no paths: delete the old (retain on failure).
func (s *Server) updateDeliveryRoute(vip net.IP, prev *dsrVIPState, paths []types.RoutePath) *types.Route {
	if len(paths) == 0 {
		// No backends: remove the delivery route (retain on failure to retry).
		if prev != nil && prev.delivery != nil {
			if err := s.vpp.RouteDel(prev.delivery); err != nil {
				s.log.Errorf("cni(dsr) del delivery route vip=%s: %v", vip, err)
				return prev.delivery
			}
		}
		return nil
	}
	if prev != nil && prev.delivery != nil && samePaths(prev.delivery.Paths, paths) {
		return prev.delivery // unchanged
	}
	route := &types.Route{
		Dst:   common.ToMaxLenCIDR(vip),
		Paths: paths,
		Table: common.PodVRFIndex,
	}
	// RouteAdd is a non-multipath add, which VPP applies as an atomic replace of
	// the prefix's paths. Skipping the prior RouteDel removes the delete-then-add
	// window that would briefly blackhole the VIP while the backend set changes.
	if err := s.vpp.RouteAdd(route); err != nil {
		s.log.Errorf("cni(dsr) add delivery route vip=%s: %v", vip, err)
		if prev != nil {
			return prev.delivery // old route still installed; retry next reconcile
		}
		return nil
	}
	return route
}

// samePaths reports whether two route path sets are equal (order-independent).
func samePaths(a, b []types.RoutePath) bool {
	if len(a) != len(b) {
		return false
	}
	type key struct {
		idx uint32
		gw  string
	}
	m := make(map[key]int)
	for _, p := range a {
		m[key{p.SwIfIndex, p.Gw.String()}]++
	}
	for _, p := range b {
		m[key{p.SwIfIndex, p.Gw.String()}]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

// findLocalPodByIP returns the local pod spec whose container IP equals ip.
func (s *Server) findLocalPodByIP(ip net.IP) *model.LocalPodSpec {
	for key := range s.podInterfaceMap {
		spec := s.podInterfaceMap[key]
		for _, cip := range spec.GetContainerIPs() {
			if cip.IP.Equal(ip) {
				return &spec
			}
		}
	}
	return nil
}

// bindVIPInPod adds or removes the VIP on the pod's loopback inside its netns.
// It lists the current addresses first so add is a no-op when already present
// and del is a no-op when already absent — neither reports a spurious failure.
func (s *Server) bindVIPInPod(podSpec *model.LocalPodSpec, vip net.IP, add bool) error {
	if podSpec.NetnsName == "" {
		return nil
	}
	return ns.WithNetNSPath(podSpec.NetnsName, func(ns.NetNS) error {
		lo, err := netlink.LinkByName("lo")
		if err != nil {
			return err
		}
		addrs, err := netlink.AddrList(lo, netlink.FAMILY_V6)
		if err != nil {
			return err
		}
		present := false
		for _, a := range addrs {
			if a.IP.Equal(vip) {
				present = true
				break
			}
		}
		addr := &netlink.Addr{IPNet: common.ToMaxLenCIDR(vip)}
		if add {
			if present {
				return nil
			}
			return netlink.AddrAdd(lo, addr)
		}
		if present {
			return netlink.AddrDel(lo, addr)
		}
		return nil
	})
}

// dsrRPFRoute adds or removes a route for the VIP in the pod's RPF VRF so the
// loose uRPF check passes (add) / no longer passes (del) a reply sourced from
// the VIP. VPP's route delete is idempotent for an absent route.
func (s *Server) dsrRPFRoute(podSpec *model.LocalPodSpec, vip net.IP, add bool) error {
	vipNet := common.ToMaxLenCIDR(vip)
	rpfVrfID := podSpec.GetRPFVrfID(vpplink.IPFamilyFromIPNet(vipNet))
	if rpfVrfID == vpplink.InvalidID {
		return nil
	}
	gw := podContainerIPForVIP(podSpec, vip)
	if gw == nil {
		return nil
	}
	paths := []types.RoutePath{{SwIfIndex: podSpec.TunTapSwIfIndex, Gw: gw}}
	if podSpec.MemifSwIfIndex != vpplink.InvalidSwIfIndex {
		paths = append(paths, types.RoutePath{SwIfIndex: podSpec.MemifSwIfIndex, Gw: gw})
	}
	route := &types.Route{Dst: vipNet, Paths: paths, Table: rpfVrfID}
	if add {
		return s.vpp.RouteAdd(route)
	}
	return s.vpp.RouteDel(route)
}

// podContainerIPForVIP returns the pod's container IP of the same family as vip.
func podContainerIPForVIP(podSpec *model.LocalPodSpec, vip net.IP) net.IP {
	wantV6 := vip.To4() == nil
	for _, cip := range podSpec.GetContainerIPs() {
		if (cip.IP.To4() == nil) == wantV6 {
			return cip.IP
		}
	}
	return nil
}
