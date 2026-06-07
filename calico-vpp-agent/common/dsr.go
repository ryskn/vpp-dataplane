package common

import "net"

// DSRService describes an SRv6-native / NAT-less (DSR) ClusterIP service.
//
// It is published by the services server (ServiceDSRClusterIPAdded/Deleted) and
// consumed in-process by:
//   - the SRv6 connectivity provider, which installs a per-service SR policy
//     (weighted ECMP over the backend nodes' End.DT6 SIDs) plus a steering entry
//     so that VIP traffic from clients without a local backend is steered to a
//     backend node; and
//   - the CNI server, which for backends that are local pods binds the VIP
//     inside the pod (so its kernel accepts dst==VIP, i.e. DSR), allows VIP as a
//     source through uRPF, and installs the pod-VRF delivery route.
//
// There is no NAT anywhere on the path: the inner packet keeps dst==VIP all the
// way to the backend pod, which replies with src==VIP, so no reverse
// translation is needed on the return path.
type DSRService struct {
	// VIP is the service ClusterIP.
	VIP net.IP
	// Backends are the IPs of all pod-backed endpoints of the service (both
	// local to this node and remote). Each consumer resolves the ones it cares
	// about (CNI: local pods; SRv6: remote backends' nodes).
	Backends []net.IP
	// ServiceID is namespace/name, for logging only.
	ServiceID string
}

// Key identifies a DSR service by its VIP.
func (d *DSRService) Key() string {
	if d == nil || d.VIP == nil {
		return ""
	}
	return d.VIP.String()
}
