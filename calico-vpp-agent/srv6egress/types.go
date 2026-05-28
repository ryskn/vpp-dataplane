package srv6egress

import (
	"net"

	srv6egressv1alpha1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1alpha1"
)

// VPPInterface is the seam between this package and the actual VPP control
// path (existing connectivity.SRv6Provider). The Manager calls these methods
// when a steering install is needed or no longer needed.
//
// Production implementation in calico-vpp-agent/connectivity/srv6.go will
// wrap getPolicyNode / AddSRv6Steering / DelSRv6Steering, scoping the
// FibTable to common.PodVRFIndex (PR #1028's pattern).
type VPPInterface interface {
	// InstallSteering programs a steering entry for the (source pod, dest CIDR)
	// pair into PodVRFIndex, targeting the SR Policy identified by bsid.
	//
	// podIP and destPrefix may use either IPv4 or IPv6; v1alpha1 supports IPv6
	// only (dual-stack End.DT4 / SrSteerIPv4 is future work).
	InstallSteering(req SteeringRequest) error

	// RemoveSteering undoes a previous InstallSteering for the same request key.
	// Safe to call when no install exists (returns nil).
	RemoveSteering(req SteeringRequest) error
}

// SteeringRequest carries the information needed to install / remove a single
// steering entry. PolicyUID identifies the owning EgressPolicy so that
// per-policy teardown can find every entry it created.
type SteeringRequest struct {
	PolicyUID  string
	PodIP      net.IP
	DestPrefix *net.IPNet
	Color      uint32
	BSID       net.IP
}

// policyState tracks an active EgressPolicy and the steering entries it has
// installed on this node.
type policyState struct {
	policy   *srv6egressv1alpha1.EgressPolicy
	installs map[string]SteeringRequest // key = SteeringRequest.key()
}

// key produces a deterministic string for diffing installs across reconciles.
func (s SteeringRequest) key() string {
	dst := ""
	if s.DestPrefix != nil {
		dst = s.DestPrefix.String()
	}
	return s.PodIP.String() + "|" + dst + "|" + s.BSID.String()
}
