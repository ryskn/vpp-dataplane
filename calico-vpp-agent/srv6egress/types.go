package srv6egress

import (
	"net"

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
)

// VPPInterface is the seam between this package and the actual VPP control
// path. The Manager calls these methods when a steering install is needed or
// no longer needed.
//
// The production implementation lives in the CNI server (it owns the local pod
// cache): it resolves req.PodIP to that pod's per-pod VRF (V6VrfID) and scopes
// the SR steering there, so only the selected pod's traffic to DestPrefix is
// steered into the SR Policy identified by BSID. The SR Policy itself (BSID →
// segment list) is installed independently by the BGP watcher.
type VPPInterface interface {
	// InstallSteering programs a steering entry for the (source pod, dest CIDR)
	// pair into the pod's per-pod VRF, targeting the SR Policy identified by BSID.
	//
	// podIP and destPrefix may use either IPv4 or IPv6; v1 supports IPv6
	// only (dual-stack End.DT4 / SrSteerIPv4 is future work).
	InstallSteering(req SteeringRequest) error

	// RemoveSteering undoes a previous InstallSteering for the same request key.
	// Safe to call when no install exists (returns nil).
	RemoveSteering(req SteeringRequest) error
}

// PodResolver resolves an EgressPolicy selector to the IPv6 addresses of the
// pods on THIS node that match it. The production implementation is backed by
// node-scoped pod + namespace informers (see resolver.go); manager unit tests
// use a no-op resolver, so computeDesiredInstalls degrades to zero installs.
type PodResolver interface {
	// MatchingLocalPodIPs returns the IPv6 addresses of local (this-node) pods
	// matching sel.NamespaceSelector + sel.PodSelector. A nil selector field
	// matches everything in its scope (standard k8s LabelSelector semantics).
	MatchingLocalPodIPs(sel srv6egressv1.Selector) ([]net.IP, error)
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
	policy   *srv6egressv1.EgressPolicy
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
