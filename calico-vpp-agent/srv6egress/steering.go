package srv6egress

import (
	"net"

	"github.com/sirupsen/logrus"

	srv6egressv1alpha1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1alpha1"
)

// steeringComputer turns a Ready EgressPolicy into the set of per-(pod, dest)
// SteeringRequests that should be installed on THIS node. It is the pure
// desired-state calculator behind the Manager's diff/apply loop: it resolves
// the policy selector to local pod IPs and crosses them with the policy's IPv6
// destination CIDRs, targeting the SR Policy BSID recorded in status.
type steeringComputer struct {
	pods PodResolver
	log  *logrus.Entry
}

// desired builds the (pod × dest) SteeringRequest set for ep on this node. It
// returns nil when the policy is not yet installable: no BSID resolved, no
// usable IPv6 destinationCIDR, or local pod resolution failed.
func (c *steeringComputer) desired(ep *srv6egressv1alpha1.EgressPolicy) []SteeringRequest {
	if ep.Status.SRPolicy == nil || ep.Status.SRPolicy.BSID == "" {
		return nil
	}
	bsid := net.ParseIP(ep.Status.SRPolicy.BSID)
	if bsid == nil {
		c.log.WithField("bsid", ep.Status.SRPolicy.BSID).Warn("status.srPolicy.bsid is not a valid IP")
		return nil
	}

	// An explicit IPv6 destinationCIDR list is required. Empty means "all
	// off-cluster destinations" in the CRD, but steering ::/0 would also catch
	// in-cluster traffic; that needs cluster-CIDR exclusion (future work).
	dests := parseV6DestCIDRs(ep.Spec.DestinationCIDRs)
	if len(dests) == 0 {
		c.log.WithField("name", ep.Name).Warn("no usable IPv6 destinationCIDRs; empty (all off-cluster) not yet supported, skipping")
		return nil
	}

	podIPs, err := c.pods.MatchingLocalPodIPs(ep.Spec.Selector)
	if err != nil {
		c.log.WithError(err).WithField("name", ep.Name).Warn("resolving local pods for selector failed")
		return nil
	}

	reqs := make([]SteeringRequest, 0, len(podIPs)*len(dests))
	for _, ip := range podIPs {
		if !isV6(ip) {
			continue // IPv6 only for v1alpha1
		}
		for _, dst := range dests {
			reqs = append(reqs, SteeringRequest{
				PolicyUID:  string(ep.UID),
				PodIP:      ip,
				DestPrefix: dst,
				Color:      ep.Spec.Egress.Color,
				BSID:       bsid,
			})
		}
	}
	return reqs
}

// parseV6DestCIDRs parses the policy's destinationCIDRs, keeping only valid
// IPv6 prefixes. Invalid / IPv4 entries are dropped (the controller validates
// these at admission; this is defence in depth on the agent side).
func parseV6DestCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil || ipnet == nil || ipnet.IP.To4() != nil {
			continue
		}
		out = append(out, ipnet)
	}
	return out
}

// isV6 reports whether ip is a non-nil IPv6 (non-IPv4) address. It centralizes
// the "v1alpha1 is IPv6-only" predicate the steering and gateway paths share.
func isV6(ip net.IP) bool { return ip != nil && ip.To4() == nil }

// parseV6 parses s as an IPv6 address, returning nil when s is empty, malformed,
// or IPv4 (v1alpha1 is IPv6-only).
func parseV6(s string) net.IP {
	if ip := net.ParseIP(s); isV6(ip) {
		return ip
	}
	return nil
}
