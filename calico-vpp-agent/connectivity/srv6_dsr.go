package connectivity

import (
	"net"

	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// dsrServiceState tracks the SR policy + steering installed for a DSR ClusterIP.
type dsrServiceState struct {
	vip    net.IP
	bsid   ip_types.IP6Address
	policy *types.SrPolicy
	steer  *types.SrSteer
}

// UpdateDSRService installs (or withdraws) the client-side steering for an
// SRv6-native / NAT-less (DSR) ClusterIP: a per-service SR policy whose weighted
// SID lists each end at a backend node's End.DT6 SID, plus a steering entry that
// sends VIP traffic into that policy (in the main table). Clients with a local
// backend never reach this steer because the CNI server installs a more-specific
// VIP delivery route in PodVRFIndex; clients without one fall through to here and
// are SRv6-steered to a backend node, which decaps into PodVRFIndex and delivers
// to its local backend. Local backends of this node are handled by the CNI
// server, so they are excluded from the policy here.
func (p *SRv6Provider) UpdateDSRService(svc *common.DSRService, isWithdraw bool) error {
	if !*config.GetCalicoVppFeatureGates().SRv6Enabled || svc == nil || svc.VIP == nil {
		return nil
	}
	key := svc.VIP.String()
	if isWithdraw {
		delete(p.dsrDesired, key)
	} else {
		p.dsrDesired[key] = svc
	}
	p.reconcileDSRServices()
	return nil
}

// reconcileDSRServices drives the installed DSR state toward the desired set,
// retrying both failed installs and failed removals. It is invoked on every DSR
// event and on connectivity changes, so a backend node's End.DT6 SID arriving
// late (BGP) or a previously failed delete is eventually applied.
func (p *SRv6Provider) reconcileDSRServices() {
	for _, svc := range p.dsrDesired {
		if err := p.programDSRService(svc); err != nil {
			p.log.Errorf("SRv6Provider DSR program vip %s: %v", svc.VIP, err)
		}
	}
	for key := range p.dsrServices {
		if _, ok := p.dsrDesired[key]; !ok {
			p.removeDSRService(key)
		}
	}
}

// programDSRService installs (idempotently) the per-service SR policy + steering.
func (p *SRv6Provider) programDSRService(svc *common.DSRService) error {
	key := svc.VIP.String()
	// Group remote backends by node (exclude this node).
	_, myIP6 := p.GetNodeIPs()
	weights := make(map[string]uint32)
	for _, beIP := range svc.Backends {
		nodeIP := p.findNodeForPrefix(beIP)
		if nodeIP == nil {
			p.log.Infof("SRv6Provider DSR: no node for backend %s (vip %s), skipping", beIP, key)
			continue
		}
		if myIP6 != nil && nodeIP.Equal(*myIP6) {
			continue // local backend, delivered by CNI in PodVRFIndex
		}
		weights[nodeIP.String()]++
	}

	if len(weights) == 0 {
		// No remote backends: local delivery suffices; drop any stale steer.
		p.removeDSRService(key)
		return nil
	}

	// One weighted SID list per backend node, ending at its End.DT6 SID.
	var sidLists []types.Srv6SidList
	for nodeIPStr, w := range weights {
		policy, err := p.getPolicyNode(nodeIPStr, types.SrBehaviorDT6)
		if err != nil || policy == nil || len(policy.SidLists) == 0 || policy.SidLists[0].NumSids == 0 {
			p.log.Infof("SRv6Provider DSR: no DT6 SID for node %s yet (vip %s), skipping", nodeIPStr, key)
			continue
		}
		sl := types.Srv6SidList{NumSids: 1, Weight: w}
		sl.Sids[0] = policy.SidLists[0].Sids[0]
		sidLists = append(sidLists, sl)
	}
	if len(sidLists) == 0 {
		p.log.Infof("SRv6Provider DSR: no usable backend node SIDs yet for vip %s; will retry on next reconcile", key)
		return nil
	}

	// Already installed identically: skip (lets the periodic re-publish retry
	// missing programming without churning steady-state state). Guard st.policy:
	// a prior partial removeDSRService may have nil'd it while keeping st.steer.
	if st, ok := p.dsrServices[key]; ok && st.steer != nil && st.policy != nil && sameSidLists(st.policy.SidLists, sidLists) {
		return nil
	}

	// Reuse the previously chosen BSID for stability; derive a fresh
	// (collision-avoiding) one only on first install for this VIP.
	var bsid ip_types.IP6Address
	if st, ok := p.dsrServices[key]; ok {
		bsid = st.bsid
	} else {
		bsid = p.dsrBsidForVIP(svc.VIP)
	}
	policy := &types.SrPolicy{
		Bsid:     bsid,
		IsEncap:  true,
		FibTable: 0,
		SidLists: sidLists,
	}
	if err := p.vpp.AddModSRv6Policy(policy); err != nil {
		return errors.Wrapf(err, "SRv6Provider DSR AddModSRv6Policy vip %s", key)
	}

	prefix, err := ip_types.ParsePrefix(svc.VIP.String() + "/128")
	if err != nil {
		return errors.Wrapf(err, "SRv6Provider DSR parse vip prefix %s", key)
	}
	steer := &types.SrSteer{
		TrafficType: types.SrSteerIPv6,
		FibTable:    0,
		Prefix:      prefix,
		Bsid:        bsid,
	}
	if st, ok := p.dsrServices[key]; ok && st.steer != nil {
		_ = p.vpp.DelSRv6Steering(st.steer)
	}
	if err := p.vpp.AddSRv6Steering(steer); err != nil {
		return errors.Wrapf(err, "SRv6Provider DSR AddSRv6Steering vip %s", key)
	}
	p.dsrServices[key] = &dsrServiceState{vip: svc.VIP, bsid: bsid, policy: policy, steer: steer}
	p.log.Infof("SRv6Provider DSR: vip %s steered over %d backend node(s)", key, len(sidLists))
	return nil
}

// removeDSRService withdraws the SR policy + steering for a VIP. On partial
// failure it nils out the parts that succeeded and keeps the rest installed, so
// the next reconcile retries only what's left (rather than re-deleting already
// gone objects or forgetting a still-present one).
func (p *SRv6Provider) removeDSRService(key string) {
	st, ok := p.dsrServices[key]
	if !ok {
		return
	}
	failed := false
	if st.steer != nil {
		if err := p.vpp.DelSRv6Steering(st.steer); err != nil {
			p.log.Errorf("SRv6Provider DSR DelSRv6Steering vip %s: %v", key, err)
			failed = true
		} else {
			st.steer = nil
		}
	}
	if st.policy != nil {
		if err := p.vpp.DelSRv6Policy(st.policy); err != nil {
			p.log.Errorf("SRv6Provider DSR DelSRv6Policy vip %s: %v", key, err)
			failed = true
		} else {
			st.policy = nil
		}
	}
	if failed {
		return // keep state; retried on next reconcile
	}
	delete(p.dsrServices, key)
}

// sameSidLists reports whether two sets of single-SID weighted lists are equal
// (order-independent). ip_types.IP6Address is an array, hence comparable.
func sameSidLists(a, b []types.Srv6SidList) bool {
	if len(a) != len(b) {
		return false
	}
	type key struct {
		sid    ip_types.IP6Address
		weight uint32
	}
	m := make(map[key]int)
	for _, sl := range a {
		m[key{sl.Sids[0], sl.Weight}]++
	}
	for _, sl := range b {
		m[key{sl.Sids[0], sl.Weight}]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

// findNodeForPrefix returns the node IP whose advertised pod prefix contains ip.
func (p *SRv6Provider) findNodeForPrefix(ip net.IP) net.IP {
	for _, np := range p.nodePrefixes {
		for _, prefix := range np.Prefixes {
			ipnet := prefix.ToIPNet()
			if ipnet != nil && ipnet.Contains(ip) {
				return np.Node
			}
		}
	}
	return nil
}

// dsrBsidForVIP derives a BSID for a service from the policy pool: the pool
// prefix with the VIP's host bytes overlaid, then perturbed if it would collide
// with a BSID already in use by another (per-node pod-connectivity) SR policy.
// Per-node BSIDs are IPAM-allocated from the same pool, so a naive derivation
// could clobber a node's pod-connectivity policy on install/withdraw; avoiding
// in-use BSIDs prevents that. The chosen value is cached per service in
// dsrServices and reused across reconciles for stability.
func (p *SRv6Provider) dsrBsidForVIP(vip net.IP) ip_types.IP6Address {
	bsid := make(net.IP, net.IPv6len)
	copy(bsid, p.policyIPPool.IP.To16())
	v := vip.To16()
	ones, _ := p.policyIPPool.Mask.Size()
	for i := ones / 8; i < net.IPv6len && i < len(v); i++ {
		bsid[i] = v[i]
	}
	taken := p.takenBsids()
	for tries := 0; tries < 1024 && taken[bsid.String()]; tries++ {
		bsid[net.IPv6len-1]++ // perturb low byte until free
	}
	return types.ToVppIP6Address(bsid)
}

// takenBsids returns the set of BSIDs already in use by non-DSR SR policies
// (per-node pod-connectivity policies, learned via BGP and/or installed in VPP),
// so DSR BSID derivation can avoid clobbering them. Our own DSR policies are
// excluded so we don't perturb away from an already-chosen stable BSID.
func (p *SRv6Provider) takenBsids() map[string]bool {
	m := make(map[string]bool)
	for _, np := range p.nodePolices {
		for _, t := range np.SRv6Tunnel {
			if t.Bsid != nil {
				m[t.Bsid.String()] = true
			}
		}
	}
	if pols, err := p.vpp.ListSRv6Policies(); err == nil {
		for _, pol := range pols {
			if p.isOwnDSRBsid(pol.Bsid) {
				continue
			}
			m[pol.Bsid.ToIP().String()] = true
		}
	}
	return m
}

func (p *SRv6Provider) isOwnDSRBsid(b ip_types.IP6Address) bool {
	for _, st := range p.dsrServices {
		if st.bsid == b {
			return true
		}
	}
	return false
}
