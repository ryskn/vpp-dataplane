package controller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"

	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/bgp"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/config"
)

// AdvertiseClusterReturn announces, once per backbone-stitched upstream, the
// cluster pod CIDR as an RFC 9252 SRv6 service route reachable via that
// upstream's End SID (with the upstream's SID structure — classic or uSID). This
// is the NAT-less return path: the backbone learns to SR-encapsulate return
// traffic (dst = pod IP) toward the gateway, which decaps into the upstream VRF
// and bounces it into the cluster fabric to the pod's node.
//
// It is a per-upstream fact, not per-policy: the gateway is a PE for the whole
// cluster pod CIDR regardless of which EgressPolicies exist. Announcing per
// policy would collapse onto one shared BGP path that the first policy deletion
// would withdraw. Idempotent; safe to re-run on controller restart.
func AdvertiseClusterReturn(ctx context.Context, cfg *config.ControllerConfig, backboneBGP map[string]bgp.Distributor, log logr.Logger) error {
	if cfg.Backbone == nil {
		return nil
	}
	podCIDR := cfg.Backbone.ClusterPodCIDR
	for upstream, peer := range cfg.Backbone.Peers {
		dist, ok := backboneBGP[upstream]
		if !ok {
			continue
		}
		up := cfg.Upstreams[upstream]
		st := up.ResolvedSIDStructure()
		adv := bgp.ServiceAdvert{
			Route: bgp.ServiceRoute{
				Prefix:   podCIDR,
				EndSID:   up.SID,
				Behavior: bgp.EndDT6,
				Nexthop:  peer.Nexthop,
			},
			Structure: bgp.SIDStructure{
				LocatorBlockBits: st.LocatorBlockBits,
				LocatorNodeBits:  st.LocatorNodeBits,
				FunctionBits:     st.FunctionBits,
				ArgumentBits:     st.ArgumentBits,
			},
		}
		if _, err := dist.Announce(ctx, "cluster-return:"+upstream, adv); err != nil {
			return fmt.Errorf("advertise cluster return on upstream %q: %w", upstream, err)
		}
		log.Info("advertised cluster return reachability to backbone",
			"upstream", upstream, "podCIDR", podCIDR, "endSID", up.SID, "usid", up.IsUSID())
	}
	return nil
}
