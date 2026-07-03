package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"

	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/bgp"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/config"
)

// defaultClusterReturnInterval is how often the cluster-return route is
// re-asserted. gobgp holds API-injected paths in memory only, so a re-assert
// (idempotent AddPath) restores reachability lost to a gobgp restart / eBGP flap.
const defaultClusterReturnInterval = 30 * time.Second

// ClusterReturnAdvertiser is a leader-elected manager.Runnable that keeps the
// NAT-less cluster-return route asserted on every backbone upstream. Running it
// as a Runnable (rather than a one-shot at startup) gives it three properties
// the old call lacked: it fires only on the elected leader (a standby replica
// never mutates the backbone BGP session), it re-asserts periodically (so a
// gobgp restart or eBGP flap self-heals), and it stops cleanly on shutdown.
type ClusterReturnAdvertiser struct {
	Config      *config.ControllerConfig
	BackboneBGP map[string]bgp.Distributor
	Log         logr.Logger
	// Interval overrides the re-assert period (defaults to 30s when zero).
	Interval time.Duration
}

// NeedLeaderElection makes the advertiser run only on the elected leader.
func (a *ClusterReturnAdvertiser) NeedLeaderElection() bool { return true }

// Start announces cluster-return reachability, then re-asserts it until ctx is
// cancelled. Announce failures are logged and retried on the next tick rather
// than propagated, so a transient backbone gobgp error never stops the manager.
func (a *ClusterReturnAdvertiser) Start(ctx context.Context) error {
	interval := a.Interval
	if interval <= 0 {
		interval = defaultClusterReturnInterval
	}
	if err := AdvertiseClusterReturn(ctx, a.Config, a.BackboneBGP, a.Log); err != nil {
		a.Log.Error(err, "initial cluster-return advertise failed; will retry")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := AdvertiseClusterReturn(ctx, a.Config, a.BackboneBGP, a.Log); err != nil {
				a.Log.Error(err, "cluster-return re-assert failed; will retry")
			}
		}
	}
}

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
