package controller

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
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
//
// When Backbone.Tenants is set it derives a per-tenant AdvSet each tick from the
// EgressPolicy → color → candidatePaths graph (§14.3), so the advertisement
// targets track the failover surface without the operator hand-writing them.
type ClusterReturnAdvertiser struct {
	Config      *config.ControllerConfig
	BackboneBGP map[string]bgp.Distributor
	Log         logr.Logger
	// Client reads EgressPolicies and Namespaces to derive per-tenant AdvSets.
	// A cache-backed client is fine: leader-elected Runnables start after the
	// cache is running.
	Client client.Client
	// Interval overrides the re-assert period (defaults to 30s when zero).
	Interval time.Duration

	// lastAdvSet remembers, per tenant, which upstreams were announced last tick
	// so a shrunk AdvSet (policy deletion / color change) is withdrawn. It is
	// updated per tenant (each tenant converges independently of the others) and
	// in-memory only: a leader hand-off just re-derives and converges (a fresh
	// leader announces the current AdvSet; any path the old leader left behind is
	// harmless — the receiver keys on the same NLRI and the next shrink withdraws
	// it, or the eBGP session drop clears it).
	lastAdvSet map[string]map[string]bool
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
	if err := a.assert(ctx); err != nil {
		a.Log.Error(err, "initial cluster-return advertise failed; will retry")
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := a.assert(ctx); err != nil {
				a.Log.Error(err, "cluster-return re-assert failed; will retry")
			}
		}
	}
}

// assert picks the advertisement mode: per-tenant derivation when
// Backbone.Tenants is configured, else the legacy cluster-wide aggregate.
func (a *ClusterReturnAdvertiser) assert(ctx context.Context) error {
	if a.Config.Backbone != nil && len(a.Config.Backbone.Tenants) > 0 {
		return a.advertiseTenants(ctx)
	}
	return AdvertiseClusterReturn(ctx, a.Config, a.BackboneBGP, a.Log)
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
//
// This is the cluster-wide mode (Backbone.Tenants unset). The per-tenant mode
// (advertiseTenants) refines the unit from the whole cluster to each tenant, but
// the same "reachability is a routing fact, not a per-policy signal" principle
// holds: a tenant's prefix is announced to its whole AdvSet, not per policy.
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

// advertiseTenants derives, per configured tenant, the AdvSet from the
// EgressPolicies that select the tenant's namespace and announces the tenant's
// pod prefix to each AdvSet upstream (primary plain, backups AS-path-prepended).
// It withdraws upstreams that dropped out of the AdvSet since the last tick.
//
// Invariant (§14.3): Upstreams(CandidateSet(color(p))) ⊆ AdvSet(T). AdvSet is
// derived, never hand-written, so forward failover can never outrun return
// reachability (an ISP the failover can pick is always one that learned a route
// for the tenant prefix, so its uRPF passes the forward source).
func (a *ClusterReturnAdvertiser) advertiseTenants(ctx context.Context) error {
	bb := a.Config.Backbone

	var policies srv6egressv1.EgressPolicyList
	if err := a.Client.List(ctx, &policies); err != nil {
		return fmt.Errorf("list egresspolicies: %w", err)
	}

	// Cache namespace label sets so a policy's namespaceSelector can be matched
	// against a tenant's namespace without a per-tenant API round-trip.
	nsLabels, err := a.namespaceLabels(ctx, bb)
	if err != nil {
		return err
	}

	// Deterministic tenant order for stable logs / test assertions.
	names := make([]string, 0, len(bb.Tenants))
	for name := range bb.Tenants {
		names = append(names, name)
	}
	sort.Strings(names)

	// Continue-on-error across tenants: one tenant's backbone failure must not
	// wedge the others. lastAdvSet is updated per tenant (below) so a tenant that
	// fails this tick still converges on the next, and errors are joined so the
	// caller still logs a retry.
	var errs []error
	for _, tenant := range names {
		if err := a.advertiseTenant(ctx, tenant, bb, &policies, nsLabels); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// advertiseTenant reconciles one tenant's AdvSet: announce the derived set,
// withdraw upstreams that dropped out since last tick, and update lastAdvSet in
// place. It converges even on partial failure — an announce error leaves the
// upstream out of the new set (next tick retries), and a withdraw error keeps
// the upstream in lastAdvSet so the next tick retries the withdraw until it
// succeeds (see below). Returns a joined error of every leg that failed.
func (a *ClusterReturnAdvertiser) advertiseTenant(ctx context.Context, tenant string, bb *config.BackboneConfig, policies *srv6egressv1.EgressPolicyList, nsLabels map[string]map[string]string) error {
	tc := bb.Tenants[tenant]
	prependCount := bb.ResolvedReturnPrependCount()
	advSet, primary := a.deriveAdvSet(policies, nsLabels[tc.Namespace])
	if len(advSet) > 0 && primary == "" {
		// Every AdvSet member is prepended equally (no plain preference): harmless
		// but worth surfacing (primary was clamped outside the peer set, etc.).
		a.Log.Info("no primary inside AdvSet; all members prepended equally", "tenant", tenant)
	}

	announced := map[string]bool{}
	var errs []error

	// Deterministic upstream order.
	ups := make([]string, 0, len(advSet))
	for up := range advSet {
		ups = append(ups, up)
	}
	sort.Strings(ups)
	for _, upstream := range ups {
		dist, ok := a.BackboneBGP[upstream]
		if !ok {
			// Defence-in-depth: Validate() enforces a peer for every candidate
			// upstream, so this is theoretically unreachable. Log loudly if hit —
			// the AdvSet is being narrowed and the return invariant (§14.3) breaks.
			a.Log.Info("skipping upstream without backbone peer — return invariant narrowed",
				"tenant", tenant, "upstream", upstream)
			continue
		}
		adv := a.tenantAdvert(tc.PodCIDR, upstream)
		// Primary is announced plain; backups are demoted with AS-path prepend so
		// return traffic prefers the primary while every AdvSet member still
		// carries the tenant prefix (§14.3 — not exclusive).
		if upstream != primary && prependCount > 0 {
			adv.Prepend = bgp.PrependSpec{ASN: bb.ReturnPrependASN, Count: prependCount}
		}
		if _, err := dist.Announce(ctx, returnKey(tenant, upstream), adv); err != nil {
			errs = append(errs, fmt.Errorf("advertise tenant %q return on upstream %q: %w", tenant, upstream, err))
			continue // leave this upstream out of the new set; next tick retries.
		}
		announced[upstream] = true
		a.Log.Info("advertised tenant return reachability to backbone",
			"tenant", tenant, "upstream", upstream, "podCIDR", tc.PodCIDR,
			"endSID", adv.Route.EndSID, "primary", upstream == primary)
	}

	// Withdraw upstreams that were announced last tick but fell out of the AdvSet
	// (policy deletion, color change, or exclusive clamp). A withdraw that fails
	// is not "done": the upstream is kept in lastAdvSet (retryWithdraw) so the
	// next tick issues the withdraw again, until it succeeds.
	retryWithdraw := map[string]bool{}
	for upstream := range a.lastAdvSet[tenant] {
		if announced[upstream] {
			continue
		}
		dist, ok := a.BackboneBGP[upstream]
		if !ok {
			continue
		}
		if err := dist.Withdraw(ctx, returnKey(tenant, upstream), a.tenantAdvert(tc.PodCIDR, upstream)); err != nil {
			// A withdraw error must NOT be treated as a completed withdraw. A
			// transient fault (gRPC blip) would otherwise let a stale return
			// advertisement linger in gobgp forever — never retried, and for an
			// exclusive clamp that is a silent sovereignty leak (a withdrawn
			// return path still alive). So keep the upstream in lastAdvSet and
			// retry the withdraw every tick until it succeeds. If gobgp's
			// DeletePath does surface "already gone" as an error, that yields a
			// once-per-tick error log — observable noise, which is the correct
			// failure direction over a silent leak. Per-tenant continue-on-error
			// already prevents this from wedging other tenants.
			a.Log.Error(err, "withdraw tenant return failed; keeping in lastAdvSet to retry next tick",
				"tenant", tenant, "upstream", upstream)
			retryWithdraw[upstream] = true
			errs = append(errs, fmt.Errorf("withdraw tenant %q return on upstream %q: %w", tenant, upstream, err))
			continue
		}
		a.Log.Info("withdrew tenant return reachability from backbone",
			"tenant", tenant, "upstream", upstream, "podCIDR", tc.PodCIDR)
	}

	// Update lastAdvSet in place so this tenant converges independently of the
	// others (a nil map on first tick / after a leader hand-off is initialized).
	// The persisted set is the announced upstreams plus any whose withdraw failed
	// this tick — so the next tick both re-announces the live set and re-tries the
	// pending withdraws. Building a copy keeps announced's meaning ("advertised
	// this tick") uncorrupted.
	if a.lastAdvSet == nil {
		a.lastAdvSet = map[string]map[string]bool{}
	}
	next := map[string]bool{}
	for up := range announced {
		next[up] = true
	}
	for up := range retryWithdraw {
		next[up] = true
	}
	if len(next) > 0 {
		a.lastAdvSet[tenant] = next
	} else {
		delete(a.lastAdvSet, tenant)
	}
	return errors.Join(errs...)
}

// tenantAdvert builds the RFC 9252 return advertisement of a tenant's pod prefix
// via one upstream's End SID (plain; the caller sets Prepend for backups). Same
// shape as AdvertiseClusterReturn, refined to a per-tenant prefix.
func (a *ClusterReturnAdvertiser) tenantAdvert(podCIDR, upstream string) bgp.ServiceAdvert {
	peer := a.Config.Backbone.Peers[upstream]
	up := a.Config.Upstreams[upstream]
	st := up.ResolvedSIDStructure()
	return bgp.ServiceAdvert{
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
}

// deriveAdvSet computes a tenant's AdvSet and primary upstream from the policies
// that select its namespace. AdvSet = (CandidateUnion clamped to any exclusive
// sovereign set) ∩ configured backbone peers. primary is the upstream of the
// highest-preference candidate among the matched policies (its return route is
// advertised plain; the rest are prepended). An empty AdvSet ("") means the
// tenant is not advertised at all — no matching policy (no intent, no
// reachability), or an empty exclusive intersection (sovereignty stops it).
func (a *ClusterReturnAdvertiser) deriveAdvSet(policies *srv6egressv1.EgressPolicyList, nsLabels map[string]string) (map[string]bool, string) {
	candidateUnion := map[string]bool{}
	// sovereign is the intersection of every exclusive color's upstream set among
	// the matched policies (nil = no exclusive color seen yet). An empty non-nil
	// map = disjoint exclusive sets = the tenant advertises nothing.
	var sovereign map[string]bool
	haveExclusive := false

	bestPref := int64(-1)
	primary := ""

	for i := range policies.Items {
		p := &policies.Items[i]
		if !p.DeletionTimestamp.IsZero() {
			continue
		}
		if !policySelectsNamespace(p, nsLabels) {
			continue
		}
		cc, ok := a.Config.Colors[p.Spec.Egress.Color]
		if !ok {
			continue // unknown color: the reconciler already marks it not-ready
		}
		colorUpstreams := map[string]bool{}
		for _, cp := range cc.CandidatePaths {
			candidateUnion[cp.Upstream] = true
			colorUpstreams[cp.Upstream] = true
			// Higher preference wins; ties break on the lexicographically smaller
			// upstream name so the primary is deterministic across ticks (API
			// return order must not flap the plain-vs-prepended choice).
			if betterPrimary(int64(cp.Preference), cp.Upstream, bestPref, primary) {
				bestPref = int64(cp.Preference)
				primary = cp.Upstream
			}
		}
		if cc.Exclusive {
			haveExclusive = true
			if sovereign == nil {
				sovereign = colorUpstreams
			} else {
				sovereign = intersect(sovereign, colorUpstreams)
			}
		}
	}

	// Exclusive clamp: restrict the derived union to the sovereign set (§14.3
	// validation (2)). The advertiser only clamps — the reconciler writes
	// Ready:False on the offending policies.
	effective := candidateUnion
	if haveExclusive {
		effective = intersect(candidateUnion, sovereign)
		// Re-pick a primary inside the clamped set (the union primary may have
		// been clamped away).
		if !effective[primary] {
			primary = ""
			bestPref = int64(-1)
			for i := range policies.Items {
				p := &policies.Items[i]
				if !p.DeletionTimestamp.IsZero() || !policySelectsNamespace(p, nsLabels) {
					continue
				}
				cc, ok := a.Config.Colors[p.Spec.Egress.Color]
				if !ok {
					continue
				}
				for _, cp := range cc.CandidatePaths {
					if effective[cp.Upstream] && betterPrimary(int64(cp.Preference), cp.Upstream, bestPref, primary) {
						bestPref = int64(cp.Preference)
						primary = cp.Upstream
					}
				}
			}
		}
	}

	// AdvSet = effective ∩ configured backbone peers (an upstream with no peer
	// has nowhere to advertise).
	advSet := map[string]bool{}
	for up := range effective {
		if _, ok := a.Config.Backbone.Peers[up]; ok {
			advSet[up] = true
		}
	}
	if !advSet[primary] {
		primary = "" // primary was outside the peer set: no plain preference
	}
	return advSet, primary
}

// namespaceLabels fetches the label map of every tenant's namespace once per
// tick (see getNamespaceLabels for the missing-namespace semantics).
func (a *ClusterReturnAdvertiser) namespaceLabels(ctx context.Context, bb *config.BackboneConfig) (map[string]map[string]string, error) {
	out := make(map[string]map[string]string, len(bb.Tenants))
	for _, tc := range bb.Tenants {
		if _, done := out[tc.Namespace]; done {
			continue
		}
		l, err := getNamespaceLabels(ctx, a.Client, tc.Namespace)
		if err != nil {
			return nil, err
		}
		out[tc.Namespace] = l
	}
	return out, nil
}

// returnKey is the per-(tenant, upstream) announce owner key.
func returnKey(tenant, upstream string) string {
	return "return:" + tenant + ":" + upstream
}

// betterPrimary reports whether candidate (pref, up) beats the current best
// (bestPref, best): higher preference wins, ties break on the smaller upstream
// name so primary selection is deterministic regardless of API return order.
func betterPrimary(pref int64, up string, bestPref int64, best string) bool {
	if pref != bestPref {
		return pref > bestPref
	}
	return best == "" || up < best
}

// intersect returns the set intersection of a and b.
func intersect(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}
