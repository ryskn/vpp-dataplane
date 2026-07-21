package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/bgp"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/config"
)

// The cluster-return advertiser must be leader-elected so a standby replica
// never mutates the backbone BGP session.
func TestClusterReturnAdvertiser_IsLeaderElected(t *testing.T) {
	if !(&ClusterReturnAdvertiser{}).NeedLeaderElection() {
		t.Fatal("cluster-return advertiser must be leader-elected")
	}
}

// --- per-tenant AdvSet derivation (§14.3 / §14.4) ---

// recordingUpstreamBGP records announces and withdraws (as ServiceAdvert) for one
// upstream's backbone distributor, so a per-tenant test can assert exactly which
// upstreams a tenant prefix reaches and whether the advert was prepended. The
// errOnAnnounce / errOnWithdraw hooks let a test inject failures to exercise the
// advertiser's continue-on-error and withdraw-tolerance convergence (F2).
type recordingUpstreamBGP struct {
	announced []bgp.ServiceAdvert
	withdrawn []bgp.ServiceAdvert
	// When set, Announce/Withdraw return this error after recording the call.
	errOnAnnounce error
	errOnWithdraw error
}

func (b *recordingUpstreamBGP) Announce(_ context.Context, _ string, adv bgp.Advertisement) (string, error) {
	if sa, ok := adv.(bgp.ServiceAdvert); ok {
		b.announced = append(b.announced, sa)
	}
	return "", b.errOnAnnounce
}
func (b *recordingUpstreamBGP) Withdraw(_ context.Context, _ string, adv bgp.Advertisement) error {
	if sa, ok := adv.(bgp.ServiceAdvert); ok {
		b.withdrawn = append(b.withdrawn, sa)
	}
	return b.errOnWithdraw
}
func (b *recordingUpstreamBGP) Close() error { return nil }

// twoUpstreamConfig defines isp-a + isp-b with backbone peers on both and a
// single tenant (team-a → 2001:db8:2000::/48). Colors: 10 = {a pref 200, b pref
// 100} intent; 20 = {a} exclusive; 30 = {b} exclusive.
func twoUpstreamConfig() *config.ControllerConfig {
	cfg := &config.ControllerConfig{
		Upstreams: map[string]config.UpstreamConfig{
			"isp-a": {SID: "fcff:0:0:e0:a::", VRF: "upstream-a"},
			"isp-b": {SID: "fcff:0:0:e0:b::", VRF: "upstream-b"},
		},
		Colors: map[uint32]config.ColorConfig{
			10: {CandidatePaths: []config.CandidatePathConfig{
				{Upstream: "isp-a", SegmentList: []string{"fcff:0:0:e0:a::"}, Preference: 200},
				{Upstream: "isp-b", SegmentList: []string{"fcff:0:0:e0:b::"}, Preference: 100},
			}},
			20: {Exclusive: true, CandidatePaths: []config.CandidatePathConfig{
				{Upstream: "isp-a", SegmentList: []string{"fcff:0:0:e0:a::"}, Preference: 100},
			}},
			30: {Exclusive: true, CandidatePaths: []config.CandidatePathConfig{
				{Upstream: "isp-b", SegmentList: []string{"fcff:0:0:e0:b::"}, Preference: 100},
			}},
		},
		Backbone: &config.BackboneConfig{
			Peers: map[string]config.BackbonePeerConfig{
				"isp-a": {GoBGPAddr: "192.0.2.14:50052", Nexthop: "fda1::2"},
				"isp-b": {GoBGPAddr: "192.0.2.15:50052", Nexthop: "fda2::2"},
			},
			Tenants: map[string]config.TenantConfig{
				"tenant-a": {Namespace: "team-a", PodCIDR: "2001:db8:2000::/48"},
			},
		},
	}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}

func tenantNamespace(name string, labels map[string]string) *corev1.Namespace {
	return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels}}
}

// tenantPolicy builds an EgressPolicy in the given color whose namespaceSelector
// matches namespaces labelled team=<team> (empty team => nil selector = all).
func tenantPolicy(name, uid string, color uint32, team string) *srv6egressv1.EgressPolicy {
	sel := srv6egressv1.Selector{}
	if team != "" {
		sel.NamespaceSelector = &metav1.LabelSelector{MatchLabels: map[string]string{"team": team}}
	}
	return &srv6egressv1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid)},
		Spec: srv6egressv1.EgressPolicySpec{
			Selector:         sel,
			DestinationCIDRs: []string{"2001:db8:100::/64"},
			Egress:           srv6egressv1.EgressSpec{Color: color},
		},
	}
}

// The invariant: for a tenant whose single intent color has two candidates
// {isp-a, isp-b}, the tenant prefix must be advertised to BOTH upstreams
// (AdvSet = candidate union), so a candidate-path failover never outruns return
// reachability.
func TestAdvertiseTenants_AdvSetIsCandidateUnion(t *testing.T) {
	cfg := twoUpstreamConfig()
	a := &recordingUpstreamBGP{}
	b := &recordingUpstreamBGP{}
	s := testScheme(t)
	c := fakeclient.NewClientBuilder().WithScheme(s).
		WithObjects(
			tenantNamespace("team-a", map[string]string{"team": "a"}),
			tenantPolicy("p1", "u1", 10, "a"),
		).Build()
	adv := &ClusterReturnAdvertiser{Config: cfg, Client: c, Log: logr.Discard(),
		BackboneBGP: map[string]bgp.Distributor{"isp-a": a, "isp-b": b}}

	if err := adv.assert(context.Background()); err != nil {
		t.Fatalf("assert: %v", err)
	}
	if len(a.announced) != 1 || len(b.announced) != 1 {
		t.Fatalf("AdvSet must be both upstreams: isp-a=%d isp-b=%d announces", len(a.announced), len(b.announced))
	}
	if a.announced[0].Route.Prefix != "2001:db8:2000::/48" {
		t.Fatalf("isp-a advert prefix = %q, want tenant podCIDR", a.announced[0].Route.Prefix)
	}
	// isp-a is the primary (pref 200): plain. isp-b is backup: with prepend
	// disabled (no ReturnPrependASN) it is still plain.
	if a.announced[0].Prepend.Count != 0 || b.announced[0].Prepend.Count != 0 {
		t.Fatalf("prepend disabled: isp-a=%+v isp-b=%+v", a.announced[0].Prepend, b.announced[0].Prepend)
	}
}

// An exclusive color clamps the AdvSet to the sovereign set: a tenant using ONLY
// color 20 (exclusive {isp-a}) must not have its prefix advertised to isp-b.
func TestAdvertiseTenants_ExclusiveClamp(t *testing.T) {
	cfg := twoUpstreamConfig()
	a := &recordingUpstreamBGP{}
	b := &recordingUpstreamBGP{}
	s := testScheme(t)
	c := fakeclient.NewClientBuilder().WithScheme(s).
		WithObjects(
			tenantNamespace("team-a", map[string]string{"team": "a"}),
			tenantPolicy("p-excl", "u1", 20, "a"), // exclusive {isp-a}
			tenantPolicy("p-intent", "u2", 10, "a"), // intent {isp-a, isp-b}
		).Build()
	adv := &ClusterReturnAdvertiser{Config: cfg, Client: c, Log: logr.Discard(),
		BackboneBGP: map[string]bgp.Distributor{"isp-a": a, "isp-b": b}}

	if err := adv.assert(context.Background()); err != nil {
		t.Fatalf("assert: %v", err)
	}
	// Union would be {a,b}, but the exclusive color clamps to {a}: isp-b must
	// receive nothing even though the intent color lists it (§14.3 sovereignty).
	if len(a.announced) != 1 {
		t.Fatalf("isp-a (sovereign) must be advertised, got %d", len(a.announced))
	}
	if len(b.announced) != 0 {
		t.Fatalf("isp-b (outside sovereign set) must NOT be advertised, got %d", len(b.announced))
	}
}

// With ReturnPrependASN set, the primary upstream is advertised plain and the
// backup carries an AS-path prepend (demoted, not withheld — §14.3).
func TestAdvertiseTenants_PrimaryPlainBackupPrepended(t *testing.T) {
	cfg := twoUpstreamConfig()
	cfg.Backbone.ReturnPrependASN = 65001
	cfg.Backbone.ReturnPrependCount = 3
	a := &recordingUpstreamBGP{}
	b := &recordingUpstreamBGP{}
	s := testScheme(t)
	c := fakeclient.NewClientBuilder().WithScheme(s).
		WithObjects(
			tenantNamespace("team-a", map[string]string{"team": "a"}),
			tenantPolicy("p1", "u1", 10, "a"), // {a pref 200 primary, b pref 100 backup}
		).Build()
	adv := &ClusterReturnAdvertiser{Config: cfg, Client: c, Log: logr.Discard(),
		BackboneBGP: map[string]bgp.Distributor{"isp-a": a, "isp-b": b}}

	if err := adv.assert(context.Background()); err != nil {
		t.Fatalf("assert: %v", err)
	}
	if len(a.announced) != 1 || a.announced[0].Prepend.Count != 0 {
		t.Fatalf("primary isp-a must be plain, got %+v", a.announced)
	}
	if len(b.announced) != 1 || b.announced[0].Prepend.Count != 3 || b.announced[0].Prepend.ASN != 65001 {
		t.Fatalf("backup isp-b must be prepended x3 ASN 65001, got %+v", b.announced)
	}
}

// Deleting the only policy that reached an upstream must withdraw the tenant
// prefix from it on the next tick (withdraw follows a shrunk AdvSet).
func TestAdvertiseTenants_WithdrawOnPolicyRemoval(t *testing.T) {
	cfg := twoUpstreamConfig()
	a := &recordingUpstreamBGP{}
	b := &recordingUpstreamBGP{}
	s := testScheme(t)
	p := tenantPolicy("p1", "u1", 10, "a") // {a, b}
	c := fakeclient.NewClientBuilder().WithScheme(s).
		WithObjects(tenantNamespace("team-a", map[string]string{"team": "a"}), p).Build()
	adv := &ClusterReturnAdvertiser{Config: cfg, Client: c, Log: logr.Discard(),
		BackboneBGP: map[string]bgp.Distributor{"isp-a": a, "isp-b": b}}

	// Tick 1: both upstreams advertised.
	if err := adv.assert(context.Background()); err != nil {
		t.Fatalf("tick1: %v", err)
	}
	if len(a.announced) != 1 || len(b.announced) != 1 {
		t.Fatalf("tick1 must advertise both, got a=%d b=%d", len(a.announced), len(b.announced))
	}

	// Delete the policy; tick 2 must withdraw from both.
	if err := c.Delete(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	if err := adv.assert(context.Background()); err != nil {
		t.Fatalf("tick2: %v", err)
	}
	if len(a.withdrawn) != 1 || len(b.withdrawn) != 1 {
		t.Fatalf("tick2 must withdraw both, got a=%d b=%d", len(a.withdrawn), len(b.withdrawn))
	}
}

// A tenant whose namespace matches no policy has no intent, so no reachability:
// nothing is advertised (§14.6 default-deny alignment).
func TestAdvertiseTenants_NoMatchingPolicyNoAdvertise(t *testing.T) {
	cfg := twoUpstreamConfig()
	a := &recordingUpstreamBGP{}
	b := &recordingUpstreamBGP{}
	s := testScheme(t)
	c := fakeclient.NewClientBuilder().WithScheme(s).
		WithObjects(
			tenantNamespace("team-a", map[string]string{"team": "a"}),
			tenantPolicy("p-other", "u1", 10, "b"), // selects team=b, not team-a
		).Build()
	adv := &ClusterReturnAdvertiser{Config: cfg, Client: c, Log: logr.Discard(),
		BackboneBGP: map[string]bgp.Distributor{"isp-a": a, "isp-b": b}}

	if err := adv.assert(context.Background()); err != nil {
		t.Fatalf("assert: %v", err)
	}
	if len(a.announced) != 0 || len(b.announced) != 0 {
		t.Fatalf("no matching policy => no advertise, got a=%d b=%d", len(a.announced), len(b.announced))
	}
}

// Regression: with Backbone.Tenants unset, the advertiser keeps the legacy
// cluster-wide behavior (single clusterPodCIDR to every peer).
func TestAdvertiseTenants_UnsetKeepsClusterWide(t *testing.T) {
	svc := &recordingServiceBGP{}
	adv := &ClusterReturnAdvertiser{Config: backboneConfig(), Log: logr.Discard(),
		BackboneBGP: map[string]bgp.Distributor{"isp-a": svc}}
	if err := adv.assert(context.Background()); err != nil {
		t.Fatalf("assert: %v", err)
	}
	if len(svc.announced) != 1 || svc.announced[0].Route.Prefix != "fd00:dead::/48" {
		t.Fatalf("Tenants unset must advertise the cluster-wide CIDR, got %+v", svc.announced)
	}
}

// --- F2 convergence / F3 deterministic primary ---

// twoTenantConfig extends twoUpstreamConfig with a second tenant (team-b →
// 2001:db8:3000::/48) so continue-on-error across tenants can be tested.
func twoTenantConfig() *config.ControllerConfig {
	cfg := twoUpstreamConfig()
	cfg.Backbone.Tenants["tenant-b"] = config.TenantConfig{Namespace: "team-b", PodCIDR: "2001:db8:3000::/48"}
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return cfg
}

// F2: a failed withdraw is retried every tick until it succeeds (a transient
// fault must not leave a stale return advertisement lingering in gobgp forever —
// that is a silent sovereignty leak). The retry must not block another tenant's
// announces, and once the withdraw finally succeeds the upstream is dropped from
// lastAdvSet so the retry stops.
func TestAdvertiseTenants_WithdrawRetriesUntilSuccess(t *testing.T) {
	cfg := twoTenantConfig()
	a := &recordingUpstreamBGP{}
	b := &recordingUpstreamBGP{}
	s := testScheme(t)
	// tenant-a matches color 10 ({a,b}); tenant-b matches color 10 too.
	pA := tenantPolicy("pa", "ua", 10, "a")
	pB := tenantPolicy("pb", "ub", 10, "b")
	c := fakeclient.NewClientBuilder().WithScheme(s).
		WithObjects(
			tenantNamespace("team-a", map[string]string{"team": "a"}),
			tenantNamespace("team-b", map[string]string{"team": "b"}),
			pA, pB,
		).Build()
	adv := &ClusterReturnAdvertiser{Config: cfg, Client: c, Log: logr.Discard(),
		BackboneBGP: map[string]bgp.Distributor{"isp-a": a, "isp-b": b}}

	// Tick 1: both tenants reach both upstreams.
	if err := adv.assert(context.Background()); err != nil {
		t.Fatalf("tick1: %v", err)
	}
	if len(a.announced) != 2 || len(b.announced) != 2 {
		t.Fatalf("tick1 want 2 announces per upstream, got a=%d b=%d", len(a.announced), len(b.announced))
	}

	// Delete tenant-a's policy (its AdvSet shrinks to empty ⇒ withdraw from both),
	// and make isp-b's withdraw fail. tenant-b must still be re-announced.
	if err := c.Delete(context.Background(), pA); err != nil {
		t.Fatal(err)
	}
	b.errOnWithdraw = fmt.Errorf("path not found")
	a.announced, b.announced = nil, nil
	a.withdrawn, b.withdrawn = nil, nil

	if err := adv.assert(context.Background()); err == nil {
		t.Fatal("tick2 must surface the withdraw error")
	}
	// tenant-b's announces are not blocked by tenant-a's withdraw failure.
	if len(a.announced) != 1 || len(b.announced) != 1 {
		t.Fatalf("tick2 tenant-b must still be announced, got a=%d b=%d", len(a.announced), len(b.announced))
	}
	// tenant-a: isp-a's withdraw succeeded, isp-b's failed.
	if len(a.withdrawn) != 1 || len(b.withdrawn) != 1 {
		t.Fatalf("tick2 must attempt withdraw on both, got a=%d b=%d", len(a.withdrawn), len(b.withdrawn))
	}
	// The failed isp-b withdraw stays pending; the succeeded isp-a one does not.
	if !adv.lastAdvSet["tenant-a"]["isp-b"] {
		t.Fatal("tick2 failed withdraw (isp-b) must remain in lastAdvSet for retry")
	}
	if adv.lastAdvSet["tenant-a"]["isp-a"] {
		t.Fatal("tick2 succeeded withdraw (isp-a) must be cleared from lastAdvSet")
	}

	// Tick 3: withdraw still failing ⇒ the pending isp-b withdraw is RE-ISSUED
	// (retry until success), and only for isp-b (isp-a already converged).
	a.withdrawn, b.withdrawn = nil, nil
	a.announced, b.announced = nil, nil
	if err := adv.assert(context.Background()); err == nil {
		t.Fatal("tick3 must still surface the failing withdraw (retry, not silent leak)")
	}
	if len(a.withdrawn) != 0 {
		t.Fatalf("tick3 must not re-withdraw the converged isp-a, got a=%d", len(a.withdrawn))
	}
	if len(b.withdrawn) != 1 {
		t.Fatalf("tick3 must retry the pending isp-b withdraw, got b=%d", len(b.withdrawn))
	}

	// Tick 4: the fault clears ⇒ the retry finally succeeds, isp-b drops out of
	// lastAdvSet, and no further withdraw is issued afterwards.
	b.errOnWithdraw = nil
	a.withdrawn, b.withdrawn = nil, nil
	if err := adv.assert(context.Background()); err != nil {
		t.Fatalf("tick4 withdraw should now succeed: %v", err)
	}
	if len(b.withdrawn) != 1 {
		t.Fatalf("tick4 must issue the now-succeeding isp-b withdraw, got b=%d", len(b.withdrawn))
	}
	if adv.lastAdvSet["tenant-a"]["isp-b"] {
		t.Fatal("tick4 succeeded withdraw must clear isp-b from lastAdvSet")
	}

	// Tick 5: fully converged ⇒ no withdraw is re-issued for tenant-a.
	a.withdrawn, b.withdrawn = nil, nil
	if err := adv.assert(context.Background()); err != nil {
		t.Fatalf("tick5: %v", err)
	}
	if len(a.withdrawn) != 0 || len(b.withdrawn) != 0 {
		t.Fatalf("tick5 must not re-withdraw the converged tenant, got a=%d b=%d", len(a.withdrawn), len(b.withdrawn))
	}
}

// F2: an announce failure on one tenant must not stop the other tenant's
// announces (continue-on-error), and the failed upstream stays out of the new
// AdvSet so the next tick retries it.
func TestAdvertiseTenants_AnnounceFailureIsolatedPerTenant(t *testing.T) {
	cfg := twoTenantConfig()
	a := &recordingUpstreamBGP{}
	b := &recordingUpstreamBGP{errOnAnnounce: fmt.Errorf("session down")}
	s := testScheme(t)
	c := fakeclient.NewClientBuilder().WithScheme(s).
		WithObjects(
			tenantNamespace("team-a", map[string]string{"team": "a"}),
			tenantNamespace("team-b", map[string]string{"team": "b"}),
			tenantPolicy("pa", "ua", 10, "a"),
			tenantPolicy("pb", "ub", 10, "b"),
		).Build()
	adv := &ClusterReturnAdvertiser{Config: cfg, Client: c, Log: logr.Discard(),
		BackboneBGP: map[string]bgp.Distributor{"isp-a": a, "isp-b": b}}

	if err := adv.assert(context.Background()); err == nil {
		t.Fatal("assert must surface the isp-b announce error")
	}
	// isp-a got both tenants despite isp-b failing on both.
	if len(a.announced) != 2 {
		t.Fatalf("isp-a must receive both tenants, got %d", len(a.announced))
	}
	// isp-b failed for both tenants, so neither is recorded in lastAdvSet.
	if adv.lastAdvSet["tenant-a"]["isp-b"] || adv.lastAdvSet["tenant-b"]["isp-b"] {
		t.Fatal("a failed announce must not be recorded in lastAdvSet")
	}
}

// F3: with an equal-preference tie the primary (plain, un-prepended) must be the
// lexicographically smaller upstream — deterministic across ticks regardless of
// policy/candidate API order. Equal preferences WITHIN a color are rejected by
// Validate, so a tie can only arise ACROSS colors matched by the same tenant.
func TestAdvertiseTenants_PrimaryTieBreakDeterministic(t *testing.T) {
	cfg := twoUpstreamConfig()
	// Two intent colors, one candidate each, equal preference (isp-b's color
	// listed first to prove order-independence). Prepend enabled so the primary
	// is observable.
	cfg.Colors[10] = config.ColorConfig{CandidatePaths: []config.CandidatePathConfig{
		{Upstream: "isp-b", SegmentList: []string{"fcff:0:0:e0:b::"}, Preference: 100},
	}}
	cfg.Colors[40] = config.ColorConfig{CandidatePaths: []config.CandidatePathConfig{
		{Upstream: "isp-a", SegmentList: []string{"fcff:0:0:e0:a::"}, Preference: 100},
	}}
	cfg.Backbone.ReturnPrependASN = 65001
	cfg.Backbone.ReturnPrependCount = 3
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	a := &recordingUpstreamBGP{}
	b := &recordingUpstreamBGP{}
	s := testScheme(t)
	c := fakeclient.NewClientBuilder().WithScheme(s).
		WithObjects(
			tenantNamespace("team-a", map[string]string{"team": "a"}),
			tenantPolicy("p1", "u1", 10, "a"),
			tenantPolicy("p2", "u2", 40, "a"),
		).Build()
	adv := &ClusterReturnAdvertiser{Config: cfg, Client: c, Log: logr.Discard(),
		BackboneBGP: map[string]bgp.Distributor{"isp-a": a, "isp-b": b}}

	if err := adv.assert(context.Background()); err != nil {
		t.Fatalf("assert: %v", err)
	}
	// isp-a < isp-b ⇒ isp-a is primary (plain), isp-b is prepended.
	if len(a.announced) != 1 || a.announced[0].Prepend.Count != 0 {
		t.Fatalf("isp-a must be the tie-break primary (plain), got %+v", a.announced)
	}
	if len(b.announced) != 1 || b.announced[0].Prepend.Count != 3 {
		t.Fatalf("isp-b must be the prepended backup, got %+v", b.announced)
	}
}
