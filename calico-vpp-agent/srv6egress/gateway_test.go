package srv6egress

import (
	"fmt"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
)

type fakeGW struct {
	installs    map[string]GatewayRequest
	removes     map[string]GatewayRequest
	failInstall bool

	// returnRoutes tracks the live per-tenant return routes keyed
	// "prefix|upstreamTable|clusterTable"; add/del counters see through
	// refcount no-ops, and delCalls records each delete's route key.
	returnRoutes  map[string]struct{}
	returnAdds    int
	returnDels    int
	delCalls      []string
	failDelReturn bool
}

func newFakeGW() *fakeGW {
	return &fakeGW{
		installs:     map[string]GatewayRequest{},
		removes:      map[string]GatewayRequest{},
		returnRoutes: map[string]struct{}{},
	}
}

func (f *fakeGW) InstallGateway(req GatewayRequest) error {
	if f.failInstall {
		return fmt.Errorf("install failed (test)")
	}
	f.installs[req.PolicyUID] = req
	return nil
}
func (f *fakeGW) RemoveGateway(req GatewayRequest) error {
	f.removes[req.PolicyUID] = req
	delete(f.installs, req.PolicyUID)
	return nil
}

func rrKey(prefix string, upstreamTable, clusterTable uint32) string {
	return fmt.Sprintf("%s|%d|%d", prefix, upstreamTable, clusterTable)
}

func (f *fakeGW) AddTenantReturnRoute(prefix string, upstreamTable, clusterTable uint32) error {
	f.returnAdds++
	f.returnRoutes[rrKey(prefix, upstreamTable, clusterTable)] = struct{}{}
	return nil
}
func (f *fakeGW) DelTenantReturnRoute(prefix string, upstreamTable, clusterTable uint32) error {
	if f.failDelReturn {
		return fmt.Errorf("del return route failed (test)")
	}
	f.returnDels++
	f.delCalls = append(f.delCalls, rrKey(prefix, upstreamTable, clusterTable))
	delete(f.returnRoutes, rrKey(prefix, upstreamTable, clusterTable))
	return nil
}

// gwPolicy builds a Ready EgressPolicy whose endpoint resolved to `endpoint`,
// with a terminal SID, VIP and upstream in status.
func gwPolicy(name, uid, endpoint, sid, vip, upstream string) *srv6egressv1.EgressPolicy {
	return &srv6egressv1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid)},
		Status: srv6egressv1.EgressPolicyStatus{
			ActiveEndpoint: endpoint,
			Upstream:       upstream,
			SRPolicy:       &srv6egressv1.SRPolicyStatus{SegmentList: []string{sid}},
			Conditions:     []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}},
		},
	}
}

func newGWManager(vpp VPPGateway) *GatewayManager {
	return NewGatewayManager(logrus.NewEntry(logrus.New()), vpp, "gw-node",
		map[string]uint32{"isp-a": 100, "isp-b": 200}, 1000)
}

type fakeAdvertiser struct {
	advertised map[string]struct{}
	withdrawn  map[string]struct{}
}

func newFakeAdvertiser() *fakeAdvertiser {
	return &fakeAdvertiser{advertised: map[string]struct{}{}, withdrawn: map[string]struct{}{}}
}
func (f *fakeAdvertiser) AdvertiseSID(sid net.IP) error {
	f.advertised[sid.String()] = struct{}{}
	return nil
}
func (f *fakeAdvertiser) WithdrawSID(sid net.IP) error {
	f.withdrawn[sid.String()] = struct{}{}
	return nil
}

// The gateway must advertise the tenant SID on install (so headend nodes can
// route to it) and withdraw it on teardown.
func TestGateway_AdvertisesAndWithdrawsSID(t *testing.T) {
	vpp := newFakeGW()
	adv := newFakeAdvertiser()
	m := newGWManager(vpp)
	m.SetSIDAdvertiser(adv)

	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))
	if !contains(adv.advertised, "fcff:0:0:e0:a:1::") {
		t.Fatalf("SID not advertised on install: %v", adv.advertised)
	}
	m.OnPolicyDelete("uid-a")
	if !contains(adv.withdrawn, "fcff:0:0:e0:a:1::") {
		t.Fatalf("SID not withdrawn on teardown: %v", adv.withdrawn)
	}
}

// A failed InstallGateway must not leak the VRF table id: reconcile allocs it
// before InstallGateway, so a later delete has to free it even though
// st.install is still nil.
func TestGateway_FailedInstallFreesVRF(t *testing.T) {
	vpp := newFakeGW()
	vpp.failInstall = true
	m := newGWManager(vpp)

	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))
	if len(m.vrfs.byUID) != 1 {
		t.Fatalf("expected 1 VRF allocated after failed install, got %d", len(m.vrfs.byUID))
	}
	m.OnPolicyDelete("uid-a")
	if len(m.vrfs.byUID) != 0 || len(m.vrfs.inUse) != 0 {
		t.Fatalf("VRF leaked after delete: byUID=%d inUse=%d", len(m.vrfs.byUID), len(m.vrfs.inUse))
	}
}

func contains(m map[string]struct{}, k string) bool {
	if _, ok := m[k]; ok {
		return true
	}
	// net.IP.String may canonicalize differently; match by parsed equality.
	want := net.ParseIP(k)
	for s := range m {
		if net.ParseIP(s).Equal(want) {
			return true
		}
	}
	return false
}

func TestGateway_InstallsForLocalEndpoint(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))

	req, ok := vpp.installs["uid-a"]
	if !ok {
		t.Fatal("expected a gateway install for the local endpoint")
	}
	if !req.TenantSID.Equal(net.ParseIP("fcff:0:0:e0:a:1::")) {
		t.Fatalf("bad request %+v", req)
	}
	if req.UpstreamTable != 100 {
		t.Fatalf("upstream table = %d, want 100 (isp-a)", req.UpstreamTable)
	}
	if req.VrfTable < 1000 {
		t.Fatalf("vrf table = %d, want >= base 1000", req.VrfTable)
	}
}

// SetClusterReturn must flow the cluster pod CIDR + cluster VRF into the install
// request so the gateway installs the shared return aggregate.
func TestGateway_ClusterReturnConfigured(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.SetClusterReturn("fd00:cafe::/48", 0)
	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))

	req := vpp.installs["uid-a"]
	if req.ReturnCIDR != "fd00:cafe::/48" || req.ReturnTable != 0 {
		t.Fatalf("cluster return not propagated: cidr=%q table=%d", req.ReturnCIDR, req.ReturnTable)
	}
}

func TestGateway_IgnoresRemoteEndpoint(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "other-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))
	if len(vpp.installs) != 0 {
		t.Fatalf("must not install for a policy whose endpoint is another node: %v", vpp.installs)
	}
}

func TestGateway_DistinctVRFsPerTenant(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))
	m.OnPolicyUpdate(gwPolicy("b", "uid-b", "gw-node", "fcff:0:0:e0:b:1::", "2001:db8:e::b", "isp-b"))

	a, b := vpp.installs["uid-a"], vpp.installs["uid-b"]
	if a.VrfTable == b.VrfTable {
		t.Fatalf("tenants must get distinct VRFs, both %d", a.VrfTable)
	}
	if a.UpstreamTable != 100 || b.UpstreamTable != 200 {
		t.Fatalf("upstream tables a=%d b=%d, want 100/200", a.UpstreamTable, b.UpstreamTable)
	}
}

// A periodic reconcile of an already-installed, unchanged policy must be a
// no-op: no teardown, no re-install (otherwise the gateway churns the VRF /
// localsid / route every tick).
func TestGateway_ReconcileIsIdempotent(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	ep := gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a")
	m.OnPolicyUpdate(ep)
	if len(vpp.installs) != 1 {
		t.Fatalf("precondition: expected 1 install, got %d", len(vpp.installs))
	}
	vrf := vpp.installs["uid-a"].VrfTable

	// Several reconciles of the unchanged policy must not tear down or move it.
	for i := 0; i < 3; i++ {
		m.ReconcileAll()
	}
	if len(vpp.removes) != 0 {
		t.Fatalf("reconcile churned a teardown: removes=%v", vpp.removes)
	}
	if got := vpp.installs["uid-a"].VrfTable; got != vrf {
		t.Fatalf("VRF changed across reconciles: %d -> %d", vrf, got)
	}
}

func TestGateway_TeardownFreesVRF(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))
	first := vpp.installs["uid-a"].VrfTable
	m.OnPolicyDelete("uid-a")
	if _, ok := vpp.removes["uid-a"]; !ok {
		t.Fatal("expected RemoveGateway on delete")
	}
	// A new policy should be able to reuse the freed VRF id.
	m.OnPolicyUpdate(gwPolicy("c", "uid-c", "gw-node", "fcff:0:0:e0:a:2::", "2001:db8:e::c", "isp-a"))
	if got := vpp.installs["uid-c"].VrfTable; got != first {
		t.Fatalf("freed VRF %d should be reused, got %d", first, got)
	}
}

// Endpoint moving away (re-resolved to another node) must tear down the entry.
func TestGateway_EndpointMoveTearsDown(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))
	if len(vpp.installs) != 1 {
		t.Fatal("precondition: installed")
	}
	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "other-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))
	if _, ok := vpp.removes["uid-a"]; !ok {
		t.Fatal("endpoint move must tear down the local gateway entry")
	}
	if len(vpp.installs) != 0 {
		t.Fatalf("install must be gone after endpoint move: %v", vpp.installs)
	}
}

func TestGateway_PruneExcept(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))
	m.OnPolicyUpdate(gwPolicy("b", "uid-b", "gw-node", "fcff:0:0:e0:b:1::", "2001:db8:e::b", "isp-b"))
	m.PruneExcept(map[string]struct{}{"uid-a": {}})
	if _, ok := vpp.removes["uid-b"]; !ok {
		t.Fatal("uid-b (absent from live set) must be torn down")
	}
	if _, ok := vpp.installs["uid-a"]; !ok {
		t.Fatal("uid-a must survive the prune")
	}
}

func TestGateway_NotReadyDeferred(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	ep := gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a")
	ep.Status.Conditions = nil // not Ready
	m.OnPolicyUpdate(ep)
	if len(vpp.installs) != 0 {
		t.Fatalf("must not install for a not-ready policy: %v", vpp.installs)
	}
}

func TestGateway_UnknownUpstreamSkipped(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-z"))
	if len(vpp.installs) != 0 {
		t.Fatalf("unknown upstream must be skipped: %v", vpp.installs)
	}
}

// --- per-tenant return routes (sovereignty fence in the dataplane) ---

// gwTenantPolicy builds a Ready policy carrying per-tenant return info:
// candidatePaths over the given upstreams (primary first) and
// status.returnPrefixes with the tenant podCIDR.
func gwTenantPolicy(name, uid, endpoint, sid string, upstreams []string, prefixes []string) *srv6egressv1.EgressPolicy {
	p := gwPolicy(name, uid, endpoint, sid, "", upstreams[0])
	cps := make([]srv6egressv1.CandidatePathStatus, len(upstreams))
	for i, up := range upstreams {
		cps[i] = srv6egressv1.CandidatePathStatus{
			Upstream: up, SegmentList: []string{sid}, Preference: uint32(200 - 10*i),
		}
	}
	p.Status.SRPolicy.CandidatePaths = cps
	p.Status.ReturnPrefixes = prefixes
	return p
}

func wantReturnRoutes(t *testing.T, vpp *fakeGW, keys ...string) {
	t.Helper()
	if len(vpp.returnRoutes) != len(keys) {
		t.Fatalf("return routes = %v, want exactly %v", vpp.returnRoutes, keys)
	}
	for _, k := range keys {
		if _, ok := vpp.returnRoutes[k]; !ok {
			t.Fatalf("return route %q missing: %v", k, vpp.returnRoutes)
		}
	}
}

// The tenant prefix must be routed into the cluster VRF from EVERY candidate
// upstream's VRF (the forward failover surface), and the per-tenant fence must
// supersede the legacy shared aggregate for that policy.
func TestGateway_PerTenantReturnRoutesInstalled(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.SetClusterReturn("fd00:cafe::/48", 7) // legacy aggregate configured too
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::",
		[]string{"isp-a", "isp-b"}, []string{"2001:db8:2000::/48"}))

	wantReturnRoutes(t, vpp,
		rrKey("2001:db8:2000::/48", 100, 7),
		rrKey("2001:db8:2000::/48", 200, 7))
	// Per-tenant info suppresses the legacy shared aggregate for this policy.
	if req := vpp.installs["uid-a"]; req.ReturnCIDR != "" {
		t.Fatalf("legacy aggregate must be suppressed when returnPrefixes set, got %q", req.ReturnCIDR)
	}
}

// A route shared by two policies of the same tenant is refcounted: removing
// one policy must not rip the route; removing both must.
func TestGateway_ReturnRouteRefcountAcrossPolicies(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	prefix := []string{"2001:db8:2000::/48"}
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", []string{"isp-a"}, prefix))
	m.OnPolicyUpdate(gwTenantPolicy("b", "uid-b", "gw-node", "fcff:0:0:e0:a:2::", []string{"isp-a"}, prefix))

	wantReturnRoutes(t, vpp, rrKey("2001:db8:2000::/48", 100, 0))
	if vpp.returnAdds != 1 {
		t.Fatalf("shared route must be installed once, got %d adds", vpp.returnAdds)
	}
	m.OnPolicyDelete("uid-a")
	wantReturnRoutes(t, vpp, rrKey("2001:db8:2000::/48", 100, 0)) // sibling still needs it
	if vpp.returnDels != 0 {
		t.Fatalf("route ripped while a sibling policy still needs it (%d dels)", vpp.returnDels)
	}
	m.OnPolicyDelete("uid-b")
	wantReturnRoutes(t, vpp) // gone
}

// A policy that goes NotReady contributes nothing: its return routes are
// pruned (fail-closed — traffic drops rather than leaks).
func TestGateway_ReturnRoutesPrunedOnNotReady(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	ep := gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", []string{"isp-a", "isp-b"}, []string{"2001:db8:2000::/48"})
	m.OnPolicyUpdate(ep)
	if len(vpp.returnRoutes) != 2 {
		t.Fatalf("precondition: expected 2 return routes, got %v", vpp.returnRoutes)
	}
	notReady := ep.DeepCopy()
	notReady.Status.Conditions = nil
	m.OnPolicyUpdate(notReady)
	wantReturnRoutes(t, vpp) // all pruned
}

// Shrinking the candidate set must remove the route from the dropped
// upstream's VRF (the BGP advertisement was withdrawn there; a leftover
// forwarding route would be a silent sovereignty leak) without churning the
// surviving one.
func TestGateway_ReturnRoutesPrunedOnCandidateShrink(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::",
		[]string{"isp-a", "isp-b"}, []string{"2001:db8:2000::/48"}))
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::",
		[]string{"isp-a"}, []string{"2001:db8:2000::/48"}))

	wantReturnRoutes(t, vpp, rrKey("2001:db8:2000::/48", 100, 0))
	if len(vpp.removes) != 0 {
		t.Fatalf("candidate shrink must not churn the gateway install: %v", vpp.removes)
	}
	if vpp.returnAdds != 2 {
		t.Fatalf("surviving route must not be re-added, got %d adds", vpp.returnAdds)
	}
}

// A candidate upstream with no configured VRF table is warned and skipped —
// the remaining upstreams still get their fence.
func TestGateway_ReturnRouteUnknownUpstreamSkipped(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::",
		[]string{"isp-a", "isp-z"}, []string{"2001:db8:2000::/48"}))
	wantReturnRoutes(t, vpp, rrKey("2001:db8:2000::/48", 100, 0))
}

// A failed delete must stay in the bookkeeping and be retried until it
// succeeds — even when the policy itself was already forgotten (a stale
// return route is a sovereignty leak, the exact failure PR D closes).
func TestGateway_ReturnRouteDeleteRetriedAfterFailure(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", []string{"isp-a"}, []string{"2001:db8:2000::/48"}))

	vpp.failDelReturn = true
	m.OnPolicyDelete("uid-a")
	if len(vpp.returnRoutes) != 1 {
		t.Fatalf("failed delete should leave the VPP route (test stub keeps it): %v", vpp.returnRoutes)
	}
	vpp.failDelReturn = false
	m.ReconcileAll() // orphan sweep retries the delete
	wantReturnRoutes(t, vpp)
}

// A policy without per-tenant status info keeps the legacy shared-aggregate
// behavior bit-for-bit: ReturnCIDR flows into the install request and no
// per-tenant route calls are made.
func TestGateway_LegacyFallbackWithoutReturnPrefixes(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.SetClusterReturn("fd00:cafe::/48", 0)
	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))

	req := vpp.installs["uid-a"]
	if req.ReturnCIDR != "fd00:cafe::/48" || req.ReturnTable != 0 {
		t.Fatalf("legacy aggregate not propagated: cidr=%q table=%d", req.ReturnCIDR, req.ReturnTable)
	}
	if vpp.returnAdds != 0 || len(vpp.returnRoutes) != 0 {
		t.Fatalf("no per-tenant routes expected in legacy mode: %v", vpp.returnRoutes)
	}
}

// A drift reinstall (SID changed) with unchanged returnPrefixes/candidates
// must not churn the return routes: the drift teardown keeps them and the
// deferred diff-based reconcile finds nothing to change. Zero Del/Add calls
// for the unchanged route set — a del→add churn would open a transient fence
// gap for routes that did not change.
func TestGateway_DriftReinstallKeepsUnchangedReturnRoutes(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::",
		[]string{"isp-a", "isp-b"}, []string{"2001:db8:2000::/48"}))
	if vpp.returnAdds != 2 {
		t.Fatalf("precondition: expected 2 return route adds, got %d", vpp.returnAdds)
	}

	// SID change => install key drifts => teardown + reinstall of the gateway
	// entry, but the return route set is identical.
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:2::",
		[]string{"isp-a", "isp-b"}, []string{"2001:db8:2000::/48"}))
	if _, ok := vpp.removes["uid-a"]; !ok {
		t.Fatal("precondition: SID drift must reinstall the gateway entry")
	}
	if vpp.returnDels != 0 || vpp.returnAdds != 2 {
		t.Fatalf("drift reinstall churned unchanged return routes: adds=%d dels=%d",
			vpp.returnAdds, vpp.returnDels)
	}
	wantReturnRoutes(t, vpp,
		rrKey("2001:db8:2000::/48", 100, 0),
		rrKey("2001:db8:2000::/48", 200, 0))
}

// A drift reinstall that ALSO shrinks the candidate set must remove only the
// stale route (dropped upstream's VRF) and keep the surviving one untouched.
func TestGateway_DriftReinstallPrunesOnlyStaleReturnRoute(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::",
		[]string{"isp-a", "isp-b"}, []string{"2001:db8:2000::/48"}))

	// SID change (drift) + isp-b dropped from the candidates.
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:2::",
		[]string{"isp-a"}, []string{"2001:db8:2000::/48"}))
	if _, ok := vpp.removes["uid-a"]; !ok {
		t.Fatal("precondition: SID drift must reinstall the gateway entry")
	}
	wantReturnRoutes(t, vpp, rrKey("2001:db8:2000::/48", 100, 0))
	if got := []string{rrKey("2001:db8:2000::/48", 200, 0)}; len(vpp.delCalls) != 1 || vpp.delCalls[0] != got[0] {
		t.Fatalf("expected exactly one delete of the stale isp-b route, got %v", vpp.delCalls)
	}
	if vpp.returnAdds != 2 {
		t.Fatalf("surviving route must not be re-added, got %d adds", vpp.returnAdds)
	}
}

// --- legacy shared aggregate sweep (F1) ---

func hasDelCall(vpp *fakeGW, key string) bool {
	for _, k := range vpp.delCalls {
		if k == key {
			return true
		}
	}
	return false
}

// When every tracked policy runs in per-tenant mode, a pre-existing legacy
// shared aggregate (installed by an older agent, or by this policy before its
// status gained returnPrefixes) is stale in EVERY upstream VRF: the sweep must
// delete it from all configured upstream tables — and only once (no VPP call
// churn on subsequent reconciles).
func TestGateway_LegacyAggregateSweptWhenAllPerTenant(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.SetClusterReturn("fd00:cafe::/48", 7)
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::",
		[]string{"isp-a"}, []string{"2001:db8:2000::/48"}))
	m.PruneExcept(map[string]struct{}{"uid-a": {}})

	m.ReconcileAll()
	for _, table := range []uint32{100, 200} {
		if !hasDelCall(vpp, rrKey("fd00:cafe::/48", table, 7)) {
			t.Fatalf("stale legacy aggregate not swept from table %d: %v", table, vpp.delCalls)
		}
	}
	dels := vpp.returnDels
	m.ReconcileAll()
	if vpp.returnDels != dels {
		t.Fatalf("sweep must not re-issue deletes every tick: %v", vpp.delCalls)
	}
}

// A legacy policy (no returnPrefixes) on upstream A still needs the aggregate
// in A's VRF; per-tenant policies on B do not. The sweep must delete only from
// B's table.
func TestGateway_LegacyAggregateSweptOnlyFromUnwantedTables(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.SetClusterReturn("fd00:cafe::/48", 7)
	m.OnPolicyUpdate(gwPolicy("legacy", "uid-legacy", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))
	m.OnPolicyUpdate(gwTenantPolicy("b", "uid-b", "gw-node", "fcff:0:0:e0:b:1::",
		[]string{"isp-b"}, []string{"2001:db8:3000::/48"}))
	m.PruneExcept(map[string]struct{}{"uid-legacy": {}, "uid-b": {}})

	m.ReconcileAll()
	if hasDelCall(vpp, rrKey("fd00:cafe::/48", 100, 7)) {
		t.Fatalf("aggregate ripped from isp-a while a legacy policy still needs it: %v", vpp.delCalls)
	}
	if !hasDelCall(vpp, rrKey("fd00:cafe::/48", 200, 7)) {
		t.Fatalf("stale aggregate not swept from isp-b's table: %v", vpp.delCalls)
	}
}

// Before PruneExcept has run (no successful List yet — e.g. agent restart with
// the apiserver unreachable), the policies map may be missing legacy policies
// that still need the aggregate: the sweep must be a no-op.
func TestGateway_LegacyAggregateSweepGatedOnSync(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.SetClusterReturn("fd00:cafe::/48", 7)
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::",
		[]string{"isp-a"}, []string{"2001:db8:2000::/48"}))

	m.ReconcileAll() // no PruneExcept yet
	for _, table := range []uint32{100, 200} {
		if hasDelCall(vpp, rrKey("fd00:cafe::/48", table, 7)) {
			t.Fatalf("sweep ran before the watcher synced: %v", vpp.delCalls)
		}
	}
}

// With no legacy aggregate configured (returnCIDR unset) there is nothing to
// sweep: no delete calls beyond per-tenant reconciliation (none here).
func TestGateway_LegacyAggregateSweepNoopWithoutReturnCIDR(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwTenantPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::",
		[]string{"isp-a"}, []string{"2001:db8:2000::/48"}))
	m.PruneExcept(map[string]struct{}{"uid-a": {}})

	m.ReconcileAll()
	if vpp.returnDels != 0 {
		t.Fatalf("no sweep expected with returnCIDR unset: %v", vpp.delCalls)
	}
}
