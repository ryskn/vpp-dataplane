package srv6egress

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	srv6egressv1alpha1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1alpha1"
)

type fakeGW struct {
	installs map[string]GatewayRequest
	removes  map[string]GatewayRequest
}

func newFakeGW() *fakeGW {
	return &fakeGW{installs: map[string]GatewayRequest{}, removes: map[string]GatewayRequest{}}
}

func (f *fakeGW) InstallGateway(req GatewayRequest) error {
	f.installs[req.PolicyUID] = req
	return nil
}
func (f *fakeGW) RemoveGateway(req GatewayRequest) error {
	f.removes[req.PolicyUID] = req
	delete(f.installs, req.PolicyUID)
	return nil
}

// gwPolicy builds a Ready EgressPolicy whose endpoint resolved to `endpoint`,
// with a terminal SID, VIP and upstream in status.
func gwPolicy(name, uid, endpoint, sid, vip, upstream string) *srv6egressv1alpha1.EgressPolicy {
	return &srv6egressv1alpha1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(uid)},
		Status: srv6egressv1alpha1.EgressPolicyStatus{
			EgressIP:       vip,
			ActiveEndpoint: endpoint,
			Upstream:       upstream,
			SRPolicy:       &srv6egressv1alpha1.SRPolicyStatus{SegmentList: []string{sid}},
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
	if !req.TenantSID.Equal(net.ParseIP("fcff:0:0:e0:a:1::")) || !req.VIP.Equal(net.ParseIP("2001:db8:e::a")) {
		t.Fatalf("bad request %+v", req)
	}
	if req.UpstreamTable != 100 {
		t.Fatalf("upstream table = %d, want 100 (isp-a)", req.UpstreamTable)
	}
	if req.VrfTable < 1000 {
		t.Fatalf("vrf table = %d, want >= base 1000", req.VrfTable)
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

func TestGateway_DistinctVRFsAndVIPsPerTenant(t *testing.T) {
	vpp := newFakeGW()
	m := newGWManager(vpp)
	m.OnPolicyUpdate(gwPolicy("a", "uid-a", "gw-node", "fcff:0:0:e0:a:1::", "2001:db8:e::a", "isp-a"))
	m.OnPolicyUpdate(gwPolicy("b", "uid-b", "gw-node", "fcff:0:0:e0:b:1::", "2001:db8:e::b", "isp-b"))

	a, b := vpp.installs["uid-a"], vpp.installs["uid-b"]
	if a.VrfTable == b.VrfTable {
		t.Fatalf("tenants must get distinct VRFs, both %d", a.VrfTable)
	}
	if a.VIP.Equal(b.VIP) {
		t.Fatal("tenants must keep distinct VIPs")
	}
	if a.UpstreamTable != 100 || b.UpstreamTable != 200 {
		t.Fatalf("upstream tables a=%d b=%d, want 100/200", a.UpstreamTable, b.UpstreamTable)
	}
}

// A periodic reconcile of an already-installed, unchanged policy must be a
// no-op: no teardown, no re-install (otherwise the gateway churns the VRF /
// localsid / SNAT every tick).
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
