package connectivity

import (
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	govppapi "go.fd.io/govpp/api"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// fakeSRv6VPP records every srv6VppAPI call so tests can assert what reached
// the dataplane and seed ListSRv6Steering output. callLog records the
// interleaving across methods so ordering-sensitive tests can verify e.g.
// "AddSRv6Steering happened before DelSRv6Policy".
type fakeSRv6VPP struct {
	steering []*types.SrSteer
	policies []*types.SrPolicy

	addModPolicy []*types.SrPolicy
	delPolicy    []*types.SrPolicy
	addSteering  []*types.SrSteer
	delSteering  []*types.SrSteer
	routeAdd     []*types.Route
	routeDel     []*types.Route
	callLog      []string

	listSteeringErr error
	addModPolicyErr error
	delSteeringErr  error
	delPolicyErr    error

	// unreachableSids drives RouteLookup: SIDs listed here resolve to a
	// drop-only route (unreachable); everything else resolves normally.
	unreachableSids map[string]bool
	routeLookupErr  error
}

func (f *fakeSRv6VPP) ListSRv6Localsid() ([]*types.SrLocalsid, error) { return nil, nil }
func (f *fakeSRv6VPP) AddSRv6Localsid(*types.SrLocalsid) error        { return nil }
func (f *fakeSRv6VPP) DelSRv6Localsid(*types.SrLocalsid) error        { return nil }
func (f *fakeSRv6VPP) ListSRv6Policies() ([]*types.SrPolicy, error)   { return f.policies, nil }
func (f *fakeSRv6VPP) SetEncapSource(net.IP) error                    { return nil }
func (f *fakeSRv6VPP) RouteAdd(r *types.Route) error                  { f.routeAdd = append(f.routeAdd, r); return nil }
func (f *fakeSRv6VPP) RouteDel(r *types.Route) error                  { f.routeDel = append(f.routeDel, r); return nil }

func (f *fakeSRv6VPP) AddModSRv6Policy(p *types.SrPolicy) error {
	f.addModPolicy = append(f.addModPolicy, p)
	f.callLog = append(f.callLog, "AddModSRv6Policy:"+p.Bsid.String())
	if f.addModPolicyErr != nil {
		return f.addModPolicyErr
	}
	for i := range f.policies {
		if f.policies[i].Bsid == p.Bsid {
			f.policies[i] = cloneSRPolicy(p)
			return nil
		}
	}
	f.policies = append(f.policies, cloneSRPolicy(p))
	return nil
}
func (f *fakeSRv6VPP) DelSRv6Policy(p *types.SrPolicy) error {
	f.delPolicy = append(f.delPolicy, p)
	f.callLog = append(f.callLog, "DelSRv6Policy:"+p.Bsid.String())
	if f.delPolicyErr != nil {
		return f.delPolicyErr
	}
	remaining := f.policies[:0]
	for _, policy := range f.policies {
		if policy.Bsid != p.Bsid {
			remaining = append(remaining, policy)
		}
	}
	f.policies = remaining
	return nil
}
func (f *fakeSRv6VPP) AddSRv6Steering(s *types.SrSteer) error {
	f.addSteering = append(f.addSteering, s)
	f.callLog = append(f.callLog, "AddSRv6Steering:"+s.Bsid.String())
	for i := range f.steering {
		if sameSteeringKey(f.steering[i], s) {
			f.steering[i] = s
			return nil
		}
	}
	f.steering = append(f.steering, s)
	return nil
}
func (f *fakeSRv6VPP) DelSRv6Steering(s *types.SrSteer) error {
	f.delSteering = append(f.delSteering, s)
	f.callLog = append(f.callLog, "DelSRv6Steering:"+s.Bsid.String())
	if f.delSteeringErr != nil {
		return f.delSteeringErr
	}
	remaining := f.steering[:0]
	for _, steering := range f.steering {
		if !sameSteeringKey(steering, s) {
			remaining = append(remaining, steering)
		}
	}
	f.steering = remaining
	return nil
}
func (f *fakeSRv6VPP) ListSRv6Steering() ([]*types.SrSteer, error) {
	return append([]*types.SrSteer(nil), f.steering...), f.listSteeringErr
}

func sameSteeringKey(a, b *types.SrSteer) bool {
	return a.TrafficType == b.TrafficType && a.FibTable == b.FibTable && a.SwIfIndex == b.SwIfIndex && a.Prefix == b.Prefix
}

func (f *fakeSRv6VPP) RouteLookup(dst *net.IPNet, tableID uint32) (*types.Route, error) {
	if f.routeLookupErr != nil {
		return nil, f.routeLookupErr
	}
	if f.unreachableSids[dst.IP.String()] {
		return &types.Route{Dst: dst, Paths: []types.RoutePath{{IsDrop: true}}}, nil
	}
	return &types.Route{Dst: dst, Paths: []types.RoutePath{{Gw: net.ParseIP("fd00::1")}}}, nil
}

func newTestProvider(fake *fakeSRv6VPP) *SRv6Provider {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	p := &SRv6Provider{
		ConnectivityProviderData: &ConnectivityProviderData{log: logrus.NewEntry(logger)},
		vpp:                      fake,
		nodePrefixes:             make(map[string]*NodeToPrefixes),
		nodePolices:              make(map[string]*NodeToPolicies),
		installedPolicies:        make(map[string]installedSRPolicy),
		dynBsids:                 make(map[string]ip_types.IP6Address),
		droppedPrefixes:          make(map[string]dropState),
		policyEvent:              func(common.CalicoVppEvent) {},
	}
	// Deterministic fake BSID allocator; tests asserting IPAM interplay override.
	next := 0
	p.allocBsid = func(handle string) (net.IP, error) {
		next++
		return net.ParseIP(fmt.Sprintf("fd00:b51d::%x", next)), nil
	}
	p.releaseBsid = func(handle string) error { return nil }
	return p
}

func mustBsid(t *testing.T, s string) ip_types.IP6Address {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil || ip.To16() == nil {
		t.Fatalf("invalid ipv6 %q", s)
	}
	return types.ToVppIP6Address(ip)
}

func mustPrefix(t *testing.T, s string) ip_types.Prefix {
	t.Helper()
	pr, err := ip_types.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return pr
}

// ---------- tunnelBsid ----------

func TestTunnelBsid(t *testing.T) {
	policyBsid := mustBsid(t, "cafe::1")
	netBsid := net.ParseIP("cafe::2")

	cases := []struct {
		name    string
		tun     common.SRv6Tunnel
		wantOK  bool
		wantStr string
	}{
		{"policy wins", common.SRv6Tunnel{Policy: &types.SrPolicy{Bsid: policyBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}, Bsid: netBsid}, true, policyBsid.String()},
		{"net.IP fallback", common.SRv6Tunnel{Bsid: netBsid}, true, types.ToVppIP6Address(netBsid).String()},
		{"policy with zero bsid falls back to net.IP", common.SRv6Tunnel{Policy: &types.SrPolicy{}, Bsid: netBsid}, true, types.ToVppIP6Address(netBsid).String()},
		{"neither set", common.SRv6Tunnel{}, false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tunnelBsid(&tc.tun)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got.String() != tc.wantStr {
				t.Fatalf("bsid = %s, want %s", got.String(), tc.wantStr)
			}
		})
	}
}

// ---------- delSRPolicy ----------

func TestDelSRPolicy_TypeAssertError(t *testing.T) {
	p := newTestProvider(&fakeSRv6VPP{})
	cn := &common.NodeConnectivity{Custom: "not a tunnel"}
	if err := p.delSRPolicy(cn); err == nil {
		t.Fatal("expected error for non-SRv6Tunnel Custom")
	}
}

func TestDelSRPolicy_NoCache(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	dst := net.ParseIP("fd00:1::11")
	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 4}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(fake.delPolicy)+len(fake.delSteering) > 0 {
		t.Fatalf("expected no VPP calls; got delPolicy=%d delSteering=%d", len(fake.delPolicy), len(fake.delSteering))
	}
}

func TestDelSRPolicy_NLRIKeyMismatchLeavesSiblingsAlone(t *testing.T) {
	// Two cached tunnels for the same endpoint, different NLRI keys. Withdrawing
	// one (color=4) must not touch the other (color=6).
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	dst := net.ParseIP("fd00:1::11")
	dt4Bsid := mustBsid(t, "cafe::4")
	dt6Bsid := mustBsid(t, "cafe::6")
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 4, Policy: &types.SrPolicy{Bsid: dt4Bsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}, Priority: 100},
			{Dst: dst, Color: 6, Policy: &types.SrPolicy{Bsid: dt6Bsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}, Priority: 100},
		},
	}
	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 4}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(fake.delPolicy) != 1 || fake.delPolicy[0].Bsid != dt4Bsid {
		t.Fatalf("expected exactly DelSRv6Policy(dt4); got %+v", fake.delPolicy)
	}
	remaining := p.nodePolices[dst.String()].SRv6Tunnel
	if len(remaining) != 1 || remaining[0].Color != 6 {
		t.Fatalf("expected dt6 sibling to survive; got %+v", remaining)
	}
}

func TestDelSRPolicy_NoMatch(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	dst := net.ParseIP("fd00:1::11")
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 4, Policy: &types.SrPolicy{Bsid: mustBsid(t, "cafe::4")}},
		},
	}
	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 99}} // unknown color
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(fake.delPolicy)+len(fake.delSteering) > 0 {
		t.Fatalf("expected no VPP calls; got delPolicy=%d delSteering=%d", len(fake.delPolicy), len(fake.delSteering))
	}
}

func TestDelSRPolicy_DeletesPolicyAndAssociatedSteering(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	bsid := mustBsid(t, "cafe::4")
	otherBsid := mustBsid(t, "cafe::dead") // unrelated steering, must survive
	prefixA := mustPrefix(t, "fd20::aaaa/128")
	prefixB := mustPrefix(t, "fd20::bbbb/128")
	prefixC := mustPrefix(t, "fd20::cccc/128")

	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{
			{Bsid: bsid, Prefix: prefixA, TrafficType: types.SrSteerIPv6},
			{Bsid: bsid, Prefix: prefixB, TrafficType: types.SrSteerIPv6},
			{Bsid: otherBsid, Prefix: prefixC, TrafficType: types.SrSteerIPv6},
		},
	}
	p := newTestProvider(fake)
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node:       dst,
		SRv6Tunnel: []common.SRv6Tunnel{{Dst: dst, Color: 6, Policy: &types.SrPolicy{Bsid: bsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}}},
	}

	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}

	if len(fake.delSteering) != 2 {
		t.Fatalf("expected 2 steering deletions; got %d", len(fake.delSteering))
	}
	for _, st := range fake.delSteering {
		if st.Bsid != bsid {
			t.Fatalf("DelSRv6Steering targeted wrong BSID %s, want %s", st.Bsid.String(), bsid.String())
		}
	}
	if len(fake.delPolicy) != 1 || fake.delPolicy[0].Bsid != bsid {
		t.Fatalf("DelSRv6Policy wrong: %+v", fake.delPolicy)
	}
	if _, ok := p.nodePolices[dst.String()]; ok {
		t.Fatalf("expected nodePolices entry to be removed")
	}
}

// Codex round #2 + #3 regression: withdrawing the top-priority candidate must
// (a) re-steer orphaned prefixes onto the surviving lower-priority candidate
// and (b) install that candidate in VPP on demand, since AddConnectivity never
// pushed it during normal operation.
func TestDelSRPolicy_FailoverOntoSurvivingCandidate(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	winnerBsid := mustBsid(t, "cafe::aa")
	loserBsid := mustBsid(t, "cafe::bb")
	prefixA := mustPrefix(t, "fd20::aaaa/128")
	prefixB := mustPrefix(t, "fd20::bbbb/128")

	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{
			{Bsid: winnerBsid, Prefix: prefixA, TrafficType: types.SrSteerIPv6},
			{Bsid: winnerBsid, Prefix: prefixB, TrafficType: types.SrSteerIPv6},
		},
	}
	p := newTestProvider(fake)
	// Both candidates DT6 (uint8(SRv6Behavior_END_DT6) == 18 in gobgp). Use the
	// raw uint that types.FromGoBGPSrBehavior maps to types.SrBehaviorDT6.
	dt6Behavior := uint8(18) // bgpapi.SRv6Behavior_END_DT6
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: dt6Behavior, Priority: 100, Policy: &types.SrPolicy{Bsid: winnerBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
			{Dst: dst, Color: 6, Distinguisher: 1, Behavior: dt6Behavior, Priority: 50, Policy: &types.SrPolicy{Bsid: loserBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
		},
	}

	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6, Distinguisher: 0}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}

	// Top candidate teardown
	if len(fake.delPolicy) != 1 || fake.delPolicy[0].Bsid != winnerBsid {
		t.Fatalf("DelSRv6Policy: got %+v", fake.delPolicy)
	}
	if len(fake.delSteering) != 2 {
		t.Fatalf("expected 2 steering deletes; got %d", len(fake.delSteering))
	}
	// On-demand install of the surviver, once even for multiple orphaned prefixes
	if len(fake.addModPolicy) != 1 || fake.addModPolicy[0].Bsid != loserBsid {
		t.Fatalf("expected one AddModSRv6Policy(loser); got %+v", fake.addModPolicy)
	}
	// Re-steering for each orphaned prefix
	if len(fake.addSteering) != 2 {
		t.Fatalf("expected 2 AddSRv6Steering calls; got %d", len(fake.addSteering))
	}
	for _, st := range fake.addSteering {
		if st.Bsid != loserBsid {
			t.Fatalf("AddSRv6Steering retargeted wrong BSID %s, want %s", st.Bsid.String(), loserBsid.String())
		}
	}
	// Surviver remains in cache
	rem := p.nodePolices[dst.String()].SRv6Tunnel
	if len(rem) != 1 || rem[0].Distinguisher != 1 {
		t.Fatalf("expected loser to survive in cache; got %+v", rem)
	}
}

// The node-IP /128 steering installed by steerNodeIPViaSID (host-network-backed
// ClusterIPs, #1028) lives in PodVRFIndex, not the main table. When its DT6
// policy is withdrawn, the failover must re-steer it into the SAME table —
// otherwise the host plane silently breaks after a candidate-path switch.
func TestDelSRPolicy_FailoverPreservesNodeIPSteeringFibTable(t *testing.T) {
	dst := net.ParseIP("fd00:1::14")
	winnerBsid := mustBsid(t, "cafe::aa")
	loserBsid := mustBsid(t, "cafe::bb")
	nodeIP := mustPrefix(t, "fd00:1::14/128")

	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{
			// node-IP /128 steered in PodVRFIndex onto the DT6 winner.
			{Bsid: winnerBsid, Prefix: nodeIP, TrafficType: types.SrSteerIPv6, FibTable: common.PodVRFIndex},
		},
	}
	p := newTestProvider(fake)
	dt6Behavior := uint8(18) // bgpapi.SRv6Behavior_END_DT6
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: dt6Behavior, Priority: 100, Policy: &types.SrPolicy{Bsid: winnerBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
			{Dst: dst, Color: 6, Distinguisher: 1, Behavior: dt6Behavior, Priority: 50, Policy: &types.SrPolicy{Bsid: loserBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
		},
	}

	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6, Distinguisher: 0}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}

	if len(fake.addSteering) != 1 {
		t.Fatalf("expected 1 re-steer; got %d", len(fake.addSteering))
	}
	re := fake.addSteering[0]
	if re.Bsid != loserBsid {
		t.Fatalf("re-steer BSID = %s, want surviving %s", re.Bsid.String(), loserBsid.String())
	}
	if re.FibTable != common.PodVRFIndex {
		t.Fatalf("re-steer FibTable = %d, want PodVRFIndex (%d): the node-IP steering must stay in the pod VRF after failover",
			re.FibTable, common.PodVRFIndex)
	}
}

// When the node's last DT6 candidate is withdrawn, the node-IP /128 steering
// (steerNodeIPViaSID, #1028) must be torn down on the same teardown path and
// NOT re-steered — leaving the host plane to fall back to native routing. This
// is the teardown half the #1028 note deferred to #1025.
func TestDelSRPolicy_TearsDownNodeIPSteeringWhenNoSurvivor(t *testing.T) {
	dst := net.ParseIP("fd00:1::14")
	bsid := mustBsid(t, "cafe::aa")
	podPrefix := mustPrefix(t, "fd20::aaaa/128")
	nodeIP := mustPrefix(t, "fd00:1::14/128")

	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{
			{Bsid: bsid, Prefix: podPrefix, TrafficType: types.SrSteerIPv6},                            // pod prefix in main table
			{Bsid: bsid, Prefix: nodeIP, TrafficType: types.SrSteerIPv6, FibTable: common.PodVRFIndex}, // node-IP /128 in PodVRFIndex
		},
	}
	p := newTestProvider(fake)
	dt6Behavior := uint8(18) // bgpapi.SRv6Behavior_END_DT6
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: dt6Behavior, Priority: 100, Policy: &types.SrPolicy{Bsid: bsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
		},
	}

	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6, Distinguisher: 0}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}

	// No surviving candidate → nothing re-steered (no leak into any table).
	if len(fake.addSteering) != 0 {
		t.Fatalf("expected no re-steer when no survivor; got %d", len(fake.addSteering))
	}
	// The node-IP /128 steering must have been torn down, in PodVRFIndex.
	foundNodeIP := false
	for _, st := range fake.delSteering {
		if st.Prefix.String() == nodeIP.String() && st.FibTable == common.PodVRFIndex {
			foundNodeIP = true
		}
	}
	if !foundNodeIP {
		t.Fatalf("node-IP /128 steering in PodVRFIndex was not torn down; deletions=%+v", fake.delSteering)
	}
}

func TestDelSRPolicy_NoSurvivingCandidateLeavesPrefixUnsteered(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	bsid := mustBsid(t, "cafe::4")
	prefix := mustPrefix(t, "fd20::1/128")
	fake := &fakeSRv6VPP{steering: []*types.SrSteer{{Bsid: bsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}}}
	p := newTestProvider(fake)
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node:       dst,
		SRv6Tunnel: []common.SRv6Tunnel{{Dst: dst, Color: 6, Policy: &types.SrPolicy{Bsid: bsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}}},
	}

	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(fake.addSteering) != 0 || len(fake.addModPolicy) != 0 {
		t.Fatalf("expected no re-steer / install when no surviving candidate; got addSteering=%d addModPolicy=%d", len(fake.addSteering), len(fake.addModPolicy))
	}
}

// ---------- delPrefixSteering ----------

func TestDelPrefixSteering_SkipsPolicyIPPool(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	_, ipNet, _ := net.ParseCIDR("cafe::/64")
	p.policyIPPool = *ipNet
	cn := &common.NodeConnectivity{
		Dst:     net.IPNet{IP: net.ParseIP("cafe::1"), Mask: net.CIDRMask(128, 128)},
		NextHop: net.ParseIP("fd00:1::11"),
	}
	if err := p.delPrefixSteering(cn); err != nil {
		t.Fatalf("delPrefixSteering: %v", err)
	}
	if len(fake.delSteering)+len(fake.routeDel) > 0 {
		t.Fatal("expected no VPP calls for policy-pool address")
	}
}

func TestDelPrefixSteering_NormalPrefixDeletesSteeringAndPrunesCache(t *testing.T) {
	prefix := mustPrefix(t, "fd20::aaaa/128")
	other := mustPrefix(t, "fd20::bbbb/128")
	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{
			{Bsid: mustBsid(t, "cafe::4"), Prefix: prefix, TrafficType: types.SrSteerIPv6},
			{Bsid: mustBsid(t, "cafe::4"), Prefix: other, TrafficType: types.SrSteerIPv6},
		},
	}
	p := newTestProvider(fake)
	node := net.ParseIP("fd00:1::11")
	p.nodePrefixes[node.String()] = &NodeToPrefixes{Node: node, Prefixes: []ip_types.Prefix{prefix, other}}
	cn := &common.NodeConnectivity{
		Dst:     net.IPNet{IP: net.ParseIP("fd20::aaaa"), Mask: net.CIDRMask(128, 128)},
		NextHop: node,
	}
	if err := p.delPrefixSteering(cn); err != nil {
		t.Fatalf("delPrefixSteering: %v", err)
	}
	if len(fake.delSteering) != 1 {
		t.Fatalf("expected exactly one DelSRv6Steering; got %d", len(fake.delSteering))
	}
	if fake.delSteering[0].Prefix.String() != prefix.String() {
		t.Fatalf("DelSRv6Steering targeted wrong prefix %s, want %s", fake.delSteering[0].Prefix.String(), prefix.String())
	}
	remaining := p.nodePrefixes[node.String()].Prefixes
	if len(remaining) != 1 || remaining[0].String() != other.String() {
		t.Fatalf("expected sibling prefix to survive cache prune; got %+v", remaining)
	}
}

// SR Policy SAFI advertisements are useful beyond ordinary inter-node
// connectivity.  srv6egress has no node prefix for the policy endpoint; it
// installs per-pod-VRF steering separately.  The provider must therefore put
// every <endpoint,color> policy in VPP without waiting for nodePrefixes.
func TestAddConnectivity_StandalonePoliciesInstalledPerColor(t *testing.T) {
	dst := net.ParseIP("fd00:1::10")
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	var events []common.CalicoVppEvent
	p.policyEvent = func(event common.CalicoVppEvent) { events = append(events, event) }

	for _, tc := range []struct {
		color uint32
		bsid  string
		sid   string
	}{
		{color: 100, bsid: "cafe::64", sid: "fcbb:bbbb:4:a1::"},
		{color: 200, bsid: "cafe::c8", sid: "fcbb:bbbb:4:b1::"},
	} {
		sids := [16]ip_types.IP6Address{}
		sids[0] = mustBsid(t, tc.sid)
		tunnel := &common.SRv6Tunnel{
			Dst: dst, Color: tc.color, Distinguisher: 1, Behavior: testDT6Behavior, Preference: 200,
			Policy: &types.SrPolicy{
				Bsid:     mustBsid(t, tc.bsid),
				IsEncap:  true,
				SidLists: []types.Srv6SidList{{NumSids: 1, Weight: 1, Sids: sids}},
			},
		}
		if err := p.AddConnectivity(&common.NodeConnectivity{NextHop: dst, Custom: tunnel}); err != nil {
			t.Fatalf("AddConnectivity color=%d: %v", tc.color, err)
		}
	}

	if len(p.nodePrefixes) != 0 {
		t.Fatalf("test unexpectedly created node prefixes: %+v", p.nodePrefixes)
	}
	if len(fake.policies) != 2 {
		t.Fatalf("VPP policies=%d, want both colors installed: %+v", len(fake.policies), fake.policies)
	}
	gotBSIDs := map[string]bool{}
	for _, policy := range fake.policies {
		gotBSIDs[policy.Bsid.String()] = true
	}
	for _, want := range []string{"cafe::64", "cafe::c8"} {
		if !gotBSIDs[want] {
			t.Fatalf("VPP policy %s missing; got %v", want, gotBSIDs)
		}
	}
	if len(events) != 2 {
		t.Fatalf("dataplane events=%d, want one successful install per color: %+v", len(events), events)
	}
	for _, event := range events {
		if event.Type != common.SRv6PolicyInstalled {
			t.Fatalf("event type=%s, want %s", event.Type, common.SRv6PolicyInstalled)
		}
	}
}

func TestAddConnectivity_PolicyLivenessOnlyAfterSuccessfulVPPInstall(t *testing.T) {
	dst := net.ParseIP("fd00:1::10")
	fake := &fakeSRv6VPP{addModPolicyErr: fmt.Errorf("injected VPP failure")}
	p := newTestProvider(fake)
	var events []common.CalicoVppEvent
	p.policyEvent = func(event common.CalicoVppEvent) { events = append(events, event) }
	tunnel := &common.SRv6Tunnel{
		Dst: dst, Color: 100, Distinguisher: 1, Preference: 200,
		Policy: &types.SrPolicy{Bsid: mustBsid(t, "cafe::64"), SidLists: []types.Srv6SidList{{NumSids: 1}}},
	}
	if err := p.AddConnectivity(&common.NodeConnectivity{NextHop: dst, Custom: tunnel}); err == nil {
		t.Fatal("expected VPP install failure")
	}
	if len(events) != 0 {
		t.Fatalf("failed install must not publish liveness, got %+v", events)
	}
	if len(p.installedPolicies) != 0 {
		t.Fatalf("failed install recorded as live: %+v", p.installedPolicies)
	}
}

func TestAddConnectivity_UnchangedReassertEmitsHeartbeatWithoutPolicyChurn(t *testing.T) {
	dst := net.ParseIP("fd00:1::10")
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	var events []common.CalicoVppEvent
	p.policyEvent = func(event common.CalicoVppEvent) { events = append(events, event) }
	tunnel := &common.SRv6Tunnel{
		Dst: dst, Color: 100, Distinguisher: 1, Preference: 200,
		Policy: &types.SrPolicy{Bsid: mustBsid(t, "cafe::64"), SidLists: []types.Srv6SidList{{NumSids: 1}}},
	}
	for i := 0; i < 2; i++ {
		if err := p.AddConnectivity(&common.NodeConnectivity{NextHop: dst, Custom: tunnel}); err != nil {
			t.Fatalf("AddConnectivity pass %d: %v", i+1, err)
		}
	}
	if len(fake.addModPolicy) != 1 {
		t.Fatalf("unchanged reassert rebuilt VPP policy %d times, want 1", len(fake.addModPolicy))
	}
	if len(events) != 2 || events[0].Type != common.SRv6PolicyInstalled || events[1].Type != common.SRv6PolicyInstalled {
		t.Fatalf("expected two successful install heartbeats, got %+v", events)
	}
}

func TestDelSRPolicy_StandaloneCandidateFailoverPublishesDataplaneTransition(t *testing.T) {
	dst := net.ParseIP("fd00:1::10")
	bsid := mustBsid(t, "cafe::64")
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	var events []common.CalicoVppEvent
	p.policyEvent = func(event common.CalicoVppEvent) { events = append(events, event) }

	makeTunnel := func(distinguisher, preference uint32, sid string) *common.SRv6Tunnel {
		sids := [16]ip_types.IP6Address{}
		sids[0] = mustBsid(t, sid)
		return &common.SRv6Tunnel{
			Dst: dst, Color: 100, Distinguisher: distinguisher, Preference: preference,
			Policy: &types.SrPolicy{Bsid: bsid, IsEncap: true, SidLists: []types.Srv6SidList{{NumSids: 1, Weight: 1, Sids: sids}}},
		}
	}
	high := makeTunnel(1, 200, "fcbb:bbbb:4:a1::")
	low := makeTunnel(2, 100, "fcbb:bbbb:4:a2::")
	for _, tunnel := range []*common.SRv6Tunnel{high, low} {
		if err := p.AddConnectivity(&common.NodeConnectivity{NextHop: dst, Custom: tunnel}); err != nil {
			t.Fatalf("AddConnectivity: %v", err)
		}
	}

	if err := p.delSRPolicy(&common.NodeConnectivity{Custom: &common.SRv6Tunnel{
		Dst: dst, Color: 100, Distinguisher: 1,
	}}); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(events) != 4 {
		t.Fatalf("events=%d, want install, heartbeat, uninstall, install: %+v", len(events), events)
	}
	wantTypes := []common.CalicoVppEventType{
		common.SRv6PolicyInstalled,
		common.SRv6PolicyInstalled,
		common.SRv6PolicyUninstalled,
		common.SRv6PolicyInstalled,
	}
	for i := range wantTypes {
		if events[i].Type != wantTypes[i] {
			t.Fatalf("event[%d]=%s, want %s (all=%+v)", i, events[i].Type, wantTypes[i], events)
		}
	}
	if len(fake.policies) != 1 || fake.policies[0].SidLists[0].Sids[0] != mustBsid(t, "fcbb:bbbb:4:a2::") {
		t.Fatalf("surviving candidate not installed: %+v", fake.policies)
	}
}

// ---------- DelConnectivity dispatcher ----------

// Re-advertising an SR Policy with the SAME NLRI key (Color, Distinguisher,
// Endpoint) must REPLACE the cached candidate in-place, not append a duplicate.
// Without this, BGP path refresh would silently grow the cache and delSRPolicy
// would iterate the same BSID multiple times — the second pass hits VPP with
// an already-gone steering / policy and used to warn with NO_SUCH_INNER_FIB
// and UNSPECIFIED.
func TestAddConnectivity_ReAdvertiseSameNLRIKeyReplacesInPlace(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	bsidA := mustBsid(t, "cafe::aaa")
	bsidB := mustBsid(t, "cafe::bbb")

	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)

	// First advertisement.
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst:           dst,
			Color:         6,
			Distinguisher: 1,
			Priority:      100,
			Policy:        &types.SrPolicy{Bsid: bsidA},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (first): %v", err)
	}

	// Re-advertisement with same NLRI key but different attrs (e.g. new BSID
	// after a path refresh). RFC 9252 says this must REPLACE the prior entry.
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst:           dst,
			Color:         6,
			Distinguisher: 1,
			Priority:      150,
			Policy:        &types.SrPolicy{Bsid: bsidB},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (second): %v", err)
	}

	cache := p.nodePolices[dst.String()].SRv6Tunnel
	if len(cache) != 1 {
		t.Fatalf("expected cache to dedup to 1 entry; got %d (%+v)", len(cache), cache)
	}
	if cache[0].Priority != 150 || cache[0].Policy.Bsid != bsidB {
		t.Fatalf("expected re-advertisement to replace in place (prio=150, bsid=%s); got prio=%d bsid=%s",
			bsidB.String(), cache[0].Priority, cache[0].Policy.Bsid.String())
	}
}

// Re-advertising with the SAME NLRI key but a DIFFERENT BSID (BGP path
// refresh updates path attributes including the BSID TLV) must tear down the
// prior BSID in VPP. Otherwise the old SR Policy stays installed with no cache
// reference, and a later withdraw — matched against only the new BSID — leaks
// it permanently.
func TestAddConnectivity_BsidChangeOnUpsertCleansUpOldBsid(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	oldBsid := mustBsid(t, "cafe::aaa1")
	newBsid := mustBsid(t, "cafe::aaa2")

	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)

	// The deliberately incomplete candidates have no SID lists, so they remain
	// cached but are not installable.  This test isolates the BSID replacement
	// and deferred cleanup path.
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst:           dst,
			Color:         6,
			Distinguisher: 1,
			Priority:      100,
			Policy:        &types.SrPolicy{Bsid: oldBsid},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (first): %v", err)
	}
	if len(fake.delPolicy) != 0 {
		t.Fatalf("expected no DelSRv6Policy on first advertisement; got %+v", fake.delPolicy)
	}

	// Re-advertisement with same NLRI key but new BSID.
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst:           dst,
			Color:         6,
			Distinguisher: 1,
			Priority:      100,
			Policy:        &types.SrPolicy{Bsid: newBsid},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (second): %v", err)
	}

	// Old BSID must be torn down so it doesn't leak.
	if len(fake.delPolicy) != 1 || fake.delPolicy[0].Bsid != oldBsid {
		t.Fatalf("expected exactly one DelSRv6Policy(oldBsid=%s) on BSID change; got %+v",
			oldBsid.String(), fake.delPolicy)
	}

	// Cache holds only the new candidate.
	cache := p.nodePolices[dst.String()].SRv6Tunnel
	if len(cache) != 1 || cache[0].Policy.Bsid != newBsid {
		t.Fatalf("expected cache to hold only new BSID %s; got %+v", newBsid.String(), cache)
	}
}

// When the upsert changes the BSID AND prefixes are wired up for the endpoint,
// the steering MUST be re-pointed at the new BSID BEFORE the old SR Policy is
// deleted. Otherwise VPP's steering hash holds steer_pl->sr_policy = freed
// pool index for the duration of the gap and packets transiting the steering
// land on undefined state. Verified by asserting the call sequence.
func TestAddConnectivity_BsidChangeCleansUpAfterRePoint(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	oldBsid := mustBsid(t, "cafe::aaa1")
	newBsid := mustBsid(t, "cafe::aaa2")
	prefix := mustPrefix(t, "fd20::5506:688f:1e5:6f80/122")

	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	// Pre-populate nodePrefixes so CreateSRv6Tunnel runs on each AddConnectivity.
	p.nodePrefixes[dst.String()] = &NodeToPrefixes{Node: dst, Prefixes: []ip_types.Prefix{prefix}}

	dt6Behavior := uint8(18) // bgpapi.SRv6Behavior_END_DT6
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Behavior: dt6Behavior, Priority: 100,
			Policy: &types.SrPolicy{Bsid: oldBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (old): %v", err)
	}

	// Reset call log so we observe only the upsert's calls.
	fake.callLog = nil

	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Behavior: dt6Behavior, Priority: 100,
			Policy: &types.SrPolicy{Bsid: newBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (new): %v", err)
	}

	addNewSteer := -1
	delOld := -1
	for i, op := range fake.callLog {
		if op == "AddSRv6Steering:"+newBsid.String() && addNewSteer == -1 {
			addNewSteer = i
		}
		if op == "DelSRv6Policy:"+oldBsid.String() && delOld == -1 {
			delOld = i
		}
	}
	if addNewSteer == -1 {
		t.Fatalf("expected AddSRv6Steering(newBsid=%s) in call log; got %v", newBsid.String(), fake.callLog)
	}
	if delOld == -1 {
		t.Fatalf("expected DelSRv6Policy(oldBsid=%s) in call log; got %v", oldBsid.String(), fake.callLog)
	}
	if !(addNewSteer < delOld) {
		t.Fatalf("AddSRv6Steering(new) must precede DelSRv6Policy(old); got log %v (newSteer@%d, delOld@%d)",
			fake.callLog, addNewSteer, delOld)
	}
}

// Failure mode: CreateSRv6Tunnel below the upsert can fail (getPolicyNode
// returned nil, AddModSRv6Policy errored, AddSRv6Steering errored), leaving
// the steering still resolving through the prior BSID. The deferred cleanup
// MUST NOT delete that BSID — VPP's sr_policy entry is still in use by a live
// steering. Simulated here by seeding ListSRv6Steering with an entry that
// continues to point at the old BSID after the upsert.
func TestAddConnectivity_BsidChangeSkipsCleanupWhenStillReferenced(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	oldBsid := mustBsid(t, "cafe::aaa1")
	newBsid := mustBsid(t, "cafe::aaa2")
	prefix := mustPrefix(t, "fd20::5506:688f:1e5:6f80/122")

	// fake.steering reports what ListSRv6Steering returns. By leaving the
	// pre-existing entry pointing at oldBsid we simulate VPP's view after a
	// failed AddSRv6Steering — steer_pl->sr_policy never got re-pointed.
	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{{Bsid: oldBsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}},
	}
	p := newTestProvider(fake)

	// Make CreateSRv6Tunnel a no-op for this test by not wiring nodePrefixes;
	// the defer should still consult ListSRv6Steering before deleting.
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Priority: 100,
			Policy: &types.SrPolicy{Bsid: oldBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (old): %v", err)
	}
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Priority: 100,
			Policy: &types.SrPolicy{Bsid: newBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (new): %v", err)
	}

	for _, p := range fake.delPolicy {
		if p.Bsid == oldBsid {
			t.Fatalf("DelSRv6Policy(oldBsid=%s) must NOT fire while steering still resolves through it; got call log %v",
				oldBsid.String(), fake.callLog)
		}
	}
}

// Eventual consistency: when the prior BSID couldn't be released on the
// first upsert (steering still referenced it), it must NOT be silently
// dropped from the cache. The next SR-policy event must re-attempt the
// cleanup; once VPP reports the BSID is no longer steered, the deferred
// DelSRv6Policy fires. Without the pendingBsidCleanup queue, the upsert
// would replace the cache entry, lose the prior BSID reference, and leak
// the SR Policy in VPP forever.
func TestAddConnectivity_BsidChangePendingRetryOnNextEvent(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	oldBsid := mustBsid(t, "cafe::aaa1")
	newBsid := mustBsid(t, "cafe::aaa2")
	otherBsid := mustBsid(t, "cafe::bbb")
	prefix := mustPrefix(t, "fd20::5506:688f:1e5:6f80/122")

	// First upsert leaves OLD still referenced (re-point "failed").
	fake := &fakeSRv6VPP{
		steering: []*types.SrSteer{{Bsid: oldBsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}},
	}
	p := newTestProvider(fake)

	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Priority: 100,
			Policy: &types.SrPolicy{Bsid: oldBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (old): %v", err)
	}
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 1, Priority: 100,
			Policy: &types.SrPolicy{Bsid: newBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (new): %v", err)
	}

	// After the first upsert, OLD should be queued — VPP still steers it.
	if len(p.pendingBsidCleanup) != 1 || p.pendingBsidCleanup[0] != oldBsid {
		t.Fatalf("expected pendingBsidCleanup=[%s] after first upsert; got %v",
			oldBsid.String(), p.pendingBsidCleanup)
	}
	for _, pol := range fake.delPolicy {
		if pol.Bsid == oldBsid {
			t.Fatalf("DelSRv6Policy(oldBsid) must not fire while steering still resolves through it; call log %v", fake.callLog)
		}
	}

	// Simulate VPP catching up: the steering is now repointed at otherBsid,
	// freeing OLD for cleanup.
	fake.steering = []*types.SrSteer{{Bsid: otherBsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}}

	// A subsequent SR-policy event (different NLRI key, not related to OLD)
	// must drain the pending queue and finally release OLD in VPP.
	if err := p.AddConnectivity(&common.NodeConnectivity{
		NextHop: dst,
		Custom: &common.SRv6Tunnel{
			Dst: dst, Color: 6, Distinguisher: 99, Priority: 50,
			Policy: &types.SrPolicy{Bsid: otherBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}},
		},
	}); err != nil {
		t.Fatalf("AddConnectivity (third event): %v", err)
	}

	if len(p.pendingBsidCleanup) != 0 {
		t.Fatalf("expected pendingBsidCleanup to drain to empty; got %v", p.pendingBsidCleanup)
	}
	sawOldCleanup := false
	for _, pol := range fake.delPolicy {
		if pol.Bsid == oldBsid {
			sawOldCleanup = true
			break
		}
	}
	if !sawOldCleanup {
		t.Fatalf("expected DelSRv6Policy(oldBsid=%s) on retry; got call log %v", oldBsid.String(), fake.callLog)
	}
}

// Re-advertising the SAME NLRI key with the SAME BSID (only priority or SID
// list changed) must NOT trigger cleanup — there is nothing to clean up.
// Guards against the BSID-change cleanup over-firing.
func TestAddConnectivity_SameBsidOnUpsertSkipsCleanup(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	bsid := mustBsid(t, "cafe::aaa")

	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)

	for _, prio := range []uint32{100, 150} {
		if err := p.AddConnectivity(&common.NodeConnectivity{
			NextHop: dst,
			Custom: &common.SRv6Tunnel{
				Dst:           dst,
				Color:         6,
				Distinguisher: 1,
				Priority:      prio,
				Policy:        &types.SrPolicy{Bsid: bsid},
			},
		}); err != nil {
			t.Fatalf("AddConnectivity prio=%d: %v", prio, err)
		}
	}

	if len(fake.delPolicy) != 0 {
		t.Fatalf("expected no DelSRv6Policy when BSID unchanged; got %+v", fake.delPolicy)
	}
}

// A second advertisement with a DIFFERENT NLRI key on the same endpoint must
// coexist as a candidate path — RFC 9256 candidate-path failover relies on
// this. This guards against the dedup logic over-applying.
func TestAddConnectivity_DifferentNLRIKeysCoexist(t *testing.T) {
	dst := net.ParseIP("fd00:1::12")
	bsidA := mustBsid(t, "cafe::aaa")
	bsidB := mustBsid(t, "cafe::bbb")

	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)

	for _, tun := range []common.SRv6Tunnel{
		{Dst: dst, Color: 6, Distinguisher: 1, Priority: 100, Policy: &types.SrPolicy{Bsid: bsidA, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
		{Dst: dst, Color: 6, Distinguisher: 2, Priority: 50, Policy: &types.SrPolicy{Bsid: bsidB, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
	} {
		tun := tun
		if err := p.AddConnectivity(&common.NodeConnectivity{NextHop: dst, Custom: &tun}); err != nil {
			t.Fatalf("AddConnectivity: %v (tun=%+v)", err, tun)
		}
	}

	cache := p.nodePolices[dst.String()].SRv6Tunnel
	if len(cache) != 2 {
		t.Fatalf("expected 2 candidate paths to coexist; got %d (%+v)", len(cache), cache)
	}
}

// Idempotent delete: when DelSRv6Steering reports NO_SUCH_INNER_FIB (the L3
// key has already been removed from VPP's steering hash) and DelSRv6Policy
// reports UNSPECIFIED (the BSID has already been removed from VPP's policy
// hash), delSRPolicy must still complete its work. Failover re-steer must
// run; nodePolices must be pruned.
func TestDelSRPolicy_IdempotentWhenVPPAlreadyMissing(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	bsid := mustBsid(t, "cafe::aaa")
	prefix := mustPrefix(t, "fd20::aaaa/128")
	surviverBsid := mustBsid(t, "cafe::bbb")

	fake := &fakeSRv6VPP{
		steering:       []*types.SrSteer{{Bsid: bsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}},
		delSteeringErr: govppapi.NO_SUCH_INNER_FIB,
		delPolicyErr:   govppapi.UNSPECIFIED,
	}
	p := newTestProvider(fake)
	dt6Behavior := uint8(18) // bgpapi.SRv6Behavior_END_DT6
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: dt6Behavior, Priority: 100, Policy: &types.SrPolicy{Bsid: bsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
			{Dst: dst, Color: 6, Distinguisher: 1, Behavior: dt6Behavior, Priority: 50, Policy: &types.SrPolicy{Bsid: surviverBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
		},
	}

	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6, Distinguisher: 0}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}

	if len(fake.delSteering) != 1 || fake.delSteering[0].Bsid != bsid {
		t.Fatalf("expected DelSRv6Steering(bsid=%s); got %+v", bsid.String(), fake.delSteering)
	}
	if len(fake.delPolicy) != 1 || fake.delPolicy[0].Bsid != bsid {
		t.Fatalf("expected DelSRv6Policy(bsid=%s); got %+v", bsid.String(), fake.delPolicy)
	}
	// Failover still runs despite the VPP errors.
	if len(fake.addModPolicy) != 1 || fake.addModPolicy[0].Bsid != surviverBsid {
		t.Fatalf("expected AddModSRv6Policy(surviver=%s) for failover; got %+v", surviverBsid.String(), fake.addModPolicy)
	}
	if len(fake.addSteering) != 1 || fake.addSteering[0].Bsid != surviverBsid {
		t.Fatalf("expected AddSRv6Steering(surviver=%s) for failover; got %+v", surviverBsid.String(), fake.addSteering)
	}
}

func TestDelConnectivity_DispatcherRoutesByEventShape(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	// Empty cn (no Custom, no Dst.IP) must error so a malformed event is loud.
	if err := p.DelConnectivity(&common.NodeConnectivity{}); err == nil {
		t.Fatal("expected error for empty cn")
	}
}

// ---------- DSR BSID lifecycle ----------

func newDSRTestProvider(fake *fakeSRv6VPP) *SRv6Provider {
	p := newTestProvider(fake)
	_, pool, _ := net.ParseCIDR("cafe::/64")
	p.policyIPPool = *pool
	p.dsrServices = map[string]*dsrServiceState{}
	return p
}

// A restart leaves dsrServices empty but VPP still holds the VIP steering; the
// existing BSID must be adopted rather than a fresh one derived (no churn/leak).
func TestAdoptExistingDSRBsid(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newDSRTestProvider(fake)
	want := mustBsid(t, "cafe::99")
	fake.steering = []*types.SrSteer{{
		TrafficType: types.SrSteerIPv6,
		Prefix:      mustPrefix(t, "2001:db8::a/128"),
		Bsid:        want,
	}}

	got, ok := p.adoptExistingDSRBsid(net.ParseIP("2001:db8::a"))
	if !ok || got != want {
		t.Fatalf("adopt = %v/%v, want %v/true", got, ok, want)
	}
	if _, ok := p.adoptExistingDSRBsid(net.ParseIP("2001:db8::b")); ok {
		t.Fatal("expected no adoption for an unsteered VIP")
	}
}

// dsrBsidForVIP must avoid BSIDs already in use and fail closed (ok=false) when
// the perturbation budget is exhausted, rather than returning a colliding value.
func TestDsrBsidForVIP_ExclusionAndFailClosed(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newDSRTestProvider(fake)
	vip := net.ParseIP("2001:db8::a")

	b1, ok := p.dsrBsidForVIP(vip)
	if !ok {
		t.Fatal("expected an initial free BSID")
	}

	// Mark b1 taken via a node pod-connectivity policy: re-deriving must perturb.
	p.nodePolices["n1"] = &NodeToPolicies{SRv6Tunnel: []common.SRv6Tunnel{{Bsid: b1.ToIP()}}}
	b2, ok := p.dsrBsidForVIP(vip)
	if !ok || b1 == b2 {
		t.Fatalf("expected perturbation away from taken BSID, got %v (ok=%v)", b2, ok)
	}

	// Mark every low-byte variant taken: perturbation only walks the low byte, so
	// all candidates collide and derivation must fail closed.
	base := b1.ToIP().To16()
	var tuns []common.SRv6Tunnel
	for i := 0; i < 256; i++ {
		v := make(net.IP, net.IPv6len)
		copy(v, base)
		v[net.IPv6len-1] = byte(i)
		tuns = append(tuns, common.SRv6Tunnel{Bsid: v})
	}
	p.nodePolices["n1"] = &NodeToPolicies{SRv6Tunnel: tuns}
	if _, ok := p.dsrBsidForVIP(vip); ok {
		t.Fatal("expected fail-closed (no free BSID) when all candidates are taken")
	}
}

// ---------- RFC 9256 candidate-path selection (§2.9) ----------

const testDT6Behavior = uint8(18) // bgpapi.SRv6Behavior_END_DT6

// Preference (not Priority) selects the active candidate: higher wins (§2.7/§2.9).
func TestGetPolicyNode_SelectsByPreference(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	lowBsid := mustBsid(t, "cafe::aa")
	highBsid := mustBsid(t, "cafe::bb")
	p := newTestProvider(&fakeSRv6VPP{})
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			// Priority is intentionally "better" on the losing candidate: it must
			// not influence selection (it only orders revalidation, §2.12).
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: testDT6Behavior, Preference: 100, Priority: 1,
				Policy: &types.SrPolicy{Bsid: lowBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
			{Dst: dst, Color: 6, Distinguisher: 1, Behavior: testDT6Behavior, Preference: 200, Priority: 255,
				Policy: &types.SrPolicy{Bsid: highBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
		},
	}
	policy, err := p.getPolicyNode(dst.String(), types.SrBehaviorDT6)
	if err != nil || policy == nil {
		t.Fatalf("getPolicyNode: %v policy=%v", err, policy)
	}
	if policy.Bsid != highBsid {
		t.Fatalf("selected bsid=%s, want preference-200 candidate %s", policy.Bsid.String(), highBsid.String())
	}
}

// Preference tie → lower originator wins, then higher discriminator (§2.9).
func TestGetPolicyNode_TieBreaks(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	aBsid := mustBsid(t, "cafe::aa")
	bBsid := mustBsid(t, "cafe::bb")
	p := newTestProvider(&fakeSRv6VPP{})
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 6, Distinguisher: 5, Behavior: testDT6Behavior, Preference: 100, OriginatorASN: 65001,
				Policy: &types.SrPolicy{Bsid: aBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
			{Dst: dst, Color: 6, Distinguisher: 9, Behavior: testDT6Behavior, Preference: 100, OriginatorASN: 65000,
				Policy: &types.SrPolicy{Bsid: bBsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
		},
	}
	policy, _ := p.getPolicyNode(dst.String(), types.SrBehaviorDT6)
	if policy == nil || policy.Bsid != bBsid {
		t.Fatalf("want lower-originator candidate (ASN 65000), got %+v", policy)
	}

	// Same originator → higher discriminator wins.
	p.nodePolices[dst.String()].SRv6Tunnel[0].OriginatorASN = 65000
	policy, _ = p.getPolicyNode(dst.String(), types.SrBehaviorDT6)
	if policy == nil || policy.Bsid != bBsid {
		t.Fatalf("want higher-discriminator candidate (disc 9), got %+v", policy)
	}
}

// ---------- dynamic BSID allocation (§6.2.1) ----------

func TestGetPolicyNode_DynamicBSID(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	released := []string{}
	p.releaseBsid = func(handle string) error { released = append(released, handle); return nil }
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			// No BSID advertised: the provider must bind one dynamically.
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: testDT6Behavior, Preference: 100,
				Policy: &types.SrPolicy{SidLists: []types.Srv6SidList{{NumSids: 1}}}},
		},
	}
	policy, err := p.getPolicyNode(dst.String(), types.SrBehaviorDT6)
	if err != nil || policy == nil {
		t.Fatalf("getPolicyNode: %v policy=%v", err, policy)
	}
	if (policy.Bsid == ip_types.IP6Address{}) {
		t.Fatal("expected a dynamically bound BSID, got zero")
	}
	first := policy.Bsid

	// The binding is policy-scoped: a second selection reuses the same BSID (§6.2.1).
	policy, _ = p.getPolicyNode(dst.String(), types.SrBehaviorDT6)
	if policy == nil || policy.Bsid != first {
		t.Fatalf("dynamic BSID must be stable, got %v want %v", policy.Bsid, first)
	}

	// Withdrawing the last candidate of the policy releases the binding.
	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6, Distinguisher: 0}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(released) != 1 {
		t.Fatalf("expected dynamic BSID released once, got %v", released)
	}
	if len(p.dynBsids) != 0 {
		t.Fatalf("dynBsids not cleaned: %v", p.dynBsids)
	}
}

// S-Flag (Specified-BSID-only, §6.2.3) forbids dynamic allocation.
func TestGetPolicyNode_SFlagWithoutBSIDInvalid(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	p := newTestProvider(&fakeSRv6VPP{})
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 6, Behavior: testDT6Behavior, Preference: 100, SpecifiedBSIDOnly: true,
				Policy: &types.SrPolicy{SidLists: []types.Srv6SidList{{NumSids: 1}}}},
		},
	}
	if policy, _ := p.getPolicyNode(dst.String(), types.SrBehaviorDT6); policy != nil {
		t.Fatalf("S-Flag candidate without BSID must be invalid, got %+v", policy)
	}
}

// ---------- SID reachability verification (§5.1) ----------

func TestGetPolicyNode_UnreachableFirstSIDInvalidates(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	sid := types.ToVppIP6Address(net.ParseIP("fd10::1"))
	fake := &fakeSRv6VPP{unreachableSids: map[string]bool{"fd10::1": true}}
	p := newTestProvider(fake)
	sids := [16]ip_types.IP6Address{}
	sids[0] = sid
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 6, Behavior: testDT6Behavior, Preference: 100,
				Policy: &types.SrPolicy{Bsid: mustBsid(t, "cafe::aa"),
					SidLists: []types.Srv6SidList{{NumSids: 1, Sids: sids}}}},
		},
	}
	if policy, _ := p.getPolicyNode(dst.String(), types.SrBehaviorDT6); policy != nil {
		t.Fatalf("candidate with unreachable first SID must be invalid, got %+v", policy)
	}

	// Lookup failure fails open: the candidate stays valid.
	fake.unreachableSids = nil
	fake.routeLookupErr = fmt.Errorf("vpp lookup broken")
	if policy, _ := p.getPolicyNode(dst.String(), types.SrBehaviorDT6); policy == nil {
		t.Fatal("lookup failure must fail open (candidate valid)")
	}
}

// Non-first SIDs are only verified when their V-Flag is set (§5.1).
func TestGetPolicyNode_VFlagVerification(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	fake := &fakeSRv6VPP{unreachableSids: map[string]bool{"fd10::2": true}}
	p := newTestProvider(fake)
	sids := [16]ip_types.IP6Address{}
	sids[0] = types.ToVppIP6Address(net.ParseIP("fd10::1"))
	sids[1] = types.ToVppIP6Address(net.ParseIP("fd10::2")) // unreachable
	tun := common.SRv6Tunnel{Dst: dst, Color: 6, Behavior: testDT6Behavior, Preference: 100,
		Policy: &types.SrPolicy{Bsid: mustBsid(t, "cafe::aa"),
			SidLists: []types.Srv6SidList{{NumSids: 2, Sids: sids}}}}

	// Without V-Flag on the second SID the candidate is fine.
	p.nodePolices[dst.String()] = &NodeToPolicies{Node: dst, SRv6Tunnel: []common.SRv6Tunnel{tun}}
	if policy, _ := p.getPolicyNode(dst.String(), types.SrBehaviorDT6); policy == nil {
		t.Fatal("unverified non-first SID must not invalidate the list")
	}

	// With V-Flag requesting verification of segment 1 it becomes invalid.
	tun.VerifyMasks = []uint32{1 << 1}
	p.nodePolices[dst.String()] = &NodeToPolicies{Node: dst, SRv6Tunnel: []common.SRv6Tunnel{tun}}
	if policy, _ := p.getPolicyNode(dst.String(), types.SrBehaviorDT6); policy != nil {
		t.Fatalf("V-Flag SID unreachable must invalidate the list, got %+v", policy)
	}
}

// ---------- drop-upon-invalid (§8.2, I-Flag) ----------

func TestDelSRPolicy_DropUponInvalid(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	bsid := mustBsid(t, "cafe::aa")
	survivorSid := "fd10::99" // unreachable -> survivor invalid -> no failover target
	prefix := mustPrefix(t, "fd20::1/128")
	sids := [16]ip_types.IP6Address{}
	sids[0] = types.ToVppIP6Address(net.ParseIP(survivorSid))

	fake := &fakeSRv6VPP{
		steering:        []*types.SrSteer{{Bsid: bsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}},
		unreachableSids: map[string]bool{survivorSid: true},
	}
	p := newTestProvider(fake)
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			// active candidate, I-Flag set
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: testDT6Behavior, Preference: 200, DropUponInvalid: true,
				Policy: &types.SrPolicy{Bsid: bsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
			// surviving candidate is unreachable -> policy exists but is invalid
			{Dst: dst, Color: 6, Distinguisher: 1, Behavior: testDT6Behavior, Preference: 100,
				Policy: &types.SrPolicy{Bsid: mustBsid(t, "cafe::bb"), SidLists: []types.Srv6SidList{{NumSids: 1, Sids: sids}}}},
		},
	}

	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6, Distinguisher: 0}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(fake.routeAdd) != 1 || len(fake.routeAdd[0].Paths) != 1 || !fake.routeAdd[0].Paths[0].IsDrop {
		t.Fatalf("expected one drop route for the orphaned prefix, got %+v", fake.routeAdd)
	}
	if len(p.droppedPrefixes) != 1 {
		t.Fatalf("droppedPrefixes not tracked: %v", p.droppedPrefixes)
	}

	// The survivor becomes reachable again: revalidation must lift the drop and re-steer.
	fake.unreachableSids = nil
	p.nodePrefixes[dst.String()] = &NodeToPrefixes{Node: dst, Prefixes: []ip_types.Prefix{prefix}}
	p.revalidatePolicies()
	if len(fake.routeDel) != 1 {
		t.Fatalf("expected the drop route removed on recovery, got %+v", fake.routeDel)
	}
	if len(p.droppedPrefixes) != 0 {
		t.Fatalf("droppedPrefixes not cleared: %v", p.droppedPrefixes)
	}
	if len(fake.addSteering) == 0 {
		t.Fatal("expected the prefix re-steered after recovery")
	}
}

// Without the I-Flag the prefix is left unsteered (fail-open), no drop route.
func TestDelSRPolicy_NoDropWithoutIFlag(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	bsid := mustBsid(t, "cafe::aa")
	prefix := mustPrefix(t, "fd20::1/128")
	fake := &fakeSRv6VPP{steering: []*types.SrSteer{{Bsid: bsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}}}
	p := newTestProvider(fake)
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: testDT6Behavior, Preference: 200,
				Policy: &types.SrPolicy{Bsid: bsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
		},
	}
	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6, Distinguisher: 0}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(fake.routeAdd) != 0 {
		t.Fatalf("no I-Flag: expected no drop route, got %+v", fake.routeAdd)
	}
}

// Withdrawing the LAST candidate removes the policy entirely: fail-open even
// with the I-Flag (RFC 9256 §8.2 applies to an existing-but-invalid policy).
func TestDelSRPolicy_DropReleasedWhenPolicyGone(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	bsid := mustBsid(t, "cafe::aa")
	survivorSid := "fd10::99"
	prefix := mustPrefix(t, "fd20::1/128")
	sids := [16]ip_types.IP6Address{}
	sids[0] = types.ToVppIP6Address(net.ParseIP(survivorSid))

	fake := &fakeSRv6VPP{
		steering:        []*types.SrSteer{{Bsid: bsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}},
		unreachableSids: map[string]bool{survivorSid: true},
	}
	p := newTestProvider(fake)
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node: dst,
		SRv6Tunnel: []common.SRv6Tunnel{
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: testDT6Behavior, Preference: 200, DropUponInvalid: true,
				Policy: &types.SrPolicy{Bsid: bsid, SidLists: []types.Srv6SidList{{NumSids: 1}}}},
			{Dst: dst, Color: 6, Distinguisher: 1, Behavior: testDT6Behavior, Preference: 100, DropUponInvalid: true,
				Policy: &types.SrPolicy{Bsid: mustBsid(t, "cafe::bb"), SidLists: []types.Srv6SidList{{NumSids: 1, Sids: sids}}}},
		},
	}

	// First withdraw engages the drop (invalid survivor remains).
	cn := &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6, Distinguisher: 0}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(p.droppedPrefixes) != 1 {
		t.Fatalf("expected drop engaged, got %v", p.droppedPrefixes)
	}
	// Second withdraw removes the last candidate: the policy is gone, drop lifted.
	cn = &common.NodeConnectivity{Custom: &common.SRv6Tunnel{Dst: dst, Color: 6, Distinguisher: 1}}
	if err := p.delSRPolicy(cn); err != nil {
		t.Fatalf("delSRPolicy: %v", err)
	}
	if len(p.droppedPrefixes) != 0 {
		t.Fatalf("expected drop released when policy ceased to exist, got %v", p.droppedPrefixes)
	}
	if len(fake.routeDel) != 1 {
		t.Fatalf("expected drop route deleted, got %+v", fake.routeDel)
	}
}

// ---------- priority-ordered revalidation (§2.12) ----------

func TestRevalidatePolicies_PriorityOrder(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	mkNode := func(ip string, prio uint32, bsid string) {
		dst := net.ParseIP(ip)
		p.nodePolices[dst.String()] = &NodeToPolicies{
			Node: dst,
			SRv6Tunnel: []common.SRv6Tunnel{
				{Dst: dst, Color: 6, Behavior: testDT6Behavior, Preference: 100, Priority: prio,
					Policy: &types.SrPolicy{Bsid: mustBsid(t, bsid), SidLists: []types.Srv6SidList{{NumSids: 1}}}},
			},
		}
		p.nodePrefixes[dst.String()] = &NodeToPrefixes{Node: dst, Prefixes: []ip_types.Prefix{mustPrefix(t, "fd20::1/128")}}
	}
	mkNode("fd00:1::22", 200, "cafe::22") // low priority (higher value)
	mkNode("fd00:1::11", 10, "cafe::11")  // high priority (lower value, §2.12)

	p.revalidatePolicies()

	if len(fake.addModPolicy) < 2 {
		t.Fatalf("expected both policies installed, got %d", len(fake.addModPolicy))
	}
	if fake.addModPolicy[0].Bsid != mustBsid(t, "cafe::11") {
		t.Fatalf("priority-10 policy must be processed first, got %s", fake.addModPolicy[0].Bsid.String())
	}
}
