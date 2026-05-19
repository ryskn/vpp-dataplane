// Copyright (C) 2026 Ryosuke Nakayama
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package connectivity

import (
	"io"
	"net"
	"testing"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// fakeSRv6VPP records every srv6VppAPI call so tests can assert what reached
// the dataplane and seed ListSRv6Steering output.
type fakeSRv6VPP struct {
	steering []*types.SrSteer

	addModPolicy []*types.SrPolicy
	delPolicy    []*types.SrPolicy
	addSteering  []*types.SrSteer
	delSteering  []*types.SrSteer
	routeAdd     []*types.Route
	routeDel     []*types.Route

	listSteeringErr error
	addModPolicyErr error
}

func (f *fakeSRv6VPP) ListSRv6Localsid() ([]*types.SrLocalsid, error) { return nil, nil }
func (f *fakeSRv6VPP) AddSRv6Localsid(*types.SrLocalsid) error        { return nil }
func (f *fakeSRv6VPP) SetEncapSource(net.IP) error                    { return nil }
func (f *fakeSRv6VPP) RouteAdd(r *types.Route) error                  { f.routeAdd = append(f.routeAdd, r); return nil }
func (f *fakeSRv6VPP) RouteDel(r *types.Route) error                  { f.routeDel = append(f.routeDel, r); return nil }

func (f *fakeSRv6VPP) AddModSRv6Policy(p *types.SrPolicy) error {
	f.addModPolicy = append(f.addModPolicy, p)
	return f.addModPolicyErr
}
func (f *fakeSRv6VPP) DelSRv6Policy(p *types.SrPolicy) error {
	f.delPolicy = append(f.delPolicy, p)
	return nil
}
func (f *fakeSRv6VPP) AddSRv6Steering(s *types.SrSteer) error {
	f.addSteering = append(f.addSteering, s)
	return nil
}
func (f *fakeSRv6VPP) DelSRv6Steering(s *types.SrSteer) error {
	f.delSteering = append(f.delSteering, s)
	return nil
}
func (f *fakeSRv6VPP) ListSRv6Steering() ([]*types.SrSteer, error) {
	return f.steering, f.listSteeringErr
}

func newTestProvider(fake *fakeSRv6VPP) *SRv6Provider {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &SRv6Provider{
		ConnectivityProviderData: &ConnectivityProviderData{log: logrus.NewEntry(logger)},
		vpp:                      fake,
		nodePrefixes:             make(map[string]*NodeToPrefixes),
		nodePolices:              make(map[string]*NodeToPolicies),
	}
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
		{"policy wins", common.SRv6Tunnel{Policy: &types.SrPolicy{Bsid: policyBsid}, Bsid: netBsid}, true, policyBsid.String()},
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
			{Dst: dst, Color: 4, Policy: &types.SrPolicy{Bsid: dt4Bsid}, Priority: 100},
			{Dst: dst, Color: 6, Policy: &types.SrPolicy{Bsid: dt6Bsid}, Priority: 100},
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
		SRv6Tunnel: []common.SRv6Tunnel{{Dst: dst, Color: 6, Policy: &types.SrPolicy{Bsid: bsid}}},
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
			{Dst: dst, Color: 6, Distinguisher: 0, Behavior: dt6Behavior, Priority: 100, Policy: &types.SrPolicy{Bsid: winnerBsid}},
			{Dst: dst, Color: 6, Distinguisher: 1, Behavior: dt6Behavior, Priority: 50, Policy: &types.SrPolicy{Bsid: loserBsid}},
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

func TestDelSRPolicy_NoSurvivingCandidateLeavesPrefixUnsteered(t *testing.T) {
	dst := net.ParseIP("fd00:1::11")
	bsid := mustBsid(t, "cafe::4")
	prefix := mustPrefix(t, "fd20::1/128")
	fake := &fakeSRv6VPP{steering: []*types.SrSteer{{Bsid: bsid, Prefix: prefix, TrafficType: types.SrSteerIPv6}}}
	p := newTestProvider(fake)
	p.nodePolices[dst.String()] = &NodeToPolicies{
		Node:       dst,
		SRv6Tunnel: []common.SRv6Tunnel{{Dst: dst, Color: 6, Policy: &types.SrPolicy{Bsid: bsid}}},
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

// ---------- DelConnectivity dispatcher ----------

func TestDelConnectivity_DispatcherRoutesByEventShape(t *testing.T) {
	fake := &fakeSRv6VPP{}
	p := newTestProvider(fake)
	// Empty cn (no Custom, no Dst.IP) must error so a malformed event is loud.
	if err := p.DelConnectivity(&common.NodeConnectivity{}); err == nil {
		t.Fatal("expected error for empty cn")
	}
}
