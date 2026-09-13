// Copyright (C) 2026 Cilium Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package podinterface

import (
	"net"
	"sort"
	"strings"
	"testing"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
)

func mustCIDR(t *testing.T, cidr string) net.IPNet {
	t.Helper()
	_, prefix, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("cannot parse %q: %v", cidr, err)
	}
	return *prefix
}

// hostPrefix is how a pod spec's container address reaches the Pod side: a /32
// or /128 of the address itself, which is what GetContainerIPs builds.
func hostPrefix(t *testing.T, addr string) net.IPNet {
	t.Helper()
	ip := net.ParseIP(addr)
	if ip == nil {
		t.Fatalf("cannot parse %q", addr)
	}
	if ip4 := ip.To4(); ip4 != nil {
		return net.IPNet{IP: ip4, Mask: net.CIDRMask(32, 32)}
	}
	return net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func podSpecWith(t *testing.T, addresses []string, routes []string) *model.LocalPodSpec {
	t.Helper()
	podSpec := &model.LocalPodSpec{InterfaceName: "eth0"}
	for _, address := range addresses {
		ip := net.ParseIP(address)
		if ip == nil {
			t.Fatalf("cannot parse %q", address)
		}
		podSpec.ContainerIPs = append(podSpec.ContainerIPs, ip)
	}
	for _, route := range routes {
		podSpec.Routes = append(podSpec.Routes, mustCIDR(t, route))
	}
	return podSpec
}

func sortedKeys(nets []net.IPNet) []string {
	out := make([]string, 0, len(nets))
	for idx := range nets {
		out = append(out, ipNetKey(nets[idx]))
	}
	sort.Strings(out)
	return out
}

func requireIPNets(t *testing.T, what string, got []net.IPNet, want ...string) {
	t.Helper()
	gotKeys := sortedKeys(got)
	wantKeys := append([]string(nil), want...)
	sort.Strings(wantKeys)
	if strings.Join(gotKeys, " ") != strings.Join(wantKeys, " ") {
		t.Fatalf("%s is %v, want %v", what, gotKeys, wantKeys)
	}
}

// --- the stored spec -> Pod-side configuration mapping ----------------------
//
// The rescan re-applies the Pod-side L3 configuration from the durable pod spec
// (errata #34 item 211), so what that spec means on the Pod side is a contract
// and not an implementation detail: the container addresses become host
// prefixes, and a device route of a family the Pod has no address in is not part
// of the configuration at all — it has no source address to be sent from, which
// is the same rule AddPodRoutes applies when it installs them.
func TestDesiredNamespaceSideMapsTheStoredSpec(t *testing.T) {
	for _, tc := range []struct {
		name      string
		addresses []string
		routes    []string
		wantAddrs []string
		wantRoute []string
	}{
		{
			name:      "IPv6 single stack, the Stage 0 shape",
			addresses: []string{"fd00::51"},
			routes:    []string{"fd00::26/128", "::/0"},
			wantAddrs: []string{"fd00::51/128"},
			wantRoute: []string{"fd00::26/128", "::/0"},
		},
		{
			name:      "IPv4 single stack",
			addresses: []string{"10.0.0.7"},
			routes:    []string{"169.254.1.1/32", "0.0.0.0/0"},
			wantAddrs: []string{"10.0.0.7/32"},
			wantRoute: []string{"169.254.1.1/32", "0.0.0.0/0"},
		},
		{
			name:      "dual stack keeps both families",
			addresses: []string{"10.0.0.7", "fd00::51"},
			routes:    []string{"0.0.0.0/0", "::/0"},
			wantAddrs: []string{"10.0.0.7/32", "fd00::51/128"},
			wantRoute: []string{"0.0.0.0/0", "::/0"},
		},
		{
			name:      "a route of a family the Pod has no address in is dropped",
			addresses: []string{"fd00::51"},
			routes:    []string{"0.0.0.0/0", "::/0"},
			wantAddrs: []string{"fd00::51/128"},
			wantRoute: []string{"::/0"},
		},
		{
			name:      "no address means no configuration to describe",
			addresses: nil,
			routes:    []string{"::/0"},
			wantAddrs: nil,
			wantRoute: nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			desired := desiredNamespaceSide(podSpecWith(t, tc.addresses, tc.routes))
			requireIPNets(t, "the desired address set", desired.Addresses, tc.wantAddrs...)
			requireIPNets(t, "the desired route set", desired.Routes, tc.wantRoute...)
		})
	}
}

// --- the "needs namespace-side reconfiguration" predicate -------------------
//
// This is the decision the rescan path turns on. The two states it has to get
// right are the two the rescan actually meets: a netdev VPP just created, which
// carries nothing, and the pre-restart netdev, which carries everything. An
// interface that already matches the stored spec must be left alone, because the
// rescan runs on every stored attachment on every restart of the lifecycle
// service.
func TestPlanNamespaceSideNeedsReconfiguration(t *testing.T) {
	for _, tc := range []struct {
		name         string
		addresses    []string
		routes       []string
		observedAddr []string
		observedRte  []string
		wantAdd      []string
		wantRemove   []string
		wantRoutes   []string
		wantNeeds    bool
	}{
		{
			name:      "a new netdev carries nothing: everything is missing",
			addresses: []string{"fd00::51"},
			routes:    []string{"fd00::26/128", "::/0"},
			// What run 19b observed in the Pod netns: only the kernel's
			// link-local, which observeNamespaceSide does not report.
			observedAddr: nil,
			observedRte:  []string{"fe80::/64"},
			wantAdd:      []string{"fd00::51/128"},
			wantRoutes:   []string{"fd00::26/128", "::/0"},
			wantNeeds:    true,
		},
		{
			name:         "the pre-restart netdev still carries everything: nothing to do",
			addresses:    []string{"fd00::51"},
			routes:       []string{"fd00::26/128", "::/0"},
			observedAddr: []string{"fd00::51/128"},
			observedRte:  []string{"fd00::26/128", "::/0", "fe80::/64"},
			wantNeeds:    false,
		},
		{
			name:         "a wrong address is replaced, not joined",
			addresses:    []string{"fd00::51"},
			routes:       []string{"::/0"},
			observedAddr: []string{"fd00::1d/128"},
			observedRte:  []string{"::/0"},
			wantAdd:      []string{"fd00::51/128"},
			wantRemove:   []string{"fd00::1d/128"},
			wantNeeds:    true,
		},
		{
			name:         "the same address with a different prefix length is a replacement",
			addresses:    []string{"fd00::51"},
			routes:       nil,
			observedAddr: []string{"fd00::51/64"},
			wantAdd:      []string{"fd00::51/128"},
			wantRemove:   []string{"fd00::51/64"},
			wantNeeds:    true,
		},
		{
			name:         "only a route is missing",
			addresses:    []string{"fd00::51"},
			routes:       []string{"fd00::26/128", "::/0"},
			observedAddr: []string{"fd00::51/128"},
			observedRte:  []string{"::/0"},
			wantRoutes:   []string{"fd00::26/128"},
			wantNeeds:    true,
		},
		{
			name:         "a route nothing stored is left alone",
			addresses:    []string{"fd00::51"},
			routes:       []string{"::/0"},
			observedAddr: []string{"fd00::51/128"},
			observedRte:  []string{"::/0", "fd00::/8", "fe80::/64"},
			wantNeeds:    false,
		},
		{
			name:         "a stored route of an unusable family is not a difference",
			addresses:    []string{"fd00::51"},
			routes:       []string{"0.0.0.0/0", "::/0"},
			observedAddr: []string{"fd00::51/128"},
			observedRte:  []string{"::/0"},
			wantNeeds:    false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			observed := namespaceSideState{}
			for _, addr := range tc.observedAddr {
				observed.Addresses = append(observed.Addresses, mustCIDRKeepingHost(t, addr))
			}
			for _, route := range tc.observedRte {
				observed.Routes = append(observed.Routes, mustCIDR(t, route))
			}

			delta := planNamespaceSide(observed, podSpecWith(t, tc.addresses, tc.routes))

			if delta.needsReconfiguration() != tc.wantNeeds {
				t.Fatalf("needsReconfiguration() = %t, want %t (%s)",
					delta.needsReconfiguration(), tc.wantNeeds, delta)
			}
			requireIPNets(t, "the addresses to add", delta.AddressesToAdd, tc.wantAdd...)
			requireIPNets(t, "the addresses to remove", delta.AddressesToRemove, tc.wantRemove...)
			requireIPNets(t, "the routes to add", delta.RoutesToAdd, tc.wantRoutes...)
		})
	}
}

// mustCIDRKeepingHost parses an address with a prefix length and keeps the host
// bits, which is what an address on an interface looks like (`fd00::51/128`),
// unlike a route destination, which is masked.
func mustCIDRKeepingHost(t *testing.T, cidr string) net.IPNet {
	t.Helper()
	ip, prefix, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("cannot parse %q: %v", cidr, err)
	}
	return net.IPNet{IP: ip, Mask: prefix.Mask}
}

// An interface that already carries the stored configuration has to produce an
// empty plan under both address encodings netlink and net can hand back: a v4
// address is returned as 4 bytes by one and 16 by the other, and a plan that
// treated the two as different addresses would delete and re-add every IPv4
// address on every rescan.
func TestPlanNamespaceSideIsStableAcrossIPv4Encodings(t *testing.T) {
	podSpec := podSpecWith(t, []string{"10.0.0.7"}, []string{"0.0.0.0/0"})
	observed := namespaceSideState{
		Addresses: []net.IPNet{{
			IP:   net.ParseIP("10.0.0.7"), // 16-byte, v4-in-v6 form
			Mask: net.CIDRMask(32, 32),
		}},
		Routes: []net.IPNet{{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}},
	}
	if delta := planNamespaceSide(observed, podSpec); delta.needsReconfiguration() {
		t.Fatalf("an unchanged IPv4 configuration produced work: %s", delta)
	}
}

// --- the observation -------------------------------------------------------

type fakeNetlinkReader struct {
	addresses []netlink.Addr
	routes    []netlink.Route
	addrErr   error
	routeErr  error
}

func (f fakeNetlinkReader) AddrList(netlink.Link, int) ([]netlink.Addr, error) {
	return f.addresses, f.addrErr
}

func (f fakeNetlinkReader) RouteList(netlink.Link, int) ([]netlink.Route, error) {
	return f.routes, f.routeErr
}

func fakeLink() netlink.Link {
	return &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 9}}
}

// The link-local address is not part of what this side manages: it is present on
// a healthy Pod interface too, because VPP brings the host side of the tun up
// when it creates it and the kernel generates the address before
// addr_gen_mode=none is written. Reporting it would make every rescan try to
// delete it.
func TestObserveNamespaceSideIgnoresLinkScopeAddresses(t *testing.T) {
	global := hostPrefix(t, "fd00::51")
	linkLocal := net.IPNet{IP: net.ParseIP("fe80::d6eb:1299:e277:7fd3"), Mask: net.CIDRMask(64, 128)}
	reader := fakeNetlinkReader{
		addresses: []netlink.Addr{
			{IPNet: &linkLocal, Scope: unix.RT_SCOPE_LINK},
			{IPNet: &global, Scope: unix.RT_SCOPE_UNIVERSE},
		},
	}

	observed, err := observeNamespaceSide(reader, fakeLink())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireIPNets(t, "the observed addresses", observed.Addresses, "fd00::51/128")
}

// A default route is reported by the kernel with no destination. It has to be
// named by the prefix the pod spec asks for, or every rescan would try to add a
// default route that is already there.
func TestObserveNamespaceSideNamesTheDefaultRoute(t *testing.T) {
	reader := fakeNetlinkReader{
		routes: []netlink.Route{
			{Family: netlink.FAMILY_V6, Dst: nil},
			{Family: netlink.FAMILY_V4, Dst: nil},
		},
	}

	observed, err := observeNamespaceSide(reader, fakeLink())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	requireIPNets(t, "the observed routes", observed.Routes, "::/0", "0.0.0.0/0")
}

// An observation that could not be taken is not an empty observation: acting on
// it would delete every address the interface has. It fails, which under the
// lifecycle profile fails the ADD and the rescan of that attachment.
func TestObserveNamespaceSideFailsWhenItCannotRead(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reader fakeNetlinkReader
	}{
		{name: "addresses", reader: fakeNetlinkReader{addrErr: errors.New("netlink receive: no buffer space")}},
		{name: "routes", reader: fakeNetlinkReader{routeErr: errors.New("netlink receive: no buffer space")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := observeNamespaceSide(tc.reader, fakeLink()); err == nil {
				t.Fatalf("a failed %s listing was reported as an empty observation", tc.name)
			}
		})
	}
}
