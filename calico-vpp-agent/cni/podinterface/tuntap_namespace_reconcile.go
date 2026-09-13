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
	"strings"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
)

// The Pod-side L3 configuration of a tun is reconciled against the stored pod
// spec rather than applied blindly, because the lifecycle profile runs the same
// steps on two paths that start from different Pod-side states
// (errata #34 item 211):
//
//   - CreatePodInterface: the netdev was just created by VPP in a namespace
//     that had none, so every address and every device route is missing;
//   - rescanLifecycleState after a VPP restart: CreateOrAttachTapV2
//     (vpplink/interfaces.go:187) creates the tun with TAP_FLAG_PERSIST and
//     first tries TAP_FLAG_ATTACH, so the netdev in the Pod namespace is either
//     a *new* one — bare, with no address, no route and default sysctls — or the
//     pre-restart one, which may still carry part or all of its configuration.
//
// Which of the two it is is not observable from the pod spec and is not decided
// by this code: the observed state of the namespace is read and the difference
// against the stored spec is applied. An interface that already carries exactly
// the stored configuration is left untouched, a missing address or route is
// added, and an address that is not in the stored spec is removed rather than
// left beside the right one — D-50 makes the attachment L3-only, which means the
// interface carries exactly the addresses the CNI decided and nothing else.
//
// Nothing here touches link-scope addresses. The kernel's own `fe80::` is
// present on a healthy Pod interface too: VPP brings the host side of the tun up
// when it creates it (`vnet_netlink_set_link_state (tif->ifindex, 1)` in the tap
// plugin), so the link-local is generated before `addr_gen_mode=none` is
// written, and writing that sysctl prevents further generation rather than
// removing what exists. The suppression that D-50 asks for is about *global*
// addresses appearing from a second source, and that is what stays enforced.

// namespaceSideState is the Pod-side L3 configuration of one interface: the
// global addresses on it and the destinations routed out of it.
//
// It is the observation the reconciliation decides from, and it is also how the
// stored pod spec is expressed, so that the two can be compared directly.
type namespaceSideState struct {
	// Addresses are the addresses on the link that are not link-scope.
	Addresses []net.IPNet
	// Routes are the destinations already routed out of the link.
	Routes []net.IPNet
}

// namespaceSideDelta is what has to change for the Pod side to carry exactly the
// L3 configuration the stored pod spec describes.
type namespaceSideDelta struct {
	// AddressesToAdd are the stored addresses the interface does not carry.
	AddressesToAdd []net.IPNet
	// AddressesToRemove are the non-link-scope addresses the interface carries
	// that the stored pod spec does not name.
	AddressesToRemove []net.IPNet
	// RoutesToAdd are the stored device routes that are not installed.
	//
	// Routes that are installed and not stored are *not* removed: the device
	// route of the prefix itself and the kernel's `fe80::/64` are put there by
	// the kernel, not by this side, and a lifecycle service that deleted routes
	// it never installed would be making a policy decision about a namespace it
	// does not own.
	RoutesToAdd []net.IPNet
}

// needsReconfiguration reports whether the Pod side differs from the stored pod
// spec at all. It is the predicate the rescan path logs: false means the
// namespace-side steps will run and change nothing.
func (d namespaceSideDelta) needsReconfiguration() bool {
	return len(d.AddressesToAdd) > 0 || len(d.AddressesToRemove) > 0 || len(d.RoutesToAdd) > 0
}

func (d namespaceSideDelta) String() string {
	if !d.needsReconfiguration() {
		return "already carries the stored L3 configuration"
	}
	parts := make([]string, 0, 3)
	if len(d.AddressesToAdd) > 0 {
		parts = append(parts, "addresses to add ["+joinIPNets(d.AddressesToAdd)+"]")
	}
	if len(d.AddressesToRemove) > 0 {
		parts = append(parts, "addresses to remove ["+joinIPNets(d.AddressesToRemove)+"]")
	}
	if len(d.RoutesToAdd) > 0 {
		parts = append(parts, "routes to add ["+joinIPNets(d.RoutesToAdd)+"]")
	}
	return strings.Join(parts, ", ")
}

func joinIPNets(nets []net.IPNet) string {
	out := make([]string, 0, len(nets))
	for idx := range nets {
		out = append(out, nets[idx].String())
	}
	return strings.Join(out, " ")
}

// ipNetKey is the identity an address or a destination is compared by. A
// prefix whose length differs is a different entry, so a stored `/128` beside an
// observed `/64` of the same address is a replacement and not a match.
func ipNetKey(prefix net.IPNet) string {
	canonical := prefix
	if ip4 := prefix.IP.To4(); ip4 != nil {
		canonical.IP = ip4
		if len(prefix.Mask) == net.IPv6len {
			// A v4 address carrying a 16-byte mask compares equal to the same
			// address with the 4-byte mask only after the mask is narrowed.
			canonical.Mask = prefix.Mask[net.IPv6len-net.IPv4len:]
		}
	}
	return canonical.String()
}

// desiredNamespaceSide maps a stored pod spec to the Pod-side L3 configuration
// it describes: the container addresses as host prefixes, and the device routes
// of the families the Pod actually has an address in.
//
// The family filter is the same rule AddPodRoutes applies, and it is here for
// the same reason: a route of a family the Pod has no address in has no source
// address to be sent from, so it is not part of the configuration this spec
// describes and its absence is not a difference to repair.
func desiredNamespaceSide(podSpec *model.LocalPodSpec) namespaceSideState {
	hasv4, hasv6 := podSpec.Hasv46()
	desired := namespaceSideState{
		Addresses: make([]net.IPNet, 0, len(podSpec.ContainerIPs)),
		Routes:    make([]net.IPNet, 0, len(podSpec.Routes)),
	}
	for _, containerIP := range podSpec.GetContainerIPs() {
		desired.Addresses = append(desired.Addresses, *containerIP)
	}
	for _, route := range podSpec.Routes {
		if !routeFamilyIsUsable(route, hasv4, hasv6) {
			continue
		}
		desired.Routes = append(desired.Routes, route)
	}
	return desired
}

// routeFamilyIsUsable says whether a device route belongs to a family the Pod
// has an address in.
func routeFamilyIsUsable(route net.IPNet, hasv4 bool, hasv6 bool) bool {
	if route.IP.To4() == nil {
		return hasv6
	}
	return hasv4
}

// planNamespaceSide computes the difference between what the Pod namespace
// carries and what the stored pod spec describes. It is pure: the observation is
// a parameter, so the whole decision is testable without a network namespace.
func planNamespaceSide(observed namespaceSideState, podSpec *model.LocalPodSpec) namespaceSideDelta {
	desired := desiredNamespaceSide(podSpec)

	observedAddresses := keyedIPNets(observed.Addresses)
	desiredAddresses := keyedIPNets(desired.Addresses)
	observedRoutes := keyedIPNets(observed.Routes)

	delta := namespaceSideDelta{}
	for idx := range desired.Addresses {
		if _, found := observedAddresses[ipNetKey(desired.Addresses[idx])]; !found {
			delta.AddressesToAdd = append(delta.AddressesToAdd, desired.Addresses[idx])
		}
	}
	for idx := range observed.Addresses {
		if _, found := desiredAddresses[ipNetKey(observed.Addresses[idx])]; !found {
			delta.AddressesToRemove = append(delta.AddressesToRemove, observed.Addresses[idx])
		}
	}
	for idx := range desired.Routes {
		if _, found := observedRoutes[ipNetKey(desired.Routes[idx])]; !found {
			delta.RoutesToAdd = append(delta.RoutesToAdd, desired.Routes[idx])
		}
	}
	return delta
}

func keyedIPNets(nets []net.IPNet) map[string]struct{} {
	keyed := make(map[string]struct{}, len(nets))
	for idx := range nets {
		keyed[ipNetKey(nets[idx])] = struct{}{}
	}
	return keyed
}

// routeDestination is the destination prefix of an installed route. A default
// route is reported by the kernel with no destination, and it is named here by
// the prefix that was asked for so that it compares equal to the `::/0` or
// `0.0.0.0/0` of a pod spec.
func routeDestination(route netlink.Route) net.IPNet {
	if route.Dst != nil {
		return *route.Dst
	}
	if route.Family == netlink.FAMILY_V4 {
		return net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	}
	return net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
}

// netlinkNamespaceSideReader is the netlink surface the observation needs. It is
// an interface so that a test can supply an observation; production always uses
// the netlink package itself.
type netlinkNamespaceSideReader interface {
	AddrList(link netlink.Link, family int) ([]netlink.Addr, error)
	RouteList(link netlink.Link, family int) ([]netlink.Route, error)
}

type realNetlinkReader struct{}

func (realNetlinkReader) AddrList(link netlink.Link, family int) ([]netlink.Addr, error) {
	return netlink.AddrList(link, family)
}

func (realNetlinkReader) RouteList(link netlink.Link, family int) ([]netlink.Route, error) {
	return netlink.RouteList(link, family)
}

// observeNamespaceSide reads the Pod-side L3 configuration the interface already
// carries. It must be called inside the Pod network namespace.
func observeNamespaceSide(reader netlinkNamespaceSideReader, contTun netlink.Link) (namespaceSideState, error) {
	observed := namespaceSideState{}

	addresses, err := reader.AddrList(contTun, netlink.FAMILY_ALL)
	if err != nil {
		return observed, errors.Wrapf(err, "failed to list the addresses of %s", contTun.Attrs().Name)
	}
	for _, address := range addresses {
		if address.Scope == unix.RT_SCOPE_LINK {
			continue
		}
		if address.IPNet == nil {
			continue
		}
		observed.Addresses = append(observed.Addresses, net.IPNet{IP: address.IP, Mask: address.Mask})
	}

	routes, err := reader.RouteList(contTun, netlink.FAMILY_ALL)
	if err != nil {
		return observed, errors.Wrapf(err, "failed to list the routes of %s", contTun.Attrs().Name)
	}
	for _, route := range routes {
		observed.Routes = append(observed.Routes, routeDestination(route))
	}

	return observed, nil
}

// reconcilePodAddresses applies the address half of the delta: the addresses the
// stored pod spec does not name are removed before the missing ones are added,
// so that a wrong address is replaced rather than joined.
//
// A failure fails the ADD, for the same reason addPodAddresses does: an
// interface that does not carry exactly the stored addresses is not a usable
// interface, and this service must not publish a binding for it.
func (i *TunTapPodInterfaceDriver) reconcilePodAddresses(contTun netlink.Link, delta namespaceSideDelta, swIfIndex uint32) error {
	for idx := range delta.AddressesToRemove {
		stale := delta.AddressesToRemove[idx]
		i.log.Infof("pod(add) tun removing an address the pod spec does not name swIfIndex=%d linux-ifIndex=%d address=%s",
			swIfIndex, contTun.Attrs().Index, stale.String())
		if err := netlink.AddrDel(contTun, &netlink.Addr{IPNet: &stale}); err != nil {
			return errors.Wrapf(err, "failed to remove IP addr %s from %s", stale.String(), contTun.Attrs().Name)
		}
	}
	for idx := range delta.AddressesToAdd {
		missing := delta.AddressesToAdd[idx]
		i.log.Infof("pod(add) tun address swIfIndex=%d linux-ifIndex=%d address=%s",
			swIfIndex, contTun.Attrs().Index, missing.String())
		if err := netlink.AddrAdd(contTun, &netlink.Addr{IPNet: &missing}); err != nil {
			return errors.Wrapf(err, "failed to add IP addr %s to %s", missing.String(), contTun.Attrs().Name)
		}
	}
	return nil
}
