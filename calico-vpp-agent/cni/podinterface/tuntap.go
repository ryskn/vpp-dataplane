// Copyright (C) 2021 Cisco Systems Inc.
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
	"fmt"
	"io"
	"net"
	"os"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"
	felixConfig "github.com/projectcalico/calico/felix/config"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// PodInterfaceProfile selects which Pod-side configuration policy a pod
// interface driver applies.
//
// It is chosen explicitly when the server is built, by the entry point that
// knows which product it is running (Issue #135 pre-merge item 4). It is never
// inferred from the interface name, the pod spec or anything else observable at
// run time: two profiles that differ in what they configure inside the Pod must
// differ by a decision someone made, not by a guess.
type PodInterfaceProfile int

const (
	// CalicoProfile is the Calico CNI backend. Its Pod-side configuration is
	// the one Calico has always applied, and it stays that way: the strict
	// ordering below is a property of the SRv6 endpoint context contract, not
	// a bug fix that Calico deployments are owed. Tightening it there is a
	// separate change with its own reasons.
	CalicoProfile PodInterfaceProfile = iota
	// LifecycleProfile is the Pod interface lifecycle service, whose Pod-side
	// configuration follows the fixed ADD order of D-50 and Issue #135
	// ruling 8.
	LifecycleProfile
)

func (p PodInterfaceProfile) String() string {
	if p == LifecycleProfile {
		return "lifecycle"
	}
	return "calico"
}

type TunTapPodInterfaceDriver struct {
	PodInterfaceDriverData
	// profile decides the Pod-side configuration policy: which steps run and
	// in which order. The code that performs each step is shared between the
	// profiles; the policy is not.
	profile             PodInterfaceProfile
	felixConfig         *felixConfig.Config
	ipipEncapRefCounts  int /* how many ippools with IPIP */
	vxlanEncapRefCounts int /* how many ippools with VXLAN */
}

func NewTunTapPodInterfaceDriver(vpp *vpplink.VppLink, log *logrus.Entry, snatPolicy common.SNATPolicy, profile PodInterfaceProfile) *TunTapPodInterfaceDriver {
	i := &TunTapPodInterfaceDriver{
		PodInterfaceDriverData: PodInterfaceDriverData{
			snatPolicy: requireSNATPolicy(snatPolicy, "tun"),
		},
		profile: profile,
	}
	i.vpp = vpp
	i.log = log
	i.Name = "tun"
	return i
}

func reduceMtuIf(podMtu *int, tunnelMtu int, tunnelEnabled bool) {
	if tunnelEnabled && tunnelMtu != 0 && tunnelMtu < *podMtu {
		*podMtu = tunnelMtu
	}
}

/**
 * Computes the pod MTU from a requested mtu : podSpecMtu (typically specified in the podSpec)
 * the felixConfig (having some encap details)
 * and other sources (typically ippool) for vxlanEnabled / ipInIpEnabled
 */
func (i *TunTapPodInterfaceDriver) computePodMtu(podSpecMtu int, fc *felixConfig.Config, ipipEnabled bool, vxlanEnabled bool) (podMtu int) {
	if fc == nil {
		// The Pod interface lifecycle profile has no Felix behind it
		// (Issue #135 ruling 3), so there is no encapsulation configuration to
		// reduce the MTU for. An empty config makes every reduction below a
		// no-op, leaving the requested MTU or the host MTU.
		fc = &felixConfig.Config{}
	}
	hostMtu := vpplink.CalicoVppMaxMTu
	if len(common.VppManagerInfo.UplinkStatuses) != 0 {
		for _, v := range common.VppManagerInfo.UplinkStatuses {
			if v.Mtu < hostMtu {
				hostMtu = v.Mtu
			}
		}
	}
	if podSpecMtu > 0 {
		podMtu = podSpecMtu
	} else {
		ipipEnabled := ipipEnabled || (fc.IpInIpEnabled != nil && *fc.IpInIpEnabled)
		vxlanEnabled := vxlanEnabled || (fc.VXLANEnabled != nil && *fc.VXLANEnabled)

		// Reproduce felix algorithm in determinePodMTU to determine pod MTU
		// The part where it defaults to the host MTU is done in AddVppInterface
		// TODO: move the code that retrieves the host mtu to this module...
		podMtu = hostMtu
		reduceMtuIf(&podMtu, vpplink.DefaultIntTo(fc.IpInIpMtu, hostMtu-20), ipipEnabled)
		reduceMtuIf(&podMtu, vpplink.DefaultIntTo(fc.VXLANMTU, hostMtu-50), vxlanEnabled)
		reduceMtuIf(&podMtu, vpplink.DefaultIntTo(fc.WireguardMTU, hostMtu-60), fc.WireguardEnabled)
		reduceMtuIf(&podMtu, hostMtu-60, *config.GetCalicoVppFeatureGates().IPSecEnabled)
	}

	if podMtu > hostMtu {
		i.log.Warnf("Configured MTU (%d) is larger than detected host interface MTU (%d)", podMtu, hostMtu)
	}

	return podMtu
}

func (i *TunTapPodInterfaceDriver) SetFelixConfig(felixConfig *felixConfig.Config) {
	i.felixConfig = felixConfig
}

/**
 * This is called when the felix config or ippool encap refcount change,
 * and update the linux mtu accordingly.
 *
 */
func (i *TunTapPodInterfaceDriver) FelixConfigChanged(newFelixConfig *felixConfig.Config, ipipEncapRefCountDelta int, vxlanEncapRefCountDelta int, podSpecs map[string]model.LocalPodSpec) {
	if newFelixConfig == nil {
		newFelixConfig = i.felixConfig
	}
	if i.felixConfig != nil {
		for name, podSpec := range podSpecs {
			oldMtu := i.computePodMtu(podSpec.Mtu, i.felixConfig, i.ipipEncapRefCounts > 0, i.vxlanEncapRefCounts > 0)
			newMtu := i.computePodMtu(podSpec.Mtu, i.felixConfig, i.ipipEncapRefCounts+ipipEncapRefCountDelta > 0, i.vxlanEncapRefCounts+vxlanEncapRefCountDelta > 0)
			if oldMtu != newMtu {
				i.log.Infof("pod(upd) reconfiguring mtu=%d pod=%s", newMtu, name)
				err := ns.WithNetNSPath(podSpec.NetnsName, func(ns.NetNS) error {
					containerInterface, err := netlink.LinkByName(podSpec.InterfaceName)
					if err != nil {
						return errors.Wrapf(err, "failed to lookup if=%s pod=%s", podSpec.InterfaceName, name)
					}
					err = netlink.LinkSetMTU(containerInterface, newMtu)
					if err != nil {
						return err
					}
					return nil
				})
				if err != nil {
					i.log.Errorf("failed to set mtu pod=%s: %v", name, err)
				}
			}
		}
	}

	i.felixConfig = newFelixConfig
	i.ipipEncapRefCounts = i.ipipEncapRefCounts + ipipEncapRefCountDelta
	i.vxlanEncapRefCounts = i.vxlanEncapRefCounts + vxlanEncapRefCountDelta
}

func (i *TunTapPodInterfaceDriver) CreateInterface(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, doHostSideConf bool) error {
	tun := &types.TapV2{
		GenericVppInterface: types.GenericVppInterface{
			NumRxQueues:       podSpec.IfSpec.NumRxQueues,
			NumTxQueues:       podSpec.IfSpec.NumTxQueues,
			RxQueueSize:       podSpec.IfSpec.RxQueueSize,
			TxQueueSize:       podSpec.IfSpec.TxQueueSize,
			HostInterfaceName: podSpec.InterfaceName,
		},
		HostNamespace: podSpec.NetnsName,
		Tag:           podSpec.GetInterfaceTag(i.Name),
		HostMtu:       i.computePodMtu(podSpec.Mtu, i.felixConfig, i.ipipEncapRefCounts > 0, i.vxlanEncapRefCounts > 0),
	}

	if *podSpec.IfSpec.IsL3 {
		tun.Flags |= types.TapFlagTun
	}

	if *config.GetCalicoVppDebug().GSOEnabled {
		tun.Flags |= types.TapFlagGSO | types.TapGROCoalesce
	}

	i.log.Debugf("Add request pod MTU: %d, computed %d", podSpec.Mtu, tun.HostMtu)

	swIfIndex, err := i.vpp.CreateOrAttachTapV2(tun)
	if err != nil {
		return errors.Wrapf(err, "Error creating tun")
	} else {
		stack.Push(i.vpp.DelTap, swIfIndex)
	}
	err = i.SpreadTxQueuesOnWorkers(swIfIndex, tun.NumTxQueues)
	if err != nil {
		return err
	}

	podSpec.TunTapSwIfIndex = swIfIndex
	i.log.Infof("pod(add) tun swIfIndex=%d", swIfIndex)

	err = i.DoPodIfNatConfiguration(podSpec, stack, swIfIndex)
	if err != nil {
		return err
	}

	i.SpreadRxQueuesOnWorkers(swIfIndex, podSpec.IfSpec.NumRxQueues)

	err = i.DoPodInterfaceConfiguration(podSpec, stack, podSpec.IfSpec, swIfIndex)
	if err != nil {
		return err
	}

	if doHostSideConf {
		err = i.configureLinux(podSpec, swIfIndex)
		if err != nil {
			return err
		}
	}
	i.log.Infof("pod(add) Done tun swIfIndex=%d", swIfIndex)

	return nil
}

func (i *TunTapPodInterfaceDriver) DeleteInterface(podSpec *model.LocalPodSpec) {
	if podSpec.TunTapSwIfIndex == vpplink.InvalidID {
		return
	}
	i.unconfigureLinux(podSpec)

	i.UndoPodInterfaceConfiguration(podSpec.TunTapSwIfIndex)
	i.UndoPodIfNatConfiguration(podSpec.TunTapSwIfIndex)

	err := i.vpp.DelTap(podSpec.TunTapSwIfIndex)
	if err != nil {
		i.log.Warnf("Error deleting tun[%d] %s", podSpec.TunTapSwIfIndex, err)
	}
	i.log.Infof("pod(del) tun swIfIndex=%d", podSpec.TunTapSwIfIndex)
}

func (i *TunTapPodInterfaceDriver) configureLinux(podSpec *model.LocalPodSpec, swIfIndex uint32) error {
	/* linux side configuration */
	err := ns.WithNetNSPath(podSpec.NetnsName, i.configureNamespaceSideTun(swIfIndex, podSpec))
	if err != nil {
		return errors.Wrapf(err, "Error in linux NS config")
	}
	return nil
}

func (i *TunTapPodInterfaceDriver) unconfigureLinux(podSpec *model.LocalPodSpec) []net.IPNet {
	containerIPs := make([]net.IPNet, 0)
	devErr := ns.WithNetNSPath(podSpec.NetnsName, func(_ ns.NetNS) error {
		dev, err := netlink.LinkByName(podSpec.InterfaceName)
		if err != nil {
			return err
		}
		addresses, err := netlink.AddrList(dev, netlink.FAMILY_ALL)
		if err != nil {
			return err
		}
		for _, addr := range addresses {
			i.log.Infof("pod(del) Found linux address=%s scope=%d", addr.IP.String(), addr.Scope)
			if addr.Scope == unix.RT_SCOPE_LINK {
				continue
			}
			containerIPs = append(containerIPs, net.IPNet{IP: addr.IP, Mask: addr.Mask})
		}
		return nil
	})
	if devErr != nil {
		switch devErr.(type) {
		case netlink.LinkNotFoundError:
			i.log.Warnf("Device to delete not found")
		default:
			i.log.Warnf("error withdrawing interface addresses: %v", devErr)
		}
	}
	return containerIPs
}

// WriteProcSys takes the sysctl path and a string value to set i.e. "0" or "1" and sets the sysctl.
// This method was copied from cni-plugin/internal/pkg/utils/network_linux.go
func WriteProcSys(path, value string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	n, err := f.Write([]byte(value))
	if err == nil && n < len(value) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

// writeProcSys is the sysctl writer suppressIPv6Autoconfiguration uses. It is a
// variable so that a test can make a sysctl fail without a Pod netns; nothing
// in production ever replaces it.
var writeProcSys = WriteProcSys

// configureContainerSysctls configures necessary sysctls required inside the container netns.
// This method was adapted from cni-plugin/internal/pkg/utils/network_linux.go
func (i *TunTapPodInterfaceDriver) configureContainerSysctls(podSpec *model.LocalPodSpec) error {
	hasv4, hasv6 := podSpec.Hasv46()
	ipFwd := "0"
	if podSpec.AllowIPForwarding {
		ipFwd = "1"
	}
	// If an IPv4 address is assigned, then configure IPv4 sysctls.
	if hasv4 {
		i.log.Info("pod(add) Configuring IPv4 forwarding")
		if err := WriteProcSys("/proc/sys/net/ipv4/ip_forward", ipFwd); err != nil {
			return err
		}
	}
	// If an IPv6 address is assigned, then configure IPv6 sysctls.
	if hasv6 {
		i.log.Info("pod(add) Configuring IPv6 forwarding")
		if err := WriteProcSys("/proc/sys/net/ipv6/conf/all/forwarding", ipFwd); err != nil {
			return err
		}
	}
	return nil
}

// suppressIPv6Autoconfiguration turns off the kernel's own IPv6 address
// configuration on the Pod-side interface: router advertisements are not
// accepted and no address, not even a link-local one, is generated from the
// link layer.
//
// D-50 makes the Pod attachment L3-only: the interface carries exactly the
// addresses the CNI decided and nothing else. An address learned from an RA, or
// a generated link-local address, would be a second and unmanaged source of Pod
// addresses, and on an L3 tun there is no Ethernet link for neighbour discovery
// to be about in the first place.
//
// This is part of the interface creation transaction rather than a best-effort
// nicety: a failure fails the ADD and the interface is rolled back (Issue #135
// ruling 8). Continuing with a warning would leave an interface whose address
// set the CNI does not control.
//
// It applies to L3 interfaces only: an L2 pod interface needs its link-local
// address for neighbour discovery, so suppressing address generation there
// would break it.
func (i *TunTapPodInterfaceDriver) suppressIPv6Autoconfiguration(podSpec *model.LocalPodSpec) error {
	acceptRAPath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/accept_ra", podSpec.InterfaceName)
	if err := writeProcSys(acceptRAPath, "0"); err != nil {
		return fmt.Errorf("failed to set %s=0: %s", acceptRAPath, err)
	}
	// addr_gen_mode 1 is IN6_ADDR_GEN_MODE_NONE: no link-local address is
	// generated for this interface.
	addrGenModePath := fmt.Sprintf("/proc/sys/net/ipv6/conf/%s/addr_gen_mode", podSpec.InterfaceName)
	if err := writeProcSys(addrGenModePath, "1"); err != nil {
		return fmt.Errorf("failed to set %s=1 (none): %s", addrGenModePath, err)
	}
	return nil
}

// namespaceSideStep names one step of the Pod-side configuration of a tun.
type namespaceSideStep string

const (
	// stepEnableIPv6 clears disable_ipv6 on the Pod netns, so that the netns
	// accepts IPv6 addresses at all.
	stepEnableIPv6 namespaceSideStep = "enable-ipv6"
	// stepSuppressIPv6Autoconf turns off the kernel's own IPv6 address
	// configuration on the interface (accept_ra, addr_gen_mode).
	stepSuppressIPv6Autoconf namespaceSideStep = "suppress-ipv6-autoconf"
	// stepAddresses adds the addresses the CNI allocated.
	stepAddresses namespaceSideStep = "addresses"
	// stepRoutes adds the device routes.
	stepRoutes namespaceSideStep = "routes"
	// stepMtu sets the MTU on the Pod-side link.
	stepMtu namespaceSideStep = "mtu"
	// stepContainerSysctls applies the forwarding sysctls of the Pod netns.
	stepContainerSysctls namespaceSideStep = "container-sysctls"
)

// namespaceSideSteps is the Pod-side configuration policy of a profile: which
// steps run, and in which order.
//
// The two profiles differ, and are kept apart on purpose (Issue #135 pre-merge
// item 4). Shared code is not shared policy: both profiles execute the same
// step implementations, but the Calico CNI backend keeps the order and the set
// of steps it has always had, because changing what a Calico deployment
// configures inside a Pod is a change to that product and needs its own
// reasons.
//
// The lifecycle profile follows the fixed ADD order of Issue #135 ruling 8:
//
//	IPv6 autoconfiguration suppression -> addresses -> device routes -> MTU
//
// The suppression comes first so that no kernel-generated address exists on the
// interface even briefly, and the addresses come before the routes so that a
// route towards the interface is never installed while it still has no source
// address. The MTU is set again at the end, where the fixed order puts it; the
// tun was already created with it, so the call is idempotent.
func namespaceSideSteps(profile PodInterfaceProfile, hasv6 bool, isL3 bool) []namespaceSideStep {
	steps := make([]namespaceSideStep, 0, 6)
	if hasv6 {
		steps = append(steps, stepEnableIPv6)
	}
	if profile == LifecycleProfile {
		if hasv6 && isL3 {
			// L3 only: an L2 pod interface needs its link-local address for
			// neighbour discovery, so suppressing address generation there
			// would break it.
			steps = append(steps, stepSuppressIPv6Autoconf)
		}
		steps = append(steps, stepAddresses, stepRoutes, stepMtu)
	} else {
		// The Calico order: routes first, then addresses, and no MTU step of
		// its own.
		steps = append(steps, stepRoutes, stepAddresses)
	}
	return append(steps, stepContainerSysctls)
}

// enableIPv6 makes sure IPv6 is enabled in the container/pod network namespace.
func enableIPv6() error {
	if err := WriteProcSys("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0"); err != nil {
		return fmt.Errorf("failed to set net.ipv6.conf.all.disable_ipv6=0: %s", err)
	}
	if err := WriteProcSys("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0"); err != nil {
		return fmt.Errorf("failed to set net.ipv6.conf.default.disable_ipv6=0: %s", err)
	}
	if err := WriteProcSys("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "0"); err != nil {
		return fmt.Errorf("failed to set net.ipv6.conf.lo.disable_ipv6=0: %s", err)
	}
	return nil
}

// addPodAddresses adds the addresses the CNI allocated to the Pod side of the
// tun. A failure fails the ADD: an interface with a missing address is not a
// usable interface.
func (i *TunTapPodInterfaceDriver) addPodAddresses(contTun netlink.Link, podSpec *model.LocalPodSpec, swIfIndex uint32) error {
	for _, containerIP := range podSpec.GetContainerIPs() {
		i.log.Infof("pod(add) tun address swIfIndex=%d linux-ifIndex=%d address=%s", swIfIndex, contTun.Attrs().Index, containerIP.String())
		err := netlink.AddrAdd(contTun, &netlink.Addr{IPNet: containerIP})
		if err != nil {
			return errors.Wrapf(err, "failed to add IP addr to %s: %v", contTun.Attrs().Name, err)
		}
	}
	return nil
}

// AddPodRoutes installs the device routes of the pod spec out of the tun, and
// applies this driver's profile policy to a route that could not be installed.
//
// Installing a route is shared code; what a failed installation means is not
// (Issue #135 merge condition 1):
//
//   - LifecycleProfile returns the failure, so the ADD fails and the caller's
//     cleanup stack rolls the interface back. What a successful CNI ADD means
//     for this service is "the namespace-side L3 realization is complete, the
//     VPP-side realization is complete, and the exact binding is published". A
//     device route that is missing leaves an attachment that looks finished
//     from every side that can be observed — the tun exists, the address is on
//     it, the binding is published, the Cilium endpoint is Ready — while the
//     Pod cannot reach the destinations that route was for. Exactly one
//     component owns the L3 realization of an attachment, and that owner must
//     not report success for a realization it knows failed.
//   - CalicoProfile logs the failure and continues, which is what this code has
//     always done ("in ipv6 '::' already exists"). Shared code is not shared
//     policy: changing what a Calico deployment does with a failed route is a
//     change to that product, needs its own reasons, and is not made here.
//
// routeAdd is a parameter rather than a direct call to netlink.RouteAdd so that
// this step, with the real policy above, can be run where there is no Pod netns
// to install routes into. configureNamespaceSideTun passes netlink.RouteAdd,
// and nothing in production passes anything else.
func (i *TunTapPodInterfaceDriver) AddPodRoutes(routeAdd func(*netlink.Route) error, linkIndex int, podSpec *model.LocalPodSpec, swIfIndex uint32, hasv4 bool, hasv6 bool) error {
	for _, route := range podSpec.Routes {
		isV6 := route.IP.To4() == nil
		if (isV6 && !hasv6) || (!isV6 && !hasv4) {
			i.log.Infof("pod(add) Skipping tun swIfIndex=%d route=%s", swIfIndex, route.String())
			continue
		}
		i.log.Infof("pod(add) tun route swIfIndex=%d linux-ifIndex=%d route=%s", swIfIndex, linkIndex, route.String())
		err := routeAdd(&netlink.Route{
			LinkIndex: linkIndex,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       &route,
		})
		if err == nil {
			continue
		}
		if i.profile != LifecycleProfile {
			// TODO : in ipv6 '::' already exists
			i.log.Errorf("Error adding tun[%d] route for %s", swIfIndex, route.String())
			continue
		}
		return errors.Wrapf(err, "failed to add device route %s on %s", route.String(), podSpec.InterfaceName)
	}
	return nil
}

// setPodMtu sets the MTU on the Pod side of the tun.
func (i *TunTapPodInterfaceDriver) setPodMtu(contTun netlink.Link, podSpec *model.LocalPodSpec) error {
	podMtu := i.computePodMtu(podSpec.Mtu, i.felixConfig, i.ipipEncapRefCounts > 0, i.vxlanEncapRefCounts > 0)
	if err := netlink.LinkSetMTU(contTun, podMtu); err != nil {
		return errors.Wrapf(err, "failed to set mtu %d on %s", podMtu, contTun.Attrs().Name)
	}
	return nil
}

// configureNamespaceSideTun configures the Pod side of the tun, running the
// steps this driver's profile prescribes in the order it prescribes them (see
// namespaceSideSteps).
func (i *TunTapPodInterfaceDriver) configureNamespaceSideTun(swIfIndex uint32, podSpec *model.LocalPodSpec) func(hostNS ns.NetNS) error {
	return func(hostNS ns.NetNS) error {
		contTun, err := netlink.LinkByName(podSpec.InterfaceName)
		if err != nil {
			return errors.Wrapf(err, "failed to lookup %q: %v", podSpec.InterfaceName, err)
		}
		hasv4, hasv6 := podSpec.Hasv46()
		isL3 := podSpec.IfSpec.IsL3 != nil && *podSpec.IfSpec.IsL3

		for _, step := range namespaceSideSteps(i.profile, hasv6, isL3) {
			switch step {
			case stepEnableIPv6:
				i.log.Infof("pod(add) tun in NS has v6 swIfIndex=%d", swIfIndex)
				err = enableIPv6()
			case stepSuppressIPv6Autoconf:
				err = i.suppressIPv6Autoconfiguration(podSpec)
			case stepAddresses:
				err = i.addPodAddresses(contTun, podSpec, swIfIndex)
			case stepRoutes:
				err = i.AddPodRoutes(netlink.RouteAdd, contTun.Attrs().Index, podSpec, swIfIndex, hasv4, hasv6)
			case stepMtu:
				err = i.setPodMtu(contTun, podSpec)
			case stepContainerSysctls:
				if err = i.configureContainerSysctls(podSpec); err != nil {
					err = errors.Wrapf(err, "error configuring sysctls for the container netns, error: %s", err)
				}
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
}
