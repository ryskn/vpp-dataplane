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

type TunTapPodInterfaceDriver struct {
	PodInterfaceDriverData
	felixConfig         *felixConfig.Config
	ipipEncapRefCounts  int /* how many ippools with IPIP */
	vxlanEncapRefCounts int /* how many ippools with VXLAN */
}

func NewTunTapPodInterfaceDriver(vpp *vpplink.VppLink, log *logrus.Entry, felixServerIpam common.FelixServerIpam) *TunTapPodInterfaceDriver {
	i := &TunTapPodInterfaceDriver{
		PodInterfaceDriverData: PodInterfaceDriverData{
			felixServerIpam: felixServerIpam,
		},
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

// configureNamespaceSideTun configures the Pod side of the tun in the order the
// ADD sequence fixes (Issue #135 ruling 8):
//
//	IPv6 autoconfiguration suppression -> addresses -> device routes -> MTU
//
// The suppression comes first so that no kernel-generated address exists on the
// interface even briefly, and the addresses come before the routes so that a
// route towards the interface is never installed while it still has no source
// address.
func (i *TunTapPodInterfaceDriver) configureNamespaceSideTun(swIfIndex uint32, podSpec *model.LocalPodSpec) func(hostNS ns.NetNS) error {
	return func(hostNS ns.NetNS) error {
		contTun, err := netlink.LinkByName(podSpec.InterfaceName)
		if err != nil {
			return errors.Wrapf(err, "failed to lookup %q: %v", podSpec.InterfaceName, err)
		}
		hasv4, hasv6 := podSpec.Hasv46()

		// Do the per-IP version set-up.  Add gateway routes etc.
		if hasv6 {
			i.log.Infof("pod(add) tun in NS has v6 swIfIndex=%d", swIfIndex)
			// Make sure ipv6 is enabled in the container/pod network namespace.
			if err = WriteProcSys("/proc/sys/net/ipv6/conf/all/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.all.disable_ipv6=0: %s", err)
			}
			if err = WriteProcSys("/proc/sys/net/ipv6/conf/default/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.default.disable_ipv6=0: %s", err)
			}
			if err = WriteProcSys("/proc/sys/net/ipv6/conf/lo/disable_ipv6", "0"); err != nil {
				return fmt.Errorf("failed to set net.ipv6.conf.lo.disable_ipv6=0: %s", err)
			}
			if podSpec.IfSpec.IsL3 != nil && *podSpec.IfSpec.IsL3 {
				if err = i.suppressIPv6Autoconfiguration(podSpec); err != nil {
					return err
				}
			}
		}

		// Add the IPs to the container side of the tun before the routes.
		for _, containerIP := range podSpec.GetContainerIPs() {
			i.log.Infof("pod(add) tun address swIfIndex=%d linux-ifIndex=%d address=%s", swIfIndex, contTun.Attrs().Index, containerIP.String())
			err = netlink.AddrAdd(contTun, &netlink.Addr{IPNet: containerIP})
			if err != nil {
				return errors.Wrapf(err, "failed to add IP addr to %s: %v", contTun.Attrs().Name, err)
			}
		}

		for _, route := range podSpec.Routes {
			isV6 := route.IP.To4() == nil
			if (isV6 && !hasv6) || (!isV6 && !hasv4) {
				i.log.Infof("pod(add) Skipping tun swIfIndex=%d route=%s", swIfIndex, route.String())
				continue
			}
			i.log.Infof("pod(add) tun route swIfIndex=%d linux-ifIndex=%d route=%s", swIfIndex, contTun.Attrs().Index, route.String())
			err = netlink.RouteAdd(&netlink.Route{
				LinkIndex: contTun.Attrs().Index,
				Scope:     netlink.SCOPE_UNIVERSE,
				Dst:       &route,
			})
			if err != nil {
				// TODO : in ipv6 '::' already exists
				i.log.Errorf("Error adding tun[%d] route for %s", swIfIndex, route.String())
			}
		}

		// The MTU was already requested when the tun was created; setting it
		// again is idempotent and puts the step where the fixed ADD order puts
		// it, after the device routes.
		podMtu := i.computePodMtu(podSpec.Mtu, i.felixConfig, i.ipipEncapRefCounts > 0, i.vxlanEncapRefCounts > 0)
		if err = netlink.LinkSetMTU(contTun, podMtu); err != nil {
			return errors.Wrapf(err, "failed to set mtu %d on %s", podMtu, contTun.Attrs().Name)
		}

		if err = i.configureContainerSysctls(podSpec); err != nil {
			return errors.Wrapf(err, "error configuring sysctls for the container netns, error: %s", err)
		}

		return nil
	}
}
