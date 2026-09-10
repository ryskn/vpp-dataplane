// Copyright (C) 2019 Cisco Systems Inc.
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

package cni

import (
	"fmt"
	"net"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/pkg/errors"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/watchers"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

type PodNSNotFoundErr struct {
	ns string
}

func (e PodNSNotFoundErr) Error() string {
	return fmt.Sprintf("Netns '%s' doesn't exist, skipping", e.ns)
}

type NetworkPod struct {
	NetworkVni  uint32
	ContainerIP *net.IPNet
}

func (s *Server) checkAvailableBuffers(podSpec *model.LocalPodSpec) error {
	podBuffers := podSpec.GetBuffersNeeded()
	buffers := podBuffers
	existingPods := uint64(len(s.podInterfaceMap))
	for _, existingPodSpec := range s.podInterfaceMap {
		buffers += existingPodSpec.GetBuffersNeeded()
	}
	s.log.Infof("pod(add) checking available buffers, %d existing pods, request for this pod: %d, total request: %d / %d", existingPods, podBuffers, buffers, s.availableBuffers)
	if buffers > s.availableBuffers {
		return errors.Errorf("Cannot create interface: Out of buffers: available buffers = %d, buffers needed = %d. "+
			"Increase buffers-per-numa in the VPP configuration or reduce CALICOVPP_TAP_RING_SIZE to allow more "+
			"pods to be scheduled. Limit the number of pods per node to prevent this error", s.availableBuffers, buffers)
	}
	return nil
}

func (s *Server) v4v6VrfsExistInVPP(podSpec *model.LocalPodSpec) bool {
	podSpec.V4VrfID = types.InvalidID
	podSpec.V6VrfID = types.InvalidID

	vrfs, err := s.vpp.ListVRFs()
	if err != nil {
		s.log.Errorf("Error listing VRFs %s", err)
		return false
	}

	for _, vrf := range vrfs {
		for _, ipFamily := range vpplink.IPFamilies {
			if vrf.Name == podSpec.GetVrfTag(ipFamily, "") {
				podSpec.SetVrfID(vrf.VrfID, ipFamily)
			}
		}
		if podSpec.V4VrfID != types.InvalidID &&
			podSpec.V6VrfID != types.InvalidID {
			return true
		}
	}

	if (podSpec.V4VrfID != types.InvalidID) !=
		(podSpec.V6VrfID != types.InvalidID) {
		s.log.Errorf("Partial VRF state v4=%d v6=%d key=%s",
			podSpec.V4VrfID,
			podSpec.V6VrfID,
			podSpec.Key(),
		)
	}

	return false
}

func (s *Server) removeConflictingContainers(newAddresses []net.IP, networkName string) {
	addrMap := make(map[string]model.LocalPodSpec)
	for _, podSpec := range s.podInterfaceMap {
		for _, addr := range podSpec.ContainerIPs {
			if podSpec.NetworkName == networkName {
				addrMap[addr.String()] = podSpec
			}
		}
	}
	podSpecsToDelete := make(map[string]model.LocalPodSpec)
	for _, newAddr := range newAddresses {
		podSpec, found := addrMap[newAddr.String()]
		if found {
			s.log.Warnf("podSpec conflict newAddr=%s, podSpec=%s", newAddr, podSpec.String())
			podSpecsToDelete[podSpec.Key()] = podSpec
		}
	}
	for _, podSpec := range podSpecsToDelete {
		s.log.Infof("Deleting conflicting podSpec=%s", podSpec.Key())
		// DelVppInterface withdraws the exact tuple this pod spec published,
		// before destroying its interface, when the durable state has one; when
		// it has none nothing is guessed and the plugin's interface delete
		// callback is the safety net (Issue #135 ruling 5).
		s.DelVppInterface(&podSpec)
		delete(s.podInterfaceMap, podSpec.Key())
		err := model.PersistCniServerState(
			model.NewCniServerState(s.podInterfaceMap),
			config.CniServerStateFilename,
		)
		if err != nil {
			s.log.Errorf("CNI state persist errored %v", err)
		}
	}
}

// AddVppInterface performs the networking for the given config and IPAM result
func (s *Server) AddVppInterface(podSpec *model.LocalPodSpec, doHostSideConf bool) (tunTapSwIfIndex uint32, err error) {
	// Declared here because the error path below is reached with goto, which
	// cannot jump over a declaration.
	var stack *vpplink.CleanupStack
	var earlySwIfIndex uint32
	var done bool

	err = ns.IsNSorErr(podSpec.NetnsName)
	if err != nil {
		return vpplink.InvalidID, PodNSNotFoundErr{podSpec.NetnsName}
	}

	if podSpec.NetworkName != "" {
		s.log.Infof("Checking network exists")
		_, ok := s.networkDefinitions.Load(podSpec.NetworkName)
		if !ok {
			s.log.Errorf("network %s does not exist", podSpec.NetworkName)
			return vpplink.InvalidID, errors.Errorf("network %s does not exist", podSpec.NetworkName)
		}
	}

	// Check if the VRFs already exist in VPP,
	// if yes we postulate the pod is already well setup
	if s.vrfsExistInVpp(podSpec) {
		s.log.Infof("VRF already exists in VPP podSpec=%s", podSpec.Key())
		if s.ifBinding != nil {
			// The VRFs surviving is not evidence that the interface did.
			// Verify the stored handle against a fresh dump instead of
			// trusting the saved sw_if_index, which VPP may have handed to a
			// different interface in the meantime, and fail rather than
			// re-resolve the binding onto whatever handle is current now
			// (00 §2.12.7 prohibition 4).
			live, err := s.storedHandleStillLive(podSpec)
			if err != nil {
				return vpplink.InvalidID, errors.Wrapf(err,
					"cannot verify the stored interface handle of pod %s", podSpec.Key())
			}
			if !live {
				return vpplink.InvalidID, errors.Errorf(
					"pod %s has VPP VRFs but its published interface handle %s is no longer live; "+
						"refusing to re-resolve the binding onto a different handle",
					podSpec.Key(), podSpec.PublishedIfAttachment)
			}
			// Exact same tuple: replaying the ADD is idempotent
			// (02 §8.1 rule 4). No cleanup stack is passed, because this call
			// created nothing that a failure would have to roll back.
			if err := s.publishIfAttachment(podSpec, nil); err != nil {
				return vpplink.InvalidID, err
			}
		}
		return podSpec.TunTapSwIfIndex, nil
	}

	// We do not have a VRF in VPP for this pod, clear the existing pod status
	// If there was state left, we assume VPP restarted and the state is not valid anymore
	//
	// The interface that state described is therefore gone, and with it the
	// meaning of any binding published for it. Withdraw the old tuple before
	// forgetting it, so the plugin's table does not keep a binding this side
	// can no longer name; the new interface publishes a new binding under the
	// normal ADD contract (00 §2.12.8).
	s.revokeIfAttachment(podSpec)
	podSpec.LocalPodSpecStatus = *model.NewLocalPodSpecStatus()

	// Do we already have a pod with this address in VPP ?
	// in this case, clean it up otherwise on the other pod's
	// deletion our route in the main VRF will be removed
	//
	// As we did not find the VRF in VPP, we shouldn't find
	// ourselves in s.podInterfaceMap
	s.removeConflictingContainers(podSpec.ContainerIPs, podSpec.NetworkName)
	stack = vpplink.NewCleanupStack()
	err = s.checkAvailableBuffers(podSpec)
	if err != nil {
		goto err
	}

	// Everything that needs a live VPP happens here, under the cleanup stack
	// this function owns.
	earlySwIfIndex, done, err = s.realizePodDataplane(podSpec, stack, doHostSideConf)
	if err != nil {
		goto err
	}
	if done {
		// A memif in a secondary network is reported without a binding: the
		// lifecycle profile rejects that combination at the request, and the
		// Calico backend publishes no bindings at all. Keeping the early
		// return here preserves what that path did before.
		return earlySwIfIndex, nil
	}

	// Publish the CNI attachment identity against the interface handle that
	// was just created, and do it here, while the cleanup stack is still in
	// scope: a failed publication has to roll the interface back and make the
	// CNI ADD fail (00 §2.12.6, completion criteria 1 and 3 of §2.12.9). This
	// is the last step of AddVppInterface, so the caller cannot return success
	// to the CNI before the binding ADD was acknowledged.
	err = s.publishIfAttachment(podSpec, stack)
	if err != nil {
		s.log.Errorf("failed to publish the CNI attachment binding: %s", err)
		goto err
	}
	return podSpec.TunTapSwIfIndex, err

err:
	s.log.Errorf("Error, try a cleanup %+v", err)
	stack.Execute()
	return vpplink.InvalidID, errors.Wrapf(err, "Error creating interface")

}

// realizePodDataplane creates the Pod's dataplane, using the seam when a test
// installed one (see realizePodInterfacesFn).
func (s *Server) realizePodDataplane(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, doHostSideConf bool) (uint32, bool, error) {
	if s.realizePodInterfacesFn != nil {
		return s.realizePodInterfacesFn(podSpec, stack, doHostSideConf)
	}
	return s.realizePodInterfaces(podSpec, stack, doHostSideConf)
}

// realizePodInterfaces creates the per-pod VRFs, the interfaces themselves and
// their routing: it is the whole of the ADD that needs a live VPP.
//
// It is a separate step from AddVppInterface so that the publication barrier —
// where the binding ADD sits relative to the cleanup stack and to the success
// return — is expressed in code that can be run without VPP, and therefore
// tested rather than only inspected (Issue #135 pre-merge item 3).
//
// Everything it creates is pushed onto the caller's cleanup stack, so a failure
// after it returns still rolls the interface back.
//
// done reports the one case that finishes the ADD early: a memif in a secondary
// network, which is reported by its own sw_if_index and publishes no binding.
func (s *Server) realizePodInterfaces(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, doHostSideConf bool) (earlySwIfIndex uint32, done bool, err error) {
	var swIfIndex uint32
	var isL3 bool
	var vni uint32

	s.log.Infof("pod(add) VRF")
	err = s.CreatePodVRF(podSpec, stack)
	if err != nil {
		goto err
	}

	s.log.Infof("pod(add) loopback")
	err = s.loopbackDriver.CreateInterface(podSpec, stack)
	if err != nil {
		goto err
	}

	if podSpec.NetworkName == "" || !podSpec.EnableMemif { // The only case where tun is not created is when we create memif interface in non main network
		s.log.Infof("pod(add) tuntap")
		err = s.tuntapDriver.CreateInterface(podSpec, stack, doHostSideConf)
		if err != nil {
			goto err
		}
	}

	if podSpec.EnableMemif && *config.GetCalicoVppFeatureGates().MemifEnabled {
		s.log.Infof("pod(add) memif")
		err = s.memifDriver.CreateInterface(podSpec, stack, doHostSideConf)
		if err != nil {
			goto err
		}
	}

	if podSpec.EnableVCL && *config.GetCalicoVppFeatureGates().VCLEnabled {
		s.log.Infof("pod(add) VCL socket")
		err = s.vclDriver.CreateInterface(podSpec, stack)
		if err != nil {
			goto err
		}
	}

	/* Routes */
	if podSpec.EnableVCL {
		s.log.Infof("pod(add) Punt routes")
		err = s.SetupPuntRoutes(podSpec, stack, podSpec.TunTapSwIfIndex)
		if err != nil {
			goto err
		}
		err = s.CreateVRFRoutesToPod(podSpec, stack)
		if err != nil {
			goto err
		}
	} else {
		pblswIfIndex, _ := podSpec.GetParamsForIfType(podSpec.PortFilteredIfType)
		swIfIndex, isL3 = podSpec.GetParamsForIfType(podSpec.DefaultIfType)
		if swIfIndex != types.InvalidID {
			s.log.Infof("pod(add) Default routes to swIfIndex=%d isL3=%t", swIfIndex, isL3)
			err = s.RoutePodInterface(podSpec, stack, swIfIndex, isL3, pblswIfIndex != types.InvalidID)
			if err != nil {
				goto err
			}
		} else {
			s.log.Warn("No default if type for pod")
		}
		if pblswIfIndex != types.InvalidID {
			err = s.CreateVRFRoutesToPod(podSpec, stack)
			if err != nil {
				goto err
			}
		}
	}

	swIfIndex, isL3 = podSpec.GetParamsForIfType(podSpec.PortFilteredIfType)
	if swIfIndex != types.InvalidID {
		s.log.Infof("pod(add) PBL routes to %d l3?:%t", swIfIndex, isL3)
		err = s.RoutePblPortsPodInterface(podSpec, stack, swIfIndex, isL3)
		if err != nil {
			goto err
		}
	}

	if podSpec.NetworkName != "" {
		value, ok := s.networkDefinitions.Load(podSpec.NetworkName)
		if !ok {
			s.log.Errorf("network not found %s", podSpec.NetworkName)
		} else {
			networkDefinition, ok := value.(*watchers.NetworkDefinition)
			if !ok || networkDefinition == nil {
				panic("networkDefinition not of type *watchers.NetworkDefinition")
			}
			vni = networkDefinition.Vni
		}
	}

	s.log.Infof("pod(add) announcing pod Addresses")
	for _, containerIP := range podSpec.GetContainerIPs() {
		common.SendEvent(common.CalicoVppEvent{
			Type: common.LocalPodAddressAdded,
			New:  NetworkPod{ContainerIP: containerIP, NetworkVni: vni},
		})
	}

	// Host ports are CNAT translations, which is Calico's service dataplane.
	// The lifecycle profile programs none of it: Cilium owns NAT, policy and
	// services there, Calico's CNAT is not deployed, and host ports are out of
	// the v1 scope for exactly that reason (Issue #135 rulings 2 and 3). The
	// request this profile serves carries no host port, so this is a statement
	// of what the profile programs rather than a change of behaviour — which is
	// the point: not programming CNAT must be a decision, not a consequence of
	// an empty list.
	if !s.lifecycleProfile {
		s.log.Infof("pod(add) HostPorts")
		err = s.AddHostPort(podSpec, stack)
		if err != nil {
			goto err
		}
	}
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PodAdded,
		New:  podSpec,
	})
	if podSpec.NetworkName != "" && podSpec.EnableMemif {
		return podSpec.MemifSwIfIndex, true, nil
	}

	s.log.Infof("pod(add) activate strict RPF on interface")
	err = s.ActivateStrictRPF(podSpec, stack)
	if err != nil {
		s.log.Errorf("failed to activate rpf strict on interface : %s", err)
		goto err
	}

	return vpplink.InvalidID, false, nil

err:
	// The caller owns the cleanup stack and runs it: a failure here and a
	// failure of the binding publication that follows must roll the same
	// things back, in the same place.
	return vpplink.InvalidID, false, err
}

// CleanUpVPPNamespace deletes the devices in the network namespace.
//
// Teardown is three independent operations (Issue #135 ruling 6):
//
//  1. withdraw the published IF-4 binding, using the exact tuple that was
//     written; best effort, and its failure never stops operation 2
//  2. destroy the VPP-side interfaces
//  3. clean up the Pod side of the interface
//
// Only operation 3 needs the Pod network namespace to still exist. A namespace
// that is already gone therefore no longer causes the binding to stay published
// and the VPP interface to stay alive, which is what the previous early return
// did.
func (s *Server) DelVppInterface(podSpec *model.LocalPodSpec) {
	netnsPresent := ns.IsNSorErr(podSpec.NetnsName) == nil
	if !netnsPresent {
		s.log.Infof("pod(del) netns '%s' doesn't exist, skipping the namespace-side cleanup only", podSpec.NetnsName)
	}

	// Operation 1, first and unconditionally: the binding names an identity
	// and a handle, neither of which lives in the Pod netns.
	s.revokeIfAttachment(podSpec)

	// Redirect-to-host is Calico's punt classifier: the ADD side of it lives in
	// the Calico CNI backend (Server.Add and its rescanState), never in this
	// profile, so there is nothing here for the DEL side to remove. Removing it
	// anyway would detach classify table index 0 — the zero value of
	// RedirectToHostClassifyTableIndex, which this profile never fills in —
	// from the interface, on nothing more than a configuration key being
	// present in a ConfigMap this container shares with vpp-manager.
	if !s.lifecycleProfile &&
		len(config.GetCalicoVppInitialConfig().RedirectToHostRules) != 0 && podSpec.NetworkName == "" {
		err := s.DelRedirectToHostOnInterface(podSpec.TunTapSwIfIndex)
		if err != nil {
			s.log.Error(err)
		}
	}

	if !s.v4v6VrfsExistInVPP(podSpec) {
		s.log.Warnf("pod(del) VRF for netns '%s' doesn't exist", podSpec.NetnsName)
		// The per-pod VRFs are gone, so the routing state this function would
		// tear down is gone with them. The interfaces may not be: destroy the
		// ones whose recorded handle is provably still ours. Outside the
		// lifecycle profile there is no incarnation to prove that with, so the
		// stored sw_if_index is not trusted and the old behaviour of leaving
		// the interfaces to VPP is kept.
		if s.lifecycleProfile {
			s.delOrphanedVppInterfaces(podSpec, netnsPresent)
		}
		return
	}

	// The counterpart of the ADD-side gate: this profile published no CNAT
	// translation, so there is none to withdraw.
	if !s.lifecycleProfile {
		s.DelHostPort(podSpec)
	}

	var vni uint32
	deleteLocalPodAddress := true
	if podSpec.NetworkName != "" {
		value, ok := s.networkDefinitions.Load(podSpec.NetworkName)
		if !ok {
			deleteLocalPodAddress = false
		} else {
			networkDefinition, ok := value.(*watchers.NetworkDefinition)
			if !ok || networkDefinition == nil {
				panic("networkDefinition not of type *watchers.NetworkDefinition")
			}
			vni = networkDefinition.Vni
		}
	}
	if deleteLocalPodAddress {
		for _, containerIP := range podSpec.GetContainerIPs() {
			common.SendEvent(common.CalicoVppEvent{
				Type: common.LocalPodAddressDeleted,
				Old:  NetworkPod{ContainerIP: containerIP, NetworkVni: vni},
			})

		}
	}

	/* Routes */
	if podSpec.EnableVCL {
		if podSpec.TunTapSwIfIndex != vpplink.InvalidID {
			s.log.Infof("pod(del) routes to podVRF")
			s.DeleteVRFRoutesToPod(podSpec)
			s.log.Infof("pod(del) punt routes")
			s.RemovePuntRoutes(podSpec, podSpec.TunTapSwIfIndex)
		}
	} else {
		pblswIfIndex, _ := podSpec.GetParamsForIfType(podSpec.PortFilteredIfType)
		if pblswIfIndex != types.InvalidID {
			s.DeleteVRFRoutesToPod(podSpec)
		}
		swIfIndex, _ := podSpec.GetParamsForIfType(podSpec.DefaultIfType)
		if swIfIndex != types.InvalidID {
			s.log.Infof("pod(del) default routes to %d", swIfIndex)
			_, isL3 := podSpec.GetParamsForIfType(podSpec.DefaultIfType)
			s.UnroutePodInterface(podSpec, swIfIndex, pblswIfIndex != types.InvalidID, isL3)
		}
	}
	pblswIfIndex, _ := podSpec.GetParamsForIfType(podSpec.PortFilteredIfType)
	if pblswIfIndex != types.InvalidID {
		s.log.Infof("pod(del) PBL routes to %d", pblswIfIndex)
		_, isL3 := podSpec.GetParamsForIfType(podSpec.PortFilteredIfType)
		s.UnroutePblPortsPodInterface(podSpec, pblswIfIndex, isL3)
	}

	/* RPF */
	s.log.Infof("pod(del) RPF VRF")
	s.DeactivateStrictRPF(podSpec)

	/* Interfaces */
	if podSpec.EnableVCL && *config.GetCalicoVppFeatureGates().VCLEnabled {
		s.log.Infof("pod(del) VCL")
		s.vclDriver.DeleteInterface(podSpec)
	}
	if podSpec.EnableMemif && *config.GetCalicoVppFeatureGates().MemifEnabled {
		s.log.Infof("pod(del) memif")
		s.memifDriver.DeleteInterface(podSpec)
	}
	s.log.Infof("pod(del) tuntap")
	s.tuntapDriver.DeleteInterface(podSpec)
	s.log.Infof("pod(del) loopback")
	s.loopbackDriver.DeleteInterface(podSpec)

	s.log.Infof("pod(del) VRF")
	s.DeletePodVRF(podSpec)
	common.SendEvent(common.CalicoVppEvent{
		Type: common.PodDeleted,
		Old:  podSpec,
	})
}

// delOrphanedVppInterfaces performs teardown operation 2 for a pod whose
// per-pod VRFs are already gone.
//
// The stored sw_if_index alone is not enough to act on: VPP may have given it
// to a different interface, and destroying that one would tear down another
// Pod's datapath. The recorded incarnation is what makes the handle provable
// (D-31), so the interfaces are destroyed only when the published tuple is
// still the live one; otherwise nothing is touched and the plugin's interface
// delete callback remains the safety net (02 §8.1 rule 7).
func (s *Server) delOrphanedVppInterfaces(podSpec *model.LocalPodSpec, netnsPresent bool) {
	if podSpec.TunTapSwIfIndex == vpplink.InvalidID {
		return
	}
	if s.ifBinding == nil {
		return
	}
	live, err := s.storedHandleStillLive(podSpec)
	if err != nil {
		s.log.WithError(err).Warnf("pod(del) cannot verify the stored handle of %s, leaving its VPP interfaces alone",
			podSpec.Key())
		return
	}
	if !live {
		s.log.Infof("pod(del) stored handle of %s is no longer live, leaving its VPP interfaces alone",
			podSpec.Key())
		return
	}
	plan := planTeardown(podSpec.PublishedIfAttachment != nil, netnsPresent, true /* vppStateStillOwned */)
	if !plan.DeleteVppInterfaces {
		return
	}
	s.log.Infof("pod(del) destroying the VPP interfaces of %s without its per-pod VRFs", podSpec.Key())
	s.tuntapDriver.DeleteInterface(podSpec)
	s.loopbackDriver.DeleteInterface(podSpec)
}
