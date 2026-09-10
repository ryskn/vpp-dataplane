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
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/cni/model"
	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// PodInterfaceProfile selects which configuration policy a pod interface
// driver applies, both inside the Pod and in VPP.
//
// It is chosen explicitly when the server is built, by the entry point that
// knows which product it is running (Issue #135 pre-merge item 4). It is never
// inferred from the interface name, the pod spec or anything else observable at
// run time: two profiles that differ in what they configure must differ by a
// decision someone made, not by a guess.
type PodInterfaceProfile int

const (
	// CalicoProfile is the Calico CNI backend. Its configuration is the one
	// Calico has always applied, and it stays that way: the differences below
	// are properties of the SRv6 endpoint context contract, not bug fixes that
	// Calico deployments are owed. Changing what a Calico deployment programs
	// is a separate change with its own reasons.
	CalicoProfile PodInterfaceProfile = iota
	// LifecycleProfile is the Pod interface lifecycle service, whose Pod-side
	// configuration follows the fixed ADD order of D-50 and Issue #135
	// ruling 8, and which programs no Calico NAT, policy or service dataplane
	// at all: Cilium owns NAT, policy and services in that profile, and
	// Calico's CNAT is not even deployed (Issue #135 ruling 3).
	LifecycleProfile
)

func (p PodInterfaceProfile) String() string {
	if p == LifecycleProfile {
		return "lifecycle"
	}
	return "calico"
}

type PodInterfaceDriverData struct {
	log *logrus.Entry
	vpp *vpplink.VppLink
	// Name is the interface kind this driver creates ("tun", "memif", ...).
	Name         string
	NDataThreads int
	// snatPolicy decides whether a Pod address is source-NATed. It is always
	// injected: see common.SNATPolicy.
	snatPolicy common.SNATPolicy
	// profile decides the configuration policy of this driver: which steps run
	// and in which order. The code that performs each step is shared between
	// the profiles; the policy is not.
	profile PodInterfaceProfile
	// podIfNat is the CNAT programming policy of this driver's profile. It is
	// chosen once, at construction, by newPodIfNatConfiguration: the lifecycle
	// profile gets a value that holds no VPP handle at all, so no CNAT call
	// exists for it to make.
	podIfNat podIfNatConfiguration
}

// newPodInterfaceDriverData builds the state every pod interface driver shares.
//
// The profile is a construction-time parameter of every driver, not of the tun
// driver alone: the CNAT configuration below is applied by the loopback and
// memif drivers too, so each of them has to know which product it is part of.
func newPodInterfaceDriverData(
	vpp *vpplink.VppLink,
	log *logrus.Entry,
	snatPolicy common.SNATPolicy,
	profile PodInterfaceProfile,
	name string,
) PodInterfaceDriverData {
	snatPolicy = requireSNATPolicy(snatPolicy, name)
	return PodInterfaceDriverData{
		log:        log,
		vpp:        vpp,
		Name:       name,
		snatPolicy: snatPolicy,
		profile:    profile,
		podIfNat:   newPodIfNatConfiguration(profile, vpp, snatPolicy),
	}
}

// requireSNATPolicy rejects a driver that would be built without an SNAT
// authority, so that the omission is a construction failure and never a
// silent "no SNAT" answer in the data path (Issue #135 pre-merge item 1).
func requireSNATPolicy(snatPolicy common.SNATPolicy, driver string) common.SNATPolicy {
	if snatPolicy == nil {
		panic("cannot build the " + driver + " pod interface driver without an SNAT policy: " +
			"inject common.NoSNATPolicy to state that no address needs SNAT")
	}
	return snatPolicy
}

// cnatDataplane is the part of the VPP binary API that Calico's CNAT
// configuration of a pod interface uses.
//
// It is an interface so that what a profile programs is observable in a test
// without a live VPP. Production always passes the real *vpplink.VppLink.
type cnatDataplane interface {
	EnableDisableCnatSNAT(swIfIndex uint32, isIP6 bool, isEnable bool) error
	RegisterPodInterface(swIfIndex uint32) error
	RemovePodInterface(swIfIndex uint32) error
	CnatEnableFeatures(swIfIndex uint32) error
}

// podIfNatConfiguration is the CNAT programming policy of a profile: what a
// driver does to a pod interface on the NAT side when it creates it, and what
// it undoes when it destroys it.
type podIfNatConfiguration interface {
	// configure programs the CNAT dataplane for swIfIndex, pushing the undo of
	// everything it programmed onto stack.
	configure(log *logrus.Entry, podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, swIfIndex uint32) error
	// unconfigure removes what configure programmed. It is best effort: it runs
	// on the teardown path, where there is nothing left to fail into.
	unconfigure(log *logrus.Entry, swIfIndex uint32)
}

// newPodIfNatConfiguration returns the CNAT programming policy of profile.
//
// The lifecycle profile gets noPodIfNat, which holds no cnatDataplane: there is
// no CNAT call for it to make, successful or otherwise. That is the point. The
// Stage 0 profile does not deploy Calico's CNAT plugin configuration at all —
// Cilium owns NAT, policy and services there (Issue #135 ruling 3) — so
// cnat_snat_policy_add_del_if returns "Feature disabled by configuration"
// (-30). Tolerating that error would be the wrong repair: a call that must not
// be made is not the same thing as a call that is allowed to fail, and an
// error-tolerant call would also swallow the same -30 in a Calico deployment
// where CNAT is supposed to be configured and is not.
func newPodIfNatConfiguration(profile PodInterfaceProfile, vpp cnatDataplane, snatPolicy common.SNATPolicy) podIfNatConfiguration {
	if profile == LifecycleProfile {
		return noPodIfNat{}
	}
	return calicoPodIfNat{vpp: vpp, snatPolicy: snatPolicy}
}

// noPodIfNat is the CNAT policy of a profile that has no CNAT: it programs
// nothing and it undoes nothing.
type noPodIfNat struct{}

func (noPodIfNat) configure(log *logrus.Entry, podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, swIfIndex uint32) error {
	if log != nil {
		log.Debugf("pod(add) interface[%d] is not registered with CNAT: this profile has no Calico NAT, policy or service dataplane", swIfIndex)
	}
	return nil
}

func (noPodIfNat) unconfigure(log *logrus.Entry, swIfIndex uint32) {}

// calicoPodIfNat is the CNAT policy of the Calico CNI backend: the pod
// interface is registered with CNAT, its NAT feature arcs are enabled, and its
// addresses are source-NATed when the IP pool authority says so.
type calicoPodIfNat struct {
	vpp        cnatDataplane
	snatPolicy common.SNATPolicy
}

func (c calicoPodIfNat) configure(log *logrus.Entry, podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, swIfIndex uint32) error {
	for _, ipFamily := range vpplink.IPFamilies {
		if podSpec.NeedsSnat(c.snatPolicy, ipFamily.IsIP6) {
			log.Infof("pod(add) Enable interface[%d] SNAT", swIfIndex)
			err := c.vpp.EnableDisableCnatSNAT(swIfIndex, ipFamily.IsIP6, true /*isEnable*/)
			if err != nil {
				return errors.Wrapf(err, "Error enabling %s snat", ipFamily.Str)
			} else {
				stack.Push(c.vpp.EnableDisableCnatSNAT, swIfIndex, ipFamily.IsIP6, false)
			}
		}
	}

	err := c.vpp.RegisterPodInterface(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error registering pod interface")
	} else {
		stack.Push(c.vpp.RemovePodInterface, swIfIndex)
	}

	err = c.vpp.CnatEnableFeatures(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error configuring nat on pod interface")
	}

	return nil
}

func (c calicoPodIfNat) unconfigure(log *logrus.Entry, swIfIndex uint32) {
	err := c.vpp.RemovePodInterface(swIfIndex)
	if err != nil {
		log.Errorf("error deregistering pod interface: %v", err)
	}

	for _, ipFamily := range vpplink.IPFamilies {
		err = c.vpp.EnableDisableCnatSNAT(swIfIndex, ipFamily.IsIP6, false /*isEnable*/)
		if err != nil {
			log.Errorf("Error disabling %s snat %v", ipFamily.Str, err)
		}
	}
}

func (i *PodInterfaceDriverData) SpreadTxQueuesOnWorkers(swIfIndex uint32, numTxQueues int) (err error) {
	i.log.WithFields(map[string]interface{}{
		"swIfIndex": swIfIndex,
	}).Debugf("Spreading %d TX queues on %d workers for pod interface: %v", numTxQueues, i.NDataThreads, i.Name)

	// set first tx queue for main worker
	err = i.vpp.SetInterfaceTxPlacement(swIfIndex, 0 /* queue */, 0 /* worker */)
	if err != nil {
		return err
	}
	// share tx queues between the rest of workers
	if i.NDataThreads > 0 {
		for txq := 1; txq < numTxQueues; txq++ {
			err = i.vpp.SetInterfaceTxPlacement(swIfIndex, txq /* queue */, (txq-1)%(i.NDataThreads)+1 /* worker */)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (i *PodInterfaceDriverData) SpreadRxQueuesOnWorkers(swIfIndex uint32, numRxQueues int) {
	i.log.WithFields(map[string]interface{}{
		"swIfIndex": swIfIndex,
	}).Debugf("Spreading %d RX queues on %d workers for pod interface: %v", numRxQueues, i.NDataThreads, i.Name)

	if i.NDataThreads > 0 {
		for queue := 0; queue < numRxQueues; queue++ {
			worker := (int(swIfIndex)*numRxQueues + queue) % i.NDataThreads
			err := i.vpp.SetInterfaceRxPlacement(swIfIndex, queue, worker, false /* main */)
			if err != nil {
				i.log.Warnf("failed to set if[%d] queue:%d worker:%d (tot workers %d): %v", swIfIndex, queue, worker, i.NDataThreads, err)
			}
		}
	}
}

// UndoPodIfNatConfiguration removes the CNAT configuration this driver's
// profile applied to swIfIndex. Under LifecycleProfile there is none, and no
// VPP call is made.
func (i *PodInterfaceDriverData) UndoPodIfNatConfiguration(swIfIndex uint32) {
	i.podIfNat.unconfigure(i.log, swIfIndex)
}

// DoPodIfNatConfiguration applies this driver's profile CNAT configuration to
// swIfIndex, pushing its undo onto stack.
//
// Under LifecycleProfile it makes no CNAT call at all: see
// newPodIfNatConfiguration.
func (i *PodInterfaceDriverData) DoPodIfNatConfiguration(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, swIfIndex uint32) (err error) {
	return i.podIfNat.configure(i.log, podSpec, stack, swIfIndex)
}

func (i *PodInterfaceDriverData) UndoPodInterfaceConfiguration(swIfIndex uint32) {
	err := i.vpp.InterfaceAdminDown(swIfIndex)
	if err != nil {
		i.log.Errorf("InterfaceAdminDown errored %s", err)
	}
}

func (i *PodInterfaceDriverData) DoPodInterfaceConfiguration(podSpec *model.LocalPodSpec, stack *vpplink.CleanupStack, ifSpec config.InterfaceSpec, swIfIndex uint32) (err error) {
	for _, ipFamily := range vpplink.IPFamilies {
		vrfID := podSpec.GetVrfID(ipFamily)
		err = i.vpp.SetInterfaceVRF(swIfIndex, vrfID, ipFamily.IsIP6)
		if err != nil {
			return errors.Wrapf(err, "error setting vpp if[%d] in pod vrf", swIfIndex)
		}
	}

	if !*ifSpec.IsL3 {
		/* L2 */
		err = i.vpp.SetPromiscOn(swIfIndex)
		if err != nil {
			return errors.Wrapf(err, "Error setting interface promisc")
		}
	}

	err = i.vpp.SetInterfaceMtu(swIfIndex, vpplink.CalicoVppMaxMTu)
	if err != nil {
		return errors.Wrapf(err, "Error setting MTU on pod interface")
	}

	err = i.vpp.InterfaceAdminUp(swIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error setting new pod if up")
	}

	/*
	 * VPP patch "ip-neighbor: do not use sas to determine NS source address"
	 * makes NS always use the interface’s link‑local address. CalicoVPP pod
	 * interfaces are unnumbered and never had IPv6 explicitly enabled, so no
	 * link‑local address existed on the pod interface. This breaks IPv6
	 * neighbor resolution and traffic. Enable IPv6 on L2 pod interfaces for
	 * ND to work; L3 pod interfaces do not have an Ethernet link to resolve.
	 */
	_, hasv6 := podSpec.Hasv46()
	if hasv6 && !*ifSpec.IsL3 {
		err = i.vpp.EnableInterfaceIP6(swIfIndex)
		if err != nil {
			return errors.Wrapf(err, "error enabling ipv6 on pod interface")
		}
	}

	err = i.vpp.SetInterfaceRxMode(swIfIndex, types.AllQueues, ifSpec.GetRxModeWithDefault(types.AdaptativeRxMode))
	if err != nil {
		return errors.Wrapf(err, "error SetInterfaceRxMode on pod if interface")
	}

	err = i.vpp.InterfaceSetUnnumbered(swIfIndex, podSpec.LoopbackSwIfIndex)
	if err != nil {
		return errors.Wrapf(err, "error setting interface unnumbered")
	}

	return nil
}
