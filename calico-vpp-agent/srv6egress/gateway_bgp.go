//go:build linux

package srv6egress

import (
	"fmt"
	"net"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
)

// bgpSIDAdvertiser advertises a gateway tenant SID as a plain /128 IPv6 route
// with this node as the next-hop, so headend nodes route the SR-encapsulated
// packet (outer dst == the SID) to this gateway. It mirrors how Calico
// advertises assigned prefixes (common.MakePath + a BGPPath event); the egress
// gateway's terminal SID is in no Calico IPAM block, hence the direct route.
type bgpSIDAdvertiser struct {
	ip4, ip6 *net.IP
}

// NewBGPSIDAdvertiser builds an advertiser using this node's BGP addresses.
func NewBGPSIDAdvertiser(spec *common.LocalNodeSpec) SIDAdvertiser {
	ip4, ip6 := common.GetBGPSpecAddresses(spec)
	return &bgpSIDAdvertiser{ip4: ip4, ip6: ip6}
}

func (a *bgpSIDAdvertiser) AdvertiseSID(sid net.IP) error {
	p, err := common.MakePath(sid.String()+"/128", false /* withdraw */, a.ip4, a.ip6, 0, 0)
	if err != nil {
		return fmt.Errorf("make path for SID %s: %w", sid, err)
	}
	common.SendEvent(common.CalicoVppEvent{Type: common.BGPPathAdded, New: p})
	return nil
}

func (a *bgpSIDAdvertiser) WithdrawSID(sid net.IP) error {
	// DeletePath matches on the NLRI, so the path is built the same way (the
	// withdrawal is carried by the BGPPathRemoved event, not IsWithdraw).
	p, err := common.MakePath(sid.String()+"/128", false, a.ip4, a.ip6, 0, 0)
	if err != nil {
		return fmt.Errorf("make path for SID %s: %w", sid, err)
	}
	common.SendEvent(common.CalicoVppEvent{Type: common.BGPPathDeleted, Old: p})
	return nil
}
