package vpplinkprog

import (
	"fmt"
	"net"

	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/routesync"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// serviceProgrammer realizes received SRv6 service routes (RFC 9252) over the
// VPP binary API. A service route (prefix + service SID) becomes:
//
//	sr policy add bsid <derived> next <serviceSID> encap
//	sr steer l3 <prefix> via bsid <derived> fib_table <vrf>
//
// The BSID is derived deterministically from the service SID inside the
// configured block, so the SID→BSID mapping needs no local state and the
// installed set is recoverable from VPP's steering+policy dumps. It implements
// routesync.ServiceVPPProgrammer.
type serviceProgrammer struct {
	vpp *vpplink.VppLink
	// block is the IPv6 block service-route BSIDs are derived into
	// (routesync.DeriveServiceBSID), and the ownership marker: only
	// policies/steerings whose BSID is inside it are touched. Always non-nil.
	block *net.IPNet
}

// servicePolicies maps BSID (string form) → terminal service SID for the SR
// policies inside our BSID block.
func (s *serviceProgrammer) servicePolicies() (map[string]net.IP, error) {
	policies, err := s.vpp.ListSRv6Policies()
	if err != nil {
		return nil, fmt.Errorf("dump SR policies: %w", err)
	}
	out := map[string]net.IP{}
	for _, pol := range policies {
		bsid := net.IP(pol.Bsid[:])
		if !s.block.Contains(bsid) {
			continue
		}
		if len(pol.SidLists) == 0 || pol.SidLists[0].NumSids == 0 {
			continue
		}
		last := pol.SidLists[0].Sids[pol.SidLists[0].NumSids-1]
		out[bsid.String()] = net.IP(last[:])
	}
	return out, nil
}

// AddService installs the SR policy (when absent) and the steering for r.
func (s *serviceProgrammer) AddService(r routesync.Route) error {
	sid := net.ParseIP(r.ServiceSID)
	if sid == nil || sid.To4() != nil {
		return fmt.Errorf("service SID %q is not IPv6", r.ServiceSID)
	}
	dst, err := parsePrefix(r.Prefix)
	if err != nil {
		return err
	}
	bsid := routesync.DeriveServiceBSID(s.block, sid)

	existing, err := s.servicePolicies()
	if err != nil {
		return err
	}
	if cur, ok := existing[bsid.String()]; ok {
		if !cur.Equal(sid) {
			// fnv32 collision between two distinct service SIDs: refuse rather
			// than steer this prefix into the wrong segment list.
			return fmt.Errorf("BSID %s already used for service SID %s (collision with %s); pick a different serviceBsidBlock", bsid, cur, sid)
		}
	} else {
		var sids [16]ip_types.IP6Address
		sids[0] = types.ToVppIP6Address(sid)
		if err := s.vpp.AddSRv6Policy(&types.SrPolicy{
			Bsid:     types.ToVppIP6Address(bsid),
			IsEncap:  true,
			SidLists: []types.Srv6SidList{{NumSids: 1, Weight: 1, Sids: sids}},
		}); err != nil {
			return fmt.Errorf("add SR policy bsid %s → %s: %w", bsid, sid, err)
		}
	}

	prefix, err := ip_types.ParsePrefix(dst.String())
	if err != nil {
		return fmt.Errorf("parse prefix %q: %w", dst, err)
	}
	if err := s.vpp.AddSRv6Steering(&types.SrSteer{
		TrafficType: types.SrSteerIPv6,
		FibTable:    r.Table,
		Prefix:      prefix,
		Bsid:        types.ToVppIP6Address(bsid),
	}); err != nil {
		return fmt.Errorf("steer %s (table %d) via bsid %s: %w", r.Prefix, r.Table, bsid, err)
	}
	return nil
}

// DelService removes the steering for r, and the SR policy only when no other
// steering still references its BSID.
func (s *serviceProgrammer) DelService(r routesync.Route) error {
	sid := net.ParseIP(r.ServiceSID)
	if sid == nil {
		return fmt.Errorf("service SID %q is not an IP", r.ServiceSID)
	}
	dst, err := parsePrefix(r.Prefix)
	if err != nil {
		return err
	}
	bsid := types.ToVppIP6Address(routesync.DeriveServiceBSID(s.block, sid))

	prefix, err := ip_types.ParsePrefix(dst.String())
	if err != nil {
		return fmt.Errorf("parse prefix %q: %w", dst, err)
	}
	if err := s.vpp.DelSRv6Steering(&types.SrSteer{
		TrafficType: types.SrSteerIPv6,
		FibTable:    r.Table,
		Prefix:      prefix,
		Bsid:        bsid,
	}); err != nil {
		return fmt.Errorf("unsteer %s (table %d): %w", r.Prefix, r.Table, err)
	}

	steers, err := s.vpp.ListSRv6Steering()
	if err != nil {
		return fmt.Errorf("dump SR steerings: %w", err)
	}
	for _, st := range steers {
		if st.Bsid == bsid {
			return nil // policy still referenced from another VRF/prefix
		}
	}
	if err := s.vpp.DelSRv6Policy(&types.SrPolicy{Bsid: bsid}); err != nil {
		return fmt.Errorf("delete SR policy bsid %s: %w", net.IP(bsid[:]), err)
	}
	return nil
}

// InstalledServiceRoutes reconstructs the owned service routes of one VRF from
// VPP's steering dump (steerings whose BSID is in our block) joined with the
// policy dump (BSID → service SID). No local state survives restarts — VPP is
// the truth.
func (s *serviceProgrammer) InstalledServiceRoutes(table uint32) ([]routesync.Route, error) {
	policies, err := s.servicePolicies()
	if err != nil {
		return nil, err
	}
	steers, err := s.vpp.ListSRv6Steering()
	if err != nil {
		return nil, fmt.Errorf("dump SR steerings: %w", err)
	}
	var owned []routesync.Route
	for _, st := range steers {
		if st.FibTable != table || st.TrafficType != types.SrSteerIPv6 {
			continue
		}
		bsid := net.IP(st.Bsid[:])
		if !s.block.Contains(bsid) {
			continue // not ours (e.g. EgressPolicy headend steering)
		}
		sid, ok := policies[bsid.String()]
		if !ok {
			continue // steering without policy; AddService will repair via reconcile
		}
		// Canonicalize the prefix exactly like parsePrefix does on the desired
		// side so Key() comparisons match.
		dst, err := parsePrefix(st.Prefix.String())
		if err != nil {
			continue
		}
		owned = append(owned, routesync.Route{
			Prefix:     dst.String(),
			Table:      table,
			ServiceSID: sid.String(),
		})
	}
	return owned, nil
}
