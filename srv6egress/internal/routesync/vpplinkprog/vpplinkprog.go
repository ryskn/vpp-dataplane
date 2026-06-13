// Package vpplinkprog implements routesync.VPPProgrammer over the native VPP
// binary API (govpp, via the repo's vpplink wrapper) instead of shelling out to
// vppctl. It is the production backend: typed RouteAdd/RouteDel and a typed FIB
// dump replace the fragile `show ip6 fib` text parsing of the exec backend.
//
// Because it speaks the VPP binary API socket (calico-vpp: /run/vpp/vpp-api.sock),
// it must run co-located with VPP (in the calico-vpp pod, or with the socket
// mounted). The off-box `kubectl exec ... vppctl` mode is only available via the
// exec backend.
//
// Routes added here carry the VPP "API" source; the vppctl backend's routes
// carry the "CLI" source. VPP tracks route ownership per source, so a govpp
// delete only removes API-sourced routes (and vice versa). Within a single
// backend this is correct and self-healing; do NOT mix backends against the
// same VRF or each will leave the other's routes behind.
package vpplinkprog

import (
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/routesync"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// Programmer programs VPP VRF FIBs through vpplink. It satisfies
// routesync.VPPProgrammer, and routesync.ServiceVPPProgrammer when a service
// BSID block is configured (SetServiceBSIDBlock).
type Programmer struct {
	vpp *vpplink.VppLink
	// installedPaths records the exact path VPP reported for each owned route in
	// the most recent InstalledRoutes() dump (keyed by Route.Key()). Del uses it
	// to remove precisely the installed path — robust to config/interface drift,
	// where the route's actual egress interface no longer matches the configured
	// one and a name-resolved delete would silently miss.
	installedPaths map[string]types.RoutePath
	// serviceBSIDBlock is the block SR-policy BSIDs for received service routes
	// are derived into (routesync.DeriveServiceBSID). Ownership marker too: only
	// policies/steerings whose BSID is inside the block are touched.
	serviceBSIDBlock *net.IPNet
}

// New connects to the VPP binary API at socket (calico-vpp: "/run/vpp/vpp-api.sock").
func New(socket string, logger *logrus.Entry) (*Programmer, error) {
	vpp, err := vpplink.NewVppLink(socket, logger)
	if err != nil {
		return nil, fmt.Errorf("connect to VPP at %s: %w", socket, err)
	}
	return &Programmer{vpp: vpp, installedPaths: map[string]types.RoutePath{}}, nil
}

// SetServiceBSIDBlock enables SRv6 service-route programming (RFC 9252).
func (p *Programmer) SetServiceBSIDBlock(block *net.IPNet) { p.serviceBSIDBlock = block }

// resolveIfIndex looks up an interface swIfIndex by name. It deliberately does
// NOT cache: an interface can be deleted and recreated with a different index
// (drift), and a stale cache would then program the wrong index.
func (p *Programmer) resolveIfIndex(name string) (uint32, error) {
	idx, err := p.vpp.SearchInterfaceWithName(name)
	if err != nil {
		return 0, fmt.Errorf("resolve interface %q: %w", name, err)
	}
	return idx, nil
}

func parsePrefix(s string) (*net.IPNet, error) {
	_, dst, err := net.ParseCIDR(s)
	if err != nil {
		return nil, fmt.Errorf("parse prefix %q: %w", s, err)
	}
	return dst, nil
}

// Add installs r via the configured egress interface (resolved fresh each call).
func (p *Programmer) Add(r routesync.Route) error {
	dst, err := parsePrefix(r.Prefix)
	if err != nil {
		return err
	}
	gw := net.ParseIP(r.Via)
	if gw == nil {
		return fmt.Errorf("via %q is not an IP", r.Via)
	}
	idx, err := p.resolveIfIndex(r.Interface)
	if err != nil {
		return err
	}
	return p.vpp.RouteAdd(&types.Route{
		Dst:   dst,
		Table: r.Table,
		Paths: []types.RoutePath{{Gw: gw, SwIfIndex: idx}},
	})
}

// Del removes r. It prefers the exact path VPP reported for this route in the
// last dump (so the delete matches what is actually installed even if the
// configured interface has since drifted); only if that is unavailable does it
// fall back to resolving the configured interface by name.
func (p *Programmer) Del(r routesync.Route) error {
	dst, err := parsePrefix(r.Prefix)
	if err != nil {
		return err
	}
	path, ok := p.installedPaths[r.Key()]
	if !ok {
		gw := net.ParseIP(r.Via)
		if gw == nil {
			return fmt.Errorf("via %q is not an IP", r.Via)
		}
		idx, err := p.resolveIfIndex(r.Interface)
		if err != nil {
			return err
		}
		path = types.RoutePath{Gw: gw, SwIfIndex: idx}
	}
	return p.vpp.RouteDel(&types.Route{
		Dst:   dst,
		Table: r.Table,
		Paths: []types.RoutePath{path},
	})
}

// InstalledRoutes dumps the VRF table and keeps the routes whose next-hop is one
// of our configured upstream peers (the ones this component owns). It also
// records each route's exact installed path so a later Del removes precisely
// that path. Route identity for diffing is (table, prefix); the carried
// Interface is the configured name, while the recorded path holds VPP's actual
// swIfIndex used for deletion.
func (p *Programmer) InstalledRoutes(table uint32, peers map[string]routesync.Upstream) ([]routesync.Route, error) {
	vppRoutes, err := p.vpp.GetRoutes(table, true /*isIPv6*/)
	if err != nil {
		return nil, fmt.Errorf("dump VPP routes table %d: %w", table, err)
	}
	// Drop stale recorded paths for this table; we repopulate from the fresh
	// dump so the map never grows unbounded as prefixes churn.
	tablePrefix := fmt.Sprintf("%d|", table)
	for k := range p.installedPaths {
		if strings.HasPrefix(k, tablePrefix) {
			delete(p.installedPaths, k)
		}
	}

	var owned []routesync.Route
	for i := range vppRoutes {
		vr := &vppRoutes[i]
		if vr.Dst == nil {
			continue
		}
		for _, path := range vr.Paths {
			if path.Gw == nil {
				continue
			}
			via := path.Gw.String()
			up, ok := peers[via]
			if !ok {
				continue // next-hop is not one of our upstreams
			}
			route := routesync.Route{
				Prefix:    vr.Dst.String(),
				Table:     table,
				Via:       via,
				Interface: up.Interface,
			}
			p.installedPaths[route.Key()] = path
			owned = append(owned, route)
			break // one owned path is enough to claim the prefix
		}
	}
	return owned, nil
}

// --- SRv6 service routes (RFC 9252, v1alpha2 BR mode) ---
//
// A received service route (prefix + service SID) is realized as
//   sr policy add bsid <derived> next <serviceSID> encap
//   sr steer l3 <prefix> via bsid <derived> fib_table <vrf>
// The BSID is derived deterministically from the service SID inside the
// configured block, so the SID→BSID mapping needs no local state and the
// installed set is recoverable from VPP's steering+policy dumps.

func (p *Programmer) requireServiceBlock() (*net.IPNet, error) {
	if p.serviceBSIDBlock == nil {
		return nil, fmt.Errorf("service routes require serviceBsidBlock in the routesync config")
	}
	return p.serviceBSIDBlock, nil
}

// servicePolicies maps BSID (string form) → terminal service SID for the SR
// policies inside our BSID block.
func (p *Programmer) servicePolicies(block *net.IPNet) (map[string]net.IP, error) {
	policies, err := p.vpp.ListSRv6Policies()
	if err != nil {
		return nil, fmt.Errorf("dump SR policies: %w", err)
	}
	out := map[string]net.IP{}
	for _, pol := range policies {
		bsid := net.IP(pol.Bsid[:])
		if !block.Contains(bsid) {
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

// AddService implements routesync.ServiceVPPProgrammer.
func (p *Programmer) AddService(r routesync.Route) error {
	block, err := p.requireServiceBlock()
	if err != nil {
		return err
	}
	sid := net.ParseIP(r.ServiceSID)
	if sid == nil || sid.To4() != nil {
		return fmt.Errorf("service SID %q is not IPv6", r.ServiceSID)
	}
	dst, err := parsePrefix(r.Prefix)
	if err != nil {
		return err
	}
	bsid := routesync.DeriveServiceBSID(block, sid)

	existing, err := p.servicePolicies(block)
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
		if err := p.vpp.AddSRv6Policy(&types.SrPolicy{
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
	if err := p.vpp.AddSRv6Steering(&types.SrSteer{
		TrafficType: types.SrSteerIPv6,
		FibTable:    r.Table,
		Prefix:      prefix,
		Bsid:        types.ToVppIP6Address(bsid),
	}); err != nil {
		return fmt.Errorf("steer %s (table %d) via bsid %s: %w", r.Prefix, r.Table, bsid, err)
	}
	return nil
}

// DelService implements routesync.ServiceVPPProgrammer. The SR policy is
// removed only when no other steering still references its BSID.
func (p *Programmer) DelService(r routesync.Route) error {
	block, err := p.requireServiceBlock()
	if err != nil {
		return err
	}
	sid := net.ParseIP(r.ServiceSID)
	if sid == nil {
		return fmt.Errorf("service SID %q is not an IP", r.ServiceSID)
	}
	dst, err := parsePrefix(r.Prefix)
	if err != nil {
		return err
	}
	bsid := types.ToVppIP6Address(routesync.DeriveServiceBSID(block, sid))

	prefix, err := ip_types.ParsePrefix(dst.String())
	if err != nil {
		return fmt.Errorf("parse prefix %q: %w", dst, err)
	}
	if err := p.vpp.DelSRv6Steering(&types.SrSteer{
		TrafficType: types.SrSteerIPv6,
		FibTable:    r.Table,
		Prefix:      prefix,
		Bsid:        bsid,
	}); err != nil {
		return fmt.Errorf("unsteer %s (table %d): %w", r.Prefix, r.Table, err)
	}

	steers, err := p.vpp.ListSRv6Steering()
	if err != nil {
		return fmt.Errorf("dump SR steerings: %w", err)
	}
	for _, st := range steers {
		if st.Bsid == bsid {
			return nil // policy still referenced from another VRF/prefix
		}
	}
	if err := p.vpp.DelSRv6Policy(&types.SrPolicy{Bsid: bsid}); err != nil {
		return fmt.Errorf("delete SR policy bsid %s: %w", net.IP(bsid[:]), err)
	}
	return nil
}

// InstalledServiceRoutes implements routesync.ServiceVPPProgrammer: it
// reconstructs the owned service routes of one VRF from VPP's steering dump
// (steerings whose BSID is in our block) joined with the policy dump
// (BSID → service SID). No local state survives restarts — VPP is the truth.
func (p *Programmer) InstalledServiceRoutes(table uint32) ([]routesync.Route, error) {
	block, err := p.requireServiceBlock()
	if err != nil {
		// No block configured → we own no service routes by definition.
		return nil, nil
	}
	policies, err := p.servicePolicies(block)
	if err != nil {
		return nil, err
	}
	steers, err := p.vpp.ListSRv6Steering()
	if err != nil {
		return nil, fmt.Errorf("dump SR steerings: %w", err)
	}
	var owned []routesync.Route
	for _, st := range steers {
		if st.FibTable != table || st.TrafficType != types.SrSteerIPv6 {
			continue
		}
		bsid := net.IP(st.Bsid[:])
		if !block.Contains(bsid) {
			continue // not ours (e.g. EgressPolicy headend steering)
		}
		sid, ok := policies[bsid.String()]
		if !ok {
			continue // steering without policy; Add will repair via reconcile
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
