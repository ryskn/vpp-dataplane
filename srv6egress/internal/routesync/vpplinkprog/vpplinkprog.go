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

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/routesync"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// Programmer programs VPP VRF FIBs through vpplink. It satisfies
// routesync.VPPProgrammer.
type Programmer struct {
	vpp *vpplink.VppLink
	// ifIndex memoizes interface name → swIfIndex (interfaces are long-lived).
	ifIndex map[string]uint32
}

// New connects to the VPP binary API at socket (calico-vpp: "/run/vpp/vpp-api.sock").
func New(socket string, logger *logrus.Entry) (*Programmer, error) {
	vpp, err := vpplink.NewVppLink(socket, logger)
	if err != nil {
		return nil, fmt.Errorf("connect to VPP at %s: %w", socket, err)
	}
	return &Programmer{vpp: vpp, ifIndex: map[string]uint32{}}, nil
}

func (p *Programmer) swIfIndex(name string) (uint32, error) {
	if idx, ok := p.ifIndex[name]; ok {
		return idx, nil
	}
	idx, err := p.vpp.SearchInterfaceWithName(name)
	if err != nil {
		return 0, fmt.Errorf("resolve interface %q: %w", name, err)
	}
	p.ifIndex[name] = idx
	return idx, nil
}

// toVppRoute maps a routesync.Route to the vpplink route type, resolving the
// egress interface name to its swIfIndex.
func (p *Programmer) toVppRoute(r routesync.Route) (*types.Route, error) {
	_, dst, err := net.ParseCIDR(r.Prefix)
	if err != nil {
		return nil, fmt.Errorf("parse prefix %q: %w", r.Prefix, err)
	}
	gw := net.ParseIP(r.Via)
	if gw == nil {
		return nil, fmt.Errorf("via %q is not an IP", r.Via)
	}
	idx, err := p.swIfIndex(r.Interface)
	if err != nil {
		return nil, err
	}
	return &types.Route{
		Dst:   dst,
		Table: r.Table,
		Paths: []types.RoutePath{{Gw: gw, SwIfIndex: idx}},
	}, nil
}

func (p *Programmer) Add(r routesync.Route) error {
	vr, err := p.toVppRoute(r)
	if err != nil {
		return err
	}
	return p.vpp.RouteAdd(vr)
}

func (p *Programmer) Del(r routesync.Route) error {
	vr, err := p.toVppRoute(r)
	if err != nil {
		return err
	}
	return p.vpp.RouteDel(vr)
}

// InstalledRoutes dumps the VRF table and keeps the routes whose next-hop is one
// of our configured upstream peers (the ones this component owns). The egress
// interface is taken from the peer config rather than resolved back from the
// swIfIndex: route identity for diffing is (table, prefix), and Del re-resolves
// the interface, so the configured name is the correct value to carry.
func (p *Programmer) InstalledRoutes(table uint32, peers map[string]routesync.Upstream) ([]routesync.Route, error) {
	vppRoutes, err := p.vpp.GetRoutes(table, true /*isIPv6*/)
	if err != nil {
		return nil, fmt.Errorf("dump VPP routes table %d: %w", table, err)
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
			owned = append(owned, routesync.Route{
				Prefix:    vr.Dst.String(),
				Table:     table,
				Via:       via,
				Interface: up.Interface,
			})
			break // one owned path is enough to claim the prefix
		}
	}
	return owned, nil
}
