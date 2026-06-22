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
//
// Plain FIB routing lives here; SRv6 service routes (RFC 9252) are programmed by
// serviceProgrammer (service.go), which Programmer exposes via ServiceProgrammer
// when a service BSID block is configured.
package vpplinkprog

import (
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/routesync"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// Programmer programs VPP VRF FIBs (plain routes) through vpplink. It satisfies
// routesync.VPPProgrammer; when constructed with a service BSID block it also
// exposes an SRv6 service-route programmer via ServiceProgrammer.
type Programmer struct {
	vpp *vpplink.VppLink
	// installedPaths records the exact path VPP reported for each owned route in
	// the most recent InstalledRoutes() dump (keyed by Route.Key()). Del uses it
	// to remove precisely the installed path — robust to config/interface drift,
	// where the route's actual egress interface no longer matches the configured
	// one and a name-resolved delete would silently miss.
	installedPaths map[string]types.RoutePath
	// svc programs SRv6 service routes; non-nil only when a service BSID block
	// was configured at construction.
	svc *serviceProgrammer
}

// New connects to the VPP binary API at socket (calico-vpp: "/run/vpp/vpp-api.sock").
// When block is non-nil the returned Programmer also programs SRv6 service
// routes (RFC 9252) whose BSIDs are derived into block.
func New(socket string, logger *logrus.Entry, block *net.IPNet) (*Programmer, error) {
	vpp, err := vpplink.NewVppLink(socket, logger)
	if err != nil {
		return nil, fmt.Errorf("connect to VPP at %s: %w", socket, err)
	}
	p := &Programmer{vpp: vpp, installedPaths: map[string]types.RoutePath{}}
	if block != nil {
		p.svc = &serviceProgrammer{vpp: vpp, block: block}
	}
	return p, nil
}

// ServiceProgrammer returns the SRv6 service-route programmer, or nil when no
// service BSID block was configured (plain-routes-only backend).
func (p *Programmer) ServiceProgrammer() routesync.ServiceVPPProgrammer {
	if p.svc == nil {
		return nil
	}
	return p.svc
}

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
