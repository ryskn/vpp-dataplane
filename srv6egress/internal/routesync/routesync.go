// Package routesync installs the upstream routes a per-VRF gobgp learned over
// eBGP into VPP's per-upstream VRF FIBs on the egress gateway.
//
// In the v1alpha1 dataplane the egress gateway terminates an SRv6 SR Policy at
// an End.DT6 SID bound to a per-upstream VRF (e.g. fcff:0:0:e0:a:: -> table
// 100). After decap, the inner packet is looked up in that VRF — which is empty
// unless the routes the upstream advertised over eBGP are installed there.
// This package bridges the gobgp RIB to the VPP VRF FIB: for each learned
// prefix whose next-hop is a configured upstream peer, it programs
// `ip route add <prefix> table <vrf> via <peer> <interface>` into VPP.
//
// The gobgp side is read via the `gobgp ... global rib -a ipv6 -j` CLI (stable
// JSON), and VPP is programmed via a configurable exec command (`vppctl`, or
// `kubectl exec ... -- vppctl` when run off-box). Both seams keep the component
// runnable without linking gobgp's gRPC stubs or VPP's binary API.
package routesync

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Upstream maps an eBGP peer (next-hop) to the VPP VRF table + egress interface
// that its routes should be installed into.
type Upstream struct {
	Peer      string `json:"peer"`      // eBGP peer address == route next-hop, e.g. "fda1::1"
	Table     uint32 `json:"table"`     // VPP VRF table id, e.g. 100
	Interface string `json:"interface"` // VPP egress interface, e.g. "virtio-0/0/12/0"
}

// Config is the operator-supplied peer->VRF mapping for one egress gateway.
type Config struct {
	Upstreams []Upstream `json:"upstreams"`
}

// byPeer indexes upstreams by peer address.
func (c *Config) byPeer() map[string]Upstream {
	m := make(map[string]Upstream, len(c.Upstreams))
	for _, u := range c.Upstreams {
		m[u.Peer] = u
	}
	return m
}

// Route is a single VPP VRF FIB entry to program.
type Route struct {
	Prefix    string
	Table     uint32
	Via       string
	Interface string
}

// Key uniquely identifies a route for diffing.
func (r Route) Key() string {
	return fmt.Sprintf("%d|%s", r.Table, r.Prefix)
}

// AddArgs / DelArgs return the vppctl argument vector for this route.
func (r Route) AddArgs() []string { return r.args("add") }
func (r Route) DelArgs() []string { return r.args("del") }

func (r Route) args(op string) []string {
	return []string{"ip", "route", op, r.Prefix,
		"table", fmt.Sprintf("%d", r.Table), "via", r.Via, r.Interface}
}

// --- gobgp RIB JSON parsing ---

// ribPath is one path entry in gobgp's `global rib -j` output.
type ribPath struct {
	Nlri struct {
		Prefix string `json:"prefix"`
	} `json:"nlri"`
	Best       bool   `json:"best"`
	NeighborIP string `json:"neighbor-ip"`
	Attrs      []struct {
		Type    int    `json:"type"`
		Nexthop string `json:"nexthop"`
	} `json:"attrs"`
}

// nexthop returns the route next-hop, preferring the MP_REACH_NLRI attribute
// (type 14) and falling back to the advertising neighbor.
func (p ribPath) nexthop() string {
	for _, a := range p.Attrs {
		if a.Type == 14 && a.Nexthop != "" {
			return a.Nexthop
		}
	}
	return p.NeighborIP
}

// ParseRIB parses `gobgp global rib -a ipv6 -j` output into prefix->nexthop for
// the best path of each prefix. An empty RIB (`null` / `{}`) yields an empty map.
func ParseRIB(b []byte) (map[string]string, error) {
	if len(b) == 0 {
		return map[string]string{}, nil
	}
	var raw map[string][]ribPath
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse gobgp rib json: %w", err)
	}
	out := make(map[string]string, len(raw))
	for prefix, paths := range raw {
		nh := ""
		for _, p := range paths {
			if p.Best {
				nh = p.nexthop()
				break
			}
		}
		if nh == "" && len(paths) > 0 {
			nh = paths[0].nexthop()
		}
		if nh != "" {
			out[prefix] = nh
		}
	}
	return out, nil
}

// DesiredRoutes maps the RIB (prefix->nexthop) to the VPP routes that should be
// installed, keeping only prefixes whose next-hop is a configured upstream peer.
// Result is sorted by Key for deterministic diffing/logging.
func DesiredRoutes(rib map[string]string, cfg *Config) []Route {
	peers := cfg.byPeer()
	var routes []Route
	for prefix, nh := range rib {
		up, ok := peers[nh]
		if !ok {
			continue // next-hop is not one of our upstreams; skip
		}
		routes = append(routes, Route{
			Prefix:    prefix,
			Table:     up.Table,
			Via:       up.Peer,
			Interface: up.Interface,
		})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Key() < routes[j].Key() })
	return routes
}

// Reconcile diffs desired vs installed and returns the routes to add and to
// delete. Both inputs may be in any order.
func Reconcile(desired, installed []Route) (add, del []Route) {
	d := make(map[string]Route, len(desired))
	for _, r := range desired {
		d[r.Key()] = r
	}
	i := make(map[string]Route, len(installed))
	for _, r := range installed {
		i[r.Key()] = r
	}
	for k, r := range d {
		if _, ok := i[k]; !ok {
			add = append(add, r)
		}
	}
	for k, r := range i {
		if _, ok := d[k]; !ok {
			del = append(del, r)
		}
	}
	sort.Slice(add, func(a, b int) bool { return add[a].Key() < add[b].Key() })
	sort.Slice(del, func(a, b int) bool { return del[a].Key() < del[b].Key() })
	return add, del
}
