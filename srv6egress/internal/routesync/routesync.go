// Package routesync installs the upstream routes a per-VRF gobgp learned over
// eBGP into VPP's per-upstream VRF FIBs on the egress gateway.
//
// On the egress gateway the dataplane terminates an SRv6 SR Policy at an
// End.DT6 SID bound to a per-upstream VRF (e.g. fcff:0:0:e0:a:: -> table
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
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"regexp"
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
	// ServiceBSIDBlock reserves an IPv6 block (mask length <= 96) for the BSIDs
	// of SR policies created for received SRv6 service routes (RFC 9252). Each
	// distinct service SID gets one deterministic BSID inside the block, so the
	// mapping survives restarts without local state. Required only when the
	// upstream advertises service routes (backbone stitching).
	ServiceBSIDBlock string `json:"serviceBsidBlock,omitempty"`
}

// ServiceBSIDNet parses ServiceBSIDBlock, or returns nil when unset.
func (c *Config) ServiceBSIDNet() (*net.IPNet, error) {
	if c.ServiceBSIDBlock == "" {
		return nil, nil
	}
	_, ipnet, err := net.ParseCIDR(c.ServiceBSIDBlock)
	if err != nil {
		return nil, fmt.Errorf("serviceBsidBlock %q: %w", c.ServiceBSIDBlock, err)
	}
	if ipnet.IP.To4() != nil {
		return nil, fmt.Errorf("serviceBsidBlock %q must be IPv6", c.ServiceBSIDBlock)
	}
	if ones, _ := ipnet.Mask.Size(); ones > 96 {
		return nil, fmt.Errorf("serviceBsidBlock %q: mask /%d leaves fewer than 32 bits for BSID derivation (need <= /96)", c.ServiceBSIDBlock, ones)
	}
	return ipnet, nil
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
	// ServiceSID, when non-empty, marks this as an SRv6 service route
	// (RFC 9252): instead of a plain FIB entry via the peer, the prefix is
	// steered into an SR encap toward this SID (backbone stitching). Canonical
	// IPv6 string.
	ServiceSID string
}

// IsService reports whether this is an SRv6 service route (SR encap action).
func (r Route) IsService() bool { return r.ServiceSID != "" }

// Key uniquely identifies a route for diffing. ServiceSID is part of the
// identity so a service route whose SID changed is replaced, not kept stale.
func (r Route) Key() string {
	return fmt.Sprintf("%d|%s|%s", r.Table, r.Prefix, r.ServiceSID)
}

// DeriveServiceBSID maps a service SID to its deterministic BSID inside block:
// the block's prefix with the last 4 bytes set to fnv1a-32(serviceSID). No
// local state is needed to recover the mapping after a restart. Collisions
// between distinct service SIDs are possible but vanishingly rare at egress
// scale; the programmer detects them at install time (policy/SID mismatch).
func DeriveServiceBSID(block *net.IPNet, serviceSID net.IP) net.IP {
	h := fnv.New32a()
	_, _ = h.Write(serviceSID.To16())
	sum := h.Sum32()
	bsid := make(net.IP, net.IPv6len)
	copy(bsid, block.IP.To16())
	bsid[12] = byte(sum >> 24)
	bsid[13] = byte(sum >> 16)
	bsid[14] = byte(sum >> 8)
	bsid[15] = byte(sum)
	return bsid
}

// SplitServiceRoutes partitions routes into plain FIB routes and SRv6 service
// routes (preserving order).
func SplitServiceRoutes(routes []Route) (plain, service []Route) {
	for _, r := range routes {
		if r.IsService() {
			service = append(service, r)
		} else {
			plain = append(plain, r)
		}
	}
	return plain, service
}

// --- gobgp RIB JSON parsing ---

// ribPrefixSIDSubTLV is an SRv6 Information Sub-TLV (type 1) as gobgp's native
// MarshalJSON emits it (the CLI marshals native bgp attr types). SID is []byte
// → base64 in JSON, decoded transparently by encoding/json.
type ribPrefixSIDSubTLV struct {
	Type             int    `json:"type"`
	SID              []byte `json:"sid"`
	EndpointBehavior uint16 `json:"endpoint_behavior"`
}

// ribPrefixSIDTLV is an SRv6 Service TLV (type 5 = L3) in the Prefix-SID attr.
type ribPrefixSIDTLV struct {
	Type    int                  `json:"type"`
	SubTLVs []ribPrefixSIDSubTLV `json:"SubTLVs"`
}

// ribPath is one path entry in gobgp's `global rib -j` output.
type ribPath struct {
	Nlri struct {
		Prefix string `json:"prefix"`
	} `json:"nlri"`
	Best       bool   `json:"best"`
	NeighborIP string `json:"neighbor-ip"`
	Attrs      []struct {
		Type    int               `json:"type"`
		Nexthop string            `json:"nexthop"`
		TLVs    []ribPrefixSIDTLV `json:"TLVs"` // Prefix-SID attr (type 40) only
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

// serviceSID extracts the SRv6 service SID from a Prefix-SID attribute
// (type 40 → SRv6 L3 Service TLV (5) → SRv6 Information Sub-TLV (1)), or ""
// when the path is a plain route (RFC 9252 reception via backbone stitching).
func (p ribPath) serviceSID() string {
	for _, a := range p.Attrs {
		if a.Type != 40 {
			continue
		}
		for _, tlv := range a.TLVs {
			if tlv.Type != 5 {
				continue
			}
			for _, sub := range tlv.SubTLVs {
				if sub.Type != 1 || len(sub.SID) != net.IPv6len {
					continue
				}
				return net.IP(sub.SID).String()
			}
		}
	}
	return ""
}

// RIBEntry is the best-path information routesync needs for one prefix.
type RIBEntry struct {
	Nexthop    string
	ServiceSID string // non-empty for SRv6 service routes (RFC 9252)
}

// ParseRIB parses `gobgp global rib -a ipv6 -j` output into prefix→best-path
// info for each prefix. An empty RIB (`null` / `{}`) yields an empty map.
func ParseRIB(b []byte) (map[string]RIBEntry, error) {
	if len(b) == 0 {
		return map[string]RIBEntry{}, nil
	}
	var raw map[string][]ribPath
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse gobgp rib json: %w", err)
	}
	out := make(map[string]RIBEntry, len(raw))
	for prefix, paths := range raw {
		var best *ribPath
		for i := range paths {
			if paths[i].Best {
				best = &paths[i]
				break
			}
		}
		if best == nil && len(paths) > 0 {
			best = &paths[0]
		}
		if best == nil {
			continue
		}
		if nh := best.nexthop(); nh != "" {
			out[prefix] = RIBEntry{Nexthop: nh, ServiceSID: best.serviceSID()}
		}
	}
	return out, nil
}

// DesiredRoutes maps the RIB (prefix→best-path info) to the VPP routes that
// should be installed, keeping only prefixes whose next-hop is a configured
// upstream peer. Paths carrying an SRv6 service SID become service routes
// (SR encap action) in the peer's VRF; the rest become plain FIB entries.
// Result is sorted by Key for deterministic diffing/logging.
func DesiredRoutes(rib map[string]RIBEntry, cfg *Config) []Route {
	peers := cfg.byPeer()
	var routes []Route
	for prefix, e := range rib {
		up, ok := peers[e.Nexthop]
		if !ok {
			continue // next-hop is not one of our upstreams; skip
		}
		routes = append(routes, Route{
			Prefix:     prefix,
			Table:      up.Table,
			Via:        up.Peer,
			Interface:  up.Interface,
			ServiceSID: e.ServiceSID,
		})
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Key() < routes[j].Key() })
	return routes
}

// fibPrefixRe matches a FIB entry header line, e.g. "2001:db8:a::/64 fib:11 ..."
// or "::/0" / "fe80::/10" (prefix at column 0).
var fibPrefixRe = regexp.MustCompile(`^([0-9A-Fa-f:]+/\d+)`)

// fibViaRe matches a forwarding via line, e.g.
// "[@0]: ipv6 via fda1::1 virtio-0/0/12/0: mtu:1500 ...".
var fibViaRe = regexp.MustCompile(`via (\S+) (\S+?):`)

// ParseOwnedRoutes parses `show ip6 fib table <table>` output and returns the
// routes this component owns in that table — i.e. those whose next-hop is one
// of our upstream peers. This lets the syncer recover its installed set from
// VPP itself (source of truth) instead of trusting in-memory state that is
// lost across a restart. Routes installed by Calico or others (different
// next-hop) are ignored, so we never delete what we did not install.
func ParseOwnedRoutes(raw []byte, table uint32, peers map[string]Upstream) []Route {
	var routes []Route
	seen := map[string]bool{}
	curPrefix := ""
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			if m := fibPrefixRe.FindStringSubmatch(line); m != nil {
				curPrefix = m[1]
			} else {
				curPrefix = "" // header / unrelated top-level line
			}
			continue
		}
		if curPrefix == "" || seen[curPrefix] {
			continue
		}
		if m := fibViaRe.FindStringSubmatch(line); m != nil {
			via, iface := m[1], m[2]
			if up, ok := peers[via]; ok {
				routes = append(routes, Route{
					Prefix:    curPrefix,
					Table:     table,
					Via:       via,
					Interface: iface,
				})
				_ = up
				seen[curPrefix] = true
			}
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].Key() < routes[j].Key() })
	return routes
}

// PeerIndex exposes the peer->upstream map for callers needing ownership info.
func (c *Config) PeerIndex() map[string]Upstream { return c.byPeer() }

// Tables returns the distinct VRF tables referenced by the config.
func (c *Config) Tables() []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, u := range c.Upstreams {
		if !seen[u.Table] {
			seen[u.Table] = true
			out = append(out, u.Table)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
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
