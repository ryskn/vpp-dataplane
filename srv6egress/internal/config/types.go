// Package config defines the bgp-controller's operator-supplied config
// (color/upstream semantic mapping). This is the "CRD-external" config that
// gives meaning to the operator-defined `color` field (per RFC 9012 §3.4.2
// which leaves color semantics intentionally out of scope of the standard).
package config

import (
	"fmt"
	"net"
	"os"

	"sigs.k8s.io/yaml"
)

// ControllerConfig is the operator-facing config for the bgp-controller.
// Loaded once at startup; reload on SIGHUP is a future enhancement.
type ControllerConfig struct {
	// Upstreams names each upstream peering and its SID/VRF binding on the
	// egress gateway. The symbolic name is referenced from Colors.
	Upstreams map[string]UpstreamConfig `json:"upstreams"`

	// Colors maps RFC 9256 color numbers to a target upstream and segment list.
	// Keyed by color value (uint32 in JSON keys is stringified, accepted both).
	Colors map[uint32]ColorConfig `json:"colors"`

	// Backbone enables backbone stitching: tenant VIPs are additionally
	// announced toward the SRv6 backbone as RFC 9252 service routes (own End
	// SID + backbone Color Ext-Comm) on the per-upstream GW↔PE eBGP sessions.
	// Optional — when unset the controller simply skips the backbone-stitch
	// stage. It is a composable capability layered on the same cluster-egress
	// pipeline, not a separate operating mode.
	// +optional
	Backbone *BackboneConfig `json:"backbone,omitempty"`
}

// BackboneConfig declares the cluster⇄backbone stitching.
type BackboneConfig struct {
	// ColorMap maps a cluster color to the backbone Color Ext-Comm value used
	// on the GW↔PE session. A color absent from the map keeps its value
	// (identity mapping = the "color continuity" default).
	// +optional
	ColorMap map[uint32]uint32 `json:"colorMap,omitempty"`

	// Peers configures the backbone-facing BGP speaker per upstream (keyed by
	// the upstream name from Upstreams). Only upstreams present here get VIP
	// service-route announcements.
	Peers map[string]BackbonePeerConfig `json:"peers"`
}

// BackbonePeerConfig is one backbone-facing gobgp (per-VRF, on the egress GW).
type BackbonePeerConfig struct {
	// GoBGPAddr is the gRPC endpoint of the gobgp instance holding the eBGP
	// session toward this upstream's backbone PE (e.g. "192.168.1.14:50052").
	GoBGPAddr string `json:"gobgpAddr"`
	// Nexthop is the next-hop the advertised VIP routes carry on that session
	// (the GW's address on the PE link, e.g. "fda1::2").
	Nexthop string `json:"nexthop"`
}

// BackboneColor resolves a cluster color to its backbone Color Ext-Comm value.
func (b *BackboneConfig) BackboneColor(clusterColor uint32) uint32 {
	if b == nil {
		return clusterColor
	}
	if v, ok := b.ColorMap[clusterColor]; ok {
		return v
	}
	return clusterColor
}

// UpstreamConfig describes a single egress upstream (per-VRF End.DT6 on the GW).
type UpstreamConfig struct {
	// SID is the egress gateway's End.DT6 SID for this upstream's VRF.
	SID string `json:"sid"`
	// VRF is the symbolic VRF name on the egress gateway (informational).
	VRF string `json:"vrf,omitempty"`
	// EgressGW is the egress gateway node name (informational; the actual
	// endpoint resolution still happens via EgressPolicy.spec.egress.endpointSelector).
	EgressGW string `json:"egressGW,omitempty"`
}

// ColorConfig binds a color to an upstream + segment list.
type ColorConfig struct {
	Upstream    string   `json:"upstream"`
	SegmentList []string `json:"segmentList"`
	// BSID is the Binding SID for this color's SR Policy. It is REQUIRED when
	// distributing over SR Policy SAFI (--bgp-encoding=sr-policy): the receiving
	// headend keys the installed VPP SR Policy on the BSID, so an absent BSID
	// yields an unusable all-zero key. Ignored by the colored-route encoding.
	// Must be an IPv6 SID, unique per color.
	// +optional
	BSID string `json:"bsid,omitempty"`
}

// Load reads a controller config yaml file.
func Load(path string) (*ControllerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read controller config %s: %w", path, err)
	}
	var cc ControllerConfig
	if err := yaml.Unmarshal(data, &cc); err != nil {
		return nil, fmt.Errorf("parse controller config %s: %w", path, err)
	}
	if err := cc.Validate(); err != nil {
		return nil, fmt.Errorf("validate controller config %s: %w", path, err)
	}
	return &cc, nil
}

// parseSID parses an SRv6 SID, requiring a syntactically valid IPv6 address.
// Returns the canonical 16-byte form so callers can compare SIDs by value
// (textual variants like "fcff:0:0:e0:a::" and "fcff::e0:a:0:0:0:0" compare
// equal; IPv4 / malformed strings are rejected).
func parseSID(s string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("%q is not a valid IP address", s)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("%q is IPv4; SRv6 SIDs must be IPv6", s)
	}
	return ip.To16(), nil
}

// Validate checks internal consistency (color → upstream cross-references) and
// that every SID (upstream SIDs and segment-list entries) is a well-formed
// IPv6 address. SID equality is checked by canonical value, not raw string.
func (c *ControllerConfig) Validate() error {
	if len(c.Colors) == 0 {
		return fmt.Errorf("no colors defined")
	}

	// Validate upstream SIDs up front and cache their canonical form.
	upstreamSID := make(map[string]net.IP, len(c.Upstreams))
	for name, up := range c.Upstreams {
		sid, err := parseSID(up.SID)
		if err != nil {
			return fmt.Errorf("upstream %q: sid %v", name, err)
		}
		upstreamSID[name] = sid
	}

	// Track BSIDs by canonical value to reject duplicates: the BSID is the
	// receiver's SR Policy install key (VPP keys its sr_policy on it), so two
	// colors sharing a BSID would collide into one policy at the headend.
	seenBSID := make(map[string]uint32, len(c.Colors))

	for color, cc := range c.Colors {
		if cc.Upstream == "" {
			return fmt.Errorf("color %d: upstream is required", color)
		}
		wantSID, ok := upstreamSID[cc.Upstream]
		if !ok {
			return fmt.Errorf("color %d: upstream %q not defined in upstreams", color, cc.Upstream)
		}
		if len(cc.SegmentList) == 0 {
			return fmt.Errorf("color %d: segmentList must not be empty", color)
		}
		// BSID is optional in the schema (the colored-route encoding ignores it),
		// but if set it must be a well-formed IPv6 SID and unique across colors.
		if cc.BSID != "" {
			bsid, err := parseSID(cc.BSID)
			if err != nil {
				return fmt.Errorf("color %d: bsid %v", color, err)
			}
			if other, dup := seenBSID[bsid.String()]; dup {
				return fmt.Errorf("color %d: bsid %q already used by color %d; BSIDs are the receiver's SR Policy install key and must be unique",
					color, cc.BSID, other)
			}
			seenBSID[bsid.String()] = color
		}
		// Every segment must be a syntactically valid IPv6 SID.
		segs := make([]net.IP, len(cc.SegmentList))
		for i, s := range cc.SegmentList {
			sid, err := parseSID(s)
			if err != nil {
				return fmt.Errorf("color %d: segmentList[%d] %v", color, i, err)
			}
			segs[i] = sid
		}
		// The SR Policy terminates at the upstream's End.DT6 SID, so the last
		// segment MUST equal that upstream's SID (compared by canonical value).
		// Otherwise the headend would steer traffic to the wrong SID
		// (VRF-isolation bypass / blackhole).
		if last := segs[len(segs)-1]; !last.Equal(wantSID) {
			return fmt.Errorf("color %d: last segment %q must equal upstream %q SID %q",
				color, cc.SegmentList[len(cc.SegmentList)-1], cc.Upstream, c.Upstreams[cc.Upstream].SID)
		}
	}

	if c.Backbone != nil {
		if len(c.Backbone.Peers) == 0 {
			return fmt.Errorf("backbone: peers must not be empty when backbone is set")
		}
		for name, p := range c.Backbone.Peers {
			if _, ok := c.Upstreams[name]; !ok {
				return fmt.Errorf("backbone.peers[%q]: upstream not defined in upstreams", name)
			}
			if p.GoBGPAddr == "" {
				return fmt.Errorf("backbone.peers[%q]: gobgpAddr is required", name)
			}
			nh := net.ParseIP(p.Nexthop)
			if nh == nil || nh.To4() != nil {
				return fmt.Errorf("backbone.peers[%q]: nexthop %q must be an IPv6 address", name, p.Nexthop)
			}
		}
		for cl := range c.Backbone.ColorMap {
			if _, ok := c.Colors[cl]; !ok {
				return fmt.Errorf("backbone.colorMap: cluster color %d not defined in colors", cl)
			}
		}
	}
	return nil
}
