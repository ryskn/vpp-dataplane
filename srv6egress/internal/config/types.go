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
	// the upstream name from Upstreams). Only upstreams present here get the
	// cluster pod-CIDR return route announced.
	Peers map[string]BackbonePeerConfig `json:"peers"`

	// ClusterPodCIDR is the cluster's pod IPv6 CIDR. It is advertised to each
	// backbone upstream (with that upstream's End SID) as the NAT-less return
	// reachability: the backbone SR-encapsulates return traffic toward the
	// gateway, which decaps into the upstream VRF and bounces it into the cluster
	// fabric to the pod's node.
	ClusterPodCIDR string `json:"clusterPodCIDR"`
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

// SID encoding modes for an upstream's egress path. The mode is a property of
// the upstream (the backbone it peers with): full SID interops with a classic
// SRv6 backbone (Linux/FRR), uSID with a NEXT-CSID backbone (e.g. Cisco 8000).
// A single path is one mode end to end; different upstreams may differ.
const (
	SidModeFull = "full" // classic 128-bit SRv6 SIDs (+ SRH)
	SidModeUSID = "usid" // NEXT-CSID compressed micro-segments
)

// SIDStructure is the SRv6 SID Structure (RFC 9252 §3.2.1): the bit layout of the
// End SID, advertised to the backbone and installed on the gateway. Kept here (not
// in the bgp package) so config carries no dependency on bgp; the controller
// converts it to bgp.SIDStructure at the announce site.
type SIDStructure struct {
	LocatorBlockBits uint32 `json:"locatorBlockBits"`
	LocatorNodeBits  uint32 `json:"locatorNodeBits"`
	FunctionBits     uint32 `json:"functionBits"`
	ArgumentBits     uint32 `json:"argumentBits,omitempty"`
}

// classicSIDStructure is the full-SID default (fcff::/40 block + 24-bit node +
// 16-bit function = an 80-bit locator + 16-bit function).
var classicSIDStructure = SIDStructure{LocatorBlockBits: 40, LocatorNodeBits: 24, FunctionBits: 16}

// usidSIDStructure is a sensible uSID default (32-bit block + 16-bit node + 16-bit
// function). Set UpstreamConfig.SIDStructure to match the actual uSID locator plan.
var usidSIDStructure = SIDStructure{LocatorBlockBits: 32, LocatorNodeBits: 16, FunctionBits: 16}

// UpstreamConfig describes a single egress upstream (per-VRF End.DT6 on the GW).
type UpstreamConfig struct {
	// SID is the egress gateway's End.DT6 SID for this upstream's VRF.
	SID string `json:"sid"`
	// VRF is the symbolic VRF name on the egress gateway (informational).
	VRF string `json:"vrf,omitempty"`
	// EgressGW is the egress gateway node name (informational; the actual
	// endpoint resolution still happens via EgressPolicy.spec.egress.endpointSelector).
	EgressGW string `json:"egressGW,omitempty"`
	// SidMode selects the SID encoding for this upstream's egress path: "full"
	// (classic 128-bit SRv6 SIDs) or "usid" (NEXT-CSID). Empty defaults to "full".
	// +optional
	SidMode string `json:"sidMode,omitempty"`
	// SIDStructure overrides the SRv6 SID Structure advertised/installed for this
	// upstream's End SID. Defaults to the classic 40/24/16 layout for full and a
	// 32/16/16 layout for usid; set it to match the actual uSID locator plan.
	// +optional
	SIDStructure *SIDStructure `json:"sidStructure,omitempty"`
}

// IsUSID reports whether this upstream uses uSID (NEXT-CSID) encoding.
func (u UpstreamConfig) IsUSID() bool { return u.SidMode == SidModeUSID }

// ResolvedSIDStructure returns the configured SID structure, or the per-mode
// default when unset.
func (u UpstreamConfig) ResolvedSIDStructure() SIDStructure {
	if u.SIDStructure != nil {
		return *u.SIDStructure
	}
	if u.IsUSID() {
		return usidSIDStructure
	}
	return classicSIDStructure
}

// defaultCandidatePreference is the preference assigned to a color's implicit
// candidate path when a legacy single-form config is normalized (RFC 9256 §2.7;
// higher wins).
const defaultCandidatePreference = 100

// ColorConfig binds a color (RFC 9256 intent) to one or more candidate paths.
// A color resolves to a set of candidate paths; the headend selects among them
// by preference (§2.7). The BSID keys the color's SR Policy at the headend and
// is shared across the candidate paths (RFC 9256 policy/candidate hierarchy).
type ColorConfig struct {
	// CandidatePaths are the RFC 9256 candidate paths for this color, higher
	// preference winning at the headend. Populated directly, or normalized from
	// the deprecated single-form (Upstream+SegmentList) by Validate().
	// +optional
	CandidatePaths []CandidatePathConfig `json:"candidatePaths,omitempty"`

	// Upstream is the deprecated single-candidate form. Use CandidatePaths.
	// +optional
	Upstream string `json:"upstream,omitempty"`
	// SegmentList is the deprecated single-candidate form. Use CandidatePaths.
	// +optional
	SegmentList []string `json:"segmentList,omitempty"`

	// BSID is the Binding SID for this color's SR Policy. It is REQUIRED when
	// distributing over SR Policy SAFI (--bgp-encoding=sr-policy): the receiving
	// headend keys the installed VPP SR Policy on the BSID, so an absent BSID
	// yields an unusable all-zero key. Ignored by the colored-route encoding.
	// Must be an IPv6 SID, unique per color; shared across candidate paths.
	// +optional
	BSID string `json:"bsid,omitempty"`

	// Exclusive marks this color's candidate set as a closed compliance boundary
	// (§14.2): egress outside the set is a violation, so OnUnavailable=Fallback is
	// rejected. Explicit by design — never inferred from candidate-set size.
	// +optional
	Exclusive bool `json:"exclusive,omitempty"`
}

// CandidatePathConfig is one RFC 9256 candidate path for a color: a concrete
// upstream + segment list, selected among a color's candidates by Preference.
type CandidatePathConfig struct {
	Upstream    string   `json:"upstream"`
	SegmentList []string `json:"segmentList"`
	// Preference is the RFC 9256 §2.7 candidate-path preference; higher wins.
	Preference uint32 `json:"preference"`
}

// Primary returns the highest-preference candidate path. Callers that need a
// single representative (status printcolumns, legacy single-form status) use it.
// Ties never occur: Validate() rejects duplicate preferences within a color.
// Only valid after Validate() has normalized CandidatePaths (never empty then).
func (c ColorConfig) Primary() CandidatePathConfig {
	best := c.CandidatePaths[0]
	for _, cp := range c.CandidatePaths[1:] {
		if cp.Preference > best.Preference {
			best = cp
		}
	}
	return best
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

// normalizeCandidatePaths folds the deprecated single-candidate form
// (Upstream+SegmentList directly on ColorConfig) into CandidatePaths so the rest
// of the pipeline only ever reads CandidatePaths. Specifying both forms is
// ambiguous and rejected. Runs before per-color validation.
func (c *ControllerConfig) normalizeCandidatePaths() error {
	for color, cc := range c.Colors {
		singleSet := cc.Upstream != "" || len(cc.SegmentList) > 0
		if singleSet && len(cc.CandidatePaths) > 0 {
			return fmt.Errorf("color %d: set either candidatePaths or the deprecated upstream/segmentList, not both", color)
		}
		if singleSet {
			cc.CandidatePaths = []CandidatePathConfig{{
				Upstream:    cc.Upstream,
				SegmentList: cc.SegmentList,
				Preference:  defaultCandidatePreference,
			}}
			cc.Upstream = ""
			cc.SegmentList = nil
			c.Colors[color] = cc
		}
	}
	return nil
}

// Validate checks internal consistency (color → upstream cross-references) and
// that every SID (upstream SIDs and segment-list entries) is a well-formed
// IPv6 address. SID equality is checked by canonical value, not raw string.
func (c *ControllerConfig) Validate() error {
	if len(c.Colors) == 0 {
		return fmt.Errorf("no colors defined")
	}
	if err := c.normalizeCandidatePaths(); err != nil {
		return err
	}

	// Validate upstream SIDs up front and cache their canonical form.
	upstreamSID := make(map[string]net.IP, len(c.Upstreams))
	for name, up := range c.Upstreams {
		sid, err := parseSID(up.SID)
		if err != nil {
			return fmt.Errorf("upstream %q: sid %v", name, err)
		}
		switch up.SidMode {
		case "", SidModeFull, SidModeUSID:
		default:
			return fmt.Errorf("upstream %q: sidMode %q must be %q or %q", name, up.SidMode, SidModeFull, SidModeUSID)
		}
		upstreamSID[name] = sid
	}

	// Track BSIDs by canonical value to reject duplicates: the BSID is the
	// receiver's SR Policy install key (VPP keys its sr_policy on it), so two
	// colors sharing a BSID would collide into one policy at the headend.
	seenBSID := make(map[string]uint32, len(c.Colors))

	for color, cc := range c.Colors {
		if len(cc.CandidatePaths) == 0 {
			return fmt.Errorf("color %d: candidatePaths must not be empty", color)
		}
		// BSID is optional in the schema (the colored-route encoding ignores it),
		// but if set it must be a well-formed IPv6 SID and unique across colors.
		// It is per color, shared across the candidate paths.
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
		// Reject duplicate preferences within a color: the headend tie-break
		// between candidate paths would otherwise be undefined.
		seenPref := make(map[uint32]int, len(cc.CandidatePaths))
		for i, cp := range cc.CandidatePaths {
			if cp.Upstream == "" {
				return fmt.Errorf("color %d: candidatePaths[%d].upstream is required", color, i)
			}
			wantSID, ok := upstreamSID[cp.Upstream]
			if !ok {
				return fmt.Errorf("color %d: candidatePaths[%d].upstream %q not defined in upstreams", color, i, cp.Upstream)
			}
			if len(cp.SegmentList) == 0 {
				return fmt.Errorf("color %d: candidatePaths[%d].segmentList must not be empty", color, i)
			}
			// An explicit preference: 0 is reserved: the SR Policy encoder's
			// zero-fallback would widen it to 100 on the wire, diverging from what
			// the config reads. normalizeCandidatePaths already stamped the legacy
			// single form with defaultCandidatePreference before this loop, so only
			// an explicitly-written 0 reaches here.
			if cp.Preference == 0 {
				return fmt.Errorf("color %d: candidatePaths[%d].preference must be >= 1; 0 is reserved for the encoder's legacy default", color, i)
			}
			if other, dup := seenPref[cp.Preference]; dup {
				return fmt.Errorf("color %d: candidatePaths[%d] and [%d] share preference %d; preferences must be unique per color",
					color, i, other, cp.Preference)
			}
			seenPref[cp.Preference] = i
			// Every segment must be a syntactically valid IPv6 SID.
			segs := make([]net.IP, len(cp.SegmentList))
			for j, s := range cp.SegmentList {
				sid, err := parseSID(s)
				if err != nil {
					return fmt.Errorf("color %d: candidatePaths[%d].segmentList[%d] %v", color, i, j, err)
				}
				segs[j] = sid
			}
			// The SR Policy terminates at the upstream's End.DT6 SID, so the last
			// segment MUST equal that upstream's SID (compared by canonical value).
			// Otherwise the headend would steer traffic to the wrong SID
			// (VRF-isolation bypass / blackhole).
			if last := segs[len(segs)-1]; !last.Equal(wantSID) {
				return fmt.Errorf("color %d: candidatePaths[%d] last segment %q must equal upstream %q SID %q",
					color, i, cp.SegmentList[len(cp.SegmentList)-1], cp.Upstream, c.Upstreams[cp.Upstream].SID)
			}
		}
	}

	if c.Backbone != nil {
		if len(c.Backbone.Peers) == 0 {
			return fmt.Errorf("backbone: peers must not be empty when backbone is set")
		}
		if c.Backbone.ClusterPodCIDR == "" {
			return fmt.Errorf("backbone: clusterPodCIDR is required when backbone is set")
		}
		if ip, _, err := net.ParseCIDR(c.Backbone.ClusterPodCIDR); err != nil || ip.To4() != nil {
			return fmt.Errorf("backbone: clusterPodCIDR %q must be an IPv6 CIDR", c.Backbone.ClusterPodCIDR)
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
