// Package config defines the bgp-controller's operator-supplied config
// (color/upstream semantic mapping). This is the "CRD-external" config that
// gives meaning to the operator-defined `color` field (per RFC 9012 §3.4.2
// which leaves color semantics intentionally out of scope of the standard).
package config

import (
	"fmt"
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

// Validate checks internal consistency (color → upstream cross-references).
func (c *ControllerConfig) Validate() error {
	if len(c.Colors) == 0 {
		return fmt.Errorf("no colors defined")
	}
	for color, cc := range c.Colors {
		if cc.Upstream == "" {
			return fmt.Errorf("color %d: upstream is required", color)
		}
		up, ok := c.Upstreams[cc.Upstream]
		if !ok {
			return fmt.Errorf("color %d: upstream %q not defined in upstreams", color, cc.Upstream)
		}
		if len(cc.SegmentList) == 0 {
			return fmt.Errorf("color %d: segmentList must not be empty", color)
		}
		// The SR Policy terminates at the upstream's End.DT6 SID, so the last
		// segment MUST equal that upstream's SID. Otherwise the headend would
		// steer traffic to the wrong SID (VRF-isolation bypass / blackhole).
		if last := cc.SegmentList[len(cc.SegmentList)-1]; last != up.SID {
			return fmt.Errorf("color %d: last segment %q must equal upstream %q SID %q",
				color, last, cc.Upstream, up.SID)
		}
	}
	return nil
}
