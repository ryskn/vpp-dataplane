package config

import "testing"

// baseValid returns a minimal internally-consistent config.
func baseValid() *ControllerConfig {
	return &ControllerConfig{
		Upstreams: map[string]UpstreamConfig{
			"isp-a": {SID: "fcff:0:0:e0:a::", VRF: "upstream-a"},
			"isp-b": {SID: "fcff:0:0:e0:b::", VRF: "upstream-b"},
		},
		Colors: map[uint32]ColorConfig{
			100: {Upstream: "isp-a", SegmentList: []string{"fcff:0:0:e0:a::"}},
			200: {Upstream: "isp-b", SegmentList: []string{"fcff:0:0:71::", "fcff:0:0:e0:b::"}},
		},
	}
}

func TestValidate_OK(t *testing.T) {
	if err := baseValid().Validate(); err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
}

func TestValidate_NoColors(t *testing.T) {
	c := &ControllerConfig{Upstreams: map[string]UpstreamConfig{"isp-a": {SID: "x::"}}}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for empty colors")
	}
}

func TestValidate_UnknownUpstream(t *testing.T) {
	c := baseValid()
	c.Colors[300] = ColorConfig{Upstream: "isp-z", SegmentList: []string{"fcff:0:0:e0:z::"}}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for undefined upstream reference")
	}
}

func TestValidate_EmptySegmentList(t *testing.T) {
	c := baseValid()
	c.Colors[100] = ColorConfig{Upstream: "isp-a", SegmentList: nil}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for empty segment list")
	}
}

// The last segment of a color's
// segment list must equal the target upstream's End.DT6 SID. A mismatch passed
// validation previously and would steer traffic to the wrong SID.
func TestValidate_LastSegmentMustMatchUpstreamSID(t *testing.T) {
	c := baseValid()
	// color 100 points at isp-a (SID fcff:0:0:e0:a::) but terminates elsewhere.
	c.Colors[100] = ColorConfig{
		Upstream:    "isp-a",
		SegmentList: []string{"fcff:0:0:e0:b::"}, // wrong terminal SID
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error when last segment != upstream SID")
	}
}

func TestValidate_MultiSegmentTerminatesAtUpstream(t *testing.T) {
	c := baseValid()
	// transit hop then correct terminal SID — must pass.
	c.Colors[100] = ColorConfig{
		Upstream:    "isp-a",
		SegmentList: []string{"fcff:0:0:79::", "fcff:0:0:e0:a::"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid multi-segment config, got: %v", err)
	}
}

// SID comparison must be by canonical IPv6 value, not raw string: an
// equivalent but differently-written terminal SID must still pass.
func TestValidate_TerminalSIDTextualVariantMatches(t *testing.T) {
	c := baseValid()
	// "fcff:0:0:e0:a::" == "fcff:0:0:e0:a:0:0:0" written without the "::".
	c.Colors[100] = ColorConfig{
		Upstream:    "isp-a",
		SegmentList: []string{"fcff:0:0:e0:a:0:0:0"},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected canonical-equal terminal SID to pass, got: %v", err)
	}
}

func TestValidate_MalformedSegmentRejected(t *testing.T) {
	c := baseValid()
	c.Colors[100] = ColorConfig{
		Upstream:    "isp-a",
		SegmentList: []string{"not-an-ip"},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for malformed (non-IP) segment")
	}
}

func TestValidate_IPv4SegmentRejected(t *testing.T) {
	c := baseValid()
	c.Colors[100] = ColorConfig{
		Upstream:    "isp-a",
		SegmentList: []string{"10.0.0.1"},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error: SRv6 SIDs must be IPv6, not IPv4")
	}
}

func TestValidate_MalformedUpstreamSIDRejected(t *testing.T) {
	c := baseValid()
	c.Upstreams["isp-a"] = UpstreamConfig{SID: "zzzz::nope", VRF: "upstream-a"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for malformed upstream SID")
	}
}

func TestValidate_DistinctBSIDsOK(t *testing.T) {
	c := baseValid()
	c.Colors[100] = ColorConfig{Upstream: "isp-a", BSID: "cafe::64", SegmentList: []string{"fcff:0:0:e0:a::"}}
	c.Colors[200] = ColorConfig{Upstream: "isp-b", BSID: "cafe::c8", SegmentList: []string{"fcff:0:0:e0:b::"}}
	if err := c.Validate(); err != nil {
		t.Fatalf("expected distinct BSIDs to pass, got: %v", err)
	}
}

// The BSID is the receiver's SR Policy install key, so two colors sharing one
// (even written differently) must be rejected.
func TestValidate_DuplicateBSIDRejected(t *testing.T) {
	c := baseValid()
	c.Colors[100] = ColorConfig{Upstream: "isp-a", BSID: "cafe::64", SegmentList: []string{"fcff:0:0:e0:a::"}}
	c.Colors[200] = ColorConfig{Upstream: "isp-b", BSID: "cafe:0:0:0:0:0:0:64", SegmentList: []string{"fcff:0:0:e0:b::"}}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for duplicate BSID across colors")
	}
}

// --- candidatePaths (RFC 9256) ---

// The deprecated single form (upstream+segmentList) must normalize into one
// candidate path with the default preference, proving backward compatibility.
func TestValidate_SingleFormNormalizedToCandidate(t *testing.T) {
	c := baseValid() // uses the deprecated single form
	if err := c.Validate(); err != nil {
		t.Fatalf("single-form config must validate, got: %v", err)
	}
	cc := c.Colors[100]
	if len(cc.CandidatePaths) != 1 {
		t.Fatalf("expected 1 normalized candidate, got %d", len(cc.CandidatePaths))
	}
	cp := cc.CandidatePaths[0]
	if cp.Upstream != "isp-a" || cp.Preference != defaultCandidatePreference ||
		len(cp.SegmentList) != 1 || cp.SegmentList[0] != "fcff:0:0:e0:a::" {
		t.Fatalf("normalized candidate = %+v", cp)
	}
	// The deprecated fields must be cleared so the rest of the pipeline reads
	// only CandidatePaths.
	if cc.Upstream != "" || cc.SegmentList != nil {
		t.Fatalf("deprecated fields not cleared after normalize: %+v", cc)
	}
}

// Specifying both the single form and candidatePaths is ambiguous and rejected.
func TestValidate_BothFormsRejected(t *testing.T) {
	c := baseValid()
	c.Colors[100] = ColorConfig{
		Upstream:    "isp-a",
		SegmentList: []string{"fcff:0:0:e0:a::"},
		CandidatePaths: []CandidatePathConfig{
			{Upstream: "isp-a", SegmentList: []string{"fcff:0:0:e0:a::"}, Preference: 100},
		},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error when both single form and candidatePaths are set")
	}
}

// A color with two candidate paths (distinct preferences) must validate; each
// candidate must terminate at its own upstream's SID.
func TestValidate_MultiCandidateOK(t *testing.T) {
	c := baseValid()
	c.Colors[100] = ColorConfig{
		CandidatePaths: []CandidatePathConfig{
			{Upstream: "isp-a", SegmentList: []string{"fcff:0:0:e0:a::"}, Preference: 200},
			{Upstream: "isp-b", SegmentList: []string{"fcff:0:0:e0:b::"}, Preference: 100},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("multi-candidate config should validate, got: %v", err)
	}
	if got := c.Colors[100].Primary().Upstream; got != "isp-a" {
		t.Fatalf("primary upstream = %q, want isp-a (pref 200)", got)
	}
}

// Duplicate preferences within a color make the headend tie-break undefined and
// must be rejected.
func TestValidate_DuplicatePreferenceRejected(t *testing.T) {
	c := baseValid()
	c.Colors[100] = ColorConfig{
		CandidatePaths: []CandidatePathConfig{
			{Upstream: "isp-a", SegmentList: []string{"fcff:0:0:e0:a::"}, Preference: 100},
			{Upstream: "isp-b", SegmentList: []string{"fcff:0:0:e0:b::"}, Preference: 100},
		},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for duplicate candidate-path preference within a color")
	}
}

// A candidate whose last segment does not equal its upstream's SID must be
// rejected (same invariant as the single form, now per candidate).
func TestValidate_MultiCandidateWrongTerminalSID(t *testing.T) {
	c := baseValid()
	c.Colors[100] = ColorConfig{
		CandidatePaths: []CandidatePathConfig{
			{Upstream: "isp-a", SegmentList: []string{"fcff:0:0:e0:a::"}, Preference: 200},
			{Upstream: "isp-b", SegmentList: []string{"fcff:0:0:e0:a::"}, Preference: 100}, // wrong terminal
		},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error when a candidate's last segment != its upstream SID")
	}
}

// An empty candidatePaths (and no single form) must be rejected.
func TestValidate_EmptyCandidatePathsRejected(t *testing.T) {
	c := baseValid()
	c.Colors[100] = ColorConfig{}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for a color with no candidate paths")
	}
}

// An exclusive color (closed compliance boundary, §14.2) parses and validates;
// exclusivity is an explicit bit, orthogonal to candidate-set size.
func TestValidate_ExclusiveColorOK(t *testing.T) {
	c := baseValid()
	c.Colors[200] = ColorConfig{
		Exclusive: true,
		CandidatePaths: []CandidatePathConfig{
			{Upstream: "isp-b", SegmentList: []string{"fcff:0:0:e0:b::"}, Preference: 100},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("exclusive color should validate, got: %v", err)
	}
	if !c.Colors[200].Exclusive {
		t.Fatal("exclusive bit did not survive validation")
	}
}

// An explicit preference: 0 is reserved (the encoder's zero-fallback would widen
// it to 100 on the wire, diverging from the config) and must be rejected.
func TestValidate_ExplicitZeroPreferenceRejected(t *testing.T) {
	c := baseValid()
	c.Colors[100] = ColorConfig{
		CandidatePaths: []CandidatePathConfig{
			{Upstream: "isp-a", SegmentList: []string{"fcff:0:0:e0:a::"}, Preference: 0},
		},
	}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for explicit candidate-path preference 0")
	}
}

// --- backbone stitching validation ---

func validBackbone() *BackboneConfig {
	return &BackboneConfig{
		ColorMap:       map[uint32]uint32{100: 1100},
		ClusterPodCIDR: "fd00:dead::/48",
		Peers: map[string]BackbonePeerConfig{
			"isp-a": {GoBGPAddr: "192.0.2.14:50052", Nexthop: "fda1::2"},
		},
	}
}

func TestValidate_BackboneOK(t *testing.T) {
	c := baseValid()
	c.Backbone = validBackbone()
	if err := c.Validate(); err != nil {
		t.Fatalf("expected valid backbone config, got: %v", err)
	}
}

func TestValidate_BackbonePeerUnknownUpstream(t *testing.T) {
	c := baseValid()
	c.Backbone = validBackbone()
	c.Backbone.Peers["isp-z"] = BackbonePeerConfig{GoBGPAddr: "x:1", Nexthop: "fda9::2"}
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for backbone peer referencing unknown upstream")
	}
}

func TestValidate_BackboneColorMapUnknownColor(t *testing.T) {
	c := baseValid()
	c.Backbone = validBackbone()
	c.Backbone.ColorMap[999] = 1999
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for colorMap entry without a defined cluster color")
	}
}

func TestValidate_BackbonePeerRequiresFields(t *testing.T) {
	c := baseValid()
	c.Backbone = validBackbone()
	c.Backbone.Peers["isp-a"] = BackbonePeerConfig{Nexthop: "fda1::2"} // no gobgpAddr
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for missing gobgpAddr")
	}
	c.Backbone.Peers["isp-a"] = BackbonePeerConfig{GoBGPAddr: "x:1", Nexthop: "10.0.0.1"} // v4 NH
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for IPv4 nexthop")
	}
}

func TestBackboneColor_IdentityWhenUnmapped(t *testing.T) {
	b := validBackbone()
	if got := b.BackboneColor(100); got != 1100 {
		t.Fatalf("mapped color = %d, want 1100", got)
	}
	if got := b.BackboneColor(200); got != 200 {
		t.Fatalf("unmapped color = %d, want identity 200", got)
	}
	var nilB *BackboneConfig
	if got := nilB.BackboneColor(300); got != 300 {
		t.Fatalf("nil backbone color = %d, want identity 300", got)
	}
}

func TestValidate_USIDUpstreamOK(t *testing.T) {
	c := baseValid()
	u := c.Upstreams["isp-a"]
	u.SidMode = SidModeUSID
	c.Upstreams["isp-a"] = u
	if err := c.Validate(); err != nil {
		t.Fatalf("usid upstream should validate, got: %v", err)
	}
}

func TestValidate_UnknownSidModeRejected(t *testing.T) {
	c := baseValid()
	u := c.Upstreams["isp-a"]
	u.SidMode = "compressed"
	c.Upstreams["isp-a"] = u
	if err := c.Validate(); err == nil {
		t.Fatal("expected error for unknown sidMode")
	}
}

func TestResolvedSIDStructure_PerMode(t *testing.T) {
	if got := (UpstreamConfig{SidMode: SidModeFull}).ResolvedSIDStructure(); got != classicSIDStructure {
		t.Fatalf("full = %+v, want classic %+v", got, classicSIDStructure)
	}
	if got := (UpstreamConfig{}).ResolvedSIDStructure(); got != classicSIDStructure {
		t.Fatalf("empty mode = %+v, want classic (default)", got)
	}
	if got := (UpstreamConfig{SidMode: SidModeUSID}).ResolvedSIDStructure(); got != usidSIDStructure {
		t.Fatalf("usid = %+v, want usid default %+v", got, usidSIDStructure)
	}
	override := SIDStructure{LocatorBlockBits: 48, LocatorNodeBits: 16, FunctionBits: 16}
	if got := (UpstreamConfig{SidMode: SidModeUSID, SIDStructure: &override}).ResolvedSIDStructure(); got != override {
		t.Fatalf("override = %+v, want %+v", got, override)
	}
}
