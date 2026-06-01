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

// Finding #4 (SPECA PROP-rfc-8402-seg-inv-008): the last segment of a color's
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
