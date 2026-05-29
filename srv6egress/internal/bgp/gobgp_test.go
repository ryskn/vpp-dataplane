package bgp

import (
	"testing"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/proto"
)

// The gobgp distributor is restart-safe only if Withdraw can rebuild the exact
// same path that Announce added — both go through coloredHostPath, so the same
// (sid, color) must produce byte-identical paths. This is what lets a fresh
// (post-restart) distributor DeletePath a route it never saw announced.
func TestColoredHostPath_Deterministic(t *testing.T) {
	p1, err := coloredHostPath("fcff:0:0:e0:a::", 100)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := coloredHostPath("fcff:0:0:e0:a::", 100)
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(p1, p2) {
		t.Fatal("coloredHostPath not deterministic for the same (sid,color)")
	}
}

func TestColoredHostPath_DistinctByColorAndSID(t *testing.T) {
	base, _ := coloredHostPath("fcff:0:0:e0:a::", 100)
	otherColor, _ := coloredHostPath("fcff:0:0:e0:a::", 200)
	otherSID, _ := coloredHostPath("fcff:0:0:e0:b::", 100)
	if proto.Equal(base, otherColor) {
		t.Fatal("paths with different color compare equal")
	}
	if proto.Equal(base, otherSID) {
		t.Fatal("paths with different SID compare equal")
	}
}

func TestColoredHostPath_Shape(t *testing.T) {
	p, err := coloredHostPath("fcff:0:0:e0:a::", 100)
	if err != nil {
		t.Fatal(err)
	}
	if p.Family.Afi != api.Family_AFI_IP6 || p.Family.Safi != api.Family_SAFI_UNICAST {
		t.Fatalf("unexpected family: %v", p.Family)
	}
	var nlri api.IPAddressPrefix
	if err := p.Nlri.UnmarshalTo(&nlri); err != nil {
		t.Fatalf("nlri: %v", err)
	}
	if nlri.PrefixLen != 128 || nlri.Prefix != "fcff:0:0:e0:a::" {
		t.Fatalf("unexpected nlri: %+v", &nlri)
	}
	// Color Extended Community must be present.
	foundColor := false
	for _, a := range p.Pattrs {
		var ext api.ExtendedCommunitiesAttribute
		if a.UnmarshalTo(&ext) == nil {
			for _, c := range ext.Communities {
				var col api.ColorExtended
				if c.UnmarshalTo(&col) == nil && col.Color == 100 {
					foundColor = true
				}
			}
		}
	}
	if !foundColor {
		t.Fatal("Color Extended Community (color=100) not found in path attributes")
	}
}
