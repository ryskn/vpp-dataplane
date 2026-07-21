package bgp

import (
	"net"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/protobuf/proto"
)

func testSRDist() *srPolicyEncoder {
	return &srPolicyEncoder{opts: (&SRPolicyOptions{}).withDefaults()}
}

var testBSID = net.ParseIP("cafe::64").To16()

// The SR Policy distributor is restart-safe only if Withdraw can rebuild the
// exact path Announce added, so the same inputs must yield byte-identical paths.
func TestSRPolicyPath_Deterministic(t *testing.T) {
	d := testSRDist()
	ep := net.ParseIP("fd00:1::14").To16()
	p1, err := d.srPolicyPath(100, 0, 0, ep, testBSID, []string{"fcff:0:0:e0:a::"})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := d.srPolicyPath(100, 0, 0, ep, testBSID, []string{"fcff:0:0:e0:a::"})
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(p1, p2) {
		t.Fatal("srPolicyPath not deterministic for the same inputs")
	}
}

func TestSRPolicyPath_DistinctByColorAndEndpoint(t *testing.T) {
	d := testSRDist()
	epA := net.ParseIP("fd00:1::14").To16()
	epB := net.ParseIP("fd00:1::15").To16()
	base, _ := d.srPolicyPath(100, 0, 0, epA, testBSID, []string{"fcff:0:0:e0:a::"})
	otherColor, _ := d.srPolicyPath(200, 0, 0, epA, testBSID, []string{"fcff:0:0:e0:a::"})
	otherEndpoint, _ := d.srPolicyPath(100, 0, 0, epB, testBSID, []string{"fcff:0:0:e0:a::"})
	if proto.Equal(base, otherColor) {
		t.Fatal("paths with different color compare equal")
	}
	if proto.Equal(base, otherEndpoint) {
		t.Fatal("paths with different endpoint compare equal")
	}
}

// Two candidate paths of the same <color, endpoint> differ by distinguisher and
// carry their own preference in the Tunnel Encap sub-TLV (RFC 9256 §2.1/§2.7).
func TestSRPolicyPath_PerCandidateDistinguisherAndPreference(t *testing.T) {
	d := testSRDist()
	ep := net.ParseIP("fd00:1::14").To16()
	c1, err := d.srPolicyPath(100, 1, 200, ep, testBSID, []string{"fcff:0:0:e0:a::"})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := d.srPolicyPath(100, 2, 100, ep, testBSID, []string{"fcff:0:0:e0:b::"})
	if err != nil {
		t.Fatal(err)
	}
	if proto.Equal(c1, c2) {
		t.Fatal("candidate paths with different distinguishers compare equal")
	}

	// NLRI distinguishers must be 1 and 2.
	var n1, n2 api.SRPolicyNLRI
	if err := c1.Nlri.UnmarshalTo(&n1); err != nil {
		t.Fatal(err)
	}
	if err := c2.Nlri.UnmarshalTo(&n2); err != nil {
		t.Fatal(err)
	}
	if n1.Distinguisher != 1 || n2.Distinguisher != 2 {
		t.Fatalf("distinguishers = %d,%d, want 1,2", n1.Distinguisher, n2.Distinguisher)
	}

	// Each path's preference sub-TLV must carry the candidate's preference.
	if got := preferenceOf(t, c1); got != 200 {
		t.Fatalf("candidate 1 preference = %d, want 200", got)
	}
	if got := preferenceOf(t, c2); got != 100 {
		t.Fatalf("candidate 2 preference = %d, want 100", got)
	}
}

// preferenceOf extracts the SR Preference sub-TLV value from a path.
func preferenceOf(t *testing.T, p *api.Path) uint32 {
	t.Helper()
	for _, a := range p.Pattrs {
		var tun api.TunnelEncapAttribute
		if a.UnmarshalTo(&tun) != nil {
			continue
		}
		for _, tlv := range tun.Tlvs {
			for _, sub := range tlv.Tlvs {
				var pref api.TunnelEncapSubTLVSRPreference
				if sub.UnmarshalTo(&pref) == nil {
					return pref.Preference
				}
			}
		}
	}
	t.Fatal("no SR Preference sub-TLV found")
	return 0
}

func TestSRPolicyPath_Shape(t *testing.T) {
	d := testSRDist()
	ep := net.ParseIP("fd00:1::14").To16()
	segList := []string{"fcff:0:0:e0:a::", "fcff:0:0:e0:b::"}
	p, err := d.srPolicyPath(100, 0, 0, ep, testBSID, segList)
	if err != nil {
		t.Fatal(err)
	}

	// AFI IPv6 / SAFI 73.
	if p.Family.Afi != api.Family_AFI_IP6 || p.Family.Safi != api.Family_SAFI_SR_POLICY {
		t.Fatalf("unexpected family: %v", p.Family)
	}

	// NLRI <distinguisher, color, endpoint>.
	var nlri api.SRPolicyNLRI
	if err := p.Nlri.UnmarshalTo(&nlri); err != nil {
		t.Fatalf("nlri: %v", err)
	}
	if nlri.Color != 100 {
		t.Fatalf("nlri color = %d, want 100", nlri.Color)
	}
	if nlri.Distinguisher != 1 {
		t.Fatalf("nlri distinguisher = %d, want default 1", nlri.Distinguisher)
	}
	if !net.IP(nlri.Endpoint).Equal(net.ParseIP("fd00:1::14")) {
		t.Fatalf("nlri endpoint = %v, want fd00:1::14", net.IP(nlri.Endpoint))
	}

	// Tunnel Encap (TLV type 15) carrying the BSID + full segment list + preference.
	var (
		foundSegList bool
		foundPref    bool
		gotBSID      string
		gotSIDs      []string
		lastBehavior api.SRv6Behavior
	)
	for _, a := range p.Pattrs {
		var tun api.TunnelEncapAttribute
		if a.UnmarshalTo(&tun) != nil {
			continue
		}
		for _, tlv := range tun.Tlvs {
			if tlv.Type != srPolicyTunnelType {
				t.Fatalf("tunnel TLV type = %d, want %d", tlv.Type, srPolicyTunnelType)
			}
			for _, sub := range tlv.Tlvs {
				var bsidTLV api.TunnelEncapSubTLVSRBindingSID
				if sub.UnmarshalTo(&bsidTLV) == nil && bsidTLV.Bsid != nil {
					var b api.SRBindingSID
					if bsidTLV.Bsid.UnmarshalTo(&b) == nil {
						gotBSID = net.IP(b.Sid).String()
					}
					continue
				}
				var pref api.TunnelEncapSubTLVSRPreference
				if sub.UnmarshalTo(&pref) == nil && pref.Preference == 100 {
					foundPref = true
					continue
				}
				var sl api.TunnelEncapSubTLVSRSegmentList
				if sub.UnmarshalTo(&sl) == nil {
					foundSegList = true
					for _, segAny := range sl.Segments {
						var seg api.SegmentTypeB
						if segAny.UnmarshalTo(&seg) == nil {
							gotSIDs = append(gotSIDs, net.IP(seg.Sid).String())
							if seg.EndpointBehaviorStructure != nil {
								lastBehavior = seg.EndpointBehaviorStructure.Behavior
							}
						}
					}
				}
			}
		}
	}
	if gotBSID != "cafe::64" {
		t.Fatalf("BSID sub-TLV = %q, want cafe::64 (receiver keys its VPP SR Policy on it)", gotBSID)
	}
	if !foundPref {
		t.Fatal("SR Preference sub-TLV not found")
	}
	if !foundSegList {
		t.Fatal("SR Segment List sub-TLV not found")
	}
	if len(gotSIDs) != 2 || gotSIDs[0] != "fcff:0:0:e0:a::" || gotSIDs[1] != "fcff:0:0:e0:b::" {
		t.Fatalf("segment SIDs = %v, want the full 2-SID list", gotSIDs)
	}
	// The terminal SID must be End.DT6 (per-VRF decap on the egress gateway).
	if lastBehavior != api.SRv6Behavior_END_DT6 {
		t.Fatalf("terminal segment behavior = %v, want END_DT6", lastBehavior)
	}
}

func TestSRPolicyPath_RejectsIPv4Segment(t *testing.T) {
	d := testSRDist()
	ep := net.ParseIP("fd00:1::14").To16()
	if _, err := d.srPolicyPath(100, 0, 0, ep, testBSID, []string{"10.0.0.1"}); err == nil {
		t.Fatal("expected IPv4 segment to be rejected")
	}
}

func TestSRPolicyBindingSID_Required(t *testing.T) {
	d := testSRDist()
	if _, err := d.bindingSID(PolicyKey{BSID: ""}); err == nil {
		t.Fatal("expected missing BSID to be rejected (receiver needs it to key the VPP SR Policy)")
	}
	if _, err := d.bindingSID(PolicyKey{BSID: "10.0.0.1"}); err == nil {
		t.Fatal("expected IPv4 BSID to be rejected")
	}
	if _, err := d.bindingSID(PolicyKey{BSID: "cafe::64"}); err != nil {
		t.Fatalf("valid IPv6 BSID rejected: %v", err)
	}
}

func TestSRPolicyEndpointIP_RejectsNonIPv6(t *testing.T) {
	d := testSRDist()
	if _, err := d.endpointIP(PolicyKey{EndpointAddr: ""}); err == nil {
		t.Fatal("expected empty endpoint address to be rejected")
	}
	if _, err := d.endpointIP(PolicyKey{EndpointAddr: "192.168.1.14"}); err == nil {
		t.Fatal("expected IPv4 endpoint address to be rejected")
	}
	if _, err := d.endpointIP(PolicyKey{EndpointAddr: "fd00:1::14"}); err != nil {
		t.Fatalf("valid IPv6 endpoint rejected: %v", err)
	}
}
