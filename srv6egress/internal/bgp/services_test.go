package bgp

import (
	"net/netip"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
)

func testServiceRoute() ServiceRoute {
	return ServiceRoute{
		Prefix:   "2001:db8:e::42/128",
		EndSID:   "fcff:0:0:e0:a::",
		Behavior: EndDT6,
		Color:    1100,
		Nexthop:  "fda1::2",
	}
}

// The service path must carry, on one IPv6-unicast NLRI: MP_REACH with the
// session next-hop, the backbone Color Ext-Comm, and a Prefix-SID attribute
// whose SRv6 L3 Service TLV holds the End SID + behavior + SID structure.
// (Wire-level transport of exactly this attribute set was verified against a
// real gobgp eBGP session in the 2026-06-13 spike.)
func TestServiceRoutePath_Attributes(t *testing.T) {
	path, err := serviceRoutePath(testServiceRoute(), DefaultSIDStructure, PrependSpec{})
	if err != nil {
		t.Fatal(err)
	}
	if path.Family.Afi != api.Family_AFI_IP6 || path.Family.Safi != api.Family_SAFI_UNICAST {
		t.Fatalf("family = %v, want IPv6 unicast", path.Family)
	}

	var gotNH, gotPrefix string
	var gotColor uint32
	var gotSID netip.Addr
	var gotBehavior uint32
	var gotStructure *api.SRv6StructureSubSubTLV

	for _, attAny := range path.Pattrs {
		m, err := attAny.UnmarshalNew()
		if err != nil {
			t.Fatal(err)
		}
		switch v := m.(type) {
		case *api.MpReachNLRIAttribute:
			if len(v.NextHops) > 0 {
				gotNH = v.NextHops[0]
			}
			if len(v.Nlris) > 0 {
				nm, _ := v.Nlris[0].UnmarshalNew()
				if p, ok := nm.(*api.IPAddressPrefix); ok {
					gotPrefix = p.Prefix
					if p.PrefixLen != 128 {
						t.Fatalf("prefixLen = %d, want 128", p.PrefixLen)
					}
				}
			}
		case *api.ExtendedCommunitiesAttribute:
			for _, cAny := range v.Communities {
				cm, _ := cAny.UnmarshalNew()
				if c, ok := cm.(*api.ColorExtended); ok {
					gotColor = c.Color
				}
			}
		case *api.PrefixSID:
			for _, tlvAny := range v.Tlvs {
				tm, _ := tlvAny.UnmarshalNew()
				l3, ok := tm.(*api.SRv6L3ServiceTLV)
				if !ok {
					continue
				}
				for _, sub := range l3.SubTlvs {
					for _, sAny := range sub.Tlv {
						sm, _ := sAny.UnmarshalNew()
						info, ok := sm.(*api.SRv6InformationSubTLV)
						if !ok {
							continue
						}
						gotSID, _ = netip.AddrFromSlice(info.Sid)
						gotBehavior = info.EndpointBehavior
						for _, ss := range info.SubSubTlvs {
							for _, ssAny := range ss.Tlv {
								ssm, _ := ssAny.UnmarshalNew()
								if st, ok := ssm.(*api.SRv6StructureSubSubTLV); ok {
									gotStructure = st
								}
							}
						}
					}
				}
			}
		}
	}

	if gotNH != "fda1::2" {
		t.Fatalf("nexthop = %q, want fda1::2", gotNH)
	}
	if gotPrefix != "2001:db8:e::42" {
		t.Fatalf("prefix = %q, want 2001:db8:e::42", gotPrefix)
	}
	if gotColor != 1100 {
		t.Fatalf("color = %d, want 1100", gotColor)
	}
	if gotSID != netip.MustParseAddr("fcff:0:0:e0:a::") {
		t.Fatalf("end SID = %s, want fcff:0:0:e0:a::", gotSID)
	}
	if gotBehavior != EndDT6 {
		t.Fatalf("behavior = %d, want %d (End.DT6)", gotBehavior, EndDT6)
	}
	if gotStructure == nil || gotStructure.LocatorBlockLength != 40 ||
		gotStructure.LocatorNodeLength != 24 || gotStructure.FunctionLength != 16 {
		t.Fatalf("SID structure = %+v, want LB40/LN24/Fun16", gotStructure)
	}
}

// A backup return advertisement carries an AS_PATH with the local ASN prepended
// Count times, so it loses BGP best-path to the primary's plain advertisement
// (§14.3 — demoted, not withheld).
func TestServiceRoutePath_Prepend(t *testing.T) {
	path, err := serviceRoutePath(testServiceRoute(), DefaultSIDStructure, PrependSpec{ASN: 65001, Count: 3})
	if err != nil {
		t.Fatal(err)
	}
	var seq []uint32
	for _, attAny := range path.Pattrs {
		m, err := attAny.UnmarshalNew()
		if err != nil {
			t.Fatal(err)
		}
		if ap, ok := m.(*api.AsPathAttribute); ok {
			for _, seg := range ap.Segments {
				if seg.Type == api.AsSegment_AS_SEQUENCE {
					seq = append(seq, seg.Numbers...)
				}
			}
		}
	}
	if len(seq) != 3 || seq[0] != 65001 || seq[1] != 65001 || seq[2] != 65001 {
		t.Fatalf("AS_PATH sequence = %v, want [65001 65001 65001]", seq)
	}
}

// No prepend spec => no AS_PATH attribute (the plain primary advertisement).
func TestServiceRoutePath_NoPrepend(t *testing.T) {
	path, err := serviceRoutePath(testServiceRoute(), DefaultSIDStructure, PrependSpec{})
	if err != nil {
		t.Fatal(err)
	}
	for _, attAny := range path.Pattrs {
		m, _ := attAny.UnmarshalNew()
		if _, ok := m.(*api.AsPathAttribute); ok {
			t.Fatal("plain advertisement must carry no AS_PATH attribute")
		}
	}
}

func TestServiceRoutePath_Validation(t *testing.T) {
	for _, tc := range []struct {
		name string
		mod  func(*ServiceRoute)
	}{
		{"bad prefix", func(r *ServiceRoute) { r.Prefix = "not-a-prefix" }},
		{"v4 prefix", func(r *ServiceRoute) { r.Prefix = "192.0.2.0/24" }},
		{"bad SID", func(r *ServiceRoute) { r.EndSID = "10.0.0.1" }},
		{"missing nexthop", func(r *ServiceRoute) { r.Nexthop = "" }},
	} {
		r := testServiceRoute()
		tc.mod(&r)
		if _, err := serviceRoutePath(r, DefaultSIDStructure, PrependSpec{}); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
}
