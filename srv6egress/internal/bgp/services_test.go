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
	path, err := serviceRoutePath(testServiceRoute(), DefaultSIDStructure)
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
		if _, err := serviceRoutePath(r, DefaultSIDStructure); err == nil {
			t.Fatalf("%s: expected error", tc.name)
		}
	}
}
