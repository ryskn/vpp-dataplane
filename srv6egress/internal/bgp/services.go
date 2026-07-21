package bgp

import (
	"fmt"
	"net"

	api "github.com/osrg/gobgp/v3/api"
	apb "google.golang.org/protobuf/types/known/anypb"
)

// EndDT6 is the IANA SRv6 Endpoint Behavior codepoint for End.DT6.
const EndDT6 = 18

// ServiceRoute is one RFC 9252 SRv6 service advertisement: a prefix made
// SR-reachable through the gateway's own End SID, colored for backbone TE
// class selection (the tenant VIP toward the backbone PE).
type ServiceRoute struct {
	Prefix   string // e.g. "2001:db8:e::42/128"
	EndSID   string // the GW's End.DT6 SID for the tenant VRF
	Behavior uint16 // IANA endpoint behavior; use EndDT6
	Color    uint32 // backbone Color Extended Community value
	Nexthop  string // next-hop on the GW-PE eBGP session
}

// SIDStructure is the SRv6 SID Structure Sub-Sub-TLV (RFC 9252 §3.2.1)
// advertised with the End SID.
type SIDStructure struct {
	LocatorBlockBits uint32
	LocatorNodeBits  uint32
	FunctionBits     uint32
	ArgumentBits     uint32
}

// DefaultSIDStructure matches the lab locator plan (fcff::/40 block + 24-bit
// node + 16-bit function).
var DefaultSIDStructure = SIDStructure{LocatorBlockBits: 40, LocatorNodeBits: 24, FunctionBits: 16}

// PrependSpec makes a service route AS-path-longer (less preferred) so a backup
// upstream's return advertisement loses to the primary's plain one, without an
// exclusive advertisement that would blackhole a failed-over forward path
// (§14.3). Count 0 = no prepend.
type PrependSpec struct {
	ASN   uint32
	Count int
}

// serviceRoutePath builds the IPv6-unicast path for route: MP_REACH + Color
// Extended Community + Prefix-SID attribute carrying the SRv6 L3 Service TLV
// (Information Sub-TLV with the End SID/behavior + SID Structure). An optional
// AS_PATH attribute (prepend.Count > 0) demotes a backup return advertisement.
func serviceRoutePath(route ServiceRoute, structure SIDStructure, prepend PrependSpec) (*api.Path, error) {
	ip, ipnet, err := net.ParseCIDR(route.Prefix)
	if err != nil {
		return nil, fmt.Errorf("prefix %q: %w", route.Prefix, err)
	}
	if ip.To4() != nil {
		return nil, fmt.Errorf("prefix %q must be IPv6", route.Prefix)
	}
	plen, _ := ipnet.Mask.Size()
	sid := net.ParseIP(route.EndSID)
	if sid == nil || sid.To4() != nil {
		return nil, fmt.Errorf("end SID %q must be IPv6", route.EndSID)
	}
	nh := route.Nexthop
	if nh == "" {
		return nil, fmt.Errorf("nexthop is required")
	}

	nlri, err := apb.New(&api.IPAddressPrefix{PrefixLen: uint32(plen), Prefix: ipnet.IP.String()})
	if err != nil {
		return nil, err
	}
	origin, err := apb.New(&api.OriginAttribute{Origin: 0}) // IGP
	if err != nil {
		return nil, err
	}
	mpReach, err := apb.New(&api.MpReachNLRIAttribute{
		Family:   v6family,
		NextHops: []string{nh},
		Nlris:    []*apb.Any{nlri},
	})
	if err != nil {
		return nil, err
	}
	colorExt, err := apb.New(&api.ColorExtended{Color: route.Color})
	if err != nil {
		return nil, err
	}
	extComm, err := apb.New(&api.ExtendedCommunitiesAttribute{Communities: []*apb.Any{colorExt}})
	if err != nil {
		return nil, err
	}

	structTLV, err := apb.New(&api.SRv6StructureSubSubTLV{
		LocatorBlockLength: structure.LocatorBlockBits,
		LocatorNodeLength:  structure.LocatorNodeBits,
		FunctionLength:     structure.FunctionBits,
		ArgumentLength:     structure.ArgumentBits,
	})
	if err != nil {
		return nil, err
	}
	info, err := apb.New(&api.SRv6InformationSubTLV{
		Sid:              sid.To16(),
		EndpointBehavior: uint32(route.Behavior),
		SubSubTlvs: map[uint32]*api.SRv6TLV{
			1: {Tlv: []*apb.Any{structTLV}}, // 1 = SID Structure Sub-Sub-TLV
		},
	})
	if err != nil {
		return nil, err
	}
	l3svc, err := apb.New(&api.SRv6L3ServiceTLV{
		SubTlvs: map[uint32]*api.SRv6TLV{
			1: {Tlv: []*apb.Any{info}}, // 1 = SRv6 Information Sub-TLV
		},
	})
	if err != nil {
		return nil, err
	}
	psid, err := apb.New(&api.PrefixSID{Tlvs: []*apb.Any{l3svc}})
	if err != nil {
		return nil, err
	}

	pattrs := []*apb.Any{origin, mpReach, extComm, psid}
	if prepend.Count > 0 && prepend.ASN != 0 {
		nums := make([]uint32, prepend.Count)
		for i := range nums {
			nums[i] = prepend.ASN
		}
		asPath, err := apb.New(&api.AsPathAttribute{
			Segments: []*api.AsSegment{{Type: api.AsSegment_AS_SEQUENCE, Numbers: nums}},
		})
		if err != nil {
			return nil, err
		}
		pattrs = append(pattrs, asPath)
	}

	return &api.Path{
		Nlri:   nlri,
		Family: v6family,
		Pattrs: pattrs,
	}, nil
}

// ServiceAdvert is an RFC 9252 SRv6 L3 service route advertised toward the
// backbone: a tenant VIP made SR-reachable via the gateway's own End SID,
// colored for backbone TE class selection.
type ServiceAdvert struct {
	Route     ServiceRoute
	Structure SIDStructure
	// Prepend demotes this advertisement via AS_PATH prepending (a backup
	// upstream's per-tenant return route, §14.3). Zero value = plain advertise.
	Prepend PrependSpec
}

func (a ServiceAdvert) BuildPath() (*api.Path, error) {
	return serviceRoutePath(a.Route, a.Structure, a.Prepend)
}

// BSID is empty: RFC 9252 service routes carry no Binding SID.
func (a ServiceAdvert) BSID() string { return "" }

func (a ServiceAdvert) String() string {
	return fmt.Sprintf("service-route prefix=%s endSID=%s color=%d",
		a.Route.Prefix, a.Route.EndSID, a.Route.Color)
}
