package bgp

import (
	"context"
	"fmt"
	"net"

	"github.com/go-logr/logr"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	apb "google.golang.org/protobuf/types/known/anypb"
)

// EndDT6 is the IANA SRv6 Endpoint Behavior codepoint for End.DT6.
const EndDT6 = 18

// ServiceRoute is one RFC 9252 SRv6 service advertisement: a prefix made
// SR-reachable through the gateway's own End SID, colored for backbone TE
// class selection (v1alpha2 BR mode: the tenant VIP toward the backbone PE).
type ServiceRoute struct {
	Prefix   string // e.g. "2001:db8:e::42/128"
	EndSID   string // the GW's End.DT6 SID for the tenant VRF
	Behavior uint16 // IANA endpoint behavior; use EndDT6
	Color    uint32 // backbone Color Extended Community value
	Nexthop  string // next-hop on the GW-PE eBGP session
}

// ServiceDistributor announces/withdraws SRv6 service routes (RFC 9252) on a
// backbone-facing BGP speaker.
type ServiceDistributor interface {
	AnnounceService(ctx context.Context, owner string, route ServiceRoute) error
	WithdrawService(ctx context.Context, owner string, route ServiceRoute) error
	Close() error
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

// goBGPServiceDistributor injects service routes into a gobgp instance (the
// per-VRF gobgp on the egress GW holding the eBGP session to a backbone PE)
// over its gRPC API.
type goBGPServiceDistributor struct {
	log       logr.Logger
	cli       api.GobgpApiClient
	conn      *grpc.ClientConn
	structure SIDStructure
}

// NewGoBGPService dials the backbone-facing gobgp gRPC endpoint.
func NewGoBGPService(addr string, structure SIDStructure, log logr.Logger) (ServiceDistributor, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial gobgp %s: %w", addr, err)
	}
	return &goBGPServiceDistributor{
		log:       log,
		cli:       api.NewGobgpApiClient(conn),
		conn:      conn,
		structure: structure,
	}, nil
}

// serviceRoutePath builds the IPv6-unicast path for route: MP_REACH + Color
// Extended Community + Prefix-SID attribute carrying the SRv6 L3 Service TLV
// (Information Sub-TLV with the End SID/behavior + SID Structure).
func serviceRoutePath(route ServiceRoute, structure SIDStructure) (*api.Path, error) {
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

	return &api.Path{
		Nlri:   nlri,
		Family: v6family,
		Pattrs: []*apb.Any{origin, mpReach, extComm, psid},
	}, nil
}

func (d *goBGPServiceDistributor) AnnounceService(ctx context.Context, owner string, route ServiceRoute) error {
	path, err := serviceRoutePath(route, d.structure)
	if err != nil {
		return fmt.Errorf("build service path: %w", err)
	}
	// AddPath is idempotent for the same NLRI; re-announce just refreshes it.
	if _, err := d.cli.AddPath(ctx, &api.AddPathRequest{TableType: api.TableType_GLOBAL, Path: path}); err != nil {
		return fmt.Errorf("gobgp AddPath (SRv6 service): %w", err)
	}
	d.log.Info("announced SRv6 service route (RFC 9252)",
		"owner", owner, "prefix", route.Prefix, "endSID", route.EndSID,
		"behavior", route.Behavior, "color", route.Color)
	return nil
}

// WithdrawService rebuilds the path from the persisted route (no in-memory
// state) and deletes it, so it works across controller restarts. Withdrawing
// a path that was never announced is a no-op at the BGP layer.
func (d *goBGPServiceDistributor) WithdrawService(ctx context.Context, owner string, route ServiceRoute) error {
	path, err := serviceRoutePath(route, d.structure)
	if err != nil {
		return fmt.Errorf("build service path: %w", err)
	}
	if _, err := d.cli.DeletePath(ctx, &api.DeletePathRequest{TableType: api.TableType_GLOBAL, Path: path}); err != nil {
		return fmt.Errorf("gobgp DeletePath (SRv6 service): %w", err)
	}
	d.log.Info("withdrew SRv6 service route (RFC 9252)",
		"owner", owner, "prefix", route.Prefix, "color", route.Color)
	return nil
}

func (d *goBGPServiceDistributor) Close() error { return d.conn.Close() }
