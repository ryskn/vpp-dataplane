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

// srPolicyTunnelType is the Tunnel Encapsulation TLV type for SR Policy
// (RFC 9012, "SR Policy" tunnel type = 15).
const srPolicyTunnelType = 15

// SRPolicyOptions tunes the SR Policy SAFI encoding.
type SRPolicyOptions struct {
	// Distinguisher disambiguates SR Policy NLRIs that share <color, endpoint>
	// (RFC 9256 §2.1). Defaults to 1.
	Distinguisher uint32
	// Preference is the candidate-path preference advertised in the SR Policy
	// (RFC 9256 §2.7); higher wins at the headend. Defaults to 100.
	Preference uint32
}

func (o *SRPolicyOptions) withDefaults() SRPolicyOptions {
	out := *o
	if out.Distinguisher == 0 {
		out.Distinguisher = 1
	}
	if out.Preference == 0 {
		out.Preference = 100
	}
	return out
}

// srPolicyDistributor distributes SR Policies natively over BGP SR Policy SAFI
// (AFI IPv6 / SAFI 73, RFC 9012). Unlike the colored-route encoding it
// advertises the policy itself: an NLRI of <distinguisher, color, endpoint>
// plus a Tunnel Encapsulation attribute carrying the FULL segment list, so a
// receiving headend installs the SR Policy end to end. This is what lets the
// controller integrate with an SRv6 backbone that consumes SR Policy SAFI.
type srPolicyDistributor struct {
	log  logr.Logger
	cli  api.GobgpApiClient
	conn *grpc.ClientConn
	opts SRPolicyOptions
}

// NewGoBGPSRPolicy dials a gobgp gRPC endpoint and distributes SR Policies over
// SR Policy SAFI (SAFI 73).
func NewGoBGPSRPolicy(addr string, opts SRPolicyOptions, log logr.Logger) (Distributor, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial gobgp %s: %w", addr, err)
	}
	return &srPolicyDistributor{
		log:  log,
		cli:  api.NewGobgpApiClient(conn),
		conn: conn,
		opts: opts.withDefaults(),
	}, nil
}

// srPolicyFamily is AFI IPv6 / SAFI 73.
var srPolicyFamily = &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_SR_POLICY}

// parseV6SID parses an IPv6 SRv6 SID, rejecting IPv4 / malformed input, and
// returns the canonical 16-byte form.
func parseV6SID(s string) (net.IP, error) {
	ip := net.ParseIP(s)
	if ip == nil || ip.To16() == nil || ip.To4() != nil {
		return nil, fmt.Errorf("%q is not an IPv6 address", s)
	}
	return ip.To16(), nil
}

// srPolicyPath builds an SR Policy SAFI path: NLRI <distinguisher, color,
// endpoint> + a Tunnel Encapsulation attribute (TLV type 15) carrying the
// Binding SID, candidate-path preference, and the full segment list. Each SID
// becomes an SRv6 SegmentTypeB; the terminal SID is tagged End.DT6 (per-VRF
// decap on the egress gateway) and transit SIDs End.
//
// The Binding SID sub-TLV is mandatory: the receiving headend keys its VPP SR
// Policy on the BSID, so omitting it would advertise an SR Policy the receiver
// installs under an all-zero, unusable BSID.
func (d *srPolicyDistributor) srPolicyPath(color uint32, endpoint, bsid net.IP, segmentList []string) (*api.Path, error) {
	nlri, err := apb.New(&api.SRPolicyNLRI{
		Length:        192, // bits: 4 (distinguisher) + 4 (color) + 16 (endpoint) octets
		Distinguisher: d.opts.Distinguisher,
		Color:         color,
		Endpoint:      endpoint,
	})
	if err != nil {
		return nil, err
	}

	bsidAny, err := apb.New(&api.SRBindingSID{Sid: bsid})
	if err != nil {
		return nil, err
	}
	bsidTLV, err := apb.New(&api.TunnelEncapSubTLVSRBindingSID{Bsid: bsidAny})
	if err != nil {
		return nil, err
	}

	segs := make([]*apb.Any, 0, len(segmentList))
	for i, s := range segmentList {
		sid, err := parseV6SID(s)
		if err != nil {
			return nil, fmt.Errorf("segment[%d]: %w", i, err)
		}
		behavior := api.SRv6Behavior_END
		if i == len(segmentList)-1 {
			behavior = api.SRv6Behavior_END_DT6
		}
		seg, err := apb.New(&api.SegmentTypeB{
			Flags:                     &api.SegmentFlags{},
			Sid:                       sid,
			EndpointBehaviorStructure: &api.SRv6EndPointBehavior{Behavior: behavior},
		})
		if err != nil {
			return nil, err
		}
		segs = append(segs, seg)
	}
	segList, err := apb.New(&api.TunnelEncapSubTLVSRSegmentList{
		Weight:   &api.SRWeight{Weight: 1},
		Segments: segs,
	})
	if err != nil {
		return nil, err
	}
	pref, err := apb.New(&api.TunnelEncapSubTLVSRPreference{Preference: d.opts.Preference})
	if err != nil {
		return nil, err
	}
	tunnel, err := apb.New(&api.TunnelEncapAttribute{
		Tlvs: []*api.TunnelEncapTLV{{
			Type: srPolicyTunnelType,
			Tlvs: []*apb.Any{bsidTLV, pref, segList},
		}},
	})
	if err != nil {
		return nil, err
	}

	origin, err := apb.New(&api.OriginAttribute{Origin: 0}) // IGP
	if err != nil {
		return nil, err
	}
	nh, err := apb.New(&api.NextHopAttribute{NextHop: endpoint.String()})
	if err != nil {
		return nil, err
	}

	return &api.Path{
		Nlri:   nlri,
		Family: srPolicyFamily,
		Pattrs: []*apb.Any{origin, nh, tunnel},
	}, nil
}

func (d *srPolicyDistributor) endpointIP(key PolicyKey) (net.IP, error) {
	ip, err := parseV6SID(key.EndpointAddr)
	if err != nil {
		return nil, fmt.Errorf("SR Policy endpoint address %q: %w", key.EndpointAddr, err)
	}
	return ip, nil
}

func (d *srPolicyDistributor) bindingSID(key PolicyKey) (net.IP, error) {
	if key.BSID == "" {
		return nil, fmt.Errorf("SR Policy SAFI requires a BSID (set colors.<n>.bsid in the controller config)")
	}
	ip, err := parseV6SID(key.BSID)
	if err != nil {
		return nil, fmt.Errorf("SR Policy BSID %q: %w", key.BSID, err)
	}
	return ip, nil
}

func (d *srPolicyDistributor) Announce(ctx context.Context, policyOwner string, key PolicyKey, segmentList []string) (string, error) {
	if len(segmentList) == 0 {
		return "", fmt.Errorf("segmentList must not be empty")
	}
	endpoint, err := d.endpointIP(key)
	if err != nil {
		return "", err
	}
	bsid, err := d.bindingSID(key)
	if err != nil {
		return "", err
	}
	path, err := d.srPolicyPath(key.Color, endpoint, bsid, segmentList)
	if err != nil {
		return "", fmt.Errorf("build SR Policy path: %w", err)
	}
	// AddPath is idempotent for the same NLRI key, so re-announcing after a
	// restart just refreshes the existing policy — no local bookkeeping needed.
	if _, err := d.cli.AddPath(ctx, &api.AddPathRequest{TableType: api.TableType_GLOBAL, Path: path}); err != nil {
		return "", fmt.Errorf("gobgp AddPath (SR Policy SAFI): %w", err)
	}
	d.log.Info("announced SR Policy via gobgp (SAFI 73)",
		"owner", policyOwner, "color", key.Color, "endpoint", key.EndpointAddr,
		"bsid", key.BSID, "segments", len(segmentList))
	return key.BSID, nil
}

// Withdraw rebuilds the SR Policy from the key + segment list (no in-memory
// state) and deletes it. The NLRI key is <distinguisher, color, endpoint>; the
// segment list is replayed from the EgressPolicy's persisted status so the
// teardown is correct across a controller restart.
func (d *srPolicyDistributor) Withdraw(ctx context.Context, policyOwner string, key PolicyKey, segmentList []string) error {
	if len(segmentList) == 0 {
		return nil // nothing was announced (policy never went Ready)
	}
	endpoint, err := d.endpointIP(key)
	if err != nil {
		return err
	}
	bsid, err := d.bindingSID(key)
	if err != nil {
		return err
	}
	path, err := d.srPolicyPath(key.Color, endpoint, bsid, segmentList)
	if err != nil {
		return fmt.Errorf("build SR Policy path: %w", err)
	}
	if _, err := d.cli.DeletePath(ctx, &api.DeletePathRequest{TableType: api.TableType_GLOBAL, Path: path}); err != nil {
		return fmt.Errorf("gobgp DeletePath (SR Policy SAFI): %w", err)
	}
	d.log.Info("withdrew SR Policy via gobgp (SAFI 73)",
		"owner", policyOwner, "color", key.Color, "endpoint", key.EndpointAddr)
	return nil
}

// Close releases the gRPC connection.
func (d *srPolicyDistributor) Close() error { return d.conn.Close() }
