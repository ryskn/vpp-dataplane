package bgp

import (
	"fmt"
	"net"

	api "github.com/osrg/gobgp/v3/api"
	apb "google.golang.org/protobuf/types/known/anypb"
)

// srPolicyTunnelType is the Tunnel Encapsulation TLV type for SR Policy
// (RFC 9012, "SR Policy" tunnel type = 15).
const srPolicyTunnelType = 15

// SRPolicyOptions holds the per-advert defaults for the SR Policy SAFI encoding.
// The controller assigns a distinguisher/preference per candidate path on the
// PolicyKey; these defaults apply only when a key leaves them zero (the
// single-candidate case).
type SRPolicyOptions struct {
	// Distinguisher disambiguates SR Policy NLRIs that share <color, endpoint>
	// (RFC 9256 §2.1). Defaults to 1.
	Distinguisher uint32
	// Preference is the candidate-path preference advertised in the SR Policy
	// (RFC 9256 §2.7); higher wins at the headend. Defaults to 100.
	Preference uint32
}

// defaultDistinguisher / defaultPreference are the single-candidate fallbacks
// used when a PolicyKey does not carry per-candidate values.
const (
	defaultDistinguisher = 1
	defaultPreference    = 100
)

func (o *SRPolicyOptions) withDefaults() SRPolicyOptions {
	out := *o
	if out.Distinguisher == 0 {
		out.Distinguisher = defaultDistinguisher
	}
	if out.Preference == 0 {
		out.Preference = defaultPreference
	}
	return out
}

// srPolicyEncoder encodes SR Policies natively over BGP SR Policy SAFI (AFI
// IPv6 / SAFI 73, RFC 9012). Unlike the colored-route encoding it advertises
// the policy itself: an NLRI of <distinguisher, color, endpoint> plus a Tunnel
// Encapsulation attribute carrying the FULL segment list, so a receiving
// headend installs the SR Policy end to end. This is what lets the controller
// integrate with an SRv6 backbone that consumes SR Policy SAFI.
type srPolicyEncoder struct{ opts SRPolicyOptions }

// NewSRPolicyEncoder returns an Encoder using the SR Policy SAFI encoding.
func NewSRPolicyEncoder(opts SRPolicyOptions) Encoder {
	return &srPolicyEncoder{opts: opts.withDefaults()}
}

func (e *srPolicyEncoder) ClusterAdvert(key PolicyKey, segmentList []string) Advertisement {
	return &SRPolicyAdvert{enc: e, Key: key, SegmentList: segmentList}
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
func (d *srPolicyEncoder) srPolicyPath(color, distinguisher, preference uint32, endpoint, bsid net.IP, segmentList []string) (*api.Path, error) {
	if distinguisher == 0 {
		distinguisher = d.opts.Distinguisher
	}
	if preference == 0 {
		preference = d.opts.Preference
	}
	nlri, err := apb.New(&api.SRPolicyNLRI{
		Length:        192, // bits: 4 (distinguisher) + 4 (color) + 16 (endpoint) octets
		Distinguisher: distinguisher,
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
	pref, err := apb.New(&api.TunnelEncapSubTLVSRPreference{Preference: preference})
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

func (d *srPolicyEncoder) endpointIP(key PolicyKey) (net.IP, error) {
	ip, err := parseV6SID(key.EndpointAddr)
	if err != nil {
		return nil, fmt.Errorf("SR Policy endpoint address %q: %w", key.EndpointAddr, err)
	}
	return ip, nil
}

func (d *srPolicyEncoder) bindingSID(key PolicyKey) (net.IP, error) {
	if key.BSID == "" {
		return nil, fmt.Errorf("SR Policy SAFI requires a BSID (set colors.<n>.bsid in the controller config)")
	}
	ip, err := parseV6SID(key.BSID)
	if err != nil {
		return nil, fmt.Errorf("SR Policy BSID %q: %w", key.BSID, err)
	}
	return ip, nil
}

// SRPolicyAdvert is an SR Policy advertised natively over SR Policy SAFI. Its
// NLRI key is <distinguisher, color, endpoint>; the segment list is replayed
// from the EgressPolicy's persisted status so Withdraw is correct across a
// controller restart.
type SRPolicyAdvert struct {
	Key         PolicyKey
	SegmentList []string
	enc         *srPolicyEncoder
}

func (a *SRPolicyAdvert) BuildPath() (*api.Path, error) {
	if len(a.SegmentList) == 0 {
		return nil, fmt.Errorf("segmentList must not be empty")
	}
	endpoint, err := a.enc.endpointIP(a.Key)
	if err != nil {
		return nil, err
	}
	bsid, err := a.enc.bindingSID(a.Key)
	if err != nil {
		return nil, err
	}
	return a.enc.srPolicyPath(a.Key.Color, a.Key.Distinguisher, a.Key.Preference, endpoint, bsid, a.SegmentList)
}

func (a *SRPolicyAdvert) BSID() string { return a.Key.BSID }

func (a *SRPolicyAdvert) String() string {
	return fmt.Sprintf("sr-policy color=%d distinguisher=%d preference=%d endpoint=%s bsid=%s segments=%d",
		a.Key.Color, a.Key.Distinguisher, a.Key.Preference, a.Key.EndpointAddr, a.Key.BSID, len(a.SegmentList))
}
