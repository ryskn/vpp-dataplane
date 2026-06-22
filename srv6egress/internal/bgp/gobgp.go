package bgp

import (
	"fmt"

	api "github.com/osrg/gobgp/v3/api"
	apb "google.golang.org/protobuf/types/known/anypb"
)

// Encoder builds the Advertisement for distributing an SR Policy to headends,
// per a chosen on-the-wire encoding (colored route or SR Policy SAFI). The
// controller is given one Encoder at startup (--bgp-encoding) and stays
// encoding-agnostic; the Distributor transport is independent of the encoding.
type Encoder interface {
	// ClusterAdvert builds the SR Policy advertisement for (key, segmentList).
	ClusterAdvert(key PolicyKey, segmentList []string) Advertisement
}

var v6family = &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}

// coloredHostPath builds an IPv6 /128 path for sid with a Color Extended
// Community and next-hop = sid.
func coloredHostPath(sid string, color uint32) (*api.Path, error) {
	nlri, err := apb.New(&api.IPAddressPrefix{PrefixLen: 128, Prefix: sid})
	if err != nil {
		return nil, err
	}
	origin, err := apb.New(&api.OriginAttribute{Origin: 0}) // IGP
	if err != nil {
		return nil, err
	}
	mpReach, err := apb.New(&api.MpReachNLRIAttribute{
		Family:   v6family,
		NextHops: []string{sid},
		Nlris:    []*apb.Any{nlri},
	})
	if err != nil {
		return nil, err
	}
	colorExt, err := apb.New(&api.ColorExtended{Color: color})
	if err != nil {
		return nil, err
	}
	extComm, err := apb.New(&api.ExtendedCommunitiesAttribute{
		Communities: []*apb.Any{colorExt},
	})
	if err != nil {
		return nil, err
	}
	return &api.Path{
		Nlri:   nlri,
		Family: v6family,
		Pattrs: []*apb.Any{origin, mpReach, extComm},
	}, nil
}

// coloredEncoder encodes SR Policies as a colored IPv6 /128 host route for the
// terminal SID (End.DT6) carrying a Color Extended Community (RFC 9012 §3.4.2).
// The SR Policy must be provisioned on the headend out of band; the route only
// carries the color the headend steers on.
type coloredEncoder struct{}

// NewColoredEncoder returns an Encoder using the colored-route encoding.
func NewColoredEncoder() Encoder { return coloredEncoder{} }

func (coloredEncoder) ClusterAdvert(key PolicyKey, segmentList []string) Advertisement {
	return &ColoredAdvert{Key: key, SegmentList: segmentList}
}

// ColoredAdvert is an SR Policy advertised as a colored IPv6 host route.
type ColoredAdvert struct {
	Key         PolicyKey
	SegmentList []string
}

func (a *ColoredAdvert) BuildPath() (*api.Path, error) {
	if len(a.SegmentList) == 0 {
		return nil, fmt.Errorf("segmentList must not be empty")
	}
	return coloredHostPath(a.SegmentList[len(a.SegmentList)-1], a.Key.Color) // terminal End.DT6 SID
}

// BSID reports the terminal SID, which the colored encoding effectively keys on
// (it carries no separate Binding SID).
func (a *ColoredAdvert) BSID() string {
	if len(a.SegmentList) == 0 {
		return ""
	}
	return a.SegmentList[len(a.SegmentList)-1]
}

func (a *ColoredAdvert) String() string {
	return fmt.Sprintf("colored-route color=%d sid=%s", a.Key.Color, a.BSID())
}
