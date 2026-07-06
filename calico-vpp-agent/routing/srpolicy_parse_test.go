// Tests for the SR Policy SAFI (RFC 9830) parsing in getSRPolicy: RFC 9256
// defaults (Preference/Priority), BSID sub-TLV flags, the SRv6 Binding SID
// sub-TLV (type 20, arrives as Unknown from gobgp), V-Flag verification masks
// and segment-list validity.
package routing

import (
	"io"
	"net"
	"testing"

	bgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func mustAny(t *testing.T, m proto.Message) *anypb.Any {
	t.Helper()
	a, err := anypb.New(m)
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}
	return a
}

func segB(t *testing.T, sid string, behavior bgpapi.SRv6Behavior, vFlag bool) *anypb.Any {
	t.Helper()
	return mustAny(t, &bgpapi.SegmentTypeB{
		Flags:                     &bgpapi.SegmentFlags{VFlag: vFlag},
		Sid:                       net.ParseIP(sid).To16(),
		EndpointBehaviorStructure: &bgpapi.SRv6EndPointBehavior{Behavior: behavior},
	})
}

func segListTLV(t *testing.T, weight *uint32, segs ...*anypb.Any) *anypb.Any {
	t.Helper()
	sl := &bgpapi.TunnelEncapSubTLVSRSegmentList{Segments: segs}
	if weight != nil {
		sl.Weight = &bgpapi.SRWeight{Weight: *weight}
	}
	return mustAny(t, sl)
}

func bsid13TLV(t *testing.T, sid string, sFlag, iFlag bool) *anypb.Any {
	t.Helper()
	return mustAny(t, &bgpapi.TunnelEncapSubTLVSRBindingSID{
		Bsid: mustAny(t, &bgpapi.SRBindingSID{Sid: net.ParseIP(sid).To16(), SFlag: sFlag, IFlag: iFlag}),
	})
}

// bsid20TLV builds the raw SRv6 Binding SID sub-TLV (type 20) the way gobgp
// hands it to us: as TunnelEncapSubTLVUnknown with the wire value.
func bsid20TLV(t *testing.T, sid string, flags byte) *anypb.Any {
	t.Helper()
	v := make([]byte, 18)
	v[0] = flags
	copy(v[2:], net.ParseIP(sid).To16())
	return mustAny(t, &bgpapi.TunnelEncapSubTLVUnknown{Type: srv6BindingSIDSubTLVType, Value: v})
}

func srPath(t *testing.T, subTLVs ...*anypb.Any) *bgpapi.Path {
	t.Helper()
	return &bgpapi.Path{
		Family: &bgpapi.Family{Afi: bgpapi.Family_AFI_IP6, Safi: bgpapi.Family_SAFI_SR_POLICY},
		Nlri: mustAny(t, &bgpapi.SRPolicyNLRI{
			Length: 192, Distinguisher: 7, Color: 100,
			Endpoint: net.ParseIP("fd00:1::11").To16(),
		}),
		Pattrs: []*anypb.Any{
			mustAny(t, &bgpapi.TunnelEncapAttribute{
				Tlvs: []*bgpapi.TunnelEncapTLV{{Type: 15, Tlvs: subTLVs}},
			}),
		},
		SourceAsn: 65001,
		SourceId:  "10.0.0.3",
	}
}

func newTestServer() *Server {
	logger := logrus.New()
	logger.SetOutput(io.Discard)
	return &Server{log: logrus.NewEntry(logger)}
}

func defaultSegList(t *testing.T) *anypb.Any {
	t.Helper()
	return segListTLV(t, nil, segB(t, "fd10::1", bgpapi.SRv6Behavior_END, false), segB(t, "fd10::2", bgpapi.SRv6Behavior_END_DT6, false))
}

// Preference / Priority sub-TLVs absent → RFC 9256 defaults (100 / 128), and
// the originator is carried from the BGP path source for §2.9 tie-breaking.
func TestGetSRPolicy_Defaults(t *testing.T) {
	s := newTestServer()
	_, tun, _, err := s.getSRPolicy(srPath(t, bsid13TLV(t, "cafe::1", false, false), defaultSegList(t)))
	if err != nil {
		t.Fatalf("getSRPolicy: %v", err)
	}
	if tun.Preference != defaultSRPolicyPreference {
		t.Fatalf("preference=%d, want default %d (RFC 9256 §2.7)", tun.Preference, defaultSRPolicyPreference)
	}
	if tun.Priority != defaultSRPolicyPriority {
		t.Fatalf("priority=%d, want default %d (RFC 9256 §2.12)", tun.Priority, defaultSRPolicyPriority)
	}
	if tun.OriginatorASN != 65001 || tun.OriginatorNode != "10.0.0.3" {
		t.Fatalf("originator=%d/%s, want 65001/10.0.0.3", tun.OriginatorASN, tun.OriginatorNode)
	}
}

func TestGetSRPolicy_ParsesPreferenceAndFlags(t *testing.T) {
	s := newTestServer()
	pref := mustAny(t, &bgpapi.TunnelEncapSubTLVSRPreference{Preference: 200})
	_, tun, _, err := s.getSRPolicy(srPath(t, pref, bsid13TLV(t, "cafe::1", true, true), defaultSegList(t)))
	if err != nil {
		t.Fatalf("getSRPolicy: %v", err)
	}
	if tun.Preference != 200 {
		t.Fatalf("preference=%d, want 200", tun.Preference)
	}
	if !tun.SpecifiedBSIDOnly || !tun.DropUponInvalid {
		t.Fatalf("S/I flags = %v/%v, want both true", tun.SpecifiedBSIDOnly, tun.DropUponInvalid)
	}
}

// The SRv6 Binding SID sub-TLV (type 20) arrives from gobgp as Unknown and must
// be decoded; when both type 13 and type 20 are present, type 20 wins
// (RFC 9830 §2.4.2: type 13 is retained for backward compatibility).
func TestGetSRPolicy_SRv6BindingSIDSubTLV(t *testing.T) {
	s := newTestServer()
	policy, tun, _, err := s.getSRPolicy(srPath(t,
		bsid13TLV(t, "cafe::13", false, false),
		bsid20TLV(t, "cafe::20", 0xC0), // S|I
		defaultSegList(t)))
	if err != nil {
		t.Fatalf("getSRPolicy: %v", err)
	}
	if got := policy.Bsid.ToIP().String(); got != "cafe::20" {
		t.Fatalf("bsid=%s, want type-20 to win", got)
	}
	if !tun.SpecifiedBSIDOnly || !tun.DropUponInvalid {
		t.Fatalf("S/I flags from type-20 = %v/%v, want both true", tun.SpecifiedBSIDOnly, tun.DropUponInvalid)
	}
}

// V-Flag marks a segment for SID verification (RFC 9256 §5.1); the mask is
// carried per segment list.
func TestGetSRPolicy_VFlagMask(t *testing.T) {
	s := newTestServer()
	sl := segListTLV(t, nil,
		segB(t, "fd10::1", bgpapi.SRv6Behavior_END, false),
		segB(t, "fd10::2", bgpapi.SRv6Behavior_END_DT6, true))
	_, tun, _, err := s.getSRPolicy(srPath(t, bsid13TLV(t, "cafe::1", false, false), sl))
	if err != nil {
		t.Fatalf("getSRPolicy: %v", err)
	}
	if len(tun.VerifyMasks) != 1 || tun.VerifyMasks[0] != 1<<1 {
		t.Fatalf("verify masks=%v, want [0b10]", tun.VerifyMasks)
	}
}

// An explicit weight of 0 invalidates the segment list (RFC 9256 §5.1).
func TestGetSRPolicy_WeightZeroRejected(t *testing.T) {
	s := newTestServer()
	zero := uint32(0)
	sl := segListTLV(t, &zero, segB(t, "fd10::1", bgpapi.SRv6Behavior_END_DT6, false))
	if _, _, _, err := s.getSRPolicy(srPath(t, bsid13TLV(t, "cafe::1", false, false), sl)); err == nil {
		t.Fatal("weight 0 must be rejected")
	}
}

// Without a BSID: S-Flag makes the candidate invalid (§6.2.3); otherwise the
// zero BSID passes through for the provider to bind dynamically (§6.2.1).
func TestGetSRPolicy_MissingBSID(t *testing.T) {
	s := newTestServer()

	policy, _, _, err := s.getSRPolicy(srPath(t, defaultSegList(t)))
	if err != nil {
		t.Fatalf("no BSID without S-Flag must be accepted (dynamic allocation): %v", err)
	}
	if policy.Bsid.ToIP().String() != "::" {
		t.Fatalf("bsid=%s, want zero (to be dynamically bound)", policy.Bsid.ToIP())
	}

	sOnly := mustAny(t, &bgpapi.TunnelEncapSubTLVSRBindingSID{
		Bsid: mustAny(t, &bgpapi.SRBindingSID{SFlag: true}),
	})
	if _, _, _, err := s.getSRPolicy(srPath(t, sOnly, defaultSegList(t))); err == nil {
		t.Fatal("S-Flag without BSID must be rejected (RFC 9256 §6.2.3)")
	}
}
