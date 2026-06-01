// Package bgp distributes SR Policies (color + endpoint + segment list) from
// the controller to headends over BGP. Two on-the-wire encodings are provided:
//
//   - colored IPv6 unicast route + Color Extended Community (RFC 9012 §3.4.2):
//     advertises the terminal SID /128 tagged with the color; a headend that
//     already holds an SR Policy for that color steers matching traffic into it
//     (RFC 9256 §8.4). See gobgp.go.
//   - SR Policy SAFI (AFI IPv6 / SAFI 73): advertises the SR Policy itself —
//     NLRI <distinguisher, color, endpoint> plus a Tunnel Encapsulation
//     attribute carrying the full segment list, so a receiving headend installs
//     the policy. See gobgp_srpolicy.go. This is the backbone-integration path.
//
// A logging stub Distributor is used for unit tests and initial bring-up.
package bgp

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
)

// PolicyKey identifies an SR Policy.
// RFC 9256 §2.1 identifies SR Policy as <headend, color, endpoint>. The
// headend is whoever receives this distribution (the agent); we carry color
// and endpoint here.
type PolicyKey struct {
	Color    uint32
	Endpoint string // node name of the SR Policy endpoint (identity / logging)
	// EndpointAddr is the endpoint's IPv6 address. It forms the endpoint field
	// of the SR Policy SAFI NLRI (RFC 9256 §2.1); the colored-route encoding
	// does not use it. Empty when the endpoint node has no resolvable address.
	EndpointAddr string
	// BSID is the Binding SID for the SR Policy. The SR Policy SAFI encoding
	// advertises it (the receiving headend keys its installed VPP SR Policy on
	// the BSID); the colored-route encoding ignores it.
	BSID string
}

// Distributor announces and withdraws SR Policies over BGP.
//
// Announce returns the chosen BSID for the policy. Implementations MAY
// generate a BSID from the controller's BSID pool, or accept one provided
// externally; for the v1alpha1 stub we synthesize a deterministic string.
//
// Withdraw takes the same key + segmentList as Announce so the route can be
// reconstructed and deleted WITHOUT relying on in-memory state. This keeps the
// distributor restart-safe: a policy deleted while the controller was down is
// still torn down correctly on restart (the reconciler replays Withdraw from
// the EgressPolicy's persisted status), so no stale BGP route is left behind.
type Distributor interface {
	Announce(ctx context.Context, policyOwner string, key PolicyKey, segmentList []string) (bsid string, err error)
	Withdraw(ctx context.Context, policyOwner string, key PolicyKey, segmentList []string) error
}

// NewLoggingStub returns a Distributor that only logs operations.
// Use during bring-up and unit tests. Replace with gobgp-backed impl for
// real BGP distribution.
func NewLoggingStub(log logr.Logger) Distributor {
	return &loggingStub{log: log}
}

type loggingStub struct {
	log logr.Logger
}

func (s *loggingStub) Announce(_ context.Context, owner string, key PolicyKey, segmentList []string) (string, error) {
	if len(segmentList) == 0 {
		return "", fmt.Errorf("segmentList must not be empty")
	}
	bsid := fmt.Sprintf("stub-bsid:%s:%d", key.Endpoint, key.Color)
	s.log.Info("announce SR Policy (stub)",
		"owner", owner, "color", key.Color, "endpoint", key.Endpoint,
		"segmentList", segmentList, "bsid", bsid)
	return bsid, nil
}

func (s *loggingStub) Withdraw(_ context.Context, owner string, key PolicyKey, segmentList []string) error {
	s.log.Info("withdraw SR Policy (stub)",
		"owner", owner, "color", key.Color, "endpoint", key.Endpoint, "segmentList", segmentList)
	return nil
}
