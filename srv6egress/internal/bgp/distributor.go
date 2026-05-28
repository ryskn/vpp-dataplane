// Package bgp distributes SR Policies (color + endpoint + segment list) from
// the controller to headends over BGP. The v1alpha1 scope uses BGP IPv6
// unicast + Color Extended Community (RFC 9012 §3.4.2); RFC 9012 SR Policy
// SAFI (BGP SAFI 73) integration is future work.
//
// v1alpha1 ships a logging stub Distributor for unit tests and the initial
// bring-up; production wires this to a gobgp client (see TODO at bottom).
package bgp

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
)

// PolicyKey identifies an SR Policy.
// RFC 9256 §2.1 identifies SR Policy as <headend, color, endpoint>. The
// headend is whoever receives this distribution (the agent); we carry color
// and endpoint here.
type PolicyKey struct {
	Color    uint32
	Endpoint string // node name (or address) of the SR Policy endpoint
}

// Distributor announces and withdraws SR Policies over BGP.
//
// Announce returns the chosen BSID for the policy. Implementations MAY
// generate a BSID from the controller's BSID pool, or accept one provided
// externally; for the v1alpha1 stub we synthesize a deterministic string.
type Distributor interface {
	Announce(ctx context.Context, policyOwner string, key PolicyKey, segmentList []string) (bsid string, err error)
	Withdraw(ctx context.Context, policyOwner string) error
}

// NewLoggingStub returns a Distributor that only logs operations.
// Use during bring-up and unit tests. Replace with gobgp-backed impl for
// real BGP distribution.
func NewLoggingStub(log logr.Logger) Distributor {
	return &loggingStub{log: log, announced: make(map[string]PolicyKey)}
}

type loggingStub struct {
	log       logr.Logger
	mu        sync.Mutex
	announced map[string]PolicyKey // policyOwner → key
}

func (s *loggingStub) Announce(_ context.Context, owner string, key PolicyKey, segmentList []string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(segmentList) == 0 {
		return "", fmt.Errorf("segmentList must not be empty")
	}
	s.announced[owner] = key
	bsid := fmt.Sprintf("stub-bsid:%s:%d", key.Endpoint, key.Color)
	s.log.Info("announce SR Policy (stub)",
		"owner", owner, "color", key.Color, "endpoint", key.Endpoint,
		"segmentList", segmentList, "bsid", bsid)
	return bsid, nil
}

func (s *loggingStub) Withdraw(_ context.Context, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.announced[owner]
	if !ok {
		// idempotent
		return nil
	}
	delete(s.announced, owner)
	s.log.Info("withdraw SR Policy (stub)",
		"owner", owner, "color", key.Color, "endpoint", key.Endpoint)
	return nil
}

// TODO(v1alpha1 wiring):
//   Replace loggingStub with a gobgp-backed Distributor that:
//   - Maintains a long-lived gobgp client connection
//   - Announces routes carrying:
//       * Color Extended Community (RFC 9012 §3.4.2) with key.Color
//       * Next-hop = key.Endpoint
//       * Segment-list via Tunnel Encapsulation attribute (RFC 9012)
//   - Withdraws those routes on Withdraw()
//   v1alpha2 will additionally adopt SR Policy SAFI 73 (RFC 9012) and
//   RFC 9252 SRv6 Services for backbone-integration scenarios (#5 §8.5).
