// Package bgp distributes the egress feature's BGP advertisements to a gobgp
// instance over its gRPC API. A single Distributor abstraction handles every
// route kind; each kind is an Advertisement that knows how to encode itself:
//
//   - colored IPv6 unicast route + Color Extended Community (RFC 9012 §3.4.2):
//     advertises the terminal SID /128 tagged with the color; a headend holding
//     an SR Policy for that color steers matching traffic into it (RFC 9256
//     §8.4). See gobgp.go.
//   - SR Policy SAFI (AFI IPv6 / SAFI 73): advertises the SR Policy itself —
//     NLRI <distinguisher, color, endpoint> plus a Tunnel Encapsulation
//     attribute carrying the full segment list, so a receiving headend installs
//     the policy. See gobgp_srpolicy.go.
//   - RFC 9252 SRv6 L3 service route: advertises a tenant VIP toward the SRv6
//     backbone, made SR-reachable via the gateway's own End SID. See services.go.
//
// The first two distribute SR Policies to headends and are selected by an
// Encoder at startup; the third advertises a VIP to the backbone. All three
// share one transport (pathClient) and one Announce/Withdraw interface — there
// is no separate "service" distributor.
package bgp

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	api "github.com/osrg/gobgp/v3/api"
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

// Advertisement is one BGP advertisement the controller distributes. An
// implementation encodes itself into the exact gobgp path to add/delete. The
// encoding is deterministic, so Withdraw rebuilds the identical path from
// persisted state (restart-safe): a route announced before a controller crash
// is torn down correctly on restart, leaving no stale path behind.
type Advertisement interface {
	// BuildPath encodes the advertisement into a gobgp path.
	BuildPath() (*api.Path, error)
	// BSID reports the binding SID / identifier the receiver keys its installed
	// state on, recorded in EgressPolicy status. Empty when not applicable
	// (e.g. RFC 9252 service routes have no BSID).
	BSID() string
	// String is a short human description for logs.
	String() string
}

// Distributor announces and withdraws BGP Advertisements. One interface covers
// SR Policy distribution to headends and RFC 9252 service routes to the
// backbone; the Advertisement carries the encoding.
//
// Announce returns the BSID the receiver keys on (Advertisement.BSID), which
// the reconciler records in status. Withdraw takes the same Advertisement
// (rebuilt from persisted status) so the path can be reconstructed and deleted
// WITHOUT in-memory state. A nil Advertisement is a no-op — nothing was ever
// announced (e.g. a policy that never went Ready).
type Distributor interface {
	Announce(ctx context.Context, owner string, adv Advertisement) (bsid string, err error)
	Withdraw(ctx context.Context, owner string, adv Advertisement) error
	Close() error
}

// gobgpDistributor is the encoding-agnostic transport: it asks the
// Advertisement to build its path and adds/deletes it via the shared client.
type gobgpDistributor struct{ c *pathClient }

// NewGoBGPDistributor dials a gobgp gRPC endpoint and distributes any
// Advertisement over it. The on-the-wire encoding is the Advertisement's
// concern, not the transport's.
func NewGoBGPDistributor(addr string, log logr.Logger) (Distributor, error) {
	c, err := dialGoBGP(addr, log)
	if err != nil {
		return nil, err
	}
	return &gobgpDistributor{c: c}, nil
}

func (d *gobgpDistributor) Announce(ctx context.Context, owner string, adv Advertisement) (string, error) {
	if adv == nil {
		return "", nil
	}
	path, err := adv.BuildPath()
	if err != nil {
		return "", fmt.Errorf("build path: %w", err)
	}
	if err := d.c.add(ctx, path); err != nil {
		return "", err
	}
	d.c.log.Info("announced via gobgp", "owner", owner, "advert", adv.String())
	return adv.BSID(), nil
}

func (d *gobgpDistributor) Withdraw(ctx context.Context, owner string, adv Advertisement) error {
	if adv == nil {
		return nil
	}
	path, err := adv.BuildPath()
	if err != nil {
		return fmt.Errorf("build path: %w", err)
	}
	if err := d.c.del(ctx, path); err != nil {
		return err
	}
	d.c.log.Info("withdrew via gobgp", "owner", owner, "advert", adv.String())
	return nil
}

func (d *gobgpDistributor) Close() error { return d.c.Close() }

// NewLoggingStub returns a Distributor that only logs operations. Use during
// bring-up and unit tests; replace with NewGoBGPDistributor for real BGP.
func NewLoggingStub(log logr.Logger) Distributor { return &loggingStub{log: log} }

type loggingStub struct{ log logr.Logger }

func (s *loggingStub) Announce(_ context.Context, owner string, adv Advertisement) (string, error) {
	if adv == nil {
		return "", nil
	}
	s.log.Info("announce (stub)", "owner", owner, "advert", adv.String())
	return adv.BSID(), nil
}

func (s *loggingStub) Withdraw(_ context.Context, owner string, adv Advertisement) error {
	if adv != nil {
		s.log.Info("withdraw (stub)", "owner", owner, "advert", adv.String())
	}
	return nil
}

func (s *loggingStub) Close() error { return nil }
