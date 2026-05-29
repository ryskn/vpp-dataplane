package bgp

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-logr/logr"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	apb "google.golang.org/protobuf/types/known/anypb"
)

// goBGPDistributor distributes SR Policies by injecting routes into a running
// gobgp instance over its gRPC API. For each announced SR Policy it adds an
// IPv6 unicast route for the terminal SID (End.DT6) carrying a Color Extended
// Community (RFC 9012 §3.4.2) — the headend matches on color to install SR
// steering (RFC 9256 §8.4).
type goBGPDistributor struct {
	log  logr.Logger
	cli  api.GobgpApiClient
	conn *grpc.ClientConn

	mu        sync.Mutex
	announced map[string]*api.Path // policyOwner -> path (for withdraw)
}

// NewGoBGP dials a gobgp gRPC endpoint (e.g. "127.0.0.1:50051").
func NewGoBGP(addr string, log logr.Logger) (Distributor, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial gobgp %s: %w", addr, err)
	}
	return &goBGPDistributor{
		log:       log,
		cli:       api.NewGobgpApiClient(conn),
		conn:      conn,
		announced: map[string]*api.Path{},
	}, nil
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

func (d *goBGPDistributor) Announce(ctx context.Context, policyOwner string, key PolicyKey, segmentList []string) (string, error) {
	if len(segmentList) == 0 {
		return "", fmt.Errorf("segmentList must not be empty")
	}
	sid := segmentList[len(segmentList)-1] // terminal End.DT6 SID
	path, err := coloredHostPath(sid, key.Color)
	if err != nil {
		return "", fmt.Errorf("build path: %w", err)
	}
	if _, err := d.cli.AddPath(ctx, &api.AddPathRequest{TableType: api.TableType_GLOBAL, Path: path}); err != nil {
		return "", fmt.Errorf("gobgp AddPath: %w", err)
	}
	d.mu.Lock()
	d.announced[policyOwner] = path
	d.mu.Unlock()
	d.log.Info("announced SR Policy via gobgp",
		"owner", policyOwner, "color", key.Color, "endpoint", key.Endpoint, "sid", sid)
	return sid, nil
}

func (d *goBGPDistributor) Withdraw(ctx context.Context, policyOwner string) error {
	d.mu.Lock()
	path, ok := d.announced[policyOwner]
	delete(d.announced, policyOwner)
	d.mu.Unlock()
	if !ok {
		return nil // idempotent
	}
	if _, err := d.cli.DeletePath(ctx, &api.DeletePathRequest{TableType: api.TableType_GLOBAL, Path: path}); err != nil {
		return fmt.Errorf("gobgp DeletePath: %w", err)
	}
	d.log.Info("withdrew SR Policy via gobgp", "owner", policyOwner)
	return nil
}

// Close releases the gRPC connection.
func (d *goBGPDistributor) Close() error { return d.conn.Close() }
