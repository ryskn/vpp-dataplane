package bgp

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	api "github.com/osrg/gobgp/v3/api"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// pathClient is the shared gobgp gRPC transport used by every distributor. It
// dials a gobgp instance and adds/deletes paths in the global table. Every
// route encoding (colored route, SR Policy SAFI, RFC 9252 service) goes through
// it, so the gRPC plumbing — dial, AddPath/DeletePath on TableType_GLOBAL,
// error wrapping, connection lifecycle — lives in exactly one place.
type pathClient struct {
	log  logr.Logger
	cli  api.GobgpApiClient
	conn *grpc.ClientConn
}

// dialGoBGP dials a gobgp gRPC endpoint (e.g. "127.0.0.1:50051").
func dialGoBGP(addr string, log logr.Logger) (*pathClient, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial gobgp %s: %w", addr, err)
	}
	return &pathClient{log: log, cli: api.NewGobgpApiClient(conn), conn: conn}, nil
}

// add installs path in the global table. AddPath is idempotent for the same
// NLRI, so re-announcing after a restart just refreshes the existing path —
// no local bookkeeping is needed.
func (c *pathClient) add(ctx context.Context, path *api.Path) error {
	if _, err := c.cli.AddPath(ctx, &api.AddPathRequest{TableType: api.TableType_GLOBAL, Path: path}); err != nil {
		return fmt.Errorf("gobgp AddPath: %w", err)
	}
	return nil
}

// del removes path from the global table. The caller rebuilds the path
// deterministically from persisted state, so withdraw works across a restart.
func (c *pathClient) del(ctx context.Context, path *api.Path) error {
	if _, err := c.cli.DeletePath(ctx, &api.DeletePathRequest{TableType: api.TableType_GLOBAL, Path: path}); err != nil {
		return fmt.Errorf("gobgp DeletePath: %w", err)
	}
	return nil
}

// Close releases the gRPC connection.
func (c *pathClient) Close() error { return c.conn.Close() }
