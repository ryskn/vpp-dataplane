package routesync

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/yaml"
)

// LoadConfig reads the peer->VRF mapping yaml.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read routesync config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse routesync config %s: %w", path, err)
	}
	if len(c.Upstreams) == 0 {
		return nil, fmt.Errorf("routesync config %s: no upstreams defined", path)
	}
	for i, u := range c.Upstreams {
		if u.Peer == "" || u.Table == 0 || u.Interface == "" {
			return nil, fmt.Errorf("upstreams[%d]: peer, table and interface are required", i)
		}
	}
	return &c, nil
}

// RIBFetcher returns the raw `gobgp global rib -a ipv6 -j` bytes.
type RIBFetcher func(ctx context.Context) ([]byte, error)

// ExecRIBFetcher fetches the RIB by running the gobgp CLI (prefix + the rib args).
func ExecRIBFetcher(gobgpPrefix []string) RIBFetcher {
	return func(ctx context.Context) ([]byte, error) {
		args := append(append([]string{}, gobgpPrefix[1:]...),
			"global", "rib", "-a", "ipv6", "-j")
		cmd := exec.CommandContext(ctx, gobgpPrefix[0], args...)
		var out, errb bytes.Buffer
		cmd.Stdout = &out
		cmd.Stderr = &errb
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("gobgp rib fetch: %w: %s", err, bytes.TrimSpace(errb.Bytes()))
		}
		return out.Bytes(), nil
	}
}

// Syncer reconciles the gobgp RIB into VPP VRF FIBs on an interval.
//
// It holds NO in-memory ownership state: on every pass the "installed" set is
// read back from VPP itself (the routes in our VRF tables whose next-hop is one
// of our upstream peers). This makes the syncer self-healing and, critically,
// correct across restarts — a route installed before a restart and withdrawn
// while the syncer was down is still discovered in VPP and removed.
type Syncer struct {
	Cfg      *Config
	Fetch    RIBFetcher
	VPP      VPPProgrammer
	Log      logr.Logger
	Interval time.Duration
}

// Run loops until ctx is cancelled, reconciling each interval.
func (s *Syncer) Run(ctx context.Context) error {
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	// Reconcile immediately, then on each tick.
	s.reconcileOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			s.reconcileOnce(ctx)
		}
	}
}

// installedFromVPP reads every configured VRF table and returns the routes we
// own (next-hop ∈ our peers). If any table read fails it returns an error so
// the caller can skip this pass rather than risk deleting live routes based on
// an incomplete view.
func (s *Syncer) installedFromVPP() ([]Route, error) {
	peers := s.Cfg.PeerIndex()
	var installed []Route
	for _, table := range s.Cfg.Tables() {
		raw, err := s.VPP.ShowFIB(table)
		if err != nil {
			return nil, err
		}
		installed = append(installed, ParseOwnedRoutes(raw, table, peers)...)
	}
	return installed, nil
}

func (s *Syncer) reconcileOnce(ctx context.Context) {
	raw, err := s.Fetch(ctx)
	if err != nil {
		s.Log.Error(err, "fetch RIB")
		return
	}
	rib, err := ParseRIB(raw)
	if err != nil {
		s.Log.Error(err, "parse RIB")
		return
	}
	desired := DesiredRoutes(rib, s.Cfg)

	installed, err := s.installedFromVPP()
	if err != nil {
		// Do NOT proceed with a partial view: deleting based on it could remove
		// routes that are actually still wanted.
		s.Log.Error(err, "read installed routes from VPP; skipping this pass")
		return
	}

	add, del := Reconcile(desired, installed)
	for _, r := range add {
		if err := s.VPP.Add(r); err != nil {
			s.Log.Error(err, "install route", "prefix", r.Prefix, "table", r.Table, "via", r.Via)
			continue
		}
		s.Log.Info("installed route", "prefix", r.Prefix, "table", r.Table, "via", r.Via, "iface", r.Interface)
	}
	for _, r := range del {
		if err := s.VPP.Del(r); err != nil {
			s.Log.Error(err, "remove route", "prefix", r.Prefix, "table", r.Table, "via", r.Via)
			continue
		}
		s.Log.Info("removed stale route", "prefix", r.Prefix, "table", r.Table, "via", r.Via)
	}
}
