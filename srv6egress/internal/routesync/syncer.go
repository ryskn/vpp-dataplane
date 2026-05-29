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
type Syncer struct {
	Cfg      *Config
	Fetch    RIBFetcher
	VPP      VPPProgrammer
	Log      logr.Logger
	Interval time.Duration

	installed map[string]Route // Key -> Route currently programmed
}

// Run loops until ctx is cancelled, reconciling each interval.
func (s *Syncer) Run(ctx context.Context) error {
	if s.installed == nil {
		s.installed = map[string]Route{}
	}
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

	installedList := make([]Route, 0, len(s.installed))
	for _, r := range s.installed {
		installedList = append(installedList, r)
	}
	add, del := Reconcile(desired, installedList)

	for _, r := range add {
		if err := s.VPP.Add(r); err != nil {
			s.Log.Error(err, "install route", "prefix", r.Prefix, "table", r.Table, "via", r.Via)
			continue
		}
		s.installed[r.Key()] = r
		s.Log.Info("installed route", "prefix", r.Prefix, "table", r.Table, "via", r.Via, "iface", r.Interface)
	}
	for _, r := range del {
		if err := s.VPP.Del(r); err != nil {
			s.Log.Error(err, "remove route", "prefix", r.Prefix, "table", r.Table, "via", r.Via)
			continue
		}
		delete(s.installed, r.Key())
		s.Log.Info("removed route", "prefix", r.Prefix, "table", r.Table, "via", r.Via)
	}
}
