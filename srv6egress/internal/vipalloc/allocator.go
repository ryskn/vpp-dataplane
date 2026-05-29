// Package vipalloc allocates per-tenant egress VIPs from a Calico IPPool.
//
// v1alpha1 scope: stub in-memory allocator suitable for unit tests and
// initial bring-up. Production integration with Calico IPAM is TODO and
// will replace InMemory with an implementation backed by
// projectcalico.org/v3 IPAM (see TODO at the bottom of this file).
package vipalloc

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

// Allocator allocates and releases per-tenant egress VIPs.
// PolicyKey is typically the EgressPolicy UID (stable across rename, unique
// across the cluster). PoolName is the Calico IPPool name.
type Allocator interface {
	// Allocate returns a VIP for the given policy, allocating from pool if
	// needed. Subsequent calls with the same policyKey return the same VIP
	// (idempotent).
	Allocate(ctx context.Context, policyKey, poolName string) (string, error)

	// Register records a VIP already assigned to policyKey (e.g. recovered
	// from an EgressPolicy's status after a controller restart). Allocate will
	// never hand the same VIP to a different policyKey afterwards. Idempotent.
	Register(ctx context.Context, policyKey, vip string) error

	// Release frees the VIP previously allocated for policyKey.
	// Safe to call when no allocation exists (returns nil).
	Release(ctx context.Context, policyKey string) error
}

// NewInMemory returns an in-memory allocator. Used for unit tests and the
// v1alpha1 bring-up phase before Calico IPAM integration is wired up.
//
// Each pool advances a per-pool counter; the returned address is a synthetic
// placeholder of the form "pool:<poolName>:<counter>" so that misconfigurations
// are easy to spot in status fields.
func NewInMemory() Allocator {
	return &inMemory{
		assigned: make(map[string]string),
		taken:    make(map[string]struct{}),
		counters: make(map[string]uint64),
	}
}

type inMemory struct {
	mu       sync.Mutex
	assigned map[string]string   // policyKey → VIP
	taken    map[string]struct{} // VIP → {} (every VIP ever handed out / registered)
	counters map[string]uint64   // poolName → next counter
}

func (a *inMemory) Allocate(_ context.Context, policyKey, poolName string) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if vip, ok := a.assigned[policyKey]; ok {
		return vip, nil
	}
	if poolName == "" {
		return "", fmt.Errorf("poolName is required")
	}
	// Advance the per-pool counter until we land on an unused synthetic VIP.
	// The skip-taken loop makes Allocate safe even when some VIPs were learned
	// via Register (e.g. after a restart) rather than handed out by us.
	for {
		a.counters[poolName]++
		vip := fmt.Sprintf("pool:%s:%d", poolName, a.counters[poolName])
		if _, used := a.taken[vip]; used {
			continue
		}
		a.assigned[policyKey] = vip
		a.taken[vip] = struct{}{}
		return vip, nil
	}
}

func (a *inMemory) Register(_ context.Context, policyKey, vip string) error {
	if vip == "" {
		return fmt.Errorf("vip is required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.assigned[policyKey] = vip
	a.taken[vip] = struct{}{}
	// If the VIP is one of our synthetic "pool:<name>:<n>" addresses, advance
	// the pool counter past n so a fresh Allocate never reissues it.
	if pool, n, ok := parseSyntheticVIP(vip); ok {
		if n > a.counters[pool] {
			a.counters[pool] = n
		}
	}
	return nil
}

func (a *inMemory) Release(_ context.Context, policyKey string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if vip, ok := a.assigned[policyKey]; ok {
		delete(a.taken, vip)
	}
	delete(a.assigned, policyKey)
	return nil
}

// parseSyntheticVIP parses "pool:<name>:<counter>" produced by Allocate.
func parseSyntheticVIP(vip string) (pool string, n uint64, ok bool) {
	if !strings.HasPrefix(vip, "pool:") {
		return "", 0, false
	}
	rest := strings.TrimPrefix(vip, "pool:")
	idx := strings.LastIndex(rest, ":")
	if idx < 0 {
		return "", 0, false
	}
	pool = rest[:idx]
	n, err := strconv.ParseUint(rest[idx+1:], 10, 64)
	if err != nil || pool == "" {
		return "", 0, false
	}
	return pool, n, true
}

// TODO(v1alpha1 → v1alpha1.1): replace inMemory with a CalicoIPAM allocator
// that calls projectcalico/calico's libcalico IPAM client to allocate /128
// from the named IPPool (which carries allowedUses: [Tunnel] for isolation
// from pod IPAM). See research issue #5 §5.3 / §9.
