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
		counters: make(map[string]uint64),
	}
}

type inMemory struct {
	mu       sync.Mutex
	assigned map[string]string // policyKey → VIP
	counters map[string]uint64 // poolName → next counter
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
	a.counters[poolName]++
	vip := fmt.Sprintf("pool:%s:%d", poolName, a.counters[poolName])
	a.assigned[policyKey] = vip
	return vip, nil
}

func (a *inMemory) Release(_ context.Context, policyKey string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.assigned, policyKey)
	return nil
}

// TODO(v1alpha1 → v1alpha1.1): replace inMemory with a CalicoIPAM allocator
// that calls projectcalico/calico's libcalico IPAM client to allocate /128
// from the named IPPool (which carries allowedUses: [Tunnel] for isolation
// from pod IPAM). See research issue #5 §5.3 / §9.
