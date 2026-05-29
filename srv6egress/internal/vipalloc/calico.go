package vipalloc

import (
	"context"
	"fmt"

	"github.com/projectcalico/calico/libcalico-go/lib/apiconfig"
	calicocli "github.com/projectcalico/calico/libcalico-go/lib/clientv3"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
)

// calicoAllocator allocates per-tenant egress VIPs from a Calico IPPool via
// libcalico IPAM. The EgressPolicy UID is used as the IPAM HandleID so that
// allocation is idempotent and a VIP can be released by handle on delete.
// State lives in Calico IPAM (etcd/Kubernetes datastore), so it survives a
// controller restart — no in-memory bookkeeping is needed.
type calicoAllocator struct {
	c calicocli.Interface
}

// NewCalico builds a Calico IPAM-backed allocator. kubeconfig may be empty to
// use the in-cluster config.
func NewCalico(kubeconfig string) (Allocator, error) {
	cfg := apiconfig.NewCalicoAPIConfig()
	cfg.Spec.DatastoreType = apiconfig.Kubernetes
	cfg.Spec.Kubeconfig = kubeconfig
	c, err := calicocli.New(*cfg)
	if err != nil {
		return nil, fmt.Errorf("calico client: %w", err)
	}
	return &calicoAllocator{c: c}, nil
}

func (a *calicoAllocator) poolCIDR(ctx context.Context, name string) (string, error) {
	p, err := a.c.IPPools().Get(ctx, name, options.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get IPPool %q: %w", name, err)
	}
	if p.Spec.CIDR == "" {
		return "", fmt.Errorf("IPPool %q has empty CIDR", name)
	}
	return p.Spec.CIDR, nil
}

func (a *calicoAllocator) Allocate(ctx context.Context, policyKey, poolName string) (string, error) {
	if poolName == "" {
		return "", fmt.Errorf("poolName is required")
	}
	// Idempotent: if this policy already holds an IP (by handle), reuse it.
	if ips, err := a.c.IPAM().IPsByHandle(ctx, policyKey); err == nil && len(ips) > 0 {
		return ips[0].String(), nil
	}
	cidr, err := a.poolCIDR(ctx, poolName)
	if err != nil {
		return "", err
	}
	handle := policyKey
	_, v6, err := a.c.IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{
		Num6:        1,
		IPv6Pools:   []cnet.IPNet{cnet.MustParseNetwork(cidr)},
		IntendedUse: "Tunnel", // matches IPPool allowedUses: [Tunnel]
		HandleID:    &handle,
		Attrs:       map[string]string{"srv6egress.ryskn.io/policy": policyKey},
	})
	if err != nil {
		return "", fmt.Errorf("AutoAssign from pool %q: %w", poolName, err)
	}
	if v6 == nil || len(v6.IPs) == 0 {
		return "", fmt.Errorf("no IPv6 assigned from pool %q", poolName)
	}
	return v6.IPs[0].IP.String(), nil
}

// Register is a no-op: Calico IPAM is the source of truth, and Allocate is
// idempotent by handle, so there is no in-memory state to seed after a restart.
func (a *calicoAllocator) Register(_ context.Context, _, _ string) error { return nil }

func (a *calicoAllocator) Release(ctx context.Context, policyKey string) error {
	if err := a.c.IPAM().ReleaseByHandle(ctx, policyKey); err != nil {
		return fmt.Errorf("ReleaseByHandle %q: %w", policyKey, err)
	}
	return nil
}
