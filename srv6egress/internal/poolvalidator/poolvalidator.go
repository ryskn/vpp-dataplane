// Package poolvalidator decides whether a named IP pool is safe to draw egress
// VIPs from. It isolates the reconciler from Calico's IPPool CRD schema: the
// controller depends on the Validator interface, not on crd.projectcalico.org,
// so a non-Calico VIP backend can ship its own validator without touching the
// reconcile loop.
package poolvalidator

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// Validator reports whether poolName may be used as an egress VIP pool.
type Validator interface {
	// ValidatePool returns nil if the pool is egress-safe, else an error
	// describing why it is not.
	ValidatePool(ctx context.Context, poolName string) error
}

// CalicoIPPoolGVK identifies the Calico IPPool CRD used for egress VIP pools.
var CalicoIPPoolGVK = schema.GroupVersionKind{
	Group:   "crd.projectcalico.org",
	Version: "v1",
	Kind:    "IPPool",
}

// tunnelAllowedUse is the IPPool allowedUses value that isolates a pool from
// pod IPAM, making it safe to draw egress VIPs from (design issue #5 §5.3).
const tunnelAllowedUse = "Tunnel"

// NewCalico returns a Validator that enforces allowedUses: [Tunnel] on the
// named Calico IPPool, read via reader (typically the manager's client).
func NewCalico(reader client.Reader) Validator {
	return &calicoValidator{reader: reader}
}

type calicoValidator struct {
	reader client.Reader
}

// ValidatePool verifies the named Calico IPPool exists and carries
// allowedUses: [Tunnel], so egress VIPs are isolated from pod IPAM. Without
// this guard a pool with allowedUses: [Workload] would hand out pod-range
// addresses as SNAT VIPs (issue #5 §5.3).
func (v *calicoValidator) ValidatePool(ctx context.Context, poolName string) error {
	if poolName == "" {
		return fmt.Errorf("egressIPPool is required")
	}
	pool := &unstructured.Unstructured{}
	pool.SetGroupVersionKind(CalicoIPPoolGVK)
	if err := v.reader.Get(ctx, client.ObjectKey{Name: poolName}, pool); err != nil {
		return fmt.Errorf("get IPPool %q: %w", poolName, err)
	}

	uses, found, err := unstructured.NestedStringSlice(pool.Object, "spec", "allowedUses")
	if err != nil {
		return fmt.Errorf("IPPool %q: read spec.allowedUses: %w", poolName, err)
	}
	if !found {
		return fmt.Errorf("IPPool %q has no spec.allowedUses; egress pools must set allowedUses: [%s]", poolName, tunnelAllowedUse)
	}
	for _, u := range uses {
		if u == tunnelAllowedUse {
			return nil
		}
	}
	return fmt.Errorf("IPPool %q allowedUses %v must include %q for egress VIP isolation", poolName, uses, tunnelAllowedUse)
}
