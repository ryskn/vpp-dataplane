package controller

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"sigs.k8s.io/controller-runtime/pkg/client"

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/config"
)

// policySelectsNamespace reports whether a policy's namespaceSelector selects a
// namespace with the given labels. A nil selector matches all namespaces; a
// malformed selector never matches (fail-closed). Shared by the reconciler and
// the return advertiser so tenant membership is derived identically everywhere.
func policySelectsNamespace(p *srv6egressv1.EgressPolicy, nsLabels map[string]string) bool {
	ns := p.Spec.Selector.NamespaceSelector
	if ns == nil {
		return true
	}
	sel, err := metav1.LabelSelectorAsSelector(ns)
	if err != nil {
		return false
	}
	return sel.Matches(labels.Set(nsLabels))
}

// getNamespaceLabels reads a namespace's labels for tenant matching. A missing
// namespace yields nil labels (only a nil namespaceSelector then matches it).
func getNamespaceLabels(ctx context.Context, c client.Reader, name string) (map[string]string, error) {
	var ns corev1.Namespace
	if err := c.Get(ctx, client.ObjectKey{Name: name}, &ns); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get namespace %q: %w", name, err)
	}
	return ns.Labels, nil
}

// tenantReturnPrefixes derives the pod prefixes of every configured tenant the
// policy selects (sorted; normally one — plural because a broad
// namespaceSelector can select several tenant namespaces). Empty when
// Backbone.Tenants is unset (legacy shared-aggregate mode).
func tenantReturnPrefixes(ctx context.Context, c client.Reader, bb *config.BackboneConfig, p *srv6egressv1.EgressPolicy) ([]string, error) {
	if bb == nil || len(bb.Tenants) == 0 {
		return nil, nil
	}
	set := map[string]struct{}{}
	for _, tc := range bb.Tenants {
		nsLabels, err := getNamespaceLabels(ctx, c, tc.Namespace)
		if err != nil {
			return nil, err
		}
		if policySelectsNamespace(p, nsLabels) {
			set[tc.PodCIDR] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for cidr := range set {
		out = append(out, cidr)
	}
	sort.Strings(out)
	return out, nil
}
