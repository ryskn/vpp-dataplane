// Package controller implements the EgressPolicy reconcile loop.
//
// On a watched EgressPolicy event the reconciler:
//  1. resolves the endpoint (exactly one node, per v1alpha1)
//  2. resolves <color, endpoint> to a segment list via the controller config
//  3. allocates a per-tenant VIP from the named Calico IPPool
//  4. distributes the SR Policy over BGP
//  5. updates status (egressIP / activeEndpoint / upstream / srPolicy / conditions)
//
// Deletion: withdraws the BGP route, releases the VIP, removes the finalizer.
package controller

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerruntimecfg "sigs.k8s.io/controller-runtime/pkg/controller"

	srv6egressv1alpha1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1alpha1"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/bgp"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/config"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/vipalloc"
)

// calicoIPPoolGVK identifies the Calico IPPool CRD used for egress VIP pools.
var calicoIPPoolGVK = schema.GroupVersionKind{
	Group:   "crd.projectcalico.org",
	Version: "v1",
	Kind:    "IPPool",
}

// tunnelAllowedUse is the IPPool allowedUses value that isolates a pool from
// pod IPAM, making it safe to draw egress VIPs from (see design issue #5 §5.3).
const tunnelAllowedUse = "Tunnel"

const finalizerName = "srv6egress.ryskn.io/finalizer"

// EgressPolicyReconciler reconciles an EgressPolicy.
type EgressPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Config *config.ControllerConfig
	VIPs   vipalloc.Allocator
	BGP    bgp.Distributor
}

// +kubebuilder:rbac:groups=srv6egress.ryskn.io,resources=egresspolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=srv6egress.ryskn.io,resources=egresspolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=srv6egress.ryskn.io,resources=egresspolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=crd.projectcalico.org,resources=ippools,verbs=get;list;watch

// Reconcile performs one reconciliation pass.
func (r *EgressPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	var ep srv6egressv1alpha1.EgressPolicy
	if err := r.Get(ctx, req.NamespacedName, &ep); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Deletion path.
	if !ep.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &ep)
	}

	// Ensure finalizer.
	if !containsString(ep.Finalizers, finalizerName) {
		ep.Finalizers = append(ep.Finalizers, finalizerName)
		if err := r.Update(ctx, &ep); err != nil {
			return ctrl.Result{}, err
		}
		// Requeue to pick up the updated object.
		return ctrl.Result{Requeue: true}, nil
	}

	// 1) Resolve color → upstream + segment list.
	cc, ok := r.Config.Colors[ep.Spec.Egress.Color]
	if !ok {
		return r.markNotReady(ctx, &ep, "UnknownColor",
			fmt.Sprintf("color %d is not defined in controller config", ep.Spec.Egress.Color))
	}

	// 2) Resolve endpoint via NodeSelector — exactly one node.
	endpoint, err := r.resolveEndpoint(ctx, ep.Spec.Egress.EndpointSelector)
	if err != nil {
		return r.markNotReady(ctx, &ep, "EndpointResolution", err.Error())
	}

	// 2b) Enforce RFC 9256 §2 SR Policy uniqueness: <color, endpoint> must be
	// unique cluster-wide. Reject if another EgressPolicy already owns it.
	if conflict, err := r.findColorEndpointConflict(ctx, &ep, endpoint); err != nil {
		return ctrl.Result{}, err
	} else if conflict != "" {
		return r.markNotReady(ctx, &ep, "DuplicateColorEndpoint",
			fmt.Sprintf("color %d + endpoint %q already used by EgressPolicy %q",
				ep.Spec.Egress.Color, endpoint, conflict))
	}

	// 3) Allocate VIP (idempotent by EgressPolicy UID).
	policyOwner := string(ep.UID)
	vip := ep.Status.EgressIP
	if vip != "" {
		// Recover prior allocation after a controller restart so the in-memory
		// allocator never reissues this VIP to another policy.
		if err := r.VIPs.Register(ctx, policyOwner, vip); err != nil {
			return ctrl.Result{}, err
		}
	} else {
		// Validate the named pool is egress-safe before allocating.
		if err := r.validateEgressIPPool(ctx, ep.Spec.Egress.EgressIPPool); err != nil {
			return r.markNotReady(ctx, &ep, "InvalidEgressIPPool", err.Error())
		}
		vip, err = r.VIPs.Allocate(ctx, policyOwner, ep.Spec.Egress.EgressIPPool)
		if err != nil {
			return r.markNotReady(ctx, &ep, "VIPAllocation", err.Error())
		}
	}

	// 4) Distribute SR Policy.
	bsid, err := r.BGP.Announce(ctx, policyOwner, bgp.PolicyKey{
		Color:    ep.Spec.Egress.Color,
		Endpoint: endpoint,
	}, cc.SegmentList)
	if err != nil {
		return r.markNotReady(ctx, &ep, "BGPDistribution", err.Error())
	}

	// 5) Update status.
	ep.Status.EgressIP = vip
	ep.Status.ActiveEndpoint = endpoint
	ep.Status.Upstream = cc.Upstream
	ep.Status.SRPolicy = &srv6egressv1alpha1.SRPolicyStatus{
		BSID:        bsid,
		Color:       ep.Spec.Egress.Color,
		SegmentList: cc.SegmentList,
	}
	setReady(&ep, metav1.ConditionTrue, "Reconciled", "EgressPolicy installed")
	if err := r.Status().Update(ctx, &ep); err != nil {
		return ctrl.Result{}, err
	}

	log.Info("reconciled", "name", ep.Name, "color", ep.Spec.Egress.Color,
		"upstream", cc.Upstream, "endpoint", endpoint, "vip", vip, "bsid", bsid)
	return ctrl.Result{}, nil
}

func (r *EgressPolicyReconciler) reconcileDelete(ctx context.Context, ep *srv6egressv1alpha1.EgressPolicy) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	if !containsString(ep.Finalizers, finalizerName) {
		return ctrl.Result{}, nil
	}

	owner := string(ep.UID)
	if err := r.BGP.Withdraw(ctx, owner); err != nil {
		return ctrl.Result{}, err
	}
	if err := r.VIPs.Release(ctx, owner); err != nil {
		return ctrl.Result{}, err
	}

	ep.Finalizers = removeString(ep.Finalizers, finalizerName)
	if err := r.Update(ctx, ep); err != nil {
		return ctrl.Result{}, err
	}
	log.Info("teardown complete", "name", ep.Name)
	return ctrl.Result{}, nil
}

// resolveEndpoint enforces the v1alpha1 invariant: exactly one node must match.
func (r *EgressPolicyReconciler) resolveEndpoint(ctx context.Context, es srv6egressv1alpha1.EndpointSelector) (string, error) {
	if es.NodeSelector == nil {
		return "", fmt.Errorf("endpointSelector.nodeSelector is required")
	}
	sel, err := metav1.LabelSelectorAsSelector(es.NodeSelector)
	if err != nil {
		return "", fmt.Errorf("invalid nodeSelector: %w", err)
	}

	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes, &client.ListOptions{LabelSelector: sel}); err != nil {
		return "", fmt.Errorf("list nodes: %w", err)
	}
	switch len(nodes.Items) {
	case 0:
		return "", fmt.Errorf("no node matches selector %q", labels.SelectorFromValidatedSet(es.NodeSelector.MatchLabels).String())
	case 1:
		return nodes.Items[0].Name, nil
	default:
		names := make([]string, 0, len(nodes.Items))
		for i := range nodes.Items {
			names = append(names, nodes.Items[i].Name)
		}
		return "", fmt.Errorf("v1alpha1 requires exactly one matching node, got %d: %v", len(nodes.Items), names)
	}
}

// findColorEndpointConflict returns the name of another (non-deleting)
// EgressPolicy that already occupies the same <color, endpoint> tuple, or "".
// A peer is considered to occupy the tuple once its reconcile has recorded the
// resolved endpoint in status.activeEndpoint. Reconciles are serialized
// (MaxConcurrentReconciles=1), so the first writer wins and later duplicates
// are rejected deterministically.
func (r *EgressPolicyReconciler) findColorEndpointConflict(ctx context.Context, me *srv6egressv1alpha1.EgressPolicy, endpoint string) (string, error) {
	var list srv6egressv1alpha1.EgressPolicyList
	if err := r.List(ctx, &list); err != nil {
		return "", fmt.Errorf("list egresspolicies: %w", err)
	}
	for i := range list.Items {
		other := &list.Items[i]
		if other.UID == me.UID {
			continue
		}
		if !other.DeletionTimestamp.IsZero() {
			continue
		}
		if other.Spec.Egress.Color == me.Spec.Egress.Color &&
			other.Status.ActiveEndpoint == endpoint {
			return other.Name, nil
		}
	}
	return "", nil
}

// validateEgressIPPool verifies the named Calico IPPool exists and carries
// allowedUses: [Tunnel], so egress VIPs are isolated from pod IPAM. Without
// this guard a pool with allowedUses: [Workload] would later (once real Calico
// IPAM is wired in) hand out pod-range addresses as SNAT VIPs (issue #5 §5.3).
func (r *EgressPolicyReconciler) validateEgressIPPool(ctx context.Context, poolName string) error {
	if poolName == "" {
		return fmt.Errorf("egressIPPool is required")
	}
	pool := &unstructured.Unstructured{}
	pool.SetGroupVersionKind(calicoIPPoolGVK)
	if err := r.Get(ctx, client.ObjectKey{Name: poolName}, pool); err != nil {
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

func (r *EgressPolicyReconciler) markNotReady(ctx context.Context, ep *srv6egressv1alpha1.EgressPolicy, reason, message string) (ctrl.Result, error) {
	setReady(ep, metav1.ConditionFalse, reason, message)
	if err := r.Status().Update(ctx, ep); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, fmt.Errorf("%s: %s", reason, message)
}

func setReady(ep *srv6egressv1alpha1.EgressPolicy, status metav1.ConditionStatus, reason, message string) {
	cond := metav1.Condition{
		Type:               "Ready",
		Status:             status,
		ObservedGeneration: ep.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
	for i := range ep.Status.Conditions {
		if ep.Status.Conditions[i].Type == "Ready" {
			if ep.Status.Conditions[i].Status == status {
				cond.LastTransitionTime = ep.Status.Conditions[i].LastTransitionTime
			}
			ep.Status.Conditions[i] = cond
			return
		}
	}
	ep.Status.Conditions = append(ep.Status.Conditions, cond)
}

// RehydrateVIPs re-registers every already-allocated egress VIP into the
// allocator BEFORE any reconcile runs. This must be called once at startup
// (with a direct API reader, before the manager's caches/controllers start),
// otherwise the restart-collision fix is order-dependent: a freshly created
// policy could allocate a synthetic VIP that an existing policy still holds in
// its status, because reconcile order is arbitrary.
//
// reader should be the manager's API reader (mgr.GetAPIReader()), which talks
// directly to the API server and works before mgr.Start().
func RehydrateVIPs(ctx context.Context, reader client.Reader, vips vipalloc.Allocator) (int, error) {
	var list srv6egressv1alpha1.EgressPolicyList
	if err := reader.List(ctx, &list); err != nil {
		return 0, fmt.Errorf("rehydrate: list egresspolicies: %w", err)
	}
	n := 0
	for i := range list.Items {
		ep := &list.Items[i]
		if ep.Status.EgressIP == "" {
			continue
		}
		if err := vips.Register(ctx, string(ep.UID), ep.Status.EgressIP); err != nil {
			return n, fmt.Errorf("rehydrate: register %s (%s): %w", ep.Name, ep.Status.EgressIP, err)
		}
		n++
	}
	return n, nil
}

// SetupWithManager wires the reconciler into the controller-runtime manager.
// MaxConcurrentReconciles is pinned to 1 so the <color, endpoint> uniqueness
// check (findColorEndpointConflict) is first-writer-wins and deterministic.
func (r *EgressPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&srv6egressv1alpha1.EgressPolicy{}).
		WithOptions(controllerruntimecfg.Options{MaxConcurrentReconciles: 1}).
		Complete(r)
}

func containsString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func removeString(s []string, v string) []string {
	out := s[:0]
	for _, x := range s {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}
