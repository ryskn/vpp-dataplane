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
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	srv6egressv1alpha1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1alpha1"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/bgp"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/config"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/vipalloc"
)

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

	// 3) Allocate VIP (idempotent by EgressPolicy UID).
	policyOwner := string(ep.UID)
	vip := ep.Status.EgressIP
	if vip == "" {
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

// SetupWithManager wires the reconciler into the controller-runtime manager.
func (r *EgressPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&srv6egressv1alpha1.EgressPolicy{}).
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
