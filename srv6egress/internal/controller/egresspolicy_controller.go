// Package controller implements the EgressPolicy reconcile loop.
//
// On a watched EgressPolicy event the reconciler:
//  1. resolves the endpoint (exactly one node, per v1)
//  2. resolves <color, endpoint> to a segment list via the controller config
//  3. withdraws a previously announced SR Policy whose key drifted (spec edit)
//  4. persists the announce intent in status (persist-then-announce)
//  5. distributes the SR Policy over BGP
//  6. marks Ready and records the effective BSID
//
// It is NAT-less L3VPN: no VIP is allocated; the pod source address is preserved
// end to end. Backbone return reachability (the cluster pod CIDR) is advertised
// once per upstream at startup (see AdvertiseClusterReturn), not per policy.
//
// Deletion: withdraws the BGP route, removes the finalizer.
package controller

import (
	"context"
	"fmt"
	"net"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerruntimecfg "sigs.k8s.io/controller-runtime/pkg/controller"

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/bgp"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/config"
)

const finalizerName = "srv6egress.ryskn.io/finalizer"

// EgressPolicyReconciler reconciles an EgressPolicy.
type EgressPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Config *config.ControllerConfig
	// BGP distributes SR Policies to headends; Encoder selects the on-the-wire
	// encoding (colored route or SR Policy SAFI), chosen at startup. The
	// transport is encoding-agnostic.
	BGP     bgp.Distributor
	Encoder bgp.Encoder
}

// +kubebuilder:rbac:groups=srv6egress.ryskn.io,resources=egresspolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=srv6egress.ryskn.io,resources=egresspolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=srv6egress.ryskn.io,resources=egresspolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch

// Reconcile performs one reconciliation pass as a pipeline of single-purpose
// stages: resolve the desired plan, then distribute the SR Policy to headends.
// Each stage fails closed via markNotReady; the orchestration below stays short
// enough to read top-to-bottom.
func (r *EgressPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	var ep srv6egressv1.EgressPolicy
	if err := r.Get(ctx, req.NamespacedName, &ep); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !ep.DeletionTimestamp.IsZero() {
		return r.reconcileDelete(ctx, &ep)
	}
	if res, done, err := r.ensureFinalizer(ctx, &ep); done {
		return res, err
	}

	// 1) Resolve the desired plan: color → upstream/segments, endpoint, and the
	// RFC 9256 <color, endpoint> uniqueness check.
	plan, res, err := r.resolvePlan(ctx, &ep)
	if err != nil {
		return res, err
	}

	// 2) Distribute the SR Policy to headends (persist-then-announce, Ready).
	if res, err := r.distributeCluster(ctx, &ep, plan); err != nil {
		return res, err
	}

	log.Info("reconciled", "name", ep.Name, "color", ep.Spec.Egress.Color,
		"upstream", plan.cc.Upstream, "endpoint", plan.endpoint)
	return ctrl.Result{}, nil
}

// ensureFinalizer adds the finalizer if missing. It returns done=true when the
// caller must stop this pass — either because the add failed, or because it
// succeeded and the object should be requeued to pick up the update.
func (r *EgressPolicyReconciler) ensureFinalizer(ctx context.Context, ep *srv6egressv1.EgressPolicy) (ctrl.Result, bool, error) {
	if containsString(ep.Finalizers, finalizerName) {
		return ctrl.Result{}, false, nil
	}
	ep.Finalizers = append(ep.Finalizers, finalizerName)
	if err := r.Update(ctx, ep); err != nil {
		return ctrl.Result{}, true, err
	}
	return ctrl.Result{Requeue: true}, true, nil
}

// reconcilePlan is the resolved desired state for one EgressPolicy: how it is
// colored/segmented (cc) and where it exits the cluster (endpoint + its IPv6
// address). Built by resolvePlan from spec + controller config + cluster state.
type reconcilePlan struct {
	cc           config.ColorConfig
	endpoint     string
	endpointAddr string
}

// resolvePlan resolves the color config, the egress endpoint (exactly one
// node), and enforces RFC 9256 §2 <color, endpoint> uniqueness. On any failure
// it marks the policy not-ready and returns the error to requeue.
func (r *EgressPolicyReconciler) resolvePlan(ctx context.Context, ep *srv6egressv1.EgressPolicy) (*reconcilePlan, ctrl.Result, error) {
	cc, ok := r.Config.Colors[ep.Spec.Egress.Color]
	if !ok {
		res, err := r.markNotReady(ctx, ep, "UnknownColor",
			fmt.Sprintf("color %d is not defined in controller config", ep.Spec.Egress.Color))
		return nil, res, err
	}

	endpoint, endpointAddr, err := r.resolveEndpoint(ctx, ep.Spec.Egress.EndpointSelector)
	if err != nil {
		res, err := r.markNotReady(ctx, ep, "EndpointResolution", err.Error())
		return nil, res, err
	}

	if conflict, err := r.findColorEndpointConflict(ctx, ep, endpoint); err != nil {
		return nil, ctrl.Result{}, err
	} else if conflict != "" {
		res, err := r.markNotReady(ctx, ep, "DuplicateColorEndpoint",
			fmt.Sprintf("color %d + endpoint %q already used by EgressPolicy %q",
				ep.Spec.Egress.Color, endpoint, conflict))
		return nil, res, err
	}

	return &reconcilePlan{cc: cc, endpoint: endpoint, endpointAddr: endpointAddr}, ctrl.Result{}, nil
}

// distributeCluster reconciles the headend-facing SR Policy distribution:
// withdraw a drifted prior announce, persist the announce intent BEFORE
// announcing (persist-then-announce, so deletion can always rebuild an exact
// withdraw), announce, then record the effective BSID and mark Ready.
func (r *EgressPolicyReconciler) distributeCluster(ctx context.Context, ep *srv6egressv1.EgressPolicy, plan *reconcilePlan) (ctrl.Result, error) {
	owner := string(ep.UID)
	cc := plan.cc
	intent := &srv6egressv1.SRPolicyStatus{
		BSID:         cc.BSID,
		Color:        ep.Spec.Egress.Color,
		SegmentList:  cc.SegmentList,
		EndpointAddr: plan.endpointAddr,
	}

	// Withdraw a previously announced SR Policy whose key/segments no longer
	// match the current intent (spec edit) — otherwise the old path would stay
	// in BGP forever.
	if prior := ep.Status.SRPolicy; prior != nil && !srPolicyIntentEqual(prior, intent) {
		priorKey := bgp.PolicyKey{
			Color:        prior.Color,
			Endpoint:     ep.Status.ActiveEndpoint,
			EndpointAddr: prior.EndpointAddr,
			BSID:         prior.BSID,
		}
		if err := r.BGP.Withdraw(ctx, owner, r.Encoder.ClusterAdvert(priorKey, prior.SegmentList)); err != nil {
			return r.markNotReady(ctx, ep, "BGPWithdrawStale", err.Error())
		}
	}

	// Persist the announce intent BEFORE announcing.
	if ep.Status.ActiveEndpoint != plan.endpoint ||
		ep.Status.Upstream != cc.Upstream || !srPolicyIntentEqual(ep.Status.SRPolicy, intent) {
		ep.Status.ActiveEndpoint = plan.endpoint
		ep.Status.Upstream = cc.Upstream
		ep.Status.SRPolicy = intent
		setReady(ep, metav1.ConditionFalse, "Announcing", "SR Policy recorded; BGP announce in progress")
		if err := r.Status().Update(ctx, ep); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Distribute (idempotent: re-announcing refreshes the path).
	adv := r.Encoder.ClusterAdvert(bgp.PolicyKey{
		Color:        ep.Spec.Egress.Color,
		Endpoint:     plan.endpoint,
		EndpointAddr: plan.endpointAddr,
		BSID:         cc.BSID,
	}, cc.SegmentList)
	bsid, err := r.BGP.Announce(ctx, owner, adv)
	if err != nil {
		return r.markNotReady(ctx, ep, "BGPDistribution", err.Error())
	}

	// Mark Ready; record the BSID the distributor actually used (the colored
	// encoding reports the terminal SID, the SR Policy SAFI the configured BSID).
	ep.Status.SRPolicy.BSID = bsid
	setReady(ep, metav1.ConditionTrue, "Reconciled", "EgressPolicy installed")
	if err := r.Status().Update(ctx, ep); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

func (r *EgressPolicyReconciler) reconcileDelete(ctx context.Context, ep *srv6egressv1.EgressPolicy) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	if !containsString(ep.Finalizers, finalizerName) {
		return ctrl.Result{}, nil
	}

	owner := string(ep.UID)

	// Rebuild the SR Policy key + segment list from the PERSISTED ANNOUNCED
	// values in status (not the mutable spec): the route in BGP was announced
	// with status.srPolicy.{color,segmentList}, which may differ from the
	// current spec if it was edited. Using status guarantees we delete exactly
	// what we added — and it works after a controller restart too (the in-memory
	// announce cache would be empty). The intent is persisted BEFORE Announce,
	// so SRPolicy is nil only if no announce was ever attempted (Withdraw of a
	// recorded-but-never-announced path is a safe no-op).
	if sp := ep.Status.SRPolicy; sp != nil {
		key := bgp.PolicyKey{
			Color:        sp.Color,
			Endpoint:     ep.Status.ActiveEndpoint,
			EndpointAddr: sp.EndpointAddr,
			BSID:         sp.BSID,
		}
		if err := r.BGP.Withdraw(ctx, owner, r.Encoder.ClusterAdvert(key, sp.SegmentList)); err != nil {
			return ctrl.Result{}, err
		}
	}

	ep.Finalizers = removeString(ep.Finalizers, finalizerName)
	if err := r.Update(ctx, ep); err != nil {
		return ctrl.Result{}, err
	}
	log.Info("teardown complete", "name", ep.Name)
	return ctrl.Result{}, nil
}

// resolveEndpoint enforces the v1 invariant: exactly one node must match.
// It returns the node name (identity) and its IPv6 address (the SR Policy SAFI
// endpoint). The address is best-effort: an empty string is returned when the
// node exposes no IPv6 InternalIP, which only the SR Policy SAFI encoding cares
// about (it then rejects the policy with a clear error).
func (r *EgressPolicyReconciler) resolveEndpoint(ctx context.Context, es srv6egressv1.EndpointSelector) (name, addr string, err error) {
	if es.NodeSelector == nil {
		return "", "", fmt.Errorf("endpointSelector.nodeSelector is required")
	}
	sel, err := metav1.LabelSelectorAsSelector(es.NodeSelector)
	if err != nil {
		return "", "", fmt.Errorf("invalid nodeSelector: %w", err)
	}

	var nodes corev1.NodeList
	if err := r.List(ctx, &nodes, &client.ListOptions{LabelSelector: sel}); err != nil {
		return "", "", fmt.Errorf("list nodes: %w", err)
	}
	switch len(nodes.Items) {
	case 0:
		return "", "", fmt.Errorf("no node matches selector %q", labels.SelectorFromValidatedSet(es.NodeSelector.MatchLabels).String())
	case 1:
		return nodes.Items[0].Name, nodeIPv6(&nodes.Items[0]), nil
	default:
		names := make([]string, 0, len(nodes.Items))
		for i := range nodes.Items {
			names = append(names, nodes.Items[i].Name)
		}
		return "", "", fmt.Errorf("v1 requires exactly one matching node, got %d: %v", len(nodes.Items), names)
	}
}

// nodeIPv6 returns the node's first IPv6 InternalIP, or "" if it has none.
func nodeIPv6(node *corev1.Node) string {
	for _, a := range node.Status.Addresses {
		if a.Type != corev1.NodeInternalIP {
			continue
		}
		if ip := net.ParseIP(a.Address); ip != nil && ip.To4() == nil {
			return a.Address
		}
	}
	return ""
}

// findColorEndpointConflict returns the name of another (non-deleting)
// EgressPolicy that already occupies the same <color, endpoint> tuple, or "".
// A peer is considered to occupy the tuple once its reconcile has recorded the
// resolved endpoint in status.activeEndpoint. Reconciles are serialized
// (MaxConcurrentReconciles=1), so the first writer wins and later duplicates
// are rejected deterministically.
func (r *EgressPolicyReconciler) findColorEndpointConflict(ctx context.Context, me *srv6egressv1.EgressPolicy, endpoint string) (string, error) {
	var list srv6egressv1.EgressPolicyList
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

func (r *EgressPolicyReconciler) markNotReady(ctx context.Context, ep *srv6egressv1.EgressPolicy, reason, message string) (ctrl.Result, error) {
	setReady(ep, metav1.ConditionFalse, reason, message)
	if err := r.Status().Update(ctx, ep); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, fmt.Errorf("%s: %s", reason, message)
}

// srPolicyIntentEqual compares the withdraw-relevant fields of two SR Policy
// status records. BSID is deliberately excluded: the colored-route encoding
// reports the terminal SID as the effective BSID after announce, which must
// not register as drift on the next reconcile (it would flap Ready).
func srPolicyIntentEqual(a, b *srv6egressv1.SRPolicyStatus) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Color != b.Color || a.EndpointAddr != b.EndpointAddr {
		return false
	}
	if len(a.SegmentList) != len(b.SegmentList) {
		return false
	}
	for i := range a.SegmentList {
		if a.SegmentList[i] != b.SegmentList[i] {
			return false
		}
	}
	return true
}

func setReady(ep *srv6egressv1.EgressPolicy, status metav1.ConditionStatus, reason, message string) {
	setCondition(ep, "Ready", status, reason, message)
}

func setCondition(ep *srv6egressv1.EgressPolicy, condType string, status metav1.ConditionStatus, reason, message string) {
	cond := metav1.Condition{
		Type:               condType,
		Status:             status,
		ObservedGeneration: ep.Generation,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
	for i := range ep.Status.Conditions {
		if ep.Status.Conditions[i].Type == condType {
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
// MaxConcurrentReconciles is pinned to 1 so the <color, endpoint> uniqueness
// check (findColorEndpointConflict) is first-writer-wins and deterministic.
func (r *EgressPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&srv6egressv1.EgressPolicy{}).
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
