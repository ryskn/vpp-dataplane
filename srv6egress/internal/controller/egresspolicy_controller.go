// Package controller implements the EgressPolicy reconcile loop.
//
// On a watched EgressPolicy event the reconciler:
//  1. resolves the endpoint (exactly one node, per v1)
//  2. resolves <color, endpoint> to a segment list via the controller config
//  3. allocates a per-tenant VIP from the named Calico IPPool
//  4. withdraws a previously announced SR Policy whose key drifted (spec edit)
//  5. persists the announce intent in status (persist-then-announce)
//  6. distributes the SR Policy over BGP
//  7. marks Ready and records the effective BSID
//
// Deletion: withdraws the BGP route, releases the VIP, removes the finalizer.
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
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/poolvalidator"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/vipalloc"
)

const finalizerName = "srv6egress.ryskn.io/finalizer"

// EgressPolicyReconciler reconciles an EgressPolicy.
type EgressPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
	Config *config.ControllerConfig
	VIPs   vipalloc.Allocator
	// BGP distributes SR Policies to headends; Encoder selects the on-the-wire
	// encoding (colored route or SR Policy SAFI), chosen at startup. The
	// transport is encoding-agnostic.
	BGP     bgp.Distributor
	Encoder bgp.Encoder
	Pools   poolvalidator.Validator
	// BackboneBGP holds the backbone-facing distributors, keyed by upstream
	// name. Empty when no upstream is stitched to a backbone — the VIP service
	// advertisement is then simply skipped, not a separate operating mode.
	// Wired from Config.Backbone.Peers in main.
	BackboneBGP map[string]bgp.Distributor
}

// +kubebuilder:rbac:groups=srv6egress.ryskn.io,resources=egresspolicies,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=srv6egress.ryskn.io,resources=egresspolicies/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=srv6egress.ryskn.io,resources=egresspolicies/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=nodes,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=events,verbs=create;patch
// +kubebuilder:rbac:groups=crd.projectcalico.org,resources=ippools,verbs=get;list;watch

// Reconcile performs one reconciliation pass as a pipeline of single-purpose
// stages: resolve the desired plan, acquire the VIP, distribute the SR Policy
// to headends, then stitch the VIP to the backbone. Each stage fails closed via
// markNotReady; the orchestration below stays short enough to read top-to-bottom.
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

	// 2) Acquire the per-tenant egress VIP (recover from status or allocate).
	vip, res, err := r.ensureVIP(ctx, &ep)
	if err != nil {
		return res, err
	}

	// 3) Distribute the SR Policy to headends (persist-then-announce, Ready).
	if res, err := r.distributeCluster(ctx, &ep, plan, vip); err != nil {
		return res, err
	}

	// 4) Stitch the VIP to the backbone (RFC 9252). A no-op when no upstream is
	// stitched; a failure here does not clobber Ready (cluster side already works).
	if res, err := r.stitchBackbone(ctx, &ep, plan, vip); err != nil {
		return res, err
	}

	log.Info("reconciled", "name", ep.Name, "color", ep.Spec.Egress.Color,
		"upstream", plan.cc.Upstream, "endpoint", plan.endpoint, "vip", vip)
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

// ensureVIP returns the policy's egress VIP: it recovers a prior allocation
// recorded in status (so the in-memory allocator never reissues it after a
// restart), or validates the pool and allocates a new one. Allocation is
// idempotent by EgressPolicy UID.
func (r *EgressPolicyReconciler) ensureVIP(ctx context.Context, ep *srv6egressv1.EgressPolicy) (string, ctrl.Result, error) {
	owner := string(ep.UID)
	if vip := ep.Status.EgressIP; vip != "" {
		if err := r.VIPs.Register(ctx, owner, vip); err != nil {
			return "", ctrl.Result{}, err
		}
		return vip, ctrl.Result{}, nil
	}
	if err := r.Pools.ValidatePool(ctx, ep.Spec.Egress.EgressIPPool); err != nil {
		res, err := r.markNotReady(ctx, ep, "InvalidEgressIPPool", err.Error())
		return "", res, err
	}
	vip, err := r.VIPs.Allocate(ctx, owner, ep.Spec.Egress.EgressIPPool)
	if err != nil {
		res, err := r.markNotReady(ctx, ep, "VIPAllocation", err.Error())
		return "", res, err
	}
	return vip, ctrl.Result{}, nil
}

// distributeCluster reconciles the headend-facing SR Policy distribution:
// withdraw a drifted prior announce, persist the announce intent BEFORE
// announcing (persist-then-announce, so deletion can always rebuild an exact
// withdraw), announce, then record the effective BSID and mark Ready.
func (r *EgressPolicyReconciler) distributeCluster(ctx context.Context, ep *srv6egressv1.EgressPolicy, plan *reconcilePlan, vip string) (ctrl.Result, error) {
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
	if ep.Status.EgressIP != vip || ep.Status.ActiveEndpoint != plan.endpoint ||
		ep.Status.Upstream != cc.Upstream || !srPolicyIntentEqual(ep.Status.SRPolicy, intent) {
		ep.Status.EgressIP = vip
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

// stitchBackbone advertises the VIP toward the backbone as an RFC 9252 service
// route (own End SID + backbone color) and surfaces the result on the
// BackboneAdvertised condition. It is a no-op when no upstream is stitched to a
// backbone; a failure does not clobber Ready (cluster-side steering already
// works) but requeues.
func (r *EgressPolicyReconciler) stitchBackbone(ctx context.Context, ep *srv6egressv1.EgressPolicy, plan *reconcilePlan, vip string) (ctrl.Result, error) {
	advertised, err := r.reconcileBackbone(ctx, ep, plan.cc, vip)
	if err != nil {
		setCondition(ep, "BackboneAdvertised", metav1.ConditionFalse, "AnnounceFailed", err.Error())
		if uerr := r.Status().Update(ctx, ep); uerr != nil {
			return ctrl.Result{}, uerr
		}
		return ctrl.Result{}, err
	}
	if advertised {
		setCondition(ep, "BackboneAdvertised", metav1.ConditionTrue, "Announced",
			"VIP advertised to backbone with own End SID (RFC 9252)")
		if uerr := r.Status().Update(ctx, ep); uerr != nil {
			return ctrl.Result{}, uerr
		}
	}
	return ctrl.Result{}, nil
}

// reconcileBackbone announces the policy's VIP as an SRv6 service route on the
// upstream's backbone session, with the same guarantees as the SR Policy path:
// stale-withdraw on drift, persist-then-announce, idempotent re-announce.
// Returns (false, nil) when backbone mode is off or the upstream has no
// backbone peer.
func (r *EgressPolicyReconciler) reconcileBackbone(ctx context.Context, ep *srv6egressv1.EgressPolicy, cc config.ColorConfig, vip string) (bool, error) {
	bb := r.Config.Backbone
	if bb == nil {
		return false, nil
	}
	peer, ok := bb.Peers[cc.Upstream]
	if !ok {
		return false, nil // upstream not stitched to a backbone
	}
	dist, ok := r.BackboneBGP[cc.Upstream]
	if !ok {
		return false, fmt.Errorf("backbone peer %q configured but no distributor wired", cc.Upstream)
	}
	vipIP := net.ParseIP(vip)
	if vipIP == nil || vipIP.To4() != nil {
		return false, fmt.Errorf("egress VIP %q is not an IPv6 address (backbone advertise requires the Calico IPAM VIP backend)", vip)
	}

	intent := &srv6egressv1.BackboneStatus{
		Prefix:   vipIP.String() + "/128",
		EndSID:   r.Config.Upstreams[cc.Upstream].SID,
		Color:    bb.BackboneColor(ep.Spec.Egress.Color),
		Upstream: cc.Upstream,
		Nexthop:  peer.Nexthop,
	}

	// Withdraw a previously announced service route whose key drifted
	// (color remap, SID change, VIP change) so it cannot leak.
	if prior := ep.Status.Backbone; prior != nil && *prior != *intent {
		if priorDist, ok := r.BackboneBGP[prior.Upstream]; ok {
			if err := priorDist.Withdraw(ctx, string(ep.UID), serviceAdvert(prior)); err != nil {
				return false, fmt.Errorf("withdraw stale backbone route: %w", err)
			}
		}
	}

	// Persist the intent BEFORE announcing (same rationale as the SR Policy).
	if ep.Status.Backbone == nil || *ep.Status.Backbone != *intent {
		ep.Status.Backbone = intent
		if err := r.Status().Update(ctx, ep); err != nil {
			return false, err
		}
	}

	if _, err := dist.Announce(ctx, string(ep.UID), serviceAdvert(intent)); err != nil {
		return false, err
	}
	return true, nil
}

// serviceRouteFromStatus rebuilds the announce/withdraw payload from the
// persisted status record.
func serviceRouteFromStatus(s *srv6egressv1.BackboneStatus) bgp.ServiceRoute {
	return bgp.ServiceRoute{
		Prefix:   s.Prefix,
		EndSID:   s.EndSID,
		Behavior: bgp.EndDT6,
		Color:    s.Color,
		Nexthop:  s.Nexthop,
	}
}

// serviceAdvert builds the backbone Advertisement from the persisted status
// record. The path is rebuilt deterministically, so withdraw works across a
// controller restart.
func serviceAdvert(s *srv6egressv1.BackboneStatus) bgp.ServiceAdvert {
	return bgp.ServiceAdvert{Route: serviceRouteFromStatus(s), Structure: bgp.DefaultSIDStructure}
}

func (r *EgressPolicyReconciler) reconcileDelete(ctx context.Context, ep *srv6egressv1.EgressPolicy) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	if !containsString(ep.Finalizers, finalizerName) {
		return ctrl.Result{}, nil
	}

	owner := string(ep.UID)

	// Backbone stitch: withdraw the backbone service route first — the VIP must
	// stop being advertised before it is released back to IPAM. Rebuilt from the
	// persisted status record (works across controller restarts).
	if bbs := ep.Status.Backbone; bbs != nil {
		if dist, ok := r.BackboneBGP[bbs.Upstream]; ok {
			if err := dist.Withdraw(ctx, owner, serviceAdvert(bbs)); err != nil {
				return ctrl.Result{}, err
			}
		} else {
			// Backbone config was removed while this route was announced; the
			// session it lived on is gone with the config, so proceed.
			log.Info("backbone route recorded but no distributor for its upstream; skipping withdraw",
				"upstream", bbs.Upstream, "prefix", bbs.Prefix)
		}
	}

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
	var list srv6egressv1.EgressPolicyList
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
