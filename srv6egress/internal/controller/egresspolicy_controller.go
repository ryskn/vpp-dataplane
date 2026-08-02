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
	"slices"
	"sort"

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
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
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
	if err != nil || plan == nil {
		// plan == nil with err == nil is a terminal not-ready (marked in
		// resolvePlan): stop without requeue.
		return res, err
	}

	// 2) Distribute the SR Policy to headends (persist-then-announce, Ready).
	if res, err := r.distributeCluster(ctx, &ep, plan); err != nil {
		return res, err
	}

	log.Info("reconciled", "name", ep.Name, "color", ep.Spec.Egress.Color,
		"candidates", len(plan.cc.CandidatePaths), "primary", plan.cc.Primary().Upstream, "endpoint", plan.endpoint)
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
	// returnPrefixes are the matched tenants' podCIDRs persisted in status so
	// the gateway agent can enforce the per-tenant return fence (empty in
	// legacy shared-aggregate mode).
	returnPrefixes []string
}

// validateDestinationCIDRs enforces the v1 IPv6-only invariant on the policy's
// destinationCIDRs. An empty list is rejected: steering ::/0 is not yet
// supported, so an unvalidated empty/IPv4 list would otherwise go Ready=True
// while the dataplane installs neither steering nor (under Drop) a blackhole —
// a fail-closed policy that silently fails open.
func validateDestinationCIDRs(cidrs []string) error {
	if len(cidrs) == 0 {
		return fmt.Errorf("destinationCIDRs must not be empty")
	}
	for _, c := range cidrs {
		ip, ipnet, err := net.ParseCIDR(c)
		if err != nil || ipnet == nil {
			return fmt.Errorf("destinationCIDR %q is not a valid CIDR", c)
		}
		if ip.To4() != nil {
			return fmt.Errorf("destinationCIDR %q must be IPv6 (v1 is IPv6-only)", c)
		}
	}
	return nil
}

// resolvePlan resolves the color config, the egress endpoint (exactly one
// node), and enforces RFC 9256 §2 <color, endpoint> uniqueness. On any failure
// it marks the policy not-ready and returns the error to requeue.
func (r *EgressPolicyReconciler) resolvePlan(ctx context.Context, ep *srv6egressv1.EgressPolicy) (*reconcilePlan, ctrl.Result, error) {
	if err := validateDestinationCIDRs(ep.Spec.DestinationCIDRs); err != nil {
		res, err := r.markNotReadyTerminal(ctx, ep, "InvalidDestinationCIDRs", err.Error())
		return nil, res, err
	}

	cc, ok := r.Config.Colors[ep.Spec.Egress.Color]
	if !ok {
		res, err := r.markNotReadyTerminal(ctx, ep, "UnknownColor",
			fmt.Sprintf("color %d is not defined in controller config", ep.Spec.Egress.Color))
		return nil, res, err
	}

	// An exclusive color is a closed compliance boundary (§14.2): OnUnavailable
	// Fallback would leak traffic to the node's default egress, outside the
	// sovereign set — a sovereignty violation. Only a spec edit fixes it, so this
	// is terminal. Empty (default Drop) and explicit Drop are allowed.
	if cc.Exclusive && ep.Spec.Egress.OnUnavailable == srv6egressv1.OnUnavailableFallback {
		res, err := r.markNotReadyTerminal(ctx, ep, "ExclusiveColorFallback",
			fmt.Sprintf("color %d is exclusive: OnUnavailable=Fallback would leak egress to the node default (sovereignty violation); use Drop", ep.Spec.Egress.Color))
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

	// Tenant-mixing check (§14.3 validation (2) / §14.4 granularity theorem): if
	// this policy's tenant uses an exclusive color, every color it references must
	// stay inside the sovereign set — otherwise the tenant prefix would be
	// advertised to an upstream outside sovereignty and return traffic could enter
	// there (return control is bounded by source-prefix granularity, so a stray
	// candidate upstream leaks the whole tenant's reachability). Not terminal:
	// changing config or a sibling policy fixes it, so requeue.
	if tenant, excess, err := r.findTenantSovereigntyConflict(ctx, ep, cc); err != nil {
		return nil, ctrl.Result{}, err
	} else if len(excess) > 0 {
		res, err := r.markNotReady(ctx, ep, "TenantSovereigntyConflict",
			fmt.Sprintf("tenant %q uses an exclusive color; color %d exits via upstream(s) %v outside the sovereign set",
				tenant, ep.Spec.Egress.Color, excess))
		return nil, res, err
	}

	// Per-tenant return fence: persist the matched tenants' podCIDRs so the
	// gateway agent installs return routes in exactly the candidate upstream
	// VRFs. The reconciler is the single derivation (and status-writer) point;
	// the agent only enforces what status carries.
	returnPrefixes, err := tenantReturnPrefixes(ctx, r.Client, r.Config.Backbone, ep)
	if err != nil {
		return nil, ctrl.Result{}, err
	}

	return &reconcilePlan{cc: cc, endpoint: endpoint, endpointAddr: endpointAddr, returnPrefixes: returnPrefixes}, ctrl.Result{}, nil
}

// findTenantSovereigntyConflict returns (tenant, excess-upstreams) when this
// policy references upstreams outside its tenant's sovereign set. It is a no-op
// (returns "", nil) unless Backbone.Tenants is configured. The sovereign set is
// the intersection of every exclusive color's upstream set among the policies
// that select the tenant's namespace; the policy's own candidate upstreams must
// be a subset of it. Only the reconciler writes status (single-writer), so this
// mixing check lives here — the advertiser only clamps the advertisement.
func (r *EgressPolicyReconciler) findTenantSovereigntyConflict(ctx context.Context, me *srv6egressv1.EgressPolicy, cc config.ColorConfig) (string, []string, error) {
	if r.Config.Backbone == nil || len(r.Config.Backbone.Tenants) == 0 {
		return "", nil, nil
	}
	myUpstreams := map[string]bool{}
	for _, cp := range cc.CandidatePaths {
		myUpstreams[cp.Upstream] = true
	}

	var list srv6egressv1.EgressPolicyList
	if err := r.List(ctx, &list); err != nil {
		return "", nil, fmt.Errorf("list egresspolicies: %w", err)
	}

	for tenant, tc := range r.Config.Backbone.Tenants {
		nsLabels, err := getNamespaceLabels(ctx, r.Client, tc.Namespace)
		if err != nil {
			return "", nil, err
		}
		if !policySelectsNamespace(me, nsLabels) {
			continue
		}
		// Sovereign set = intersection of every matched exclusive color's upstream
		// set. nil until the first exclusive color is seen; empty non-nil = no
		// upstream is universally sovereign (disjoint exclusive sets).
		var sovereign map[string]bool
		for i := range list.Items {
			p := &list.Items[i]
			if !p.DeletionTimestamp.IsZero() || !policySelectsNamespace(p, nsLabels) {
				continue
			}
			pc, ok := r.Config.Colors[p.Spec.Egress.Color]
			if !ok || !pc.Exclusive {
				continue
			}
			ups := map[string]bool{}
			for _, cp := range pc.CandidatePaths {
				ups[cp.Upstream] = true
			}
			if sovereign == nil {
				sovereign = ups
			} else {
				sovereign = intersect(sovereign, ups)
			}
		}
		if sovereign == nil {
			continue // no exclusive color in this tenant: nothing to enforce
		}
		var excess []string
		for up := range myUpstreams {
			if !sovereign[up] {
				excess = append(excess, up)
			}
		}
		if len(excess) > 0 {
			sort.Strings(excess)
			return tenant, excess, nil
		}
	}
	return "", nil, nil
}

// candidateStatus builds the persisted candidate-path array from the resolved
// color config, in config order (= distinguisher order).
func candidateStatus(cc config.ColorConfig) []srv6egressv1.CandidatePathStatus {
	out := make([]srv6egressv1.CandidatePathStatus, len(cc.CandidatePaths))
	for i, cp := range cc.CandidatePaths {
		out[i] = srv6egressv1.CandidatePathStatus{
			Upstream:    cp.Upstream,
			SegmentList: cp.SegmentList,
			Preference:  cp.Preference,
		}
	}
	return out
}

// primaryCandidate returns the highest-preference candidate from a persisted
// array (the deprecated single-form status mirrors it). The array is never
// empty here — resolvePlan derives it from a validated, non-empty color config.
func primaryCandidate(cps []srv6egressv1.CandidatePathStatus) srv6egressv1.CandidatePathStatus {
	best := cps[0]
	for _, cp := range cps[1:] {
		if cp.Preference > best.Preference {
			best = cp
		}
	}
	return best
}

// candidateKey builds the per-candidate SR Policy key. The distinguisher is the
// config index+1 (RFC 9256 §2.1: candidates sharing <color, endpoint> differ by
// distinguisher); the preference rides in the Tunnel Encap sub-TLV.
func candidateKey(ep *srv6egressv1.EgressPolicy, endpoint, endpointAddr, bsid string, idx int, cp srv6egressv1.CandidatePathStatus) bgp.PolicyKey {
	return bgp.PolicyKey{
		Color:         ep.Spec.Egress.Color,
		Endpoint:      endpoint,
		EndpointAddr:  endpointAddr,
		BSID:          bsid,
		Distinguisher: uint32(idx + 1),
		Preference:    cp.Preference,
	}
}

// distributeCluster reconciles the headend-facing SR Policy distribution:
// withdraw a drifted prior announce (all candidates), persist the announce
// intent BEFORE announcing (persist-then-announce, so deletion can always
// rebuild an exact withdraw), announce every candidate, then record the
// effective BSID and mark Ready.
func (r *EgressPolicyReconciler) distributeCluster(ctx context.Context, ep *srv6egressv1.EgressPolicy, plan *reconcilePlan) (ctrl.Result, error) {
	owner := string(ep.UID)
	cc := plan.cc
	cps := candidateStatus(cc)
	primary := primaryCandidate(cps)
	intent := &srv6egressv1.SRPolicyStatus{
		BSID:           cc.BSID,
		Color:          ep.Spec.Egress.Color,
		SegmentList:    primary.SegmentList, // deprecated single-form mirror
		CandidatePaths: cps,
		EndpointAddr:   plan.endpointAddr,
	}

	// Withdraw a previously announced SR Policy whose candidate set no longer
	// matches the current intent (spec edit) — otherwise the old candidate paths
	// would stay in BGP forever. v1 is coarse: on any drift, withdraw every prior
	// candidate before re-announcing the current set.
	if prior := ep.Status.SRPolicy; prior != nil && !srPolicyIntentEqual(prior, intent) {
		for _, adv := range priorAdverts(r.Encoder, ep, prior) {
			if err := r.BGP.Withdraw(ctx, owner, adv); err != nil {
				return r.markNotReady(ctx, ep, "BGPWithdrawStale", err.Error())
			}
		}
	}

	// Persist the announce intent BEFORE announcing.
	if ep.Status.ActiveEndpoint != plan.endpoint ||
		ep.Status.Upstream != primary.Upstream ||
		!slices.Equal(ep.Status.ReturnPrefixes, plan.returnPrefixes) ||
		!srPolicyIntentEqual(ep.Status.SRPolicy, intent) {
		ep.Status.ActiveEndpoint = plan.endpoint
		ep.Status.Upstream = primary.Upstream
		ep.Status.ReturnPrefixes = plan.returnPrefixes
		ep.Status.SRPolicy = intent
		setReady(ep, metav1.ConditionFalse, "Announcing", "SR Policy recorded; BGP announce in progress")
		if err := r.Status().Update(ctx, ep); err != nil {
			return ctrl.Result{}, err
		}
	}

	// Distribute every candidate (idempotent: re-announcing refreshes the path).
	// The primary candidate's BSID is recorded in status; a partial failure marks
	// not-ready and re-reconcile re-announces the full set.
	var primaryBSID string
	for i, cp := range cps {
		adv := r.Encoder.ClusterAdvert(candidateKey(ep, plan.endpoint, plan.endpointAddr, cc.BSID, i, cp), cp.SegmentList)
		bsid, err := r.BGP.Announce(ctx, owner, adv)
		if err != nil {
			return r.markNotReady(ctx, ep, "BGPDistribution", err.Error())
		}
		if cp.Upstream == primary.Upstream && cp.Preference == primary.Preference {
			primaryBSID = bsid
		}
	}

	// Mark Ready; record the BSID the distributor actually used (the colored
	// encoding reports the terminal SID, the SR Policy SAFI the configured BSID).
	ep.Status.SRPolicy.BSID = primaryBSID
	setReady(ep, metav1.ConditionTrue, "Reconciled", "EgressPolicy installed")
	if err := r.Status().Update(ctx, ep); err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// priorAdverts rebuilds the per-candidate withdraw adverts from a persisted SR
// Policy status. It replays config-order (= distinguisher order) so each
// withdraw reconstructs the exact NLRI key that was announced — restart-safe and
// independent of any in-memory state.
func priorAdverts(enc bgp.Encoder, ep *srv6egressv1.EgressPolicy, sp *srv6egressv1.SRPolicyStatus) []bgp.Advertisement {
	cps := sp.CandidatePaths
	if len(cps) == 0 && len(sp.SegmentList) > 0 {
		// Legacy status written before candidatePaths existed: treat the
		// single-form segment list as one candidate (distinguisher 1).
		cps = []srv6egressv1.CandidatePathStatus{{SegmentList: sp.SegmentList}}
	}
	out := make([]bgp.Advertisement, 0, len(cps))
	for i, cp := range cps {
		key := bgp.PolicyKey{
			Color:         sp.Color,
			Endpoint:      ep.Status.ActiveEndpoint,
			EndpointAddr:  sp.EndpointAddr,
			BSID:          sp.BSID,
			Distinguisher: uint32(i + 1),
			Preference:    cp.Preference,
		}
		out = append(out, enc.ClusterAdvert(key, cp.SegmentList))
	}
	return out
}

func (r *EgressPolicyReconciler) reconcileDelete(ctx context.Context, ep *srv6egressv1.EgressPolicy) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)
	if !containsString(ep.Finalizers, finalizerName) {
		return ctrl.Result{}, nil
	}

	owner := string(ep.UID)

	// Rebuild every candidate's SR Policy key + segment list from the PERSISTED
	// ANNOUNCED values in status (not the mutable spec): the routes in BGP were
	// announced with status.srPolicy.{color,candidatePaths}, which may differ
	// from the current spec if it was edited. Using status guarantees we delete
	// exactly what we added — and it works after a controller restart too (the
	// in-memory announce cache would be empty). The intent is persisted BEFORE
	// Announce, so SRPolicy is nil only if no announce was ever attempted
	// (Withdraw of a recorded-but-never-announced path is a safe no-op).
	if sp := ep.Status.SRPolicy; sp != nil {
		for _, adv := range priorAdverts(r.Encoder, ep, sp) {
			if _, err := adv.BuildPath(); err != nil {
				// Deterministic encode failure (e.g. sr-policy with an empty
				// BSID/endpoint): nothing valid could have been announced, so there
				// is nothing to withdraw. Log and continue rather than wedging the
				// object in Terminating forever on every reconcile.
				log.Error(err, "cannot rebuild withdraw advert; skipping without withdraw", "name", ep.Name, "advert", adv.String())
				continue
			}
			if err := r.BGP.Withdraw(ctx, owner, adv); err != nil {
				// Transient transport error: keep the finalizer and retry.
				return ctrl.Result{}, err
			}
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

// markNotReadyTerminal is markNotReady for spec/config errors that cannot be
// fixed by retrying (unknown color, invalid destinationCIDRs): it records the
// condition but returns no error, so the reconciler does not hot-loop at error
// level. A spec edit re-triggers reconcile via the EgressPolicy watch, and a
// config change requires a process restart, so a rate-limited requeue buys
// nothing here.
func (r *EgressPolicyReconciler) markNotReadyTerminal(ctx context.Context, ep *srv6egressv1.EgressPolicy, reason, message string) (ctrl.Result, error) {
	setReady(ep, metav1.ConditionFalse, reason, message)
	if err := r.Status().Update(ctx, ep); err != nil {
		return ctrl.Result{}, err
	}
	ctrl.LoggerFrom(ctx).Info("policy not ready (terminal spec error, not requeued)", "reason", reason, "message", message)
	return ctrl.Result{}, nil
}

// srPolicyIntentEqual compares the withdraw-relevant fields of two SR Policy
// status records, including the FULL candidate-path set (config order matters:
// it fixes the distinguisher). BSID is deliberately excluded: the colored-route
// encoding reports the terminal SID as the effective BSID after announce, which
// must not register as drift on the next reconcile (it would flap Ready).
func srPolicyIntentEqual(a, b *srv6egressv1.SRPolicyStatus) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Color != b.Color || a.EndpointAddr != b.EndpointAddr {
		return false
	}
	if len(a.CandidatePaths) != len(b.CandidatePaths) {
		return false
	}
	for i := range a.CandidatePaths {
		if !candidatePathEqual(a.CandidatePaths[i], b.CandidatePaths[i]) {
			return false
		}
	}
	return true
}

// candidatePathEqual compares two candidate paths by upstream, preference, and
// segment list (order-sensitive).
func candidatePathEqual(a, b srv6egressv1.CandidatePathStatus) bool {
	if a.Upstream != b.Upstream || a.Preference != b.Preference {
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
	setCondition(ep, srv6egressv1.ConditionReady, status, reason, message)
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
