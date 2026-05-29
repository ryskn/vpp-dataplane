package controller

import (
	"context"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	srv6egressv1alpha1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1alpha1"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/bgp"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/config"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/vipalloc"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := srv6egressv1alpha1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	// Register the Calico IPPool CRD as unstructured so the fake client can
	// serve it via GET.
	s.AddKnownTypeWithName(calicoIPPoolGVK, &unstructured.Unstructured{})
	listGVK := calicoIPPoolGVK
	listGVK.Kind = "IPPoolList"
	s.AddKnownTypeWithName(listGVK, &unstructured.UnstructuredList{})
	return s
}

func testConfig() *config.ControllerConfig {
	return &config.ControllerConfig{
		Upstreams: map[string]config.UpstreamConfig{
			"isp-a": {SID: "fcff:0:0:e0:a::", VRF: "upstream-a"},
			"isp-b": {SID: "fcff:0:0:e0:b::", VRF: "upstream-b"},
		},
		Colors: map[uint32]config.ColorConfig{
			100: {Upstream: "isp-a", SegmentList: []string{"fcff:0:0:e0:a::"}},
			200: {Upstream: "isp-b", SegmentList: []string{"fcff:0:0:e0:b::"}},
		},
	}
}

func egressNode(name string) *corev1.Node {
	return &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"srv6egress.ryskn.io/role": "egress"},
		},
	}
}

func ippool(name string, allowedUses ...string) *unstructured.Unstructured {
	p := &unstructured.Unstructured{}
	p.SetGroupVersionKind(calicoIPPoolGVK)
	p.SetName(name)
	if allowedUses != nil {
		_ = unstructured.SetNestedStringSlice(p.Object, allowedUses, "spec", "allowedUses")
	}
	return p
}

func newPolicy(name, uid string, color uint32, pool string) *srv6egressv1alpha1.EgressPolicy {
	return &srv6egressv1alpha1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			UID:        types.UID(uid),
			Finalizers: []string{finalizerName}, // pre-add to skip the requeue step
		},
		Spec: srv6egressv1alpha1.EgressPolicySpec{
			Selector: srv6egressv1alpha1.Selector{},
			Egress: srv6egressv1alpha1.EgressSpec{
				EndpointSelector: srv6egressv1alpha1.EndpointSelector{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"srv6egress.ryskn.io/role": "egress"},
					},
				},
				Color:        color,
				EgressIPPool: pool,
			},
		},
	}
}

func newReconciler(t *testing.T, objs ...client.Object) *EgressPolicyReconciler {
	t.Helper()
	s := testScheme(t)
	c := fakeclient.NewClientBuilder().
		WithScheme(s).
		WithObjects(objs...).
		WithStatusSubresource(&srv6egressv1alpha1.EgressPolicy{}).
		Build()
	return &EgressPolicyReconciler{
		Client: c,
		Scheme: s,
		Config: testConfig(),
		VIPs:   vipalloc.NewInMemory(),
		BGP:    bgp.NewLoggingStub(logr.Discard()),
	}
}

// recordingBGP records the args of the last Announce/Withdraw.
type recordingBGP struct {
	wOwner string
	wKey   bgp.PolicyKey
	wSegs  []string
}

func (b *recordingBGP) Announce(_ context.Context, _ string, key bgp.PolicyKey, segs []string) (string, error) {
	if len(segs) == 0 {
		return "", nil
	}
	return segs[len(segs)-1], nil
}
func (b *recordingBGP) Withdraw(_ context.Context, owner string, key bgp.PolicyKey, segs []string) error {
	b.wOwner, b.wKey, b.wSegs = owner, key, segs
	return nil
}

func reconcile(t *testing.T, r *EgressPolicyReconciler, name string) error {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name},
	})
	return err
}

func getReady(t *testing.T, r *EgressPolicyReconciler, name string) metav1.Condition {
	t.Helper()
	var ep srv6egressv1alpha1.EgressPolicy
	if err := r.Get(context.Background(), types.NamespacedName{Name: name}, &ep); err != nil {
		t.Fatal(err)
	}
	for _, c := range ep.Status.Conditions {
		if c.Type == "Ready" {
			return c
		}
	}
	t.Fatalf("%s has no Ready condition", name)
	return metav1.Condition{}
}

func TestReconcile_HappyPath(t *testing.T) {
	r := newReconciler(t, egressNode("egress-1"), ippool("tenant-egress-pool", "Tunnel"),
		newPolicy("tenant-a", "uid-a", 100, "tenant-egress-pool"))
	if err := reconcile(t, r, "tenant-a"); err != nil {
		t.Fatalf("reconcile error: %v", err)
	}
	cond := getReady(t, r, "tenant-a")
	if cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready=True, got %s (%s: %s)", cond.Status, cond.Reason, cond.Message)
	}
}

// Finding #2 (RFC 9256 §2 uniqueness): two policies with the same
// <color, endpoint> must not both go Ready.
func TestReconcile_DuplicateColorEndpointRejected(t *testing.T) {
	r := newReconciler(t,
		egressNode("egress-1"),
		ippool("tenant-egress-pool", "Tunnel"),
		newPolicy("tenant-a", "uid-a", 100, "tenant-egress-pool"),
		newPolicy("tenant-b", "uid-b", 100, "tenant-egress-pool"),
	)
	if err := reconcile(t, r, "tenant-a"); err != nil {
		t.Fatalf("reconcile A: %v", err)
	}
	if c := getReady(t, r, "tenant-a"); c.Status != metav1.ConditionTrue {
		t.Fatalf("A expected Ready=True, got %s", c.Status)
	}
	// B shares color 100 + the same resolved endpoint → must be rejected.
	err := reconcile(t, r, "tenant-b")
	if err == nil {
		t.Fatal("expected reconcile B to error on duplicate")
	}
	c := getReady(t, r, "tenant-b")
	if c.Status != metav1.ConditionFalse || c.Reason != "DuplicateColorEndpoint" {
		t.Fatalf("B expected Ready=False/DuplicateColorEndpoint, got %s/%s", c.Status, c.Reason)
	}
}

// Finding #5: an egressIPPool without allowedUses:[Tunnel] must be rejected.
func TestReconcile_IPPoolWithoutTunnelRejected(t *testing.T) {
	r := newReconciler(t,
		egressNode("egress-1"),
		ippool("workload-pool", "Workload"),
		newPolicy("tenant-a", "uid-a", 100, "workload-pool"),
	)
	err := reconcile(t, r, "tenant-a")
	if err == nil {
		t.Fatal("expected reconcile to error on non-Tunnel pool")
	}
	c := getReady(t, r, "tenant-a")
	if c.Status != metav1.ConditionFalse || c.Reason != "InvalidEgressIPPool" {
		t.Fatalf("expected Ready=False/InvalidEgressIPPool, got %s/%s", c.Status, c.Reason)
	}
}

func TestReconcile_IPPoolMissingRejected(t *testing.T) {
	r := newReconciler(t,
		egressNode("egress-1"),
		newPolicy("tenant-a", "uid-a", 100, "nonexistent-pool"),
	)
	if err := reconcile(t, r, "tenant-a"); err == nil {
		t.Fatal("expected error when IPPool does not exist")
	}
	c := getReady(t, r, "tenant-a")
	if c.Reason != "InvalidEgressIPPool" {
		t.Fatalf("expected InvalidEgressIPPool, got %s", c.Reason)
	}
}

// Finding #1 (order-independence): RehydrateVIPs must register every existing
// VIP from status before any reconcile, so a newly created policy reconciled
// BEFORE the old policy is re-seen still cannot be handed a colliding VIP.
func TestRehydrateVIPs_RegistersExistingThenNoCollision(t *testing.T) {
	ctx := context.Background()

	// Existing policy with a VIP already recorded in status (survived restart).
	existing := newPolicy("tenant-old", "uid-old", 100, "tenant-egress-pool")
	existing.Status.EgressIP = "pool:tenant-egress-pool:1"

	r := newReconciler(t,
		egressNode("egress-1"),
		ippool("tenant-egress-pool", "Tunnel"),
		existing,
		// brand-new policy created around restart time, no status yet.
		newPolicy("tenant-new", "uid-new", 200, "tenant-egress-pool"),
	)

	// Startup rehydrate (uses the same client as reader).
	n, err := RehydrateVIPs(ctx, r.Client, r.VIPs)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("expected 1 VIP rehydrated, got %d", n)
	}

	// Now reconcile the NEW policy FIRST (the order that previously collided).
	if err := reconcile(t, r, "tenant-new"); err != nil {
		t.Fatalf("reconcile tenant-new: %v", err)
	}
	var nw srv6egressv1alpha1.EgressPolicy
	if err := r.Get(ctx, types.NamespacedName{Name: "tenant-new"}, &nw); err != nil {
		t.Fatal(err)
	}
	if nw.Status.EgressIP == "pool:tenant-egress-pool:1" {
		t.Fatalf("collision: tenant-new got the VIP already held by tenant-old (%s)", nw.Status.EgressIP)
	}
	if nw.Status.EgressIP != "pool:tenant-egress-pool:2" {
		t.Fatalf("expected counter advanced to :2 after rehydrate, got %q", nw.Status.EgressIP)
	}
}

// Delete must withdraw the route using the PERSISTED announced color/segments
// from status, not the (possibly edited) mutable spec — otherwise it would try
// to delete a route that was never advertised and leave the real one stale.
func TestReconcile_DeleteUsesAnnouncedColorNotSpec(t *testing.T) {
	ctx := context.Background()
	rec := &recordingBGP{}
	s := testScheme(t)
	c := fakeclient.NewClientBuilder().
		WithScheme(s).
		WithObjects(egressNode("egress-1"), ippool("tenant-egress-pool", "Tunnel"),
			newPolicy("tenant-a", "uid-a", 100, "tenant-egress-pool")).
		WithStatusSubresource(&srv6egressv1alpha1.EgressPolicy{}).
		Build()
	r := &EgressPolicyReconciler{Client: c, Scheme: s, Config: testConfig(),
		VIPs: vipalloc.NewInMemory(), BGP: rec}

	// Announce with color 100 → status.srPolicy.color = 100.
	if err := reconcile(t, r, "tenant-a"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Edit spec.egress.color to 200 (simulate a spec change), then delete.
	var ep srv6egressv1alpha1.EgressPolicy
	if err := r.Get(ctx, types.NamespacedName{Name: "tenant-a"}, &ep); err != nil {
		t.Fatal(err)
	}
	if ep.Status.SRPolicy == nil || ep.Status.SRPolicy.Color != 100 {
		t.Fatalf("precondition: expected status.srPolicy.color=100, got %+v", ep.Status.SRPolicy)
	}
	ep.Spec.Egress.Color = 200
	if err := r.Update(ctx, &ep); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, &ep); err != nil { // sets deletionTimestamp (finalizer present)
		t.Fatal(err)
	}
	if err := reconcile(t, r, "tenant-a"); err != nil {
		t.Fatalf("reconcileDelete: %v", err)
	}

	// Withdraw must use the announced color (100), not the edited spec (200).
	if rec.wKey.Color != 100 {
		t.Fatalf("Withdraw used color %d, want persisted announced 100", rec.wKey.Color)
	}
	if len(rec.wSegs) == 0 || rec.wSegs[len(rec.wSegs)-1] != "fcff:0:0:e0:a::" {
		t.Fatalf("Withdraw used segments %v, want the announced color-100 list", rec.wSegs)
	}
}
