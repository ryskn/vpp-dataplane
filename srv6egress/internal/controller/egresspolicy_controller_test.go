package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/bgp"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/config"
)

func testScheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := srv6egressv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
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
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "fd00:1::14"},
			},
		},
	}
}

func newPolicy(name, uid string, color uint32) *srv6egressv1.EgressPolicy {
	return &srv6egressv1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:       name,
			UID:        types.UID(uid),
			Finalizers: []string{finalizerName}, // pre-add to skip the requeue step
		},
		Spec: srv6egressv1.EgressPolicySpec{
			Selector: srv6egressv1.Selector{},
			Egress: srv6egressv1.EgressSpec{
				EndpointSelector: srv6egressv1.EndpointSelector{
					NodeSelector: &metav1.LabelSelector{
						MatchLabels: map[string]string{"srv6egress.ryskn.io/role": "egress"},
					},
				},
				Color: color,
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
		WithStatusSubresource(&srv6egressv1.EgressPolicy{}).
		Build()
	return &EgressPolicyReconciler{
		Client:  c,
		Scheme:  s,
		Config:  testConfig(),
		BGP:     bgp.NewLoggingStub(logr.Discard()),
		Encoder: bgp.NewColoredEncoder(),
	}
}

// recordingBGP records the args of the last Announce/Withdraw. Cluster adverts
// are colored-route encoded (see newReconciler), so it decodes the PolicyKey +
// segment list straight off the recorded Advertisement.
type recordingBGP struct {
	wOwner string
	wKey   bgp.PolicyKey
	wSegs  []string
}

func (b *recordingBGP) Announce(_ context.Context, _ string, adv bgp.Advertisement) (string, error) {
	if adv == nil {
		return "", nil
	}
	return adv.BSID(), nil
}
func (b *recordingBGP) Withdraw(_ context.Context, owner string, adv bgp.Advertisement) error {
	b.wOwner = owner
	if ca, ok := adv.(*bgp.ColoredAdvert); ok {
		b.wKey, b.wSegs = ca.Key, ca.SegmentList
	}
	return nil
}
func (b *recordingBGP) Close() error { return nil }

func reconcile(t *testing.T, r *EgressPolicyReconciler, name string) error {
	t.Helper()
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Name: name},
	})
	return err
}

func getReady(t *testing.T, r *EgressPolicyReconciler, name string) metav1.Condition {
	t.Helper()
	var ep srv6egressv1.EgressPolicy
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
	r := newReconciler(t, egressNode("egress-1"), newPolicy("tenant-a", "uid-a", 100))
	if err := reconcile(t, r, "tenant-a"); err != nil {
		t.Fatalf("reconcile error: %v", err)
	}
	cond := getReady(t, r, "tenant-a")
	if cond.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready=True, got %s (%s: %s)", cond.Status, cond.Reason, cond.Message)
	}
}

// The endpoint node's IPv6 address must be resolved and persisted in status so
// the SR Policy SAFI encoding can build the NLRI and Withdraw can rebuild it
// after a restart.
func TestReconcile_PersistsEndpointAddr(t *testing.T) {
	r := newReconciler(t, egressNode("egress-1"), newPolicy("tenant-a", "uid-a", 100))
	if err := reconcile(t, r, "tenant-a"); err != nil {
		t.Fatalf("reconcile error: %v", err)
	}
	var ep srv6egressv1.EgressPolicy
	if err := r.Get(context.Background(), types.NamespacedName{Name: "tenant-a"}, &ep); err != nil {
		t.Fatal(err)
	}
	if ep.Status.SRPolicy == nil || ep.Status.SRPolicy.EndpointAddr != "fd00:1::14" {
		t.Fatalf("status.srPolicy.endpointAddr = %+v, want fd00:1::14", ep.Status.SRPolicy)
	}
}

// RFC 9256 §2 (uniqueness): two policies with the same
// <color, endpoint> must not both go Ready.
func TestReconcile_DuplicateColorEndpointRejected(t *testing.T) {
	r := newReconciler(t,
		egressNode("egress-1"),
		newPolicy("tenant-a", "uid-a", 100),
		newPolicy("tenant-b", "uid-b", 100),
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

// Delete must withdraw the route using the PERSISTED announced color/segments
// from status, not the (possibly edited) mutable spec — otherwise it would try
// to delete a route that was never advertised and leave the real one stale.
func TestReconcile_DeleteUsesAnnouncedColorNotSpec(t *testing.T) {
	ctx := context.Background()
	rec := &recordingBGP{}
	s := testScheme(t)
	c := fakeclient.NewClientBuilder().
		WithScheme(s).
		WithObjects(egressNode("egress-1"), newPolicy("tenant-a", "uid-a", 100)).
		WithStatusSubresource(&srv6egressv1.EgressPolicy{}).
		Build()
	r := &EgressPolicyReconciler{Client: c, Scheme: s, Config: testConfig(),
		BGP: rec, Encoder: bgp.NewColoredEncoder()}

	// Announce with color 100 → status.srPolicy.color = 100.
	if err := reconcile(t, r, "tenant-a"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	// Edit spec.egress.color to 200 (simulate a spec change), then delete.
	var ep srv6egressv1.EgressPolicy
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

// research#19 (F1) regression: the announce intent must be persisted BEFORE
// Announce. If the post-announce Ready write fails and the policy is then
// deleted, Withdraw must still see the real key/segments from status — with
// the old announce-then-persist order it saw nil and the path leaked in BGP.
func TestReconcile_WithdrawableAfterStatusWriteFailure(t *testing.T) {
	ctx := context.Background()
	rec := &recordingBGP{}
	s := testScheme(t)
	statusWrites := 0
	c := fakeclient.NewClientBuilder().
		WithScheme(s).
		WithObjects(egressNode("egress-1"), newPolicy("tenant-a", "uid-a", 100)).
		WithStatusSubresource(&srv6egressv1.EgressPolicy{}).
		WithInterceptorFuncs(interceptor.Funcs{
			SubResourceUpdate: func(ctx context.Context, cl client.Client, sub string, obj client.Object, opts ...client.SubResourceUpdateOption) error {
				if _, ok := obj.(*srv6egressv1.EgressPolicy); ok && sub == "status" {
					statusWrites++
					if statusWrites == 2 { // the Ready write, right after Announce
						return apierrors.NewConflict(
							schema.GroupResource{Group: "srv6egress.ryskn.io", Resource: "egresspolicies"},
							obj.GetName(), fmt.Errorf("simulated conflict"))
					}
				}
				return cl.SubResource(sub).Update(ctx, obj, opts...)
			},
		}).
		Build()
	r := &EgressPolicyReconciler{Client: c, Scheme: s, Config: testConfig(),
		BGP: rec, Encoder: bgp.NewColoredEncoder()}

	// First reconcile: intent persisted (write 1 OK), announced, Ready write
	// (write 2) fails → requeue with error.
	if err := reconcile(t, r, "tenant-a"); err == nil {
		t.Fatal("expected the simulated Ready-write conflict to surface")
	}

	// Policy is deleted before any retry succeeds.
	var ep srv6egressv1.EgressPolicy
	if err := r.Get(ctx, types.NamespacedName{Name: "tenant-a"}, &ep); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete(ctx, &ep); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, "tenant-a"); err != nil {
		t.Fatalf("reconcileDelete: %v", err)
	}

	// Withdraw must have been replayed from the persisted intent.
	if len(rec.wSegs) == 0 || rec.wSegs[len(rec.wSegs)-1] != "fcff:0:0:e0:a::" {
		t.Fatalf("Withdraw segments = %v, want the announced color-100 list (orphan path!)", rec.wSegs)
	}
	if rec.wKey.Color != 100 {
		t.Fatalf("Withdraw color = %d, want 100", rec.wKey.Color)
	}
}

// A spec edit that changes the SR Policy key (color) must withdraw the OLD
// announced path during the next reconcile — not leave it in BGP forever.
func TestReconcile_SpecEditWithdrawsOldAnnounce(t *testing.T) {
	ctx := context.Background()
	rec := &recordingBGP{}
	s := testScheme(t)
	c := fakeclient.NewClientBuilder().
		WithScheme(s).
		WithObjects(egressNode("egress-1"), newPolicy("tenant-a", "uid-a", 100)).
		WithStatusSubresource(&srv6egressv1.EgressPolicy{}).
		Build()
	r := &EgressPolicyReconciler{Client: c, Scheme: s, Config: testConfig(),
		BGP: rec, Encoder: bgp.NewColoredEncoder()}

	if err := reconcile(t, r, "tenant-a"); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	var ep srv6egressv1.EgressPolicy
	if err := r.Get(ctx, types.NamespacedName{Name: "tenant-a"}, &ep); err != nil {
		t.Fatal(err)
	}
	ep.Spec.Egress.Color = 200
	if err := r.Update(ctx, &ep); err != nil {
		t.Fatal(err)
	}
	if err := reconcile(t, r, "tenant-a"); err != nil {
		t.Fatalf("reconcile after edit: %v", err)
	}

	// The color-100 path must have been withdrawn with its real segment list.
	if rec.wKey.Color != 100 {
		t.Fatalf("stale Withdraw color = %d, want 100", rec.wKey.Color)
	}
	if len(rec.wSegs) == 0 || rec.wSegs[len(rec.wSegs)-1] != "fcff:0:0:e0:a::" {
		t.Fatalf("stale Withdraw segments = %v, want the color-100 list", rec.wSegs)
	}
	// And the policy must be re-announced + Ready under color 200.
	if err := r.Get(ctx, types.NamespacedName{Name: "tenant-a"}, &ep); err != nil {
		t.Fatal(err)
	}
	if ep.Status.SRPolicy == nil || ep.Status.SRPolicy.Color != 200 {
		t.Fatalf("status.srPolicy = %+v, want color 200", ep.Status.SRPolicy)
	}
	if c := getReady(t, r, "tenant-a"); c.Status != metav1.ConditionTrue {
		t.Fatalf("expected Ready=True after edit reconcile, got %s (%s)", c.Status, c.Reason)
	}
}

// --- backbone return advertisement (per-upstream, at startup) ---

// recordingServiceBGP records backbone RFC 9252 service announces.
type recordingServiceBGP struct {
	announced []bgp.ServiceAdvert
}

func (b *recordingServiceBGP) Announce(_ context.Context, _ string, adv bgp.Advertisement) (string, error) {
	if sa, ok := adv.(bgp.ServiceAdvert); ok {
		b.announced = append(b.announced, sa)
	}
	return "", nil
}
func (b *recordingServiceBGP) Withdraw(_ context.Context, _ string, _ bgp.Advertisement) error {
	return nil
}
func (b *recordingServiceBGP) Close() error { return nil }

func backboneConfig() *config.ControllerConfig {
	cfg := testConfig()
	cfg.Backbone = &config.BackboneConfig{
		ClusterPodCIDR: "fd00:dead::/48",
		Peers: map[string]config.BackbonePeerConfig{
			"isp-a": {GoBGPAddr: "192.0.2.14:50052", Nexthop: "fda1::2"},
		},
	}
	return cfg
}

// AdvertiseClusterReturn announces the cluster pod CIDR per backbone upstream
// with that upstream's End SID — the NAT-less return reachability.
func TestAdvertiseClusterReturn(t *testing.T) {
	svc := &recordingServiceBGP{}
	if err := AdvertiseClusterReturn(context.Background(), backboneConfig(),
		map[string]bgp.Distributor{"isp-a": svc}, logr.Discard()); err != nil {
		t.Fatalf("advertise: %v", err)
	}
	if len(svc.announced) != 1 {
		t.Fatalf("announced = %v, want one cluster-return route", svc.announced)
	}
	got := svc.announced[0].Route
	if got.Prefix != "fd00:dead::/48" || got.EndSID != "fcff:0:0:e0:a::" ||
		got.Nexthop != "fda1::2" || got.Behavior != bgp.EndDT6 {
		t.Fatalf("cluster-return route = %+v", got)
	}
}

// A uSID upstream must carry the uSID SID structure in its return advertisement.
func TestAdvertiseClusterReturn_USIDStructure(t *testing.T) {
	svc := &recordingServiceBGP{}
	cfg := backboneConfig()
	u := cfg.Upstreams["isp-a"]
	u.SidMode = config.SidModeUSID
	cfg.Upstreams["isp-a"] = u

	if err := AdvertiseClusterReturn(context.Background(), cfg,
		map[string]bgp.Distributor{"isp-a": svc}, logr.Discard()); err != nil {
		t.Fatalf("advertise: %v", err)
	}
	if len(svc.announced) != 1 {
		t.Fatalf("want one announce, got %d", len(svc.announced))
	}
	st := svc.announced[0].Structure
	if st.LocatorBlockBits != 32 || st.LocatorNodeBits != 16 || st.FunctionBits != 16 {
		t.Fatalf("usid structure = %+v, want 32/16/16", st)
	}
}

// No backbone configured → AdvertiseClusterReturn is a no-op.
func TestAdvertiseClusterReturn_NoBackbone(t *testing.T) {
	svc := &recordingServiceBGP{}
	if err := AdvertiseClusterReturn(context.Background(), testConfig(),
		map[string]bgp.Distributor{"isp-a": svc}, logr.Discard()); err != nil {
		t.Fatalf("advertise: %v", err)
	}
	if len(svc.announced) != 0 {
		t.Fatalf("expected no announces without backbone config, got %v", svc.announced)
	}
}
