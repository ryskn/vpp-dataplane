package srv6egress

import (
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	srv6egressv1alpha1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1alpha1"
)

type fakeVPP struct {
	installs map[string]SteeringRequest
	removes  map[string]SteeringRequest
}

func newFakeVPP() *fakeVPP {
	return &fakeVPP{
		installs: make(map[string]SteeringRequest),
		removes:  make(map[string]SteeringRequest),
	}
}

func (f *fakeVPP) InstallSteering(req SteeringRequest) error {
	f.installs[req.key()] = req
	return nil
}

func (f *fakeVPP) RemoveSteering(req SteeringRequest) error {
	f.removes[req.key()] = req
	delete(f.installs, req.key())
	return nil
}

// readyPolicy returns an EgressPolicy with Ready=True and a populated BSID.
// The manager uses a no-op pod resolver here, so this test only verifies the
// policy state lifecycle (add → delete).
func readyPolicy(name, uid, bsid string) *srv6egressv1alpha1.EgressPolicy {
	return &srv6egressv1alpha1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			UID:  types.UID(uid),
		},
		Status: srv6egressv1alpha1.EgressPolicyStatus{
			SRPolicy: &srv6egressv1alpha1.SRPolicyStatus{
				BSID:  bsid,
				Color: 100,
			},
			Conditions: []metav1.Condition{
				{Type: "Ready", Status: metav1.ConditionTrue},
			},
		},
	}
}

func TestManager_AddAndDelete(t *testing.T) {
	log := logrus.NewEntry(logrus.New())
	vpp := newFakeVPP()
	m := NewManager(log, vpp)

	ep := readyPolicy("tenant-a-via-isp-a", "uid-a", "cafe::1")
	m.OnPolicyUpdate(ep)
	if len(m.policies) != 1 {
		t.Fatalf("expected 1 active policy, got %d", len(m.policies))
	}

	m.OnPolicyDelete("uid-a")
	if len(m.policies) != 0 {
		t.Fatalf("expected 0 active policies after delete, got %d", len(m.policies))
	}
}

func TestManager_NotReadyDeferred(t *testing.T) {
	log := logrus.NewEntry(logrus.New())
	vpp := newFakeVPP()
	m := NewManager(log, vpp)

	ep := &srv6egressv1alpha1.EgressPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tenant-pending",
			UID:  types.UID("uid-p"),
		},
		// no Ready condition; the manager must not crash and must not call VPP
	}
	m.OnPolicyUpdate(ep)
	if len(vpp.installs) != 0 {
		t.Fatalf("expected no installs for not-ready policy, got %d", len(vpp.installs))
	}
}

// research#20 (F2) regression: a policy deleted while no watch was running
// must be pruned (and its steering removed) when the watcher re-Lists.
func TestManager_PruneExcept(t *testing.T) {
	log := logrus.NewEntry(logrus.New())
	vpp := newFakeVPP()
	m := NewManager(log, vpp)

	m.OnPolicyUpdate(readyPolicy("tenant-a", "uid-a", "cafe::1"))
	m.OnPolicyUpdate(readyPolicy("tenant-b", "uid-b", "cafe::2"))

	// Simulate steering installed for uid-b before the watch gap.
	_, dst, _ := net.ParseCIDR("2001:db8:a::/64")
	req := SteeringRequest{
		PolicyUID:  "uid-b",
		PodIP:      net.ParseIP("fd20::1"),
		DestPrefix: dst,
		Color:      100,
		BSID:       net.ParseIP("cafe::2"),
	}
	m.policies["uid-b"].installs[req.key()] = req

	// uid-b was deleted during the gap: the fresh List only contains uid-a.
	m.PruneExcept(map[string]struct{}{"uid-a": {}})

	if len(m.policies) != 1 {
		t.Fatalf("expected only uid-a tracked after prune, got %d", len(m.policies))
	}
	if _, ok := m.policies["uid-a"]; !ok {
		t.Fatal("uid-a must survive the prune")
	}
	if _, ok := vpp.removes[req.key()]; !ok {
		t.Fatal("uid-b steering must be torn down by the prune")
	}
}

func TestSteeringRequest_Key_Stable(t *testing.T) {
	_, dst, _ := net.ParseCIDR("2001:db8::/64")
	r1 := SteeringRequest{
		PolicyUID:  "u1",
		PodIP:      net.ParseIP("fd20::1"),
		DestPrefix: dst,
		Color:      100,
		BSID:       net.ParseIP("cafe::1"),
	}
	r2 := r1
	if r1.key() != r2.key() {
		t.Fatalf("key not stable: %q vs %q", r1.key(), r2.key())
	}
}
