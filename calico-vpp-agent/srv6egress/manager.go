package srv6egress

import (
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
)

// Manager is the per-node coordinator. It holds the current set of active
// EgressPolicies and the steering entries each has installed; it diffs and
// reconciles installs on every change (policy add/update/delete, pod
// add/delete, SR Policy add/withdraw). The desired-state calculation is
// delegated to a steeringComputer, keeping the Manager a lean lifecycle/diff
// coordinator.
type Manager struct {
	log      *logrus.Entry
	vpp      VPPInterface
	steering *steeringComputer

	mu       sync.Mutex
	policies map[string]*policyState // key = EgressPolicy.UID
}

// NewManager constructs a Manager with a no-op pod resolver (zero matches).
// Used by unit tests; production wiring uses NewManagerWithResolver.
func NewManager(log *logrus.Entry, vpp VPPInterface) *Manager {
	return NewManagerWithResolver(log, vpp, nopResolver{})
}

// NewManagerWithResolver constructs a Manager that resolves policy selectors to
// local pod IPs via pods. The caller wires vpp (the CNI server) and pods (the
// informer-backed resolver) and feeds events via the On* methods.
func NewManagerWithResolver(log *logrus.Entry, vpp VPPInterface, pods PodResolver) *Manager {
	l := log.WithField("component", "srv6egress-manager")
	return &Manager{
		log:      l,
		vpp:      vpp,
		steering: &steeringComputer{pods: pods, log: l},
		policies: make(map[string]*policyState),
	}
}

// OnPolicyUpdate is called for create + update events on EgressPolicy.
// The Manager replaces the cached policy and reconciles installs.
func (m *Manager) OnPolicyUpdate(ep *srv6egressv1.EgressPolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()

	uid := string(ep.UID)
	if uid == "" {
		m.log.Warn("EgressPolicy with empty UID ignored")
		return
	}

	prev, existed := m.policies[uid]
	if !existed {
		prev = &policyState{installs: make(map[string]SteeringRequest)}
		m.policies[uid] = prev
	}
	prev.policy = ep
	m.reconcileLocked(prev)
}

// OnPolicyDelete is called when an EgressPolicy is removed.
// All installs that the policy created are torn down.
func (m *Manager) OnPolicyDelete(uid string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	st, ok := m.policies[uid]
	if !ok {
		return
	}
	for _, req := range st.installs {
		if err := m.vpp.RemoveSteering(req); err != nil {
			m.log.WithError(err).WithField("uid", uid).
				Warn("failed to remove steering on policy delete; continuing")
		}
	}
	delete(m.policies, uid)
}

// ReconcileAll re-reconciles every tracked policy. Called when pod/namespace
// membership may have changed (informer events), so newly-matching pods get
// steered and departed ones get their steering cleaned up.
func (m *Manager) ReconcileAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, st := range m.policies {
		m.reconcileLocked(st)
	}
}

// reconcileLocked recomputes the desired install set for one policy (via the
// steeringComputer) and diffs it against the previously installed set, applying
// the difference through the VPP seam. m.mu must be held.
func (m *Manager) reconcileLocked(st *policyState) {
	if st.policy == nil {
		return
	}
	if !isReady(st.policy) {
		// Controller hasn't allocated a VIP / resolved the SR Policy yet;
		// the BGP layer will not have a BSID for us either.
		m.log.WithField("name", st.policy.Name).Debug("policy not yet Ready; deferring")
		return
	}

	desired := m.steering.desired(st.policy)
	desiredKeys := make(map[string]struct{}, len(desired))
	for _, req := range desired {
		desiredKeys[req.key()] = struct{}{}
	}

	// Remove installs no longer desired.
	for k, req := range st.installs {
		if _, keep := desiredKeys[k]; keep {
			continue
		}
		if err := m.vpp.RemoveSteering(req); err != nil {
			m.log.WithError(err).WithField("key", k).Warn("RemoveSteering failed")
			continue
		}
		delete(st.installs, k)
	}

	// Add new installs.
	for _, req := range desired {
		k := req.key()
		if _, exists := st.installs[k]; exists {
			continue
		}
		if err := m.vpp.InstallSteering(req); err != nil {
			m.log.WithError(err).WithField("key", k).Warn("InstallSteering failed")
			continue
		}
		st.installs[k] = req
	}
}

// nopResolver matches no pods. Used by NewManager (unit tests) so the policy
// lifecycle can be exercised without informers.
type nopResolver struct{}

func (nopResolver) MatchingLocalPodIPs(srv6egressv1.Selector) ([]net.IP, error) {
	return nil, nil
}

// isReady returns true once the controller has marked the policy Ready=True.
func isReady(ep *srv6egressv1.EgressPolicy) bool {
	for _, c := range ep.Status.Conditions {
		if c.Type == "Ready" && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
}

// PruneExcept tears down every tracked policy whose UID is not in live.
// Called with the UID set from a fresh List on watch (re)connect: Deleted
// events that fired while no watch was running are lost for good (a new watch
// only replays current objects as ADDED), so this is the only way their
// steering gets cleaned up.
func (m *Manager) PruneExcept(live map[string]struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for uid, st := range m.policies {
		if _, ok := live[uid]; ok {
			continue
		}
		for _, req := range st.installs {
			if err := m.vpp.RemoveSteering(req); err != nil {
				m.log.WithError(err).WithField("uid", uid).
					Warn("prune: RemoveSteering failed; continuing")
			}
		}
		delete(m.policies, uid)
	}
}

// Reset clears all installs (used during agent shutdown). Best-effort; errors
// from VPP are logged but do not stop the loop.
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for uid, st := range m.policies {
		for _, req := range st.installs {
			if err := m.vpp.RemoveSteering(req); err != nil {
				m.log.WithError(err).WithField("uid", uid).Warn("reset: RemoveSteering failed")
			}
		}
	}
	m.policies = make(map[string]*policyState)
}
