package srv6egress

import (
	"net"
	"sync"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	srv6egressv1alpha1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1alpha1"
)

// Manager is the per-node coordinator. It holds the current set of active
// EgressPolicies and the steering entries each has installed; it diffs and
// reconciles installs on every change (policy add/update/delete, pod
// add/delete, SR Policy add/withdraw).
type Manager struct {
	log *logrus.Entry
	vpp VPPInterface

	mu       sync.Mutex
	policies map[string]*policyState // key = EgressPolicy.UID
}

// NewManager constructs a Manager. The caller is responsible for wiring vpp
// (typically the connectivity.SRv6Provider) and feeding events via the
// On* methods.
func NewManager(log *logrus.Entry, vpp VPPInterface) *Manager {
	return &Manager{
		log:      log.WithField("component", "srv6egress-manager"),
		vpp:      vpp,
		policies: make(map[string]*policyState),
	}
}

// OnPolicyUpdate is called for create + update events on EgressPolicy.
// The Manager replaces the cached policy and reconciles installs.
func (m *Manager) OnPolicyUpdate(ep *srv6egressv1alpha1.EgressPolicy) {
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

// reconcileLocked recomputes the desired install set for one policy and
// diffs it against the previously installed set. m.mu must be held.
//
// v1alpha1 skeleton: this function lays out the diff logic. The actual
// "which pods match the selector on this node" and "is the BSID ready"
// queries are TODOs marked inline — wiring happens when integrated with
// the agent's local pod cache and the BGP-side SR Policy store.
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

	desired := m.computeDesiredInstalls(st.policy)
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

// computeDesiredInstalls builds the (pod × dest) SteeringRequest set for one
// policy on this node.
//
// TODO(wire-up): plug in (a) the agent's local pod cache filtered by
// EgressPolicy.spec.selector, and (b) the SR Policy BSID resolved from the
// BGP layer (color + endpoint → BSID).
func (m *Manager) computeDesiredInstalls(ep *srv6egressv1alpha1.EgressPolicy) []SteeringRequest {
	if ep.Status.SRPolicy == nil || ep.Status.SRPolicy.BSID == "" {
		return nil
	}
	bsid := net.ParseIP(ep.Status.SRPolicy.BSID)
	if bsid == nil {
		m.log.WithField("bsid", ep.Status.SRPolicy.BSID).Warn("status.srPolicy.bsid is not a valid IP")
		return nil
	}

	// Placeholder: returns empty until pod-cache + selector wiring lands.
	// The real implementation walks the local pod cache, filters by selector,
	// and emits one SteeringRequest per (pod IP × destinationCIDR).
	_ = bsid // silence unused until wiring; intentional for skeleton
	return nil
}

// isReady returns true once the controller has marked the policy Ready=True.
func isReady(ep *srv6egressv1alpha1.EgressPolicy) bool {
	for _, c := range ep.Status.Conditions {
		if c.Type == "Ready" && c.Status == metav1.ConditionTrue {
			return true
		}
	}
	return false
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
