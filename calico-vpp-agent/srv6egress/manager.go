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
	// liveBSIDs is the set of SR Policy BSIDs currently installed in the
	// dataplane (key = bsid.String()), tracked from the BGP watcher's
	// SRv6PolicyAdded/Deleted events. Steering is only installed for a policy
	// whose resolved BSID is live; otherwise OnUnavailable applies.
	liveBSIDs map[string]struct{}
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
		log:       l,
		vpp:       vpp,
		steering:  &steeringComputer{pods: pods, log: l},
		policies:  make(map[string]*policyState),
		liveBSIDs: make(map[string]struct{}),
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
		prev = &policyState{
			installs:   make(map[string]SteeringRequest),
			blackholes: make(map[string]SteeringRequest),
		}
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
	for _, req := range st.blackholes {
		if err := m.vpp.RemoveBlackhole(req); err != nil {
			m.log.WithError(err).WithField("uid", uid).
				Warn("failed to remove blackhole on policy delete; continuing")
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
	m.reconcileAllLocked()
}

// reconcileAllLocked re-reconciles every tracked policy. m.mu must be held.
func (m *Manager) reconcileAllLocked() {
	for _, st := range m.policies {
		m.reconcileLocked(st)
	}
}

// OnSRPolicyAdded marks bsid live (the BGP watcher installed the SR Policy in
// VPP) and re-reconciles, so any policy whose status BSID matches gets steered.
func (m *Manager) OnSRPolicyAdded(bsid net.IP) {
	if bsid == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.liveBSIDs[bsid.String()] = struct{}{}
	m.reconcileAllLocked()
}

// OnSRPolicyDeleted marks bsid absent (the BGP watcher withdrew the SR Policy
// from VPP) and re-reconciles, so any policy relying on it falls back per its
// OnUnavailable mode instead of blackholing into a now-missing BSID.
func (m *Manager) OnSRPolicyDeleted(bsid net.IP) {
	if bsid == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.liveBSIDs, bsid.String())
	m.reconcileAllLocked()
}

// bsidLive reports whether bsid is currently installed in the dataplane.
// m.mu must be held.
func (m *Manager) bsidLive(bsid net.IP) bool {
	if bsid == nil {
		return false
	}
	_, ok := m.liveBSIDs[bsid.String()]
	return ok
}

// reconcileLocked recomputes the desired install set for one policy (via the
// steeringComputer) and diffs it against the previously installed set, applying
// the difference through the VPP seam. m.mu must be held.
//
// Steering is installed only when the policy is Ready AND its resolved BSID is
// live in the dataplane. When the BSID is absent (withdrawn, or not yet
// installed) the policy is unavailable: existing steering is torn down and the
// OnUnavailable mode decides whether to blackhole (Drop, fail-closed) or leak
// to the node default egress (Fallback, fail-open).
func (m *Manager) reconcileLocked(st *policyState) {
	if st.policy == nil {
		return
	}

	bsid := policyBSID(st.policy)
	available := st.policy != nil && isReady(st.policy) && bsid != nil && m.bsidLive(bsid)

	if !available {
		// Tear down any steering: it would point at an absent BSID and blackhole.
		for k, req := range st.installs {
			if err := m.vpp.RemoveSteering(req); err != nil {
				m.log.WithError(err).WithField("key", k).Warn("RemoveSteering failed")
			}
			delete(st.installs, k)
		}
		m.applyUnavailableLocked(st)
		return
	}

	// Available again: drop any blackholes before (re)installing steering.
	m.clearBlackholesLocked(st)

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

// applyUnavailableLocked enacts the policy's OnUnavailable mode while its SR
// Policy is absent. Drop (the default) installs a blackhole per desired (pod,
// dest) pair so traffic fails closed; Fallback removes any blackholes so
// traffic uses the node default egress. m.mu must be held.
func (m *Manager) applyUnavailableLocked(st *policyState) {
	if onUnavailableDrop(st.policy) {
		// BSID-agnostic: fail-closed must hold even before the SR Policy BSID is
		// resolved (bring-up), where desired() would return nil and leak.
		desired := m.steering.blackholeTargets(st.policy)
		desiredKeys := make(map[string]struct{}, len(desired))
		for _, req := range desired {
			desiredKeys[req.key()] = struct{}{}
		}
		// Remove blackholes no longer desired (pod departed / dest changed).
		for k, req := range st.blackholes {
			if _, keep := desiredKeys[k]; keep {
				continue
			}
			if err := m.vpp.RemoveBlackhole(req); err != nil {
				m.log.WithError(err).WithField("key", k).Warn("RemoveBlackhole failed")
				continue
			}
			delete(st.blackholes, k)
		}
		// Install blackholes for newly-desired pairs.
		for _, req := range desired {
			k := req.key()
			if _, exists := st.blackholes[k]; exists {
				continue
			}
			if err := m.vpp.InstallBlackhole(req); err != nil {
				m.log.WithError(err).WithField("key", k).Warn("InstallBlackhole failed")
				continue
			}
			st.blackholes[k] = req
		}
		return
	}
	// Fallback: ensure no blackhole lingers (traffic leaks to node default egress).
	m.clearBlackholesLocked(st)
}

// clearBlackholesLocked removes and forgets every blackhole tracked for st.
// m.mu must be held.
func (m *Manager) clearBlackholesLocked(st *policyState) {
	for k, req := range st.blackholes {
		if err := m.vpp.RemoveBlackhole(req); err != nil {
			m.log.WithError(err).WithField("key", k).Warn("RemoveBlackhole failed")
		}
		delete(st.blackholes, k)
	}
}

// policyBSID returns the SR Policy BSID resolved in the policy status, or nil
// when no (valid) BSID is present yet. The steering computer sources it the
// same way.
func policyBSID(ep *srv6egressv1.EgressPolicy) net.IP {
	if ep == nil || ep.Status.SRPolicy == nil || ep.Status.SRPolicy.BSID == "" {
		return nil
	}
	return net.ParseIP(ep.Status.SRPolicy.BSID)
}

// onUnavailableDrop reports whether the policy should blackhole (fail-closed)
// when its SR Policy is unavailable. Empty defaults to Drop.
func onUnavailableDrop(ep *srv6egressv1.EgressPolicy) bool {
	return ep == nil || ep.Spec.Egress.OnUnavailable != "Fallback"
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
		for _, req := range st.blackholes {
			if err := m.vpp.RemoveBlackhole(req); err != nil {
				m.log.WithError(err).WithField("uid", uid).
					Warn("prune: RemoveBlackhole failed; continuing")
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
		for _, req := range st.blackholes {
			if err := m.vpp.RemoveBlackhole(req); err != nil {
				m.log.WithError(err).WithField("uid", uid).Warn("reset: RemoveBlackhole failed")
			}
		}
	}
	m.policies = make(map[string]*policyState)
}
