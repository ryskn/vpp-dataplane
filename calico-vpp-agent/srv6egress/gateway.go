package srv6egress

import (
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
)

// VPPGateway is the seam for the egress-gateway (endpoint) data path. The
// GatewayManager calls it when this node is the endpoint of an EgressPolicy and
// must terminate the tenant's SRv6 traffic and forward it to the upstream VRF
// (and carry the return back to the pod).
//
// The production implementation drives VPP via vpplink (a stock End.DT6 localsid
// that decaps into a per-tenant VRF + inter-VRF routes). It is NAT-less: the pod
// source address is preserved end to end (L3VPN). It is wired in the agent main
// when this node may act as an egress gateway.
type VPPGateway interface {
	// InstallGateway provisions the per-tenant gateway data path: a dedicated
	// VRF, an End.DT6 localsid for the tenant SID that decaps into that VRF, the
	// egress default route to the shared upstream VRF, and an optional shared
	// return aggregate. Idempotent.
	InstallGateway(req GatewayRequest) error
	// RemoveGateway tears down everything InstallGateway created for req.
	// Safe to call when nothing is installed.
	RemoveGateway(req GatewayRequest) error
	// AddTenantReturnRoute installs the per-tenant return route "prefix ->
	// lookup-in-table clusterTable" in the upstream VRF — the dataplane
	// counterpart of the per-tenant BGP return advertisement (AdvSet).
	// Idempotent.
	AddTenantReturnRoute(prefix string, upstreamTable, clusterTable uint32) error
	// DelTenantReturnRoute removes it. Unlike the legacy shared aggregate it
	// MUST be removed once no policy needs it: a stale route forwards traffic
	// arriving in a VRF whose BGP advertisement was already withdrawn
	// (sovereignty leak). Safe to call when absent.
	DelTenantReturnRoute(prefix string, upstreamTable, clusterTable uint32) error
}

// SIDAdvertiser makes a gateway tenant SID reachable cluster-wide by
// advertising a BGP route to it (next-hop = this node). Calico advertises a
// node's own localsid SIDs via their IPAM block; the egress gateway's
// controller-assigned terminal SID is in no block, so the gateway advertises
// it directly. Optional: nil means the SID must be made reachable by other
// means (e.g. a static route).
type SIDAdvertiser interface {
	AdvertiseSID(sid net.IP) error
	WithdrawSID(sid net.IP) error
}

// GatewayRequest is the resolved per-policy gateway provisioning intent on the
// endpoint node.
type GatewayRequest struct {
	PolicyUID string
	// TenantSID is the terminal SRv6 SID (the policy's segment-list tail): the
	// End.DT6 SID this gateway terminates for the tenant.
	TenantSID net.IP
	// VrfTable is the per-tenant VRF table id the gateway decaps into (manager
	// allocated, stable for the policy's lifetime).
	VrfTable uint32
	// UpstreamTable is the shared upstream VRF holding the routes learned from
	// the upstream peer; the tenant VRF forwards to it (egress).
	UpstreamTable uint32
	// ReturnCIDR / ReturnTable optionally install a shared return aggregate in the
	// upstream VRF: the cluster pod CIDR -> lookup-in-table ReturnTable (the cluster
	// VRF), so return traffic (dst = pod IP) re-enters the cluster SRv6 fabric. An
	// empty ReturnCIDR skips it (return provided by other means).
	ReturnCIDR  string
	ReturnTable uint32
	// USID installs the tenant SID as a uSID (uDT6) via the v2 localsid API with
	// the SID structure below, matching the upstream's uSID locator plan; false
	// installs a classic End.DT6.
	USID            bool
	LocatorBlockLen uint8
	LocatorNodeLen  uint8
	FunctionLen     uint8
	// Upstream is the symbolic upstream name (for logging / mapping).
	Upstream string
}

// UpstreamSIDSpec is the per-upstream SID encoding the gateway installs for a
// tenant terminating on that upstream: a classic End.DT6 (USID false) or a uSID
// uDT6 (USID true) with the given SID structure.
type UpstreamSIDSpec struct {
	USID            bool
	LocatorBlockLen uint8
	LocatorNodeLen  uint8
	FunctionLen     uint8
}

// key identifies a gateway install for diffing across reconciles. The tenant SID
// + VRF fully determine the per-tenant installed state.
func (r GatewayRequest) key() string {
	sid := ""
	if r.TenantSID != nil {
		sid = r.TenantSID.String()
	}
	return fmt.Sprintf("%s|%d", sid, r.VrfTable)
}

// gwState tracks a policy this node is the endpoint for, and the gateway entry
// it provisioned.
type gwState struct {
	policy  *srv6egressv1.EgressPolicy
	install *GatewayRequest // nil until provisioned
}

// tenantReturnRoute identifies one per-tenant return route: a tenant prefix
// routed from an upstream VRF into the cluster VRF. Refcount key across the
// policies of a tenant.
type tenantReturnRoute struct {
	prefix        string
	upstreamTable uint32
	clusterTable  uint32
}

// GatewayManager provisions the endpoint-side data path for EgressPolicies
// whose resolved endpoint is THIS node. It is fed the same cluster-wide
// EgressPolicy events as the headend Manager; it acts only on policies whose
// status.activeEndpoint matches nodeName.
type GatewayManager struct {
	log      *logrus.Entry
	vpp      VPPGateway
	nodeName string
	// upstreamTables maps an upstream name to the shared upstream VRF table id
	// (mirrors the vpp-route-sync per-upstream table mapping on this gateway).
	upstreamTables map[string]uint32

	mu       sync.Mutex
	policies map[string]*gwState // key = EgressPolicy.UID
	vrfs     *vrfAllocator
	sids     SIDAdvertiser // optional; advertises the tenant SID over BGP
	// pendingSID collects SID advertise/withdraw closures produced under mu.
	// They are run by flushPendingSID after the lock is released, because the
	// advertiser broadcasts a blocking pub/sub event and must not stall every
	// other gateway operation while a consumer is backed up.
	pendingSID []func()

	// returnCIDR / returnTable configure the shared return aggregate (see
	// SetClusterReturn); an empty returnCIDR disables it. returnTable is also
	// the target of the per-tenant return routes.
	returnCIDR  string
	returnTable uint32
	// returnRoutes tracks, per policy UID, the per-tenant return routes
	// installed on its behalf; returnRefs refcounts each route across the
	// policies of a tenant so the VPP route is added on 0->1 and removed on
	// 1->0 (a sibling policy's removal must not rip a shared route).
	returnRoutes map[string]map[tenantReturnRoute]struct{}
	returnRefs   map[tenantReturnRoute]int
	// sidModes is the per-upstream SID encoding (see SetUpstreamSIDModes); an
	// upstream absent from the map defaults to classic End.DT6.
	sidModes map[string]UpstreamSIDSpec
}

// SetSIDAdvertiser wires BGP advertisement of provisioned tenant SIDs. Call
// before the watcher starts. Optional; nil keeps SIDs un-advertised.
func (m *GatewayManager) SetSIDAdvertiser(a SIDAdvertiser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sids = a
}

// SetClusterReturn configures the return-path target. clusterVRF is the table
// return traffic is bounced into — by the legacy shared aggregate (podCIDR ->
// clusterVRF in every upstream VRF; empty podCIDR disables it) AND by the
// per-tenant return routes derived from status.returnPrefixes, which use
// clusterVRF as their target regardless of podCIDR. Call before the watcher
// starts.
func (m *GatewayManager) SetClusterReturn(podCIDR string, clusterVRF uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.returnCIDR = podCIDR
	m.returnTable = clusterVRF
}

// SetUpstreamSIDModes configures the per-upstream SID encoding (classic vs uSID).
// An upstream absent from the map defaults to classic End.DT6. Call before the
// watcher starts.
func (m *GatewayManager) SetUpstreamSIDModes(modes map[string]UpstreamSIDSpec) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sidModes = modes
}

// NewGatewayManager builds a GatewayManager for nodeName. upstreamTables gives
// the shared upstream VRF table per upstream name; vrfBase is the first table
// id used for per-tenant VRFs (allocated upward, must not collide with the
// upstream tables or the cluster's own VRFs).
func NewGatewayManager(log *logrus.Entry, vpp VPPGateway, nodeName string,
	upstreamTables map[string]uint32, vrfBase uint32) *GatewayManager {
	return &GatewayManager{
		log:            log.WithField("component", "srv6egress-gateway"),
		vpp:            vpp,
		nodeName:       nodeName,
		upstreamTables: upstreamTables,
		policies:       make(map[string]*gwState),
		vrfs:           newVRFAllocator(vrfBase),
		returnRoutes:   make(map[string]map[tenantReturnRoute]struct{}),
		returnRefs:     make(map[tenantReturnRoute]int),
	}
}

// OnPolicyUpdate is called for create+update events on EgressPolicy.
func (m *GatewayManager) OnPolicyUpdate(ep *srv6egressv1.EgressPolicy) {
	defer m.flushPendingSID() // runs after Unlock (LIFO): sends off the lock
	m.mu.Lock()
	defer m.mu.Unlock()

	uid := string(ep.UID)
	if uid == "" {
		return
	}
	st, ok := m.policies[uid]
	if !ok {
		st = &gwState{}
		m.policies[uid] = st
	}
	st.policy = ep
	m.reconcileLocked(uid, st)
}

// OnPolicyDelete tears down the gateway entry (if any) and forgets the policy.
func (m *GatewayManager) OnPolicyDelete(uid string) {
	defer m.flushPendingSID()
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.policies[uid]
	if !ok {
		return
	}
	m.teardownLocked(uid, st)
	delete(m.policies, uid)
}

// ReconcileAll re-reconciles every tracked policy (periodic retry; the SR
// localsid or cnat set may have failed transiently).
func (m *GatewayManager) ReconcileAll() {
	defer m.flushPendingSID()
	m.mu.Lock()
	defer m.mu.Unlock()
	for uid, st := range m.policies {
		m.reconcileLocked(uid, st)
	}
	// Retry return-route deletes that failed during a teardown whose policy is
	// already forgotten — a stale per-tenant return route is a sovereignty leak
	// and must be retried until the delete succeeds.
	for uid := range m.returnRoutes {
		if _, ok := m.policies[uid]; !ok {
			m.reconcileReturnLocked(uid, nil)
		}
	}
}

// flushPendingSID runs the SID advertise/withdraw closures collected under mu,
// with the lock released, so a blocking pub/sub broadcast cannot stall gateway
// reconciliation. Safe to call when nothing is pending.
func (m *GatewayManager) flushPendingSID() {
	m.mu.Lock()
	ops := m.pendingSID
	m.pendingSID = nil
	m.mu.Unlock()
	for _, op := range ops {
		op()
	}
}

// reconcileLocked installs or removes this node's gateway entry for one policy
// depending on whether this node is its (ready) endpoint. m.mu must be held.
func (m *GatewayManager) reconcileLocked(uid string, st *gwState) {
	want, req := m.desired(st.policy)

	// No longer wanted (endpoint moved, policy not ready, …): tear down.
	// Return routes may exist even when st.install is nil (InstallGateway
	// failed after the return reconcile) — prune them too (fail-closed).
	if !want {
		if st.install != nil || len(m.returnRoutes[uid]) > 0 {
			m.teardownLocked(uid, st)
		}
		return
	}

	// Per-tenant return fence: converge the (prefix × candidate-upstream-VRF)
	// route set on every pass — prefix/candidate drift must prune stale routes
	// even when the localsid install below is unchanged. Deferred so it runs
	// after a drift-triggered teardown (which prunes) has been re-installed.
	defer func() { m.reconcileReturnLocked(uid, m.desiredReturnRoutes(st.policy)) }()

	// Allocate (or recover) the per-tenant VRF BEFORE the drift check so the
	// request key includes the (stable, UID-keyed) table id; otherwise a freshly
	// built req has VrfTable==0 and never matches the installed key, churning a
	// teardown+reinstall on every periodic reconcile. The VRF stays allocated
	// across a failed install (freed only on teardown).
	req.VrfTable = m.vrfs.alloc(uid)

	// Already installed with the same parameters: nothing to do.
	if st.install != nil {
		if st.install.key() == req.key() {
			return
		}
		// Parameters drifted (SID/VIP changed): tear the old one down first.
		m.teardownLocked(uid, st)
		req.VrfTable = m.vrfs.alloc(uid) // teardown freed it; re-allocate
	}

	if err := m.vpp.InstallGateway(req); err != nil {
		m.log.WithError(err).WithField("uid", uid).Warn("InstallGateway failed; will retry")
		return
	}
	cp := req
	st.install = &cp
	// Advertise the tenant SID so headend nodes can route the SR-encapsulated
	// packet to this gateway (best-effort; the data path is already installed).
	// Deferred off the lock: AdvertiseSID broadcasts a blocking pub/sub event.
	if m.sids != nil {
		sid := req.TenantSID
		m.pendingSID = append(m.pendingSID, func() {
			if err := m.sids.AdvertiseSID(sid); err != nil {
				m.log.WithError(err).WithField("sid", sid).
					Warn("failed to advertise gateway SID; reachability may be incomplete")
			}
		})
	}
	m.log.WithFields(logrus.Fields{
		"uid": uid, "sid": req.TenantSID,
		"vrf": req.VrfTable, "upstream": req.Upstream,
	}).Info("installed egress gateway entry")
}

func (m *GatewayManager) teardownLocked(uid string, st *gwState) {
	// Per-tenant return routes contribute nothing once the policy is gone or
	// NotReady: prune them (refcounted — a route shared with a sibling policy
	// of the same tenant survives).
	m.reconcileReturnLocked(uid, nil)
	if st.install != nil {
		// Deferred off the lock: WithdrawSID broadcasts a blocking pub/sub event.
		if m.sids != nil && st.install.TenantSID != nil {
			sid := st.install.TenantSID
			m.pendingSID = append(m.pendingSID, func() {
				if err := m.sids.WithdrawSID(sid); err != nil {
					m.log.WithError(err).WithField("sid", sid).
						Warn("failed to withdraw gateway SID; continuing")
				}
			})
		}
		if err := m.vpp.RemoveGateway(*st.install); err != nil {
			m.log.WithError(err).WithField("uid", uid).Warn("RemoveGateway failed; continuing")
		}
		st.install = nil
	}
	// Free the VRF unconditionally: reconcileLocked allocs it before
	// InstallGateway, so a failed-install-then-deleted/pruned policy (st.install
	// still nil) would otherwise leak the table id forever.
	m.vrfs.free(uid)
}

// desired returns whether this node should provision a gateway entry for ep,
// and the (VRF-unallocated) request describing it.
func (m *GatewayManager) desired(ep *srv6egressv1.EgressPolicy) (bool, GatewayRequest) {
	if ep == nil || !isReady(ep) {
		return false, GatewayRequest{}
	}
	if ep.Status.ActiveEndpoint != m.nodeName {
		return false, GatewayRequest{} // this node is not the endpoint
	}
	sp := ep.Status.SRPolicy
	if sp == nil || len(sp.SegmentList) == 0 {
		return false, GatewayRequest{}
	}
	sid := parseV6(sp.SegmentList[len(sp.SegmentList)-1])
	if sid == nil {
		m.log.WithField("name", ep.Name).Warn("terminal SID is not IPv6; skipping gateway install")
		return false, GatewayRequest{}
	}
	upstreamTable, ok := m.upstreamTables[ep.Status.Upstream]
	if !ok {
		m.log.WithField("upstream", ep.Status.Upstream).
			Warn("no upstream VRF table configured for upstream; skipping gateway install")
		return false, GatewayRequest{}
	}
	spec := m.sidModes[ep.Status.Upstream]
	// Per-tenant return info in status supersedes the legacy shared aggregate
	// for this policy: the fence is installed per (prefix, candidate upstream
	// VRF) by reconcileReturnLocked instead.
	returnCIDR := m.returnCIDR
	if len(ep.Status.ReturnPrefixes) > 0 {
		returnCIDR = ""
	}
	return true, GatewayRequest{
		PolicyUID:       string(ep.UID),
		TenantSID:       sid,
		UpstreamTable:   upstreamTable,
		ReturnCIDR:      returnCIDR,
		ReturnTable:     m.returnTable,
		USID:            spec.USID,
		LocatorBlockLen: spec.LocatorBlockLen,
		LocatorNodeLen:  spec.LocatorNodeLen,
		FunctionLen:     spec.FunctionLen,
		Upstream:        ep.Status.Upstream,
	}
}

// desiredReturnRoutes derives the per-tenant return routes a Ready local
// policy asks of this gateway: each status.returnPrefixes prefix routed from
// every candidate upstream's VRF (the forward failover surface) into the
// cluster VRF. Unknown upstreams are warned and skipped, as in desired().
// Nil when status carries no per-tenant info (legacy shared-aggregate mode).
func (m *GatewayManager) desiredReturnRoutes(ep *srv6egressv1.EgressPolicy) map[tenantReturnRoute]struct{} {
	if ep == nil || len(ep.Status.ReturnPrefixes) == 0 {
		return nil
	}
	ups := map[string]struct{}{}
	if sp := ep.Status.SRPolicy; sp != nil {
		for _, cp := range sp.CandidatePaths {
			if cp.Upstream != "" {
				ups[cp.Upstream] = struct{}{}
			}
		}
	}
	// Legacy single-form status (no candidatePaths): fall back to the primary.
	if len(ups) == 0 && ep.Status.Upstream != "" {
		ups[ep.Status.Upstream] = struct{}{}
	}
	out := map[tenantReturnRoute]struct{}{}
	for up := range ups {
		table, ok := m.upstreamTables[up]
		if !ok {
			m.log.WithField("upstream", up).
				Warn("no upstream VRF table for candidate upstream; skipping its return route")
			continue
		}
		for _, prefix := range ep.Status.ReturnPrefixes {
			out[tenantReturnRoute{prefix: prefix, upstreamTable: table, clusterTable: m.returnTable}] = struct{}{}
		}
	}
	return out
}

// reconcileReturnLocked converges the per-tenant return routes installed on a
// policy's behalf to the desired set, refcounting each route across policies.
// A failed add is not recorded (the next reconcile retries); a failed delete
// keeps the route recorded so the next pass retries — a stale return route is
// a sovereignty leak and must never be silently dropped from the bookkeeping.
// m.mu must be held.
func (m *GatewayManager) reconcileReturnLocked(uid string, desired map[tenantReturnRoute]struct{}) {
	cur := m.returnRoutes[uid]
	for rt := range desired {
		if _, ok := cur[rt]; ok {
			continue
		}
		if m.returnRefs[rt] == 0 {
			if err := m.vpp.AddTenantReturnRoute(rt.prefix, rt.upstreamTable, rt.clusterTable); err != nil {
				m.log.WithError(err).WithFields(logrus.Fields{
					"prefix": rt.prefix, "upstreamTable": rt.upstreamTable,
				}).Warn("AddTenantReturnRoute failed; will retry")
				continue
			}
			m.log.WithFields(logrus.Fields{
				"prefix": rt.prefix, "upstreamTable": rt.upstreamTable, "clusterTable": rt.clusterTable,
			}).Info("installed per-tenant return route")
		}
		if cur == nil {
			cur = map[tenantReturnRoute]struct{}{}
			m.returnRoutes[uid] = cur
		}
		cur[rt] = struct{}{}
		m.returnRefs[rt]++
	}
	for rt := range cur {
		if _, ok := desired[rt]; ok {
			continue
		}
		if m.returnRefs[rt] == 1 {
			if err := m.vpp.DelTenantReturnRoute(rt.prefix, rt.upstreamTable, rt.clusterTable); err != nil {
				m.log.WithError(err).WithFields(logrus.Fields{
					"prefix": rt.prefix, "upstreamTable": rt.upstreamTable,
				}).Warn("DelTenantReturnRoute failed; will retry (stale route is a sovereignty leak)")
				continue
			}
			m.log.WithFields(logrus.Fields{
				"prefix": rt.prefix, "upstreamTable": rt.upstreamTable,
			}).Info("removed per-tenant return route")
		}
		m.returnRefs[rt]--
		if m.returnRefs[rt] == 0 {
			delete(m.returnRefs, rt)
		}
		delete(cur, rt)
	}
	if len(cur) == 0 {
		delete(m.returnRoutes, uid)
	}
}

// PruneExcept tears down gateway entries for policies not in live (deleted
// while no watch was running). Mirrors Manager.PruneExcept.
func (m *GatewayManager) PruneExcept(live map[string]struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for uid, st := range m.policies {
		if _, ok := live[uid]; ok {
			continue
		}
		m.teardownLocked(uid, st)
		delete(m.policies, uid)
	}
}

// Reset tears down every gateway entry (graceful shutdown). Best-effort.
func (m *GatewayManager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for uid, st := range m.policies {
		m.teardownLocked(uid, st)
	}
	m.policies = make(map[string]*gwState)
}

// vrfAllocator hands out per-tenant VRF table ids from a base, reusing the
// same id for a given policy UID across reconciles and reclaiming freed ids
// (lowest free first, so the table-id space stays compact).
type vrfAllocator struct {
	base  uint32
	byUID map[string]uint32
	inUse map[uint32]struct{}
}

func newVRFAllocator(base uint32) *vrfAllocator {
	return &vrfAllocator{
		base:  base,
		byUID: make(map[string]uint32),
		inUse: make(map[uint32]struct{}),
	}
}

func (a *vrfAllocator) alloc(uid string) uint32 {
	if t, ok := a.byUID[uid]; ok {
		return t
	}
	for t := a.base; ; t++ {
		if _, taken := a.inUse[t]; taken {
			continue
		}
		a.inUse[t] = struct{}{}
		a.byUID[uid] = t
		return t
	}
}

func (a *vrfAllocator) free(uid string) {
	if t, ok := a.byUID[uid]; ok {
		delete(a.inUse, t)
		delete(a.byUID, uid)
	}
}
