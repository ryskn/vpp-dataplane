package connectivity

import (
	"context"
	"fmt"
	"math"
	"net"
	"sort"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectcalico/calico/libcalico-go/lib/ipam"
	cnet "github.com/projectcalico/calico/libcalico-go/lib/net"
	"github.com/projectcalico/calico/libcalico-go/lib/options"
	govppapi "go.fd.io/govpp/api"

	"github.com/projectcalico/vpp-dataplane/v3/calico-vpp-agent/common"
	"github.com/projectcalico/vpp-dataplane/v3/config"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/ip_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// isAlreadyGoneOnDelete: VPP returns NO_SUCH_INNER_FIB (-4) / UNSPECIFIED (-1)
// when the steering/policy is already absent — an idempotent delete.
func isAlreadyGoneOnDelete(err error) bool {
	if err == nil {
		return false
	}
	var vppErr govppapi.VPPApiError
	if !errors.As(err, &vppErr) {
		return false
	}
	return vppErr == govppapi.NO_SUCH_INNER_FIB || vppErr == govppapi.UNSPECIFIED
}

// NodeToPrefixes is data holder for node and traffic destination prefixes (subnets) that should end in the given node
type NodeToPrefixes struct {
	Node     net.IP
	Prefixes []ip_types.Prefix
}

// NodeToPolicies is data holder for node and SRv6 tunnel ending in the given node
type NodeToPolicies struct {
	Node       net.IP
	SRv6Tunnel []common.SRv6Tunnel
}

// installedSRPolicy is the last successfully reconciled dataplane state for
// one RFC 9256 SR Policy <endpoint, color>.  Candidate paths are selected
// inside that policy; different colors on the same endpoint must coexist in
// VPP under their distinct BSIDs.
type installedSRPolicy struct {
	tunnel common.SRv6Tunnel
	policy *types.SrPolicy
}

// srv6VppAPI is the subset of *vpplink.VppLink SRv6Provider uses, so tests can
// substitute a fake.
type srv6VppAPI interface {
	ListSRv6Localsid() ([]*types.SrLocalsid, error)
	AddSRv6Localsid(*types.SrLocalsid) error
	DelSRv6Localsid(*types.SrLocalsid) error
	AddModSRv6Policy(*types.SrPolicy) error
	ListSRv6Policies() ([]*types.SrPolicy, error)
	AddSRv6Steering(*types.SrSteer) error
	DelSRv6Steering(*types.SrSteer) error
	DelSRv6Policy(*types.SrPolicy) error
	ListSRv6Steering() ([]*types.SrSteer, error)
	SetEncapSource(net.IP) error
	RouteAdd(*types.Route) error
	RouteDel(*types.Route) error
	RouteLookup(dst *net.IPNet, tableID uint32) (*types.Route, error)
}

// SRv6Provider is node connectivity provider that uses segment routing over IPv6 (SRv6) to connect the nodes
// For more info about SRv6, see https://datatracker.ietf.org/doc/html/rfc8986.
type SRv6Provider struct {
	*ConnectivityProviderData
	// vpp shadows the embedded ConnectivityProviderData.vpp so tests can inject
	// a fake; production wires the real *vpplink.VppLink through here.
	vpp srv6VppAPI

	// nodePrefixes is internal data holder for information from common.NodeConnectivity data
	// from common.ConnectivityAdded event
	nodePrefixes map[string]*NodeToPrefixes
	// nodePolices is internal data holder for information about SRv6 tunnel(policies)
	// from common.SRv6PolicyAdded event
	nodePolices map[string]*NodeToPolicies
	// policyIPPool is IP pool for Policy BSIDs (BSID = IPv6 address in SRv6)
	policyIPPool net.IPNet
	// localSidIPPool is IP pool for LocalSID's SIDs (SID = IPv6 address in SRv6)
	localSidIPPool net.IPNet
	// dsrServices tracks the SR policy + steering installed for SRv6-native /
	// NAT-less (DSR) ClusterIP services, keyed by VIP string.
	dsrServices map[string]*dsrServiceState
	// dsrDesired is the desired DSR service set (by VIP) — the source of truth
	// reconciled against dsrServices, so failed installs AND removals retry.
	dsrDesired map[string]*common.DSRService
	// pendingBsidCleanup holds prior BSIDs not yet freeable (a steering still
	// resolves through them); drained on later SR-policy events to avoid leaks.
	pendingBsidCleanup []ip_types.IP6Address
	// installedPolicies tracks successful VPP installs by <endpoint,color>.
	// It both suppresses unchanged AddMod churn and lets us publish dataplane
	// liveness transitions (as opposed to raw BGP intent) to srv6egress.
	installedPolicies map[string]installedSRPolicy
	policyEvent       func(common.CalicoVppEvent)

	// dynBsids maps "<endpoint>|<color>" to the BSID dynamically bound to that
	// SR Policy (RFC 9256 §6.2.1) when candidates arrive without one. The
	// binding is policy-scoped: it survives candidate-path changes and is
	// released only when the policy's last candidate is withdrawn.
	dynBsids map[string]ip_types.IP6Address
	// allocBsid/releaseBsid provision dynamic BSIDs. Production wires Calico
	// IPAM on the policy pool (handle-scoped for restart attribution); tests
	// inject fakes.
	allocBsid   func(handle string) (net.IP, error)
	releaseBsid func(handle string) error
	// droppedPrefixes tracks drop routes installed for drop-upon-invalid
	// (RFC 9256 §8.2, I-Flag): prefix@table -> the endpoint whose invalid
	// policy is holding it, plus the route to delete on release.
	droppedPrefixes map[string]dropState
}

// dropState is one fail-closed drop route installed while an SR Policy with the
// I-Flag is invalid (RFC 9256 §8.2).
type dropState struct {
	nodeip string
	route  *types.Route
}

func NewSRv6Provider(d *ConnectivityProviderData) *SRv6Provider {
	p := &SRv6Provider{
		ConnectivityProviderData: d,
		vpp:                      d.vpp,
		nodePrefixes:             make(map[string]*NodeToPrefixes),
		nodePolices:              make(map[string]*NodeToPolicies),
		dsrServices:              make(map[string]*dsrServiceState),
		dsrDesired:               make(map[string]*common.DSRService),
		installedPolicies:        make(map[string]installedSRPolicy),
		dynBsids:                 make(map[string]ip_types.IP6Address),
		droppedPrefixes:          make(map[string]dropState),
	}
	if *config.GetCalicoVppFeatureGates().SRv6Enabled {
		p.localSidIPPool = cnet.MustParseNetwork(config.GetCalicoVppSrv6().LocalsidPool).IPNet
		p.policyIPPool = cnet.MustParseNetwork(config.GetCalicoVppSrv6().PolicyPool).IPNet
	}
	p.allocBsid = p.ipamAllocBsid
	p.releaseBsid = p.ipamReleaseBsid
	p.policyEvent = common.SendEvent

	p.log.Infof("SRv6Provider NewSRv6Provider")
	return p
}

// dynBsidKey identifies the SR Policy a dynamic BSID is bound to. RFC 9256
// §6.2.1 scopes the binding to the policy <color, endpoint>, not the candidate.
func dynBsidKey(nodeip string, color uint32) string {
	return nodeip + "|" + fmt.Sprint(color)
}

// ipamAllocBsid allocates a dynamic BSID from the policy pool through Calico
// IPAM, attributed to the handle. Any stale allocation under the same handle
// (left over from a previous agent run) is released first, so restarts do not
// leak pool addresses.
func (p *SRv6Provider) ipamAllocBsid(handle string) (net.IP, error) {
	ctx := context.Background()
	if err := p.Clientv3().IPAM().ReleaseByHandle(ctx, handle); err != nil {
		p.log.Debugf("SRv6Provider ipamAllocBsid: no stale allocation for %s: %v", handle, err)
	}
	_, v6Assignments, err := p.Clientv3().IPAM().AutoAssign(ctx, ipam.AutoAssignArgs{
		Num6:        1,
		IPv6Pools:   []cnet.IPNet{{IPNet: p.policyIPPool}},
		HandleID:    &handle,
		IntendedUse: "Tunnel",
	})
	if err != nil {
		return nil, errors.Wrapf(err, "SRv6Provider dynamic BSID allocation (handle %s)", handle)
	}
	if v6Assignments == nil || len(v6Assignments.IPs) == 0 {
		return nil, fmt.Errorf("SRv6Provider dynamic BSID pool %s exhausted", p.policyIPPool.String())
	}
	return v6Assignments.IPs[0].IP, nil
}

func (p *SRv6Provider) ipamReleaseBsid(handle string) error {
	return p.Clientv3().IPAM().ReleaseByHandle(context.Background(), handle)
}

func (p *SRv6Provider) GetSwifindexes() []uint32 {
	return []uint32{}
}

func (p *SRv6Provider) EnableDisable(isEnable bool) {
}

func (p *SRv6Provider) Enabled(cn *common.NodeConnectivity) bool {
	return *config.GetCalicoVppFeatureGates().SRv6Enabled
}

// RescanState recreates(if missing in VPP) the static parts of the SRv6 tunneling on this node:
// 1. missing locasids (possible SRv6 tunnel endpoints) if they are not existing.
// 2. source encapsulation setting (pointing to IP of this node)
func (p *SRv6Provider) RescanState() {
	p.log.Infof("SRv6Provider RescanState")

	if !*config.GetCalicoVppFeatureGates().SRv6Enabled {
		return
	}

	err := p.setEncapSource()
	if err != nil {
		p.log.Errorf("setEncapSource Error : %v", err)
	}

	localSids, err := p.vpp.ListSRv6Localsid()
	if err != nil {
		p.log.Errorf("SRv6Provider Error listing SRv6Localsid: %v", err)
	}
	_, err = p.createLocalSidTunnels(localSids)
	if err != nil {
		p.log.Errorf("SRv6Provider Error creating SRv6Localsid: %v", err)
	}

	// Re-run candidate selection in priority order (RFC 9256 §2.12): picks up
	// FIB changes affecting SID reachability and retries failed installs.
	p.revalidatePolicies()
}

func (p *SRv6Provider) CreateSRv6Tunnel(dst net.IP, prefixDst ip_types.Prefix, policyTunnel *types.SrPolicy) (err error) {
	p.log.Infof("SRv6Provider CreateSRv6Tunnel")

	// Install the policy first: steering into a BSID with no policy behind it
	// is a blackhole, so a failed policy add must abort before steering.
	if err := p.vpp.AddModSRv6Policy(policyTunnel); err != nil {
		return errors.Wrapf(err, "SRv6Provider CreateSRv6Tunnel AddModSRv6Policy")
	}
	srSteer := &types.SrSteer{
		TrafficType: types.SrSteerIPv4,
		Prefix:      prefixDst,
		Bsid:        policyTunnel.Bsid,
	}

	// Change the traffic type if is an IPv6 addr
	if vpplink.IsIP6(srSteer.Prefix.Address.ToIP()) {
		srSteer.TrafficType = types.SrSteerIPv6
	}
	// A valid candidate is taking over: lift any drop-upon-invalid route
	// (RFC 9256 §8.2) held on this prefix before steering through it.
	p.clearDropRoute(srSteer.Prefix, srSteer.FibTable)
	if err := p.vpp.AddSRv6Steering(srSteer); err != nil {
		return errors.Wrapf(err, "SRv6Provider CreateSRv6Tunnel AddSRv6Steering")
	}
	return nil
}

// dropKey identifies one fail-closed drop route (RFC 9256 §8.2).
func dropKey(prefix ip_types.Prefix, table uint32) string {
	return prefix.String() + "@" + fmt.Sprint(table)
}

// clearDropRoute removes the drop-upon-invalid route held on prefix, if any.
// Called before (re)steering the prefix through a valid policy.
func (p *SRv6Provider) clearDropRoute(prefix ip_types.Prefix, table uint32) {
	key := dropKey(prefix, table)
	ds, ok := p.droppedPrefixes[key]
	if !ok {
		return
	}
	if err := p.vpp.RouteDel(ds.route); err != nil && !isAlreadyGoneOnDelete(err) {
		// Keep it tracked so a later pass retries; the drop route would
		// otherwise shadow the fresh steering.
		p.log.Warnf("SRv6Provider clearDropRoute %s: %v; will retry", key, err)
		return
	}
	p.log.Infof("SRv6Provider drop-upon-invalid released for %s", key)
	delete(p.droppedPrefixes, key)
}

// engageDropRoute installs the fail-closed drop for a prefix whose SR Policy
// became invalid with the I-Flag set (RFC 9256 §8.2): the traffic is dropped
// rather than escaping to ordinary routing.
func (p *SRv6Provider) engageDropRoute(nodeip string, orphan *types.SrSteer) {
	key := dropKey(orphan.Prefix, orphan.FibTable)
	if _, ok := p.droppedPrefixes[key]; ok {
		return
	}
	route := &types.Route{
		Dst:   orphan.Prefix.ToIPNet(),
		Table: orphan.FibTable,
		Paths: []types.RoutePath{{IsDrop: true}},
	}
	if err := p.vpp.RouteAdd(route); err != nil {
		p.log.Warnf("SRv6Provider engageDropRoute %s: %v; falling back to fail-open", key, err)
		return
	}
	p.droppedPrefixes[key] = dropState{nodeip: nodeip, route: route}
	p.log.Infof("SRv6Provider drop-upon-invalid engaged for %s (RFC 9256 §8.2)", key)
}

// releaseDropsForNode lifts every drop held for nodeip's policies. Called when
// the policy ceases to exist (all candidates withdrawn): with no policy left
// there is no drop-upon-invalid state to honor, traffic reverts to routing.
func (p *SRv6Provider) releaseDropsForNode(nodeip string) {
	for key, ds := range p.droppedPrefixes {
		if ds.nodeip != nodeip {
			continue
		}
		if err := p.vpp.RouteDel(ds.route); err != nil && !isAlreadyGoneOnDelete(err) {
			p.log.Warnf("SRv6Provider releaseDropsForNode %s: %v; will retry", key, err)
			continue
		}
		p.log.Infof("SRv6Provider drop-upon-invalid released for %s (policy gone)", key)
		delete(p.droppedPrefixes, key)
	}
}

// steerNodeIPViaSID steers pod traffic to a remote node's own IP onto that node's
// End.DT6 SID (in PodVRFIndex) so host-network backed ClusterIPs work under SRv6.
func (p *SRv6Provider) steerNodeIPViaSID(nodeip string) {
	nodeIP := net.ParseIP(nodeip)
	if nodeIP == nil || !vpplink.IsIP6(nodeIP) {
		return // IPv6 only; IPv4 node IPs would need End.DT4
	}
	policy, err := p.getPolicyNode(nodeip, types.SrBehaviorDT6)
	if err != nil || policy == nil {
		p.log.Debugf("SRv6Provider steerNodeIPViaSID: no DT6 policy for %s yet, will retry later", nodeip)
		return
	}
	prefix, err := ip_types.ParsePrefix(nodeIP.String() + "/128")
	if err != nil {
		p.log.Errorf("SRv6Provider steerNodeIPViaSID parse prefix %s: %v", nodeip, err)
		return
	}
	// policy is already installed by CreateSRv6Tunnel; only add the steering.
	srSteer := &types.SrSteer{
		TrafficType: types.SrSteerIPv6,
		FibTable:    common.PodVRFIndex,
		Prefix:      prefix,
		Bsid:        policy.Bsid,
	}
	p.clearDropRoute(srSteer.Prefix, srSteer.FibTable)
	if err := p.vpp.AddSRv6Steering(srSteer); err != nil {
		p.log.Errorf("SRv6Provider steerNodeIPViaSID AddSRv6Steering node=%s prefix=%s: %v", nodeip, prefix.String(), err)
	}
}

// containsPrefix reports whether prefixes already holds p (compared by string).
func containsPrefix(prefixes []ip_types.Prefix, p ip_types.Prefix) bool {
	for i := range prefixes {
		if prefixes[i].String() == p.String() {
			return true
		}
	}
	return false
}

func srPolicyGroupKey(nodeip string, color uint32) string {
	return nodeip + "|" + fmt.Sprint(color)
}

func cloneSRPolicy(policy *types.SrPolicy) *types.SrPolicy {
	if policy == nil {
		return nil
	}
	cloned := *policy
	cloned.SidLists = append([]types.Srv6SidList(nil), policy.SidLists...)
	return &cloned
}

func sameSRPolicy(a, b *types.SrPolicy) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Bsid != b.Bsid || a.IsSpray != b.IsSpray || a.IsEncap != b.IsEncap || a.FibTable != b.FibTable || len(a.SidLists) != len(b.SidLists) {
		return false
	}
	for i := range a.SidLists {
		if a.SidLists[i] != b.SidLists[i] {
			return false
		}
	}
	return true
}

func cloneInstalledSRPolicy(tunnel *common.SRv6Tunnel, policy *types.SrPolicy) installedSRPolicy {
	clonedTunnel := *tunnel
	clonedTunnel.Policy = cloneSRPolicy(policy)
	clonedTunnel.Bsid = policy.Bsid.ToIP()
	clonedTunnel.VerifyMasks = append([]uint32(nil), tunnel.VerifyMasks...)
	return installedSRPolicy{tunnel: clonedTunnel, policy: clonedTunnel.Policy}
}

func (p *SRv6Provider) emitPolicyState(eventType common.CalicoVppEventType, state installedSRPolicy) {
	if p.policyEvent == nil || state.policy == nil {
		return
	}
	tunnel := state.tunnel
	cn := &common.NodeConnectivity{
		NextHop: tunnel.Dst,
		Custom:  &tunnel,
	}
	event := common.CalicoVppEvent{Type: eventType}
	if eventType == common.SRv6PolicyInstalled {
		event.New = cn
	} else {
		event.Old = cn
	}
	p.policyEvent(event)
}

// reconcilePolicyColor installs the selected candidate for one RFC 9256 SR
// Policy <endpoint,color>, even when the endpoint has no ordinary node prefix.
// That latter case is the srv6egress headend path: EgressPolicy steering refers
// directly to the policy's BSID from a per-pod VRF.
//
// forceTransition is used after a withdraw that removed steering from the
// selected BSID.  Publishing Uninstalled then Installed makes consumers rebuild
// their steering even when failover keeps the same BSID.
func (p *SRv6Provider) reconcilePolicyColor(nodeip string, color uint32, forceTransition bool) error {
	if p.installedPolicies == nil {
		p.installedPolicies = make(map[string]installedSRPolicy)
	}
	key := srPolicyGroupKey(nodeip, color)
	prior, hadPrior := p.installedPolicies[key]
	selected, desired, err := p.getPolicyColor(nodeip, color)
	if err != nil {
		return err
	}

	actual, err := p.vpp.ListSRv6Policies()
	if err != nil {
		return errors.Wrapf(err, "SRv6Provider list policies for endpoint=%s color=%d", nodeip, color)
	}

	if desired == nil {
		if !hadPrior {
			return nil
		}
		// A policy that became invalid/absent must not leave steering resolving
		// through its BSID.  Withdraw handling normally removed these already;
		// the list makes this path idempotent.
		steering, listErr := p.vpp.ListSRv6Steering()
		if listErr != nil {
			return errors.Wrapf(listErr, "SRv6Provider list steering for endpoint=%s color=%d", nodeip, color)
		}
		for _, st := range steering {
			if st.Bsid != prior.policy.Bsid {
				continue
			}
			if err := p.vpp.DelSRv6Steering(st); err != nil && !isAlreadyGoneOnDelete(err) {
				return errors.Wrapf(err, "SRv6Provider delete steering for bsid=%s", prior.policy.Bsid.String())
			}
		}
		for _, policy := range actual {
			if policy.Bsid != prior.policy.Bsid {
				continue
			}
			if err := p.vpp.DelSRv6Policy(prior.policy); err != nil && !isAlreadyGoneOnDelete(err) {
				return errors.Wrapf(err, "SRv6Provider delete policy bsid=%s", prior.policy.Bsid.String())
			}
			break
		}
		delete(p.installedPolicies, key)
		p.emitPolicyState(common.SRv6PolicyUninstalled, prior)
		return nil
	}

	actualMatches := false
	actualHasBSID := false
	for _, policy := range actual {
		if policy.Bsid != desired.Bsid {
			continue
		}
		actualHasBSID = true
		actualMatches = sameSRPolicy(policy, desired)
		break
	}
	// Once this provider has recorded the exact desired policy, BSID presence is
	// enough for an unchanged re-assert.  VPP dumps may normalize otherwise
	// equivalent list fields; treating that cosmetic difference as drift would
	// delete/re-add a live policy every 30 seconds.
	if hadPrior && sameSRPolicy(prior.policy, desired) && actualHasBSID {
		actualMatches = true
	}
	if !actualMatches {
		if err := p.vpp.AddModSRv6Policy(desired); err != nil {
			return errors.Wrapf(err, "SRv6Provider install policy endpoint=%s color=%d bsid=%s", nodeip, color, desired.Bsid.String())
		}
	}

	next := cloneInstalledSRPolicy(selected, desired)
	if hadPrior && (forceTransition || !sameSRPolicy(prior.policy, desired) || !actualMatches) {
		p.emitPolicyState(common.SRv6PolicyUninstalled, prior)
	}
	p.installedPolicies[key] = next
	// Emit a success heartbeat even for an unchanged BGP re-assertion.  The
	// srv6egress subscriber is registered asynchronously during startup and may
	// have missed the first install; the controller's periodic re-assert heals it.
	p.emitPolicyState(common.SRv6PolicyInstalled, next)
	return nil
}

// AddConnectivity reconciles the dynamic SRv6 state learned from ordinary
// ConnectivityAdded events and BGP SRv6PolicyAdded events.  A complete legacy
// inter-node tunnel is assembled incrementally as its node prefixes and policy
// arrive.  The policy itself is independently installed as soon as its BGP
// candidate is usable, allowing consumers such as srv6egress to supply their
// own steering without an ordinary node prefix.  Static localsids and the
// encapsulation source are created in RescanState.
func (p *SRv6Provider) AddConnectivity(cn *common.NodeConnectivity) error {
	p.log.Infof("SRv6Provider AddConnectivity %s", cn.String())

	var nodeip string
	// Set by the upsert below when it supersedes a prior BSID; freed (or queued)
	// by drainPendingBsidCleanup at function end, after the steering re-point.
	var orphanedBsid ip_types.IP6Address
	var orphanedBsidValid bool
	var policyColor uint32
	var policyUpdate bool

	// processing normal NodeConnectivity data only IPv6 destination
	if vpplink.IsIP6(cn.NextHop) && !p.isSRv6TunnelInfoFromBGP(cn) {
		// destination IP can't be from policy IPPool, because this IPPool is reserved for policy BSIDs
		if p.policyIPPool.Contains(cn.Dst.IP) {
			p.log.Infof("SRv6Provider AddConnectivity no valid prefix %s", cn.Dst.String())
			return nil
		}

		// variables processing
		nodeip = cn.NextHop.String()                         // destination node IP
		prefix, err := ip_types.ParsePrefix(cn.Dst.String()) // traffic destination that should use SRv6 tunnel
		if err != nil {
			return errors.Wrapf(err, "SRv6Provider unable to parse prefix")
		}

		// Creating SRv6 traffic forwarding (this is where one call of this method finishes)
		if p.localSidIPPool.Contains(cn.Dst.IP) {
			p.log.Debugf("SRv6Provider AddConnectivity localSidIPPool prefix %s", cn.Dst.String())
			err = p.vpp.RouteAdd(&types.Route{
				Dst:   prefix.ToIPNet(),
				Paths: []types.RoutePath{{Gw: cn.NextHop.To16(), SwIfIndex: common.VppManagerInfo.GetMainSwIfIndex()}},
			})

			return err
		}

		p.log.Debugf("SRv6Provider AddConnectivity prefix %s for node %s", prefix.String(), nodeip)

		// storing info in nodePrefixes
		if p.nodePrefixes[nodeip] == nil {
			p.nodePrefixes[nodeip] = &NodeToPrefixes{
				Node:     cn.NextHop,
				Prefixes: []ip_types.Prefix{},
			}
		}
		// Dedup: AddConnectivity is re-invoked for unchanged routes on the
		// "connectivity(same)" path and on every updateAllIPConnectivity();
		// without this each pass would append again and CreateSRv6Tunnel would
		// re-run AddModSRv6Policy (del+add), rebuilding the shared SR policy.
		if !containsPrefix(p.nodePrefixes[nodeip].Prefixes, prefix) {
			p.nodePrefixes[nodeip].Prefixes = append(p.nodePrefixes[nodeip].Prefixes, prefix)
		}

		// stopping processing until we have also needed SRv6 tunnel data (SRv6 policy)
		// from the destination node (BGP transportation)
		if p.nodePolices[nodeip] == nil {
			p.log.Infof("SRv6Provider no policies for %s", nodeip)
			return nil
		}

	} else if p.isSRv6TunnelInfoFromBGP(cn) && cn.Custom != nil { // getting SRv6 tunnel data from BGP

		// storing info in nodePolices
		policyData, ok := cn.Custom.(*common.SRv6Tunnel)
		if !ok {
			return fmt.Errorf("cn.Custom is not a (*common.SRv6Tunnel) %v", cn.Custom)
		}
		nodeip = policyData.Dst.String()
		policyColor = policyData.Color
		policyUpdate = true
		if p.nodePolices[policyData.Dst.String()] == nil {
			p.nodePolices[policyData.Dst.String()] = &NodeToPolicies{
				Node:       policyData.Dst,
				SRv6Tunnel: []common.SRv6Tunnel{},
			}
		}

		p.log.Debugf("SRv6Provider new policy %s with behavior %d on node %s and priority %d", policyData.Bsid.String(), policyData.Behavior, nodeip, policyData.Priority)
		// RFC 9012 NLRI key <Distinguisher, Color, Endpoint>: same key replaces
		// the prior candidate in place (endpoint = map key), never appends.
		entry := p.nodePolices[policyData.Dst.String()]
		replaced := false
		for i := range entry.SRv6Tunnel {
			if entry.SRv6Tunnel[i].Color != policyData.Color || entry.SRv6Tunnel[i].Distinguisher != policyData.Distinguisher {
				continue
			}
			// BSID changed: hand the prior one to the deferred cleanup
			// (freed after the steering is re-pointed, never while live).
			oldBsid, oldOk := tunnelBsid(&entry.SRv6Tunnel[i])
			newBsid, newOk := tunnelBsid(policyData)
			if oldOk && newOk && oldBsid != newBsid {
				orphanedBsid = oldBsid
				orphanedBsidValid = true
			}
			entry.SRv6Tunnel[i] = *policyData
			replaced = true
			break
		}
		if !replaced {
			entry.SRv6Tunnel = append(entry.SRv6Tunnel, *policyData)
		}

		if p.nodePrefixes[nodeip] == nil {
			p.log.Debugf("SRv6Provider no prefixes for %s", nodeip)
			// Fall through so the function-end drain still runs; the
			// CreateSRv6Tunnel block below is gated on nodePrefixes != nil.
		}

	}

	// We got all needed data (normal common.NodeConnectivity and SRv6 tunnel info from tunnel-end node transported by BGP)
	// we can create dynamic parts of SRv6 tunnel (SR steering and SR policy)
	p.installNode(nodeip)
	if policyUpdate {
		// SR Policies are first-class dataplane objects keyed by
		// <endpoint,color>.  Install them even when no ordinary node prefix exists;
		// srv6egress adds its own per-pod-VRF steering to their BSIDs.
		if err := p.reconcilePolicyColor(nodeip, policyColor, false); err != nil {
			p.drainPendingBsidCleanup(orphanedBsid, orphanedBsidValid)
			return err
		}
	}

	p.drainPendingBsidCleanup(orphanedBsid, orphanedBsidValid)

	// A backend node's End.DT6 SID may have just become available (or a pending
	// DSR removal may need retrying); reconcile the DSR services.
	p.reconcileDSRServices()

	return nil
}

// installNode creates the dynamic parts of the SRv6 tunnel (SR policy and
// steering) for one endpoint node, once both its prefixes and policy
// candidates are known. Selection runs per prefix behavior (RFC 9256 §2.9).
func (p *SRv6Provider) installNode(nodeip string) {
	if p.nodePrefixes[nodeip] == nil {
		return
	}
	p.log.Debugf("SRv6Provider check new tunnel for node %s, prefixes %d", nodeip, len(p.nodePrefixes[nodeip].Prefixes))

	for _, prefix := range p.nodePrefixes[nodeip].Prefixes {
		prefixBehavior := types.SrBehaviorDT4
		if vpplink.IsIP6(prefix.Address.ToIP()) {
			prefixBehavior = types.SrBehaviorDT6
		}

		policy, err := p.getPolicyNode(nodeip, prefixBehavior)
		if err == nil && policy != nil {
			if err := p.CreateSRv6Tunnel(p.nodePrefixes[nodeip].Node, prefix, policy); err != nil {
				p.log.Error(err)
			}
		}
	}

	// Bring the host plane onto SRv6 too: steer pod traffic to this node's
	// IP via its End.DT6 SID so host-network backed ClusterIPs work.
	p.steerNodeIPViaSID(nodeip)
}

// revalidatePolicies re-runs candidate selection and installation for every
// endpoint, ordered by SR Policy priority (RFC 9256 §2.12: lower value first;
// the policy takes the lowest priority among its candidates). Invoked from
// RescanState so FIB changes (SID reachability) and previously failed installs
// are picked up, most important policies first.
func (p *SRv6Provider) revalidatePolicies() {
	type item struct {
		nodeip string
		prio   uint32
	}
	items := make([]item, 0, len(p.nodePolices))
	for nodeip, entry := range p.nodePolices {
		prio := uint32(math.MaxUint32)
		for i := range entry.SRv6Tunnel {
			if entry.SRv6Tunnel[i].Priority < prio {
				prio = entry.SRv6Tunnel[i].Priority
			}
		}
		items = append(items, item{nodeip, prio})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].prio < items[j].prio })
	for _, it := range items {
		p.installNode(it.nodeip)
		entry := p.nodePolices[it.nodeip]
		colorsSeen := make(map[uint32]struct{}, len(entry.SRv6Tunnel))
		colors := make([]uint32, 0, len(entry.SRv6Tunnel))
		for i := range entry.SRv6Tunnel {
			color := entry.SRv6Tunnel[i].Color
			if _, seen := colorsSeen[color]; seen {
				continue
			}
			colorsSeen[color] = struct{}{}
			colors = append(colors, color)
		}
		sort.Slice(colors, func(i, j int) bool { return colors[i] < colors[j] })
		for _, color := range colors {
			if err := p.reconcilePolicyColor(it.nodeip, color, false); err != nil {
				p.log.Errorf("SRv6Provider revalidate endpoint=%s color=%d: %v", it.nodeip, color, err)
			}
		}
	}
}

// drainPendingBsidCleanup deletes queued BSIDs no steering resolves through
// (one ListSRv6Steering classifies all); still-referenced ones stay queued.
func (p *SRv6Provider) drainPendingBsidCleanup(orphanedBsid ip_types.IP6Address, orphanedBsidValid bool) {
	if orphanedBsidValid {
		p.pendingBsidCleanup = append(p.pendingBsidCleanup, orphanedBsid)
	}
	if len(p.pendingBsidCleanup) == 0 {
		return
	}
	steering, listErr := p.vpp.ListSRv6Steering()
	if listErr != nil {
		p.log.Warnf("SRv6Provider drainPendingBsidCleanup: ListSRv6Steering failed: %v; %d BSID cleanups deferred",
			listErr, len(p.pendingBsidCleanup))
		return
	}
	referenced := make(map[ip_types.IP6Address]struct{}, len(steering))
	for _, st := range steering {
		referenced[st.Bsid] = struct{}{}
	}
	queue := p.pendingBsidCleanup
	p.pendingBsidCleanup = nil
	for _, bsid := range queue {
		if _, stillSteered := referenced[bsid]; stillSteered {
			p.log.Debugf("SRv6Provider drainPendingBsidCleanup: BSID %s still steered; re-queued", bsid)
			p.pendingBsidCleanup = append(p.pendingBsidCleanup, bsid)
			continue
		}
		err := p.vpp.DelSRv6Policy(&types.SrPolicy{Bsid: bsid})
		if err == nil || isAlreadyGoneOnDelete(err) {
			p.log.Debugf("SRv6Provider drainPendingBsidCleanup: BSID %s freed: %v", bsid, err)
			continue
		}
		// Hard error: keep the BSID queued to retry on the next event.
		p.log.Warnf("SRv6Provider drainPendingBsidCleanup: BSID %s cleanup failed: %v; re-queued", bsid, err)
		p.pendingBsidCleanup = append(p.pendingBsidCleanup, bsid)
	}
}

// DelConnectivity tears down state from AddConnectivity. cn.Custom set =
// SRv6PolicyDeleted (NLRI-key teardown); cn.Dst set = ConnectivityDeleted
// (prefix steering). Per-step failures are logged, not fatal.
func (p *SRv6Provider) DelConnectivity(cn *common.NodeConnectivity) error {
	p.log.Infof("SRv6Provider DelConnectivity %s", cn.String())
	if cn.Custom != nil {
		return p.delSRPolicy(cn)
	}
	if cn.Dst.IP != nil {
		return p.delPrefixSteering(cn)
	}
	return fmt.Errorf("SRv6Provider DelConnectivity: cn has neither Custom nor Dst.IP")
}

func (p *SRv6Provider) delSRPolicy(cn *common.NodeConnectivity) error {
	policyData, ok := cn.Custom.(*common.SRv6Tunnel)
	if !ok || policyData == nil {
		return fmt.Errorf("SRv6Provider DelConnectivity: cn.Custom is not a *common.SRv6Tunnel: %T", cn.Custom)
	}
	// A withdraw may free a queued BSID; retry the drain on any return path.
	defer p.drainPendingBsidCleanup(ip_types.IP6Address{}, false)
	nodeip := policyData.Dst.String()
	entry := p.nodePolices[nodeip]
	if entry == nil {
		p.log.Infof("SRv6Provider DelConnectivity: no cached policies for endpoint %s", nodeip)
		return nil
	}

	// Match cached tunnels by <Distinguisher, Color, Endpoint> NLRI key.
	// Withdraws carry only the NLRI key (no BSID); the cached tunnel preserves
	// the BSID we installed, which is what VPP needs to delete.
	// Withdraws also carry no flags, so drop-upon-invalid (I-Flag) intent is
	// read from the cached tunnels and the superseding advertisement alike.
	dropRequested := policyData.DropUponInvalid
	var matched []ip_types.IP6Address
	remaining := entry.SRv6Tunnel[:0]
	for _, tun := range entry.SRv6Tunnel {
		if tun.Color == policyData.Color && tun.Distinguisher == policyData.Distinguisher {
			if b, ok := tunnelBsid(&tun); ok {
				matched = append(matched, b)
			}
			dropRequested = dropRequested || tun.DropUponInvalid
			continue
		}
		remaining = append(remaining, tun)
	}
	if len(matched) == 0 {
		p.log.Infof("SRv6Provider DelConnectivity: no cached policy matched endpoint=%s color=%d distinguisher=%d",
			nodeip, policyData.Color, policyData.Distinguisher)
		return nil
	}
	for _, tun := range remaining {
		dropRequested = dropRequested || tun.DropUponInvalid
	}
	// RFC 9256 §8.2 applies while the policy exists but is invalid. With no
	// candidate left at all the policy is gone, so fail-open is correct.
	dropRequested = dropRequested && len(remaining) > 0

	steering, listErr := p.vpp.ListSRv6Steering()
	if listErr != nil {
		p.log.Warnf("SRv6Provider DelConnectivity: failed to list steering: %v", listErr)
	}
	// logDel: silent on success, debug when VPP says it's already gone, warn otherwise.
	logDel := func(what string, err error) {
		if err == nil {
			return
		}
		log := p.log.Warnf
		if isAlreadyGoneOnDelete(err) {
			log = p.log.Debugf
		}
		log("SRv6Provider DelConnectivity: %s: %v", what, err)
	}

	// Track which prefixes lose their steering: after we delete this BSID,
	// the RFC 9256 candidate-path failover wants the next-best surviving
	// policy of the same behavior to take over. Re-steer happens below, after
	// the cache prune, so getPolicyNode sees the post-withdraw state.
	// Keep the full steering entry (not just the prefix): the failover re-steer
	// must preserve the FibTable it was installed in. Pod prefixes are steered
	// in the main table, but the node-IP /128 steering (steerNodeIPViaSID, for
	// host-network-backed ClusterIPs) lives in PodVRFIndex; re-steering it into
	// the wrong table would silently break that path after failover.
	var orphaned []*types.SrSteer
	for _, bsid := range matched {
		for _, st := range steering {
			if st.Bsid != bsid {
				continue
			}
			orphaned = append(orphaned, st)
			logDel(fmt.Sprintf("DelSRv6Steering bsid=%s prefix=%s", st.Bsid, st.Prefix), p.vpp.DelSRv6Steering(st))
		}
		logDel(fmt.Sprintf("DelSRv6Policy bsid=%s", bsid), p.vpp.DelSRv6Policy(&types.SrPolicy{Bsid: bsid}))
	}

	if len(remaining) == 0 {
		delete(p.nodePolices, nodeip)
		// Policy gone entirely: no drop-upon-invalid state left to honor.
		p.releaseDropsForNode(nodeip)
	} else {
		entry.SRv6Tunnel = remaining
	}

	// Release the dynamic BSID binding (RFC 9256 §6.2.1) once the last
	// candidate of its SR Policy <endpoint, color> is gone.
	p.releaseUnusedDynBsids(nodeip, policyData.Color, remaining)

	// Generic node-prefix steering uses the selected candidate per behavior.
	// Track which survivor we install on demand here so multiple orphaned
	// prefixes targeting the same BSID do not churn that install.  The
	// endpoint+color reconciliation below then confirms/publishes final policy
	// state for standalone consumers too.
	installed := make(map[ip_types.IP6Address]struct{})
	for _, st := range orphaned {
		p.resteerOrphan(nodeip, st, installed, dropRequested)
	}
	forceTransition := false
	if prior, ok := p.installedPolicies[srPolicyGroupKey(nodeip, policyData.Color)]; ok && prior.policy != nil {
		for _, bsid := range matched {
			if bsid == prior.policy.Bsid {
				forceTransition = true
				break
			}
		}
	}
	if err := p.reconcilePolicyColor(nodeip, policyData.Color, forceTransition); err != nil {
		return errors.Wrapf(err, "SRv6Provider reconcile withdrawn policy endpoint=%s color=%d", nodeip, policyData.Color)
	}
	return nil
}

// releaseUnusedDynBsids frees the dynamic BSID bound to <nodeip, color> when
// no candidate of that SR Policy survives (RFC 9256 §6.2.1: the binding lives
// as long as the policy does).
func (p *SRv6Provider) releaseUnusedDynBsids(nodeip string, color uint32, remaining []common.SRv6Tunnel) {
	key := dynBsidKey(nodeip, color)
	if _, ok := p.dynBsids[key]; !ok {
		return
	}
	for i := range remaining {
		if remaining[i].Color == color {
			return // policy still has candidates; keep the binding
		}
	}
	if err := p.releaseBsid(dynBsidHandle(nodeip, color)); err != nil {
		p.log.Warnf("SRv6Provider: release dynamic BSID for endpoint=%s color=%d: %v", nodeip, color, err)
	}
	delete(p.dynBsids, key)
	p.log.Infof("SRv6Provider: released dynamic BSID for endpoint=%s color=%d", nodeip, color)
}

// resteerOrphan re-points a prefix whose steering BSID just got deleted at the
// next-best surviving valid candidate (RFC 9256 §2.9) of the matching behavior
// on the same endpoint. The chosen policy may have never been installed in VPP
// (it was masked by the withdrawn candidate), so install it on demand — guarded
// by `installed` so we install at most once per delSRPolicy call. If no valid
// candidate remains: with dropRequested (I-Flag, RFC 9256 §8.2) the prefix gets
// a fail-closed drop route; otherwise it is left unsteered and AddConnectivity
// picks it up when a new candidate is later advertised. The orphan's FibTable
// is preserved so the node-IP /128 steering stays in PodVRFIndex (and pod
// prefixes in the main table) across the failover.
func (p *SRv6Provider) resteerOrphan(nodeip string, orphan *types.SrSteer, installed map[ip_types.IP6Address]struct{}, dropRequested bool) {
	prefix := orphan.Prefix
	behavior := types.SrBehaviorDT4
	if vpplink.IsIP6(prefix.Address.ToIP()) {
		behavior = types.SrBehaviorDT6
	}
	policy, err := p.getPolicyNode(nodeip, behavior)
	if err != nil || policy == nil {
		if dropRequested {
			p.engageDropRoute(nodeip, orphan)
			return
		}
		p.log.Infof("SRv6Provider DelConnectivity: no surviving policy for endpoint=%s prefix=%s behavior=%d; prefix left unsteered",
			nodeip, prefix.String(), behavior)
		return
	}
	if _, ok := installed[policy.Bsid]; !ok {
		if err := p.vpp.AddModSRv6Policy(policy); err != nil {
			p.log.Warnf("SRv6Provider DelConnectivity: AddModSRv6Policy bsid=%s for failover: %v",
				policy.Bsid.String(), err)
			return
		}
		installed[policy.Bsid] = struct{}{}
	}
	srSteer := &types.SrSteer{
		TrafficType: types.SrSteerIPv4,
		FibTable:    orphan.FibTable, // preserve the table the orphan was steered in
		Prefix:      prefix,
		Bsid:        policy.Bsid,
	}
	if vpplink.IsIP6(prefix.Address.ToIP()) {
		srSteer.TrafficType = types.SrSteerIPv6
	}
	p.clearDropRoute(srSteer.Prefix, srSteer.FibTable)
	if err := p.vpp.AddSRv6Steering(srSteer); err != nil {
		p.log.Warnf("SRv6Provider DelConnectivity: AddSRv6Steering prefix=%s bsid=%s: %v",
			prefix.String(), policy.Bsid.String(), err)
		return
	}
	p.log.Infof("SRv6Provider DelConnectivity: re-steered prefix=%s onto surviving bsid=%s behavior=%d table=%d",
		prefix.String(), policy.Bsid.String(), behavior, orphan.FibTable)
}

func (p *SRv6Provider) delPrefixSteering(cn *common.NodeConnectivity) error {
	if p.policyIPPool.Contains(cn.Dst.IP) {
		p.log.Debugf("SRv6Provider DelConnectivity skip policyIPPool prefix %s", cn.Dst.String())
		return nil
	}
	prefix, err := ip_types.ParsePrefix(cn.Dst.String())
	if err != nil {
		return errors.Wrapf(err, "SRv6Provider DelConnectivity unable to parse prefix %s", cn.Dst.String())
	}
	if p.localSidIPPool.Contains(cn.Dst.IP) {
		if delErr := p.vpp.RouteDel(&types.Route{
			Dst:   prefix.ToIPNet(),
			Paths: []types.RoutePath{{Gw: cn.NextHop.To16(), SwIfIndex: common.VppManagerInfo.GetMainSwIfIndex()}},
		}); delErr != nil {
			p.log.Warnf("SRv6Provider DelConnectivity: RouteDel localSidIPPool %s: %v", cn.Dst.String(), delErr)
		}
		return nil
	}

	nodeip := cn.NextHop.String()
	prefixKey := prefix.String()
	steering, listErr := p.vpp.ListSRv6Steering()
	if listErr != nil {
		p.log.Warnf("SRv6Provider DelConnectivity: failed to list steering: %v", listErr)
	}
	for _, st := range steering {
		if st.Prefix.String() != prefixKey {
			continue
		}
		if err := p.vpp.DelSRv6Steering(st); err != nil {
			log := p.log.Warnf
			if isAlreadyGoneOnDelete(err) {
				log = p.log.Debugf
			}
			log("SRv6Provider DelConnectivity: DelSRv6Steering prefix=%s bsid=%s: %v", st.Prefix, st.Bsid, err)
		}
	}

	if entry := p.nodePrefixes[nodeip]; entry != nil {
		remaining := entry.Prefixes[:0]
		for _, px := range entry.Prefixes {
			if px.String() != prefixKey {
				remaining = append(remaining, px)
			}
		}
		if len(remaining) == 0 {
			delete(p.nodePrefixes, nodeip)
		} else {
			entry.Prefixes = remaining
		}
	}
	return nil
}

// tunnelBsid prefers Policy.Bsid (already ip_types.IP6Address) over the net.IP
// form. Returns ok=false only for a malformed cached tunnel where neither field
// is set — caller should skip it.
func tunnelBsid(t *common.SRv6Tunnel) (ip_types.IP6Address, bool) {
	if t.Policy != nil && (t.Policy.Bsid != ip_types.IP6Address{}) {
		return t.Policy.Bsid, true
	}
	if len(t.Bsid) != 0 {
		return types.ToVppIP6Address(t.Bsid), true
	}
	return ip_types.IP6Address{}, false
}

// isSRv6TunnelInfoFromBGP checks whether given NodeConnectivity data is from BGP watcher that should pass
// SRv6 tunnel information from node where the tunnel should end
func (p *SRv6Provider) isSRv6TunnelInfoFromBGP(cn *common.NodeConnectivity) bool {
	return cn.Dst.IP == nil
}

// getPolicyNode selects the active candidate path for a node+behavior per
// RFC 9256 §2.9 and returns its installable policy. Selection runs over VALID
// candidates only: a candidate needs a usable BSID (specified, or dynamically
// bound per §6.2.1) and at least one segment list whose first SID (and any
// V-Flag SID) resolves in the FIB (§5.1). Among the valid ones the highest
// Preference wins, ties broken by lower originator then higher discriminator.
// Note the Priority field plays no role here — it only orders revalidation
// (§2.12, see revalidatePolicies).
func (p *SRv6Provider) getPolicyNode(nodeip string, behavior types.SrBehavior) (*types.SrPolicy, error) {
	p.log.Debugf("SRv6Provider getPolicyNode node: %s, with behavior: %d", nodeip, behavior)
	entry := p.nodePolices[nodeip]
	if entry == nil {
		p.log.Debugf("SRv6Provider getPolicyNode: nodePolices[%s] is nil", nodeip)
		return nil, nil
	}

	reach := map[string]bool{} // per-selection SID reachability cache
	var best *common.SRv6Tunnel
	var bestPolicy *types.SrPolicy
	for i := range entry.SRv6Tunnel {
		tunnel := &entry.SRv6Tunnel[i]
		if tunnel.Policy == nil || types.FromGoBGPSrBehavior(tunnel.Behavior) != behavior {
			continue
		}
		if !p.ensureBsid(nodeip, tunnel) {
			continue
		}
		pol := p.usablePolicy(nodeip, tunnel, reach)
		if pol == nil {
			continue
		}
		if best == nil || preferredCandidate(tunnel, best) {
			best, bestPolicy = tunnel, pol
		}
	}
	if bestPolicy == nil {
		p.log.Debugf("SRv6Provider getPolicyNode: no valid candidate for node %s behavior %d", nodeip, behavior)
	} else {
		p.log.Debugf("SRv6Provider getPolicyNode: selected bsid=%s preference=%d discriminator=%d",
			bestPolicy.Bsid.String(), best.Preference, best.Distinguisher)
	}
	return bestPolicy, nil
}

// getPolicyColor selects the active candidate inside one SR Policy
// <endpoint,color>.  Unlike getPolicyNode (the legacy node-connectivity lookup
// by terminal behavior), this preserves independent policies of the same
// behavior on one endpoint -- exactly the shape used by srv6egress colors.
func (p *SRv6Provider) getPolicyColor(nodeip string, color uint32) (*common.SRv6Tunnel, *types.SrPolicy, error) {
	p.log.Debugf("SRv6Provider getPolicyColor node=%s color=%d", nodeip, color)
	entry := p.nodePolices[nodeip]
	if entry == nil {
		return nil, nil, nil
	}

	reach := map[string]bool{}
	var best *common.SRv6Tunnel
	var bestPolicy *types.SrPolicy
	for i := range entry.SRv6Tunnel {
		tunnel := &entry.SRv6Tunnel[i]
		if tunnel.Color != color || tunnel.Policy == nil {
			continue
		}
		if !p.ensureBsid(nodeip, tunnel) {
			continue
		}
		policy := p.usablePolicy(nodeip, tunnel, reach)
		if policy == nil {
			continue
		}
		if best == nil || preferredCandidate(tunnel, best) {
			best, bestPolicy = tunnel, policy
		}
	}
	if bestPolicy == nil {
		p.log.Debugf("SRv6Provider getPolicyColor: no valid candidate for node=%s color=%d", nodeip, color)
		return nil, nil, nil
	}
	p.log.Debugf("SRv6Provider getPolicyColor: selected bsid=%s color=%d preference=%d discriminator=%d",
		bestPolicy.Bsid.String(), color, best.Preference, best.Distinguisher)
	return best, bestPolicy, nil
}

// preferredCandidate reports whether a beats b per RFC 9256 §2.9: higher
// Preference, then lower originator <ASN, node>, then higher discriminator.
// Protocol-Origin is constant here (every candidate arrives via BGP) and the
// optional "prefer the currently installed path" rule is not implemented.
func preferredCandidate(a, b *common.SRv6Tunnel) bool {
	if a.Preference != b.Preference {
		return a.Preference > b.Preference
	}
	if a.OriginatorASN != b.OriginatorASN {
		return a.OriginatorASN < b.OriginatorASN
	}
	if a.OriginatorNode != b.OriginatorNode {
		return a.OriginatorNode < b.OriginatorNode
	}
	return a.Distinguisher > b.Distinguisher
}

// ensureBsid makes sure the candidate has a usable BSID, dynamically binding
// one from the policy pool when the advertisement carried none (RFC 9256
// §6.2.1). The binding is per SR Policy <endpoint, color> and reused across
// candidate-path changes. Returns false when the candidate cannot get a BSID
// (S-Flag set, or pool exhausted) — it is then invalid (§6.2.3).
func (p *SRv6Provider) ensureBsid(nodeip string, tunnel *common.SRv6Tunnel) bool {
	if _, ok := tunnelBsid(tunnel); ok {
		return true
	}
	if tunnel.SpecifiedBSIDOnly {
		p.log.Warnf("SRv6Provider: candidate endpoint=%s color=%d has S-Flag but no BSID; invalid (RFC 9256 §6.2.3)",
			nodeip, tunnel.Color)
		return false
	}
	key := dynBsidKey(nodeip, tunnel.Color)
	bsid, ok := p.dynBsids[key]
	if !ok {
		ip, err := p.allocBsid(dynBsidHandle(nodeip, tunnel.Color))
		if err != nil {
			p.log.Warnf("SRv6Provider: dynamic BSID allocation failed for endpoint=%s color=%d: %v",
				nodeip, tunnel.Color, err)
			return false
		}
		bsid = types.ToVppIP6Address(ip)
		p.dynBsids[key] = bsid
		p.log.Infof("SRv6Provider: dynamically bound BSID %s to policy endpoint=%s color=%d (RFC 9256 §6.2.1)",
			bsid.String(), nodeip, tunnel.Color)
	}
	tunnel.Policy.Bsid = bsid
	tunnel.Bsid = bsid.ToIP()
	return true
}

// dynBsidHandle is the Calico IPAM handle attributing a dynamic BSID to its SR
// Policy; stable across agent restarts so stale allocations can be reclaimed.
func dynBsidHandle(nodeip string, color uint32) string {
	return "cvp-srv6-dyn-bsid-" + strings.ReplaceAll(nodeip, ":", "-") + "-" + fmt.Sprint(color)
}

// usablePolicy applies RFC 9256 §5.1 SID resolution to the candidate's segment
// lists: the first SID always, plus any segment whose V-Flag requested
// verification. Lists that do not resolve are dropped; returns nil when none
// survive (candidate invalid). Lookup failures fail open (assumed reachable).
func (p *SRv6Provider) usablePolicy(nodeip string, tunnel *common.SRv6Tunnel, reach map[string]bool) *types.SrPolicy {
	kept := make([]types.Srv6SidList, 0, len(tunnel.Policy.SidLists))
	for i, sl := range tunnel.Policy.SidLists {
		var mask uint32
		if i < len(tunnel.VerifyMasks) {
			mask = tunnel.VerifyMasks[i]
		}
		if p.sidListResolvable(sl, mask, reach) {
			kept = append(kept, sl)
		} else {
			p.log.Warnf("SRv6Provider: segment list %d of endpoint=%s color=%d invalid: SID unresolvable in FIB (RFC 9256 §5.1)",
				i, nodeip, tunnel.Color)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	if len(kept) == len(tunnel.Policy.SidLists) {
		return tunnel.Policy
	}
	filtered := *tunnel.Policy
	filtered.SidLists = kept
	return &filtered
}

func (p *SRv6Provider) sidListResolvable(sl types.Srv6SidList, verifyMask uint32, cache map[string]bool) bool {
	for i := 0; i < int(sl.NumSids) && i < len(sl.Sids); i++ {
		if i != 0 && (i >= 32 || verifyMask&(1<<uint(i)) == 0) {
			continue // first SID always verified; others only on V-Flag (§5.1)
		}
		if !p.sidReachable(sl.Sids[i], cache) {
			return false
		}
	}
	return true
}

func (p *SRv6Provider) sidReachable(sid ip_types.IP6Address, cache map[string]bool) bool {
	key := sid.String()
	if v, hit := cache[key]; hit {
		return v
	}
	dst := &net.IPNet{IP: sid.ToIP(), Mask: net.CIDRMask(128, 128)}
	route, err := p.vpp.RouteLookup(dst, 0)
	ok := false
	switch {
	case err != nil:
		// Fail open: a lookup failure must not invalidate every policy.
		p.log.Warnf("SRv6Provider: SID reachability lookup %s failed; assuming reachable: %v", key, err)
		ok = true
	case route == nil:
		// no covering entry
	default:
		// The IPv6 FIB always matches ::/0 (default drop); only count non-drop paths.
		for _, path := range route.Paths {
			if !path.IsDrop {
				ok = true
				break
			}
		}
	}
	cache[key] = ok
	return ok
}

func (p *SRv6Provider) setEncapSource() (err error) {
	p.log.Infof("SRv6Provider setEncapSource")
	_, nodeIP6 := p.GetNodeIPs()
	if nodeIP6 == nil {
		return fmt.Errorf("no ip6 found for node")
	}
	if err = p.vpp.SetEncapSource(*nodeIP6); err != nil {
		p.log.Errorf("SRv6Provider setEncapSource: %v", err)
		return errors.Wrapf(err, "SRv6Provider setEncapSource")
	}
	p.log.Debugf("SRv6Provider setEncapSource with IP6 %s", nodeIP6.String())
	return err
}

func (p *SRv6Provider) createLocalSidTunnels(currentLocalSids []*types.SrLocalsid) (localSids []*types.SrLocalsid, err error) {
	p.log.Infof("SRv6Provider createLocalSidTunnels")
	endDt4Exist := false
	endDt6Exist := false
	// End.DT{4,6} must decap into the pod VRF (PodVRFIndex), not the main table.
	// The decapped inner packet is looked up there, where pod routes and the
	// SRv6-native (DSR) ClusterIP delivery routes live. VPP takes the decap VRF
	// from the localsid's sw_if_index (dumped as SwIfIndex), so a correctly
	// configured End.DT has SwIfIndex == PodVRFIndex.
	podVRF := interface_types.InterfaceIndex(common.PodVRFIndex)
	for _, localSid := range currentLocalSids {
		p.log.Debugf("Found existing SRv6Localsid: %s", localSid.String())

		isDT6 := localSid.Behavior == types.SrBehaviorDT6
		isDT4 := localSid.Behavior == types.SrBehaviorDT4
		if !isDT6 && !isDT4 {
			continue
		}

		if localSid.SwIfIndex == podVRF {
			endDt6Exist = endDt6Exist || isDT6
			endDt4Exist = endDt4Exist || isDT4
			continue
		}

		// Migrate a stale localsid created by an older agent to decap into the
		// main table: delete it and re-add it at the same SID address decapping
		// into PodVRFIndex, so remote nodes keep encapsulating to the same SID.
		p.log.Infof("SRv6Provider migrating End.DT localsid %s into PodVRFIndex", localSid.Localsid.String())
		if err := p.vpp.DelSRv6Localsid(localSid); err != nil {
			p.log.Errorf("SRv6Provider migrate: delete stale localsid %s: %v", localSid.Localsid.String(), err)
			continue
		}
		migrated := &types.SrLocalsid{
			Localsid:  localSid.Localsid,
			EndPsp:    false,
			SwIfIndex: podVRF,
			Behavior:  localSid.Behavior,
		}
		if err := p.vpp.AddSRv6Localsid(migrated); err != nil {
			p.log.Errorf("SRv6Provider migrate: re-add localsid %s in PodVRFIndex: %v", localSid.Localsid.String(), err)
			continue
		}
		endDt6Exist = endDt6Exist || isDT6
		endDt4Exist = endDt4Exist || isDT4
	}
	if !endDt4Exist {
		if localSidDT4, err := p.setEndDT(4); err != nil {
			p.log.Errorf("SRv6Provider Error setEndDT4: %v", err)
		} else {
			localSids = append(localSids, localSidDT4)
		}
	}

	if !endDt6Exist {
		if localSidDT6, err := p.setEndDT(6); err != nil {
			p.log.Errorf("SRv6Provider Error setEndDT6: %v", err)
		} else {
			localSids = append(localSids, localSidDT6)
		}
	}
	return localSids, err
}

// Add a new SRLocalSid with end.DT4 or end.DT6 behavior
func (p *SRv6Provider) setEndDT(typeDT int) (newLocalSid *types.SrLocalsid, err error) {
	p.log.Infof("SRv6Provider setLocalsid setEndDT%d", typeDT)

	var behavior types.SrBehavior
	switch typeDT {
	case 4:
		behavior = types.SrBehaviorDT4
	case 6:
		behavior = types.SrBehaviorDT6
	}

	poolLocalSIDName := "sr-localsids-pool-" + *config.NodeName
	newLocalSidAddr, err := p.getSidFromPool(poolLocalSIDName)

	if err != nil {
		p.log.Infof("SRv6Provider Error adding LocalSidAddr")
		return nil, errors.Wrapf(err, "SRv6Provider  Error getSidFromPool")
	}
	p.log.Infof("SRv6Provider new LocalSid ip %s", newLocalSidAddr.String())
	newLocalSid = &types.SrLocalsid{
		Localsid: newLocalSidAddr,
		EndPsp:   false,
		// End.DT{4,6} read the decap VRF from sw_if_index (dumped as
		// XconnectIfaceOrVrfTable), not fib_table. Point it at PodVRFIndex so the
		// decapped inner packet is looked up in the pod VRF, where pod routes and
		// SRv6-native (DSR) ClusterIP delivery routes live.
		SwIfIndex: interface_types.InterfaceIndex(common.PodVRFIndex),
		Behavior:  behavior,
	}
	if err = p.vpp.AddSRv6Localsid(newLocalSid); err != nil {
		p.log.Infof("SRv6Provider Error adding LocalSid")
		return nil, errors.Wrapf(err, "SRv6Provider Error adding LocalSid")
	}

	return newLocalSid, err
}

func (p *SRv6Provider) getSidFromPool(poolName string) (newSidAddr ip_types.IP6Address, err error) {
	ippool, err := p.Clientv3().IPPools().Get(context.Background(), poolName, options.GetOptions{})
	if err != nil || ippool == nil {
		p.log.Infof("SRv6Provider Error assigning ip LocalSid")
		return newSidAddr, errors.Wrapf(err, "SRv6Provider Error getSidFromPool")
	}

	poolIPNet := []cnet.IPNet{cnet.MustParseNetwork(ippool.Spec.CIDR)}
	_, newSids, err := p.Clientv3().IPAM().AutoAssign(context.Background(), ipam.AutoAssignArgs{
		Num6:        1,
		IPv6Pools:   poolIPNet,
		IntendedUse: "Tunnel",
	})
	if err != nil || newSids == nil || len(newSids.IPs) == 0 {
		p.log.Infof("SRv6Provider Error assigning ip LocalSid")
		if err == nil {
			err = fmt.Errorf("SRv6 SID pool %s exhausted", poolName)
		}
		return newSidAddr, errors.Wrap(err, "SRv6Provider Error getSidFromPool")
	}

	newSidAddr = types.ToVppIP6Address(newSids.IPs[0].IP)

	return newSidAddr, nil
}
