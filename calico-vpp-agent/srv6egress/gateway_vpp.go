package srv6egress

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/generated/bindings/interface_types"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// tenantLocalsid builds the End.DT6 localsid for the tenant SID, decapping into
// its VRF. The decap VRF table is carried in SwIfIndex (the VPP API's
// xconnect_iface_or_vrf_table field for End.DT behaviors), NOT FibTable —
// FibTable is the table the SID itself is installed in (the main table 0, so the
// arriving SR packets match it). A uSID upstream additionally carries the SID
// structure (programmed via the v2 API).
func tenantLocalsid(req GatewayRequest) *types.SrLocalsid {
	ls := &types.SrLocalsid{
		Localsid:  types.ToVppIP6Address(req.TenantSID),
		Behavior:  types.SrBehaviorDT6,
		SwIfIndex: interface_types.InterfaceIndex(req.VrfTable),
	}
	if req.USID {
		ls.LocatorBlockLen = req.LocatorBlockLen
		ls.LocatorNodeLen = req.LocatorNodeLen
		ls.FunctionLen = req.FunctionLen
	}
	return ls
}

// vppGateway implements VPPGateway over vpplink.
//
// NAT-less L3VPN model. Per tenant the gateway installs, in a dedicated VRF:
//   - End.DT6 <tenant VRF> for the tenant SID — decap straight into the VRF FIB.
//     No loopback, no SNAT: the pod source address is preserved end to end.
//   - tenant VRF default -> lookup-in-table <upstream VRF> (egress to the backbone).
//   - optional shared return aggregate in the upstream VRF: the cluster pod CIDR ->
//     lookup-in-table <cluster VRF>, so return traffic (dst = pod IP) re-enters the
//     cluster SRv6 fabric and is carried back to the pod's node. Shared across the
//     tenants on an upstream; installed idempotently and left in place on teardown.
//
// Everything is driven via RunCli (CliInband) as a single coherent provisioning unit.
type vppGateway struct {
	vpp *vpplink.VppLink
	log *logrus.Entry
}

// NewVPPGateway builds the production VPPGateway.
func NewVPPGateway(vpp *vpplink.VppLink, log *logrus.Entry) VPPGateway {
	return &vppGateway{vpp: vpp, log: log.WithField("subcomponent", "gateway-vpp")}
}

func (g *vppGateway) cli(cmd string) error {
	out, err := g.vpp.RunCli(cmd)
	if err != nil {
		return fmt.Errorf("vppctl %q: %w", cmd, err)
	}
	// vppctl reports many errors on stdout with a zero return; surface them.
	if s := strings.ToLower(out); s != "" &&
		(strings.Contains(s, "unknown input") || strings.Contains(s, "failed") ||
			strings.Contains(s, "error")) {
		return fmt.Errorf("vppctl %q: %s", cmd, out)
	}
	return nil
}

// cliOK runs cmd but treats an error whose message contains any of okSubstrings
// as success — for idempotent re-application of a command whose target already
// exists (a route/table already present on a retry).
func (g *vppGateway) cliOK(cmd string, okSubstrings ...string) error {
	err := g.cli(cmd)
	if err == nil {
		return nil
	}
	lo := strings.ToLower(err.Error())
	for _, s := range okSubstrings {
		if strings.Contains(lo, s) {
			return nil
		}
	}
	return err
}

// InstallGateway provisions the per-tenant NAT-less gateway data path: ensure the
// tenant + upstream VRFs exist, then install the End.DT6 decap into the tenant VRF,
// the egress default route to the upstream VRF, and (if configured) the shared
// return aggregate. Each step is idempotent so a retry converges.
func (g *vppGateway) InstallGateway(req GatewayRequest) error {
	if req.TenantSID == nil {
		return fmt.Errorf("gateway install: incomplete request %+v", req)
	}
	if err := g.bindVRFs(req.VrfTable, req.UpstreamTable); err != nil {
		return err
	}
	return g.installTenantDataPath(req)
}

// bindVRFs ensures the shared upstream VRF and the tenant VRF exist (add is
// tolerated if already present).
func (g *vppGateway) bindVRFs(vrf, upstreamTable uint32) error {
	if err := g.cliOK(fmt.Sprintf("ip6 table add %d", upstreamTable), "already"); err != nil {
		return err
	}
	return g.cliOK(fmt.Sprintf("ip6 table add %d", vrf), "already")
}

// findLocalsid returns the installed localsid with ls's address, or nil.
// AddSRv6Localsid is not idempotent, so callers check first; the returned
// entry's SwIfIndex carries the decap VRF the persisted localsid uses (the
// dump maps xconnect_iface_or_vrf_table into SwIfIndex).
func (g *vppGateway) findLocalsid(ls *types.SrLocalsid) *types.SrLocalsid {
	list, err := g.vpp.ListSRv6Localsid()
	if err != nil {
		return nil
	}
	for _, l := range list {
		if l.Localsid == ls.Localsid {
			return l
		}
	}
	return nil
}

// installTenantDataPath installs the End.DT6 decap, the egress default route, and
// (if configured) the shared return aggregate.
func (g *vppGateway) installTenantDataPath(req GatewayRequest) error {
	vrf := req.VrfTable
	// End.DT6 (or uDT6 for a uSID upstream): decap straight into the tenant VRF
	// FIB. No SNAT, no loopback; the pod source address is preserved (L3VPN).
	// AddSRv6Localsid is NOT idempotent, and the manager re-runs InstallGateway
	// after an agent-only restart (VPP keeps the localsid, but the in-memory
	// vrfAllocator restarts, so this tenant may now map to a different table id).
	ls := tenantLocalsid(req)
	switch existing := g.findLocalsid(ls); {
	case existing == nil:
		if err := g.vpp.AddSRv6Localsid(ls); err != nil {
			return fmt.Errorf("install tenant localsid %s: %w", req.TenantSID, err)
		}
	case uint32(existing.SwIfIndex) != vrf:
		// Persisted localsid decaps into a stale VRF (baked from a previous
		// process's allocation). Left as-is it would decap into a table with no
		// egress route (blackhole) or another tenant's VRF (cross-wire). Rewrite
		// it so decap lands in this process's VRF. Delete keys on the SID
		// address, so ls removes the persisted entry regardless of its old VRF.
		g.log.WithFields(logrus.Fields{
			"sid": req.TenantSID, "staleVRF": uint32(existing.SwIfIndex), "vrf": vrf,
		}).Info("rewriting tenant localsid decap VRF after restart")
		if err := g.vpp.DelSRv6Localsid(ls); err != nil {
			return fmt.Errorf("replace tenant localsid %s (del): %w", req.TenantSID, err)
		}
		if err := g.vpp.AddSRv6Localsid(ls); err != nil {
			return fmt.Errorf("replace tenant localsid %s (add): %w", req.TenantSID, err)
		}
	}
	// egress: the tenant VRF default leaves via the shared upstream VRF.
	if err := g.cliOK(fmt.Sprintf("ip route add ::/0 table %d via ip6-lookup-in-table %d", vrf, req.UpstreamTable), "already", "exist"); err != nil {
		return err
	}
	// return: bounce the cluster pod CIDR from the upstream VRF into the cluster
	// VRF, where the cluster SRv6 fabric carries it back to the pod's node. Shared
	// across tenants on the upstream; idempotent; left in place on teardown.
	if req.ReturnCIDR != "" {
		if err := g.cliOK(fmt.Sprintf("ip route add %s table %d via ip6-lookup-in-table %d", req.ReturnCIDR, req.UpstreamTable, req.ReturnTable), "already", "exist"); err != nil {
			return err
		}
	}
	return nil
}

func (g *vppGateway) RemoveGateway(req GatewayRequest) error {
	if req.TenantSID == nil {
		return nil
	}
	vrf := req.VrfTable
	var firstErr error
	rec := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	rec(g.cli(fmt.Sprintf("ip route del ::/0 table %d via ip6-lookup-in-table %d", vrf, req.UpstreamTable)))
	rec(g.vpp.DelSRv6Localsid(tenantLocalsid(req)))
	// The shared return aggregate and the VRF tables are left for a later sweep:
	// other tenants on the same upstream still need the aggregate, and deleting a
	// VRF while the SR FIB still references it can crash some VPP builds.
	return firstErr
}

// AddTenantReturnRoute installs the per-tenant return route "prefix ->
// lookup-in-table clusterTable" in the upstream VRF. Idempotent; the upstream
// VRF is ensured first (install ordering with InstallGateway is not guaranteed).
func (g *vppGateway) AddTenantReturnRoute(prefix string, upstreamTable, clusterTable uint32) error {
	if err := g.cliOK(fmt.Sprintf("ip6 table add %d", upstreamTable), "already"); err != nil {
		return err
	}
	return g.cliOK(fmt.Sprintf("ip route add %s table %d via ip6-lookup-in-table %d", prefix, upstreamTable, clusterTable), "already", "exist")
}

// DelTenantReturnRoute removes the per-tenant return route. Unlike the shared
// aggregate (left in place on teardown) this MUST go: a stale route keeps
// forwarding from a VRF whose BGP advertisement was already withdrawn.
func (g *vppGateway) DelTenantReturnRoute(prefix string, upstreamTable, clusterTable uint32) error {
	return g.cliOK(fmt.Sprintf("ip route del %s table %d via ip6-lookup-in-table %d", prefix, upstreamTable, clusterTable), "no such", "not found")
}
