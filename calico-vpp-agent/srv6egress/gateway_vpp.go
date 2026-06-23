package srv6egress

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
	"github.com/projectcalico/vpp-dataplane/v3/vpplink/types"
)

// tenantLocalsid builds the End.DT6 localsid for the tenant SID, decapping into
// its VRF. A uSID upstream carries the SID structure so the wrapper programs it
// as a uDT6 via the v2 API; otherwise it is a classic End.DT6.
func tenantLocalsid(req GatewayRequest) *types.SrLocalsid {
	ls := &types.SrLocalsid{
		Localsid: types.ToVppIP6Address(req.TenantSID),
		Behavior: types.SrBehaviorDT6,
		FibTable: req.VrfTable,
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

// installTenantDataPath installs the End.DT6 decap, the egress default route, and
// (if configured) the shared return aggregate.
func (g *vppGateway) installTenantDataPath(req GatewayRequest) error {
	vrf := req.VrfTable
	// End.DT6 (or uDT6 for a uSID upstream): decap straight into the tenant VRF
	// FIB. No SNAT, no loopback; the pod source address is preserved (L3VPN).
	// AddSRv6Localsid is idempotent (re-adding the same localsid is a no-op in VPP).
	if err := g.vpp.AddSRv6Localsid(tenantLocalsid(req)); err != nil {
		return fmt.Errorf("install tenant localsid %s: %w", req.TenantSID, err)
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
