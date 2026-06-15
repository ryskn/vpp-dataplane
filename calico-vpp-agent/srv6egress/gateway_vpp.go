package srv6egress

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/projectcalico/vpp-dataplane/v3/vpplink"
)

// fibIndexRe extracts the fib index from `show ip6 fib table <id> summary`,
// whose header reads e.g. "ipv6-VRF:1000, fib_index:16, ...".
var fibIndexRe = regexp.MustCompile(`fib_index:(\d+)`)

// vppGateway implements VPPGateway over vpplink. The End.DT6.In behavior and
// per-fib cnat SNAT are CLI-only in our VPP build (private patches 0006/0007),
// so they are driven via RunCli (CliInband); the rest are plain table/route
// operations also expressed as CLI for a single coherent provisioning unit.
//
// Per tenant the gateway installs, in a dedicated VRF:
//   - a loopback (carries a link-local-only interface so ip6 features attach)
//   - cnat-snat on that loopback (so the re-injected inner packet is SNAT'd)
//   - End.DT6.In <loopback> for the tenant SID (decap -> ip6-input on loopback)
//   - per-fib SNAT: pod src -> tenant VIP, fib == rfib == tenant VRF
//   - tenant VRF default -> lookup-in-table <upstream VRF> (forward + return)
//   - VIP/128 in the upstream VRF -> lookup-in-table <tenant VRF> (bounce return)
type vppGateway struct {
	vpp *vpplink.VppLink
	log *logrus.Entry
}

// NewVPPGateway builds the production VPPGateway.
func NewVPPGateway(vpp *vpplink.VppLink, log *logrus.Entry) VPPGateway {
	return &vppGateway{vpp: vpp, log: log.WithField("subcomponent", "gateway-vpp")}
}

// loopName / loopLinkLocal derive a deterministic per-VRF loopback identity.
// VPP loopbacks are named loopN by creation order, so we instead create one
// and bind it; we track it by the tenant VRF in the CLI script. For simplicity
// the loopback is addressed with a ULA derived from the VRF id.
func loopV6(vrf uint32) string {
	// fd6e::<vrf>/64 — only needs to ip6-enable the loopback. A /128 is
	// rejected by VPP as an interface address; the per-VRF host part keeps it
	// distinct (the loopbacks live in isolated VRFs anyway).
	return fmt.Sprintf("fd6e::%x/64", vrf)
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

// fibIndex resolves the VPP fib INDEX of an IPv6 VRF table id. The cnat
// snat-policy CLI keys on the fib index (NOT the table id used by `ip route
// table` / `ip6-lookup-in-table`); passing a table id that is not also a valid
// fib index makes VPP dereference an out-of-range slot and crash.
func (g *vppGateway) fibIndex(tableID uint32) (uint32, error) {
	out, err := g.vpp.RunCli(fmt.Sprintf("show ip6 fib table %d summary", tableID))
	if err != nil {
		return 0, fmt.Errorf("resolve fib index for table %d: %w", tableID, err)
	}
	m := fibIndexRe.FindStringSubmatch(out)
	if m == nil {
		return 0, fmt.Errorf("no fib_index in `show ip6 fib table %d summary`: %s", tableID, out)
	}
	idx, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		return 0, fmt.Errorf("parse fib index %q: %w", m[1], err)
	}
	return uint32(idx), nil
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

func (g *vppGateway) InstallGateway(req GatewayRequest) error {
	if req.TenantSID == nil || req.VIP == nil {
		return fmt.Errorf("gateway install: incomplete request %+v", req)
	}
	sid := req.TenantSID.String()
	vip := req.VIP.String()
	vrf := req.VrfTable

	// Deterministic per-VRF loopback (instance == VRF table id) so a retry
	// reuses the same loop<vrf> rather than leaking a new loopback (and
	// colliding on its address) on every attempt. It is the End.DT6.In RX
	// interface; ip6-input runs its features (cnat-snat) on the decapped packet.
	loName := fmt.Sprintf("loop%d", vrf)
	created := false
	if _, err := g.vpp.SearchInterfaceWithName(loName); err != nil {
		if cerr := g.cli(fmt.Sprintf("create loopback interface instance %d", vrf)); cerr != nil {
			return fmt.Errorf("create %s: %w", loName, cerr)
		}
		created = true
	}

	// Ensure the shared upstream VRF and the tenant VRF exist (add is tolerated
	// if already present), then bind the loopback into the tenant VRF.
	if err := g.cliOK(fmt.Sprintf("ip6 table add %d", req.UpstreamTable), "already"); err != nil {
		return err
	}
	if err := g.cliOK(fmt.Sprintf("ip6 table add %d", vrf), "already"); err != nil {
		return err
	}
	if err := g.cli(fmt.Sprintf("set interface ip6 table %s %d", loName, vrf)); err != nil {
		return err
	}

	// cnat snat-policy keys on the FIB INDEX of the tenant VRF, not its table id.
	fibIdx, err := g.fibIndex(vrf)
	if err != nil {
		return err
	}

	if err := g.cli(fmt.Sprintf("set interface state %s up", loName)); err != nil {
		return err
	}
	if created {
		// The address only needs setting once (it ip6-enables the loopback);
		// re-setting it on the existing loop<vrf> would fail as a conflict.
		if err := g.cli(fmt.Sprintf("set interface ip address %s %s", loName, loopV6(vrf))); err != nil {
			return err
		}
	}
	// cnat-snat feature add is idempotent in VPP.
	if err := g.cli(fmt.Sprintf("set interface feature %s cnat-snat-ip6 arc ip6-unicast", loName)); err != nil {
		return err
	}
	// sr localsid add reports "identical localsid already exists" on a retry,
	// which cli() does not treat as an error.
	if err := g.cli(fmt.Sprintf("sr localsid address %s behavior end.dt6.in %s", sid, loName)); err != nil {
		return err
	}
	// forward + return leave the tenant VRF via the shared upstream VRF (route
	// table args + lookup-in-table are all table ids).
	if err := g.cliOK(fmt.Sprintf("ip route add ::/0 table %d via ip6-lookup-in-table %d", vrf, req.UpstreamTable), "already", "exist"); err != nil {
		return err
	}
	// per-fib SNAT (fib/rfib are the resolved FIB INDEX). Idempotent: updates
	// the per-fib entry if present.
	if err := g.cli(fmt.Sprintf("set cnat snat-policy addr %s fib %d rfib %d", vip, fibIdx, fibIdx)); err != nil {
		return err
	}
	// bounce the return (dst=VIP on the shared uplink VRF) into the tenant VRF.
	if err := g.cliOK(fmt.Sprintf("ip route add %s/128 table %d via ip6-lookup-in-table %d", vip, req.UpstreamTable, vrf), "already", "exist"); err != nil {
		return err
	}
	return nil
}

func (g *vppGateway) RemoveGateway(req GatewayRequest) error {
	if req.TenantSID == nil {
		return nil
	}
	sid := req.TenantSID.String()
	vrf := req.VrfTable
	var firstErr error
	rec := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if req.VIP != nil {
		rec(g.cli(fmt.Sprintf("ip route del %s/128 table %d via ip6-lookup-in-table %d",
			req.VIP.String(), req.UpstreamTable, vrf)))
		// Deleting a per-fib snat entry: addr omitted => is_delete for that fib.
		// fib/rfib are the FIB INDEX; if the table is already gone the snat is
		// too, so skip rather than pass a stale/invalid index (which can crash).
		if fibIdx, ferr := g.fibIndex(vrf); ferr == nil {
			rec(g.cli(fmt.Sprintf("set cnat snat-policy addr fib %d rfib %d", fibIdx, fibIdx)))
		}
	}
	rec(g.cli(fmt.Sprintf("ip route del ::/0 table %d via ip6-lookup-in-table %d", vrf, req.UpstreamTable)))
	rec(g.cli(fmt.Sprintf("sr localsid del address %s", sid)))
	// Delete the deterministic loopback (after its localsid is gone). The VRF
	// table is left for a later sweep; deleting it while the SR FIB still
	// references it can crash some VPP builds.
	rec(g.cliOK(fmt.Sprintf("delete loopback interface intfc loop%d", vrf), "unknown", "not", "no such"))
	return firstErr
}
