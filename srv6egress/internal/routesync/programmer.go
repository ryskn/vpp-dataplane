package routesync

import (
	"bytes"
	"fmt"
	"os/exec"
)

// VPPProgrammer applies/removes a plain FIB route in VPP and reads back the
// routes it owns in a VRF. Implementations back this with vppctl (ExecProgrammer:
// standalone / off-box via kubectl exec) or govpp/vpplink (the native VPP
// binary API, in-pod; see internal/routesync/vpplinkprog).
//
// A backend that can also program SRv6 service routes (RFC 9252) exposes that
// capability through ServiceProgrammer; one that cannot returns nil there. This
// keeps service support a first-class, explicitly-declared capability rather
// than something the syncer discovers by reflection.
type VPPProgrammer interface {
	Add(r Route) error
	Del(r Route) error
	// InstalledRoutes returns the routes in the given VRF table whose next-hop
	// is one of peers — i.e. the routes this component owns. The syncer uses it
	// to recover its installed set from VPP itself (source of truth), so state
	// is not lost across a restart. Returning an error must NOT be treated as
	// "table is empty" (that would delete still-wanted routes).
	InstalledRoutes(table uint32, peers map[string]Upstream) ([]Route, error)
	// ServiceProgrammer returns this backend's SRv6 service-route programmer, or
	// nil if the backend cannot program service routes. When nil, the syncer
	// reports any received service routes as unsupported (it never downgrades
	// them to plain FIB entries).
	ServiceProgrammer() ServiceVPPProgrammer
}

// ServiceVPPProgrammer programs SRv6 service routes (RFC 9252): a service route
// is not a plain FIB entry but an SR policy (segment list = [service SID]) plus
// an SR steer of the prefix in the VRF. A VPPProgrammer that supports them
// returns a non-nil ServiceProgrammer; only the vpplink (govpp) backend does.
type ServiceVPPProgrammer interface {
	AddService(r Route) error
	DelService(r Route) error
	// InstalledServiceRoutes returns the service routes installed in the given
	// VRF table whose BSID lies in the configured service BSID block — i.e. the
	// ones this component owns. Like InstalledRoutes, an error must NOT be
	// treated as "empty".
	InstalledServiceRoutes(table uint32) ([]Route, error)
}

// ExecProgrammer programs VPP by running a configurable command (the "vpp exec"
// prefix) with the vppctl argument vector appended. Examples for the prefix:
//
//	["vppctl"]                                              // in the vpp container
//	["kubectl","-n","calico-vpp-dataplane","exec",
//	 "calico-vpp-node-xxxxx","-c","vpp","--","vppctl"]      // off-box via kubectl
type ExecProgrammer struct {
	// Prefix is the command + leading args; the route's vppctl args are appended.
	Prefix []string
	// Run executes a command and returns combined output; swappable in tests.
	Run func(name string, args ...string) ([]byte, error)
}

// NewExecProgrammer builds an ExecProgrammer with the real exec runner.
func NewExecProgrammer(prefix []string) *ExecProgrammer {
	return &ExecProgrammer{
		Prefix: prefix,
		Run: func(name string, args ...string) ([]byte, error) {
			cmd := exec.Command(name, args...)
			var buf bytes.Buffer
			cmd.Stdout = &buf
			cmd.Stderr = &buf
			err := cmd.Run()
			return buf.Bytes(), err
		},
	}
}

func (p *ExecProgrammer) run(vppArgs []string) error {
	if len(p.Prefix) == 0 {
		return fmt.Errorf("vpp exec prefix is empty")
	}
	full := append(append([]string{}, p.Prefix[1:]...), vppArgs...)
	out, err := p.Run(p.Prefix[0], full...)
	if err != nil {
		return fmt.Errorf("vpp exec failed: %w: %s", err, bytes.TrimSpace(out))
	}
	// vppctl prints CLI errors to stdout with a 0 exit code; surface them.
	if b := bytes.TrimSpace(out); len(b) > 0 &&
		(bytes.Contains(b, []byte("unknown input")) || bytes.Contains(b, []byte("failed"))) {
		return fmt.Errorf("vppctl error: %s", b)
	}
	return nil
}

// routeArgs builds the vppctl `ip route add|del ...` argument vector for r.
// This is vppctl-specific serialization, so it lives with the vppctl-backed
// programmer rather than on the backend-agnostic Route value (a vpplink-backed
// programmer would not use string args at all).
func routeArgs(r Route, op string) []string {
	return []string{"ip", "route", op, r.Prefix,
		"table", fmt.Sprintf("%d", r.Table), "via", r.Via, r.Interface}
}

func (p *ExecProgrammer) Add(r Route) error { return p.run(routeArgs(r, "add")) }
func (p *ExecProgrammer) Del(r Route) error { return p.run(routeArgs(r, "del")) }

// ServiceProgrammer reports that the vppctl backend cannot program SRv6 service
// routes (no typed SR policy / steering API over the CLI seam).
func (p *ExecProgrammer) ServiceProgrammer() ServiceVPPProgrammer { return nil }

// InstalledRoutes runs `show ip6 fib table <table>` and parses the routes this
// component owns. The text-parsing is an ExecProgrammer-internal detail; the
// VPPProgrammer interface deals in typed Routes.
func (p *ExecProgrammer) InstalledRoutes(table uint32, peers map[string]Upstream) ([]Route, error) {
	raw, err := p.showFIB(table)
	if err != nil {
		return nil, err
	}
	return ParseOwnedRoutes(raw, table, peers), nil
}

func (p *ExecProgrammer) showFIB(table uint32) ([]byte, error) {
	if len(p.Prefix) == 0 {
		return nil, fmt.Errorf("vpp exec prefix is empty")
	}
	args := append(append([]string{}, p.Prefix[1:]...),
		"show", "ip6", "fib", "table", fmt.Sprintf("%d", table))
	out, err := p.Run(p.Prefix[0], args...)
	if err != nil {
		return nil, fmt.Errorf("vpp show ip6 fib table %d: %w: %s", table, err, bytes.TrimSpace(out))
	}
	return out, nil
}
