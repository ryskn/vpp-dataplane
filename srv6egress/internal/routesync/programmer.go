package routesync

import (
	"bytes"
	"fmt"
	"os/exec"
)

// VPPProgrammer applies/removes a route in VPP. Implementations back this with
// vppctl (standalone) or, in-agent, with vpplink (native VPP binary API).
type VPPProgrammer interface {
	Add(r Route) error
	Del(r Route) error
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

func (p *ExecProgrammer) Add(r Route) error { return p.run(r.AddArgs()) }
func (p *ExecProgrammer) Del(r Route) error { return p.run(r.DelArgs()) }
