// Copyright (C) 2026 Calico-VPP contributors.
// Licensed under the Apache License, Version 2.0.

// Regression test for getSRPolicy segment-count handling.
//
// Two historical panic paths are covered:
//
//   - 17+ segments → policySidListsids[16] out-of-range on the fixed
//     [16]ip_types.IP6Address array (VPP's sr.api defines sids[16]).
//   - 0 segments  → segments[len(segments)-1] dereferences index -1.
//
// Run modes:
//   go test -run TestSRPolicyBoundCheck ./calico-vpp-agent/routing/...
//     -> asserts fixed behavior: getSRPolicy returns an error instead of
//        panicking for malformed input.
//   EXPECT_BUG=1 go test -run TestSRPolicyBoundCheck ./...
//     -> asserts the historical buggy behavior: child crashes with
//        "index out of range".

package routing

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	bgpapi "github.com/osrg/gobgp/v3/api"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/types/known/anypb"
)

const srPolicyChildEnv = "VPPDP_SRPOLICY_CHILD"

// childCallGetSRPolicy is executed in the spawned subprocess.
// CHILD_CASE selects which malformed input to send:
//
//	"overflow" — 17 SegmentTypeB entries
//	"empty"    — 0 segments (segment list sub-TLV omitted)
func childCallGetSRPolicy() {
	srv := &Server{log: logrus.New().WithField("test", "srpolicy-child")}

	mode := os.Getenv("CHILD_CASE")
	if mode == "" {
		mode = "overflow"
	}

	// Build a minimal SR Policy NLRI.
	endpoint := []byte{
		0x20, 0x01, 0x0d, 0xb8,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
	}
	nlriAny, err := anypb.New(&bgpapi.SRPolicyNLRI{
		Length:        192,
		Distinguisher: 1,
		Color:         100,
		Endpoint:      endpoint,
	})
	if err != nil {
		os.Stderr.WriteString("anypb.New nlri: " + err.Error() + "\n")
		os.Exit(2)
	}

	// Build segments according to the test case.
	var segs []*anypb.Any
	if mode == "overflow" {
		for i := 0; i < 17; i++ {
			sid := []byte{
				0x20, 0x01, 0x0d, 0xb8,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, byte(i + 1),
			}
			a, err := anypb.New(&bgpapi.SegmentTypeB{
				Sid:   sid,
				Flags: &bgpapi.SegmentFlags{},
			})
			if err != nil {
				os.Stderr.WriteString("anypb.New seg: " + err.Error() + "\n")
				os.Exit(2)
			}
			segs = append(segs, a)
		}
	}

	segListAny, err := anypb.New(&bgpapi.TunnelEncapSubTLVSRSegmentList{
		Weight:   &bgpapi.SRWeight{Weight: 12},
		Segments: segs,
	})
	if err != nil {
		os.Stderr.WriteString("anypb.New segList: " + err.Error() + "\n")
		os.Exit(2)
	}

	bsidInner, err := anypb.New(&bgpapi.SRBindingSID{
		Sid: []byte{
			0x20, 0x01, 0x0d, 0xb8,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0xef,
		},
	})
	if err != nil {
		os.Stderr.WriteString("anypb.New bsid: " + err.Error() + "\n")
		os.Exit(2)
	}
	bsidTLVAny, err := anypb.New(&bgpapi.TunnelEncapSubTLVSRBindingSID{Bsid: bsidInner})
	if err != nil {
		os.Stderr.WriteString("anypb.New bsidTLV: " + err.Error() + "\n")
		os.Exit(2)
	}

	tunTLV := &bgpapi.TunnelEncapTLV{
		Type: 15,
		Tlvs: []*anypb.Any{bsidTLVAny, segListAny},
	}
	tunAttrAny, err := anypb.New(&bgpapi.TunnelEncapAttribute{
		Tlvs: []*bgpapi.TunnelEncapTLV{tunTLV},
	})
	if err != nil {
		os.Stderr.WriteString("anypb.New tunAttr: " + err.Error() + "\n")
		os.Exit(2)
	}

	path := &bgpapi.Path{
		Nlri:   nlriAny,
		Pattrs: []*anypb.Any{tunAttrAny},
		Family: &bgpapi.Family{
			Afi:  bgpapi.Family_AFI_IP6,
			Safi: bgpapi.Family_SAFI_SR_POLICY,
		},
	}

	_, _, _, gerr := srv.getSRPolicy(path)
	if gerr != nil {
		os.Stdout.WriteString("getSRPolicy returned error: " + gerr.Error() + "\n")
		return
	}
	os.Stdout.WriteString("getSRPolicy returned OK (no error, no panic)\n")
}

func runSRPolicyChild(t *testing.T, mode string) (output string, exitErr *exec.ExitError) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestSRPolicyBoundCheck")
	cmd.Env = append(os.Environ(),
		srPolicyChildEnv+"=1",
		"CHILD_CASE="+mode,
	)
	out, err := cmd.CombinedOutput()
	output = string(out)
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			exitErr = e
		} else {
			t.Fatalf("subprocess invocation error: %v\noutput:\n%s", err, output)
		}
	}
	return output, exitErr
}

func TestSRPolicyBoundCheck(t *testing.T) {
	if os.Getenv(srPolicyChildEnv) == "1" {
		childCallGetSRPolicy()
		return
	}

	expectBug := os.Getenv("EXPECT_BUG") == "1"

	for _, mode := range []string{"overflow", "empty"} {
		t.Run(mode, func(t *testing.T) {
			output, exitErr := runSRPolicyChild(t, mode)

			switch {
			case expectBug:
				// Historical buggy behavior: child crashes with index out of range.
				if exitErr == nil || exitErr.ExitCode() == 0 {
					t.Fatalf("BUG NOT REPRODUCED (%s): child exited cleanly; output:\n%s", mode, output)
				}
				if exitErr.ExitCode() == 2 {
					t.Fatalf("test fixture failure (exit 2); output:\n%s", output)
				}
				if !strings.Contains(output, "index out of range") {
					t.Fatalf("BUG NOT REPRODUCED with expected diagnostic (%s); output:\n%s", mode, output)
				}
				t.Logf("BUG REPRODUCED (%s): child exit %d, panic observed in getSRPolicy.\n%s",
					mode, exitErr.ExitCode(), output)

			default:
				// Fixed behavior: child returns a guarded error, never panics.
				if exitErr != nil {
					t.Fatalf("FIX REGRESSED (%s): child exited non-zero (exit %d); output:\n%s",
						mode, exitErr.ExitCode(), output)
				}
				if !strings.Contains(output, "getSRPolicy returned error") {
					t.Fatalf("FIX REGRESSED (%s): expected guarded error return; got:\n%s", mode, output)
				}
				t.Logf("FIXED behavior confirmed (%s): getSRPolicy returns error instead of panic.\n%s",
					mode, output)
			}
		})
	}
}
