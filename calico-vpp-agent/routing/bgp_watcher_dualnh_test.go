// Copyright (C) 2026 Calico-VPP contributors.
// Licensed under the Apache License, Version 2.0.

// Repro for Finding #1: getNexthop calls logrus.Fatalf (which calls os.Exit(1))
// when an MP_REACH_NLRI carries 2 nexthops, even though RFC 2545 §3 mandates
// that IPv6 BGP advertisements may legitimately carry a global + link-local
// nexthop pair (length 32 octets on the wire, 2 entries in gobgp's gRPC API
// per pkg/apiutil/attribute.go:NewMpReachNLRIAttributeFromNative).
//
// Run modes:
//   go test -run TestDualNexthopReproduction ./calico-vpp-agent/routing/...
//     → asserts current (buggy) behavior: child exits non-zero and logs
//       "Cannot process more than one Nlri".
//   WANT_FIXED=1 go test -run TestDualNexthopReproduction ./calico-vpp-agent/routing/...
//     → asserts fixed behavior: child returns the global nexthop without
//       crashing.

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

const dualNHChildEnv = "VPPDP_DUALNH_CHILD"

// childCallGetNexthop runs inside the spawned subprocess.
// It builds an MP_REACH_NLRI with two nexthops (RFC 2545 §3, IPv6 standard
// global + link-local pair) and calls Server.getNexthop.
// Buggy path: logrus.Fatalf -> os.Exit(1).
// Fixed path: returns "2001:db8::1".
func childCallGetNexthop() {
	srv := &Server{log: logrus.New().WithField("test", "dualnh-child")}

	mp := &bgpapi.MpReachNLRIAttribute{
		Family:   &bgpapi.Family{Afi: bgpapi.Family_AFI_IP6, Safi: bgpapi.Family_SAFI_UNICAST},
		NextHops: []string{"2001:db8::1", "fe80::1"}, // RFC 2545 §3 dual nexthop
	}
	attr, err := anypb.New(mp)
	if err != nil {
		// Internal failure constructing the test fixture is not the bug.
		// Use exit code 2 so the parent can distinguish.
		os.Stderr.WriteString("anypb.New: " + err.Error() + "\n")
		os.Exit(2)
	}
	path := &bgpapi.Path{Pattrs: []*anypb.Any{attr}}

	got := srv.getNexthop(path)
	// Reachable only on the fixed code path.
	os.Stdout.WriteString("getNexthop returned: " + got + "\n")
}

func TestDualNexthopReproduction(t *testing.T) {
	if os.Getenv(dualNHChildEnv) == "1" {
		childCallGetNexthop()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestDualNexthopReproduction")
	cmd.Env = append(os.Environ(), dualNHChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	exitErr, isExitErr := err.(*exec.ExitError)
	output := string(out)

	wantFixed := os.Getenv("WANT_FIXED") == "1"

	switch {
	case wantFixed:
		// After fix: child must exit cleanly and emit the global address.
		if err != nil {
			t.Fatalf("FIX REGRESSED: child exited non-zero (%v); output:\n%s", err, output)
		}
		if !strings.Contains(output, "2001:db8::1") {
			t.Fatalf("FIX REGRESSED: expected '2001:db8::1' in output; got:\n%s", output)
		}
		t.Logf("FIXED behavior confirmed: getNexthop returned global address without crashing.\n%s", output)

	default:
		// Current (buggy) behavior: child must crash with the diagnostic.
		if !isExitErr || exitErr.ExitCode() == 0 {
			t.Fatalf("BUG NOT REPRODUCED: child exited cleanly (err=%v); output:\n%s", err, output)
		}
		if exitErr.ExitCode() == 2 {
			t.Fatalf("test fixture failure (exit 2); output:\n%s", output)
		}
		if !strings.Contains(output, "Cannot process more than one Nlri") {
			t.Fatalf("BUG NOT REPRODUCED with expected diagnostic; output:\n%s", output)
		}
		t.Logf("BUG REPRODUCED: child exit %d, diagnostic present. RFC 2545 §3 dual-NH IPv6 BGP UPDATE crashes calico-vpp-agent.\n%s",
			exitErr.ExitCode(), output)
	}
}
