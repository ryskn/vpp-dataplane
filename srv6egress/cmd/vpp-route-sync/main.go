// vpp-route-sync installs upstream routes learned by the egress gateway's
// per-VRF gobgp into VPP's per-upstream VRF FIBs.
//
// It periodically reads `gobgp ... global rib -a ipv6 -j`, keeps the prefixes
// whose next-hop is a configured upstream peer, and programs
// `ip route add/del <prefix> table <vrf> via <peer> <iface>` into VPP via a
// configurable exec command.
//
// Example (run on the egress node, vppctl in PATH):
//
//	vpp-route-sync --config /etc/srv6egress/routesync.yaml \
//	  --gobgp-cmd "gobgp -p 50052" --vpp-exec "vppctl"
//
// Example (run off-box, VPP reached via kubectl):
//
//	vpp-route-sync --config routesync.yaml \
//	  --gobgp-cmd "gobgp -p 50052" \
//	  --vpp-exec "kubectl -n calico-vpp-dataplane exec calico-vpp-node-xxxxx -c vpp -- vppctl"
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/routesync"
)

func main() {
	var (
		configPath string
		gobgpCmd   string
		vppExec    string
		interval   time.Duration
	)
	flag.StringVar(&configPath, "config", "/etc/srv6egress/routesync.yaml",
		"Path to the peer->VRF mapping config.")
	flag.StringVar(&gobgpCmd, "gobgp-cmd", "gobgp -p 50052",
		"Command (with args) used to invoke the gobgp CLI.")
	flag.StringVar(&vppExec, "vpp-exec", "vppctl",
		"Command (with args) used to run a vppctl invocation; route args are appended.")
	flag.DurationVar(&interval, "interval", 5*time.Second, "Reconcile interval.")
	flag.Parse()

	log := zap.New(zap.UseDevMode(true)).WithName("vpp-route-sync")

	cfg, err := routesync.LoadConfig(configPath)
	if err != nil {
		log.Error(err, "load config")
		os.Exit(1)
	}
	log.Info("config loaded", "upstreams", len(cfg.Upstreams), "interval", interval.String())

	s := &routesync.Syncer{
		Cfg:      cfg,
		Fetch:    routesync.ExecRIBFetcher(strings.Fields(gobgpCmd)),
		VPP:      routesync.NewExecProgrammer(strings.Fields(vppExec)),
		Log:      log,
		Interval: interval,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	log.Info("starting vpp-route-sync")
	if err := s.Run(ctx); err != nil && err != context.Canceled {
		log.Error(err, "run")
		os.Exit(1)
	}
}
