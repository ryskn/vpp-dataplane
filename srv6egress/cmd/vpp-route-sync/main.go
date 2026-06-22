// vpp-route-sync installs upstream routes learned by the egress gateway's
// per-VRF gobgp into VPP's per-upstream VRF FIBs.
//
// It periodically reads `gobgp ... global rib -a ipv6 -j`, keeps the prefixes
// whose next-hop is a configured upstream peer, and programs them into VPP via
// the selected backend: --vpp-backend=govpp (default; native binary API, must
// run co-located with VPP) or --vpp-backend=vppctl (shell out; supports off-box
// kubectl exec).
//
// Example (production, on the egress node, native VPP binary API — default):
//
//	vpp-route-sync --config /etc/srv6egress/routesync.yaml \
//	  --gobgp-cmd "gobgp -p 50052" \
//	  --vpp-backend govpp --vpp-api-socket /run/vpp/vpp-api.sock
//
// Example (standalone, vppctl in PATH):
//
//	vpp-route-sync --config /etc/srv6egress/routesync.yaml \
//	  --gobgp-cmd "gobgp -p 50052" \
//	  --vpp-backend vppctl --vpp-exec "vppctl"
//
// Example (off-box, VPP reached via kubectl — vppctl backend only):
//
//	vpp-route-sync --config routesync.yaml \
//	  --gobgp-cmd "gobgp -p 50052" \
//	  --vpp-backend vppctl \
//	  --vpp-exec "kubectl -n calico-vpp-dataplane exec calico-vpp-node-xxxxx -c vpp -- vppctl"
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/routesync"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/routesync/vpplinkprog"
)

func main() {
	var (
		configPath string
		gobgpCmd   string
		vppBackend string
		vppExec    string
		vppSocket  string
		interval   time.Duration
	)
	flag.StringVar(&configPath, "config", "/etc/srv6egress/routesync.yaml",
		"Path to the peer->VRF mapping config.")
	flag.StringVar(&gobgpCmd, "gobgp-cmd", "gobgp -p 50052",
		"Command (with args) used to invoke the gobgp CLI.")
	flag.StringVar(&vppBackend, "vpp-backend", "govpp",
		"VPP programming backend: 'govpp' (native binary API via vpplink; must run co-located with VPP) or 'vppctl' (shell out; supports off-box kubectl exec).")
	flag.StringVar(&vppExec, "vpp-exec", "vppctl",
		"Command (with args) for the vppctl invocation; route args are appended. Used when --vpp-backend=vppctl.")
	flag.StringVar(&vppSocket, "vpp-api-socket", "/run/vpp/vpp-api.sock",
		"VPP binary API socket. Used when --vpp-backend=govpp. (calico-vpp names it vpp-api.sock.)")
	flag.DurationVar(&interval, "interval", 5*time.Second, "Reconcile interval.")
	flag.Parse()

	log := zap.New(zap.UseDevMode(true)).WithName("vpp-route-sync")

	cfg, err := routesync.LoadConfig(configPath)
	if err != nil {
		log.Error(err, "load config")
		os.Exit(1)
	}
	log.Info("config loaded", "upstreams", len(cfg.Upstreams), "interval", interval.String())

	// SRv6 service routes (RFC 9252) need a BSID block; the block is handed to
	// the backend at construction so the capability is set up once, up front.
	block, _ := cfg.ServiceBSIDNet() // already validated in LoadConfig
	vpp, err := newProgrammer(vppBackend, vppExec, vppSocket, block)
	if err != nil {
		log.Error(err, "init VPP backend", "backend", vppBackend)
		os.Exit(1)
	}
	log.Info("VPP backend selected", "backend", vppBackend)

	if block != nil {
		if vpp.ServiceProgrammer() != nil {
			log.Info("SRv6 service routes enabled", "serviceBsidBlock", block.String())
		} else {
			log.Info("serviceBsidBlock configured but the VPP backend cannot program service routes (use --vpp-backend=govpp); they will be reported as unsupported")
		}
	}

	s := &routesync.Syncer{
		Cfg:      cfg,
		Fetch:    routesync.ExecRIBFetcher(strings.Fields(gobgpCmd)),
		VPP:      vpp,
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

// newProgrammer selects the VPP programming backend. govpp is the production
// path (native binary API) and the only one that can program SRv6 service
// routes (when block is non-nil); vppctl is kept for standalone / off-box
// bring-up and ignores block (it reports service routes as unsupported).
func newProgrammer(backend, vppExec, vppSocket string, block *net.IPNet) (routesync.VPPProgrammer, error) {
	switch backend {
	case "govpp":
		return vpplinkprog.New(vppSocket, logrus.WithField("component", "vpp-route-sync"), block)
	case "vppctl":
		return routesync.NewExecProgrammer(strings.Fields(vppExec)), nil
	default:
		return nil, fmt.Errorf("unknown vpp-backend %q (want 'govpp' or 'vppctl')", backend)
	}
}
