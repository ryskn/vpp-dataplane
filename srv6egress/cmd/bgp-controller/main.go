// bgp-controller is the central reconciler for EgressPolicy v1alpha1.
//
// Responsibilities:
//   - Watch EgressPolicy CRDs across the cluster
//   - Resolve <color, endpoint> → upstream + segment list via operator-supplied config
//   - Allocate per-tenant egress VIPs from a Calico IPPool
//   - Distribute SR Policies over BGP (Color Extended Community / RFC 9012)
//   - Update EgressPolicy status
//
// v1alpha1 scope: stub BGP and VIP allocators are wired in by default so the
// binary runs without external dependencies; production deployments should
// flip these to the real gobgp / Calico IPAM backends (see srv6egress/internal/bgp
// and srv6egress/internal/vipalloc TODOs).
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	srv6egressv1alpha1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1alpha1"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/bgp"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/config"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/controller"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/vipalloc"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(srv6egressv1alpha1.AddToScheme(scheme))
}

func main() {
	var (
		configPath           string
		metricsAddr          string
		probeAddr            string
		enableLeaderElection bool
	)
	flag.StringVar(&configPath, "config", "/etc/srv6egress/controller-config.yaml",
		"Path to the operator-supplied controller config (color/upstream mapping).")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address for metrics endpoint.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address for liveness/readiness probes.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election (set when running multiple controller replicas).")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))
	log := ctrl.Log.WithName("bgp-controller")

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Error(err, "load controller config")
		os.Exit(1)
	}
	log.Info("config loaded", "upstreams", len(cfg.Upstreams), "colors", len(cfg.Colors))

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme: scheme,
		Metrics: metricsserver.Options{
			BindAddress: metricsAddr,
		},
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "srv6egress-bgp-controller.srv6egress.ryskn.io",
	})
	if err != nil {
		log.Error(err, "start manager")
		os.Exit(1)
	}

	// v1alpha1: stub allocator + stub BGP distributor.
	// Production: swap these for Calico-IPAM and gobgp-backed implementations.
	// The BGP stub does NOT emit real BGP UPDATEs (no Color Extended Community
	// is sent), so headends receive no SR Policy — loudly warn operators that
	// this build does not actually steer traffic.
	log.Info("WARNING: v1alpha1 build uses STUB BGP distributor and STUB VIP allocator — " +
		"no real BGP UPDATE is sent and VIPs are synthetic placeholders; " +
		"NOT for production traffic steering")
	vipAlloc := vipalloc.NewInMemory()
	bgpDist := bgp.NewLoggingStub(log.WithName("bgp"))

	if err := (&controller.EgressPolicyReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Config: cfg,
		VIPs:   vipAlloc,
		BGP:    bgpDist,
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "setup EgressPolicy reconciler")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		log.Error(err, "add healthz")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		log.Error(err, "add readyz")
		os.Exit(1)
	}

	// Re-register VIPs already recorded in EgressPolicy statuses BEFORE the
	// manager starts reconciling. Uses the direct API reader (no cache needed
	// pre-Start). This makes the restart-collision fix order-independent: every
	// existing VIP is known to the allocator before any reconcile can allocate.
	if n, err := controller.RehydrateVIPs(context.Background(), mgr.GetAPIReader(), vipAlloc); err != nil {
		log.Error(err, "rehydrate VIP allocations")
		os.Exit(1)
	} else {
		log.Info("rehydrated existing VIP allocations", "count", n)
	}

	log.Info("starting bgp-controller", "version", versionString())
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "run manager")
		os.Exit(1)
	}
}

// versionString is intentionally unfilled in v1alpha1; ldflags inject later.
var (
	buildVersion = "v1alpha1-dev"
	buildCommit  = "unknown"
)

func versionString() string {
	return fmt.Sprintf("%s (%s)", buildVersion, buildCommit)
}
