// bgp-controller is the central reconciler for EgressPolicy v1.
//
// Responsibilities:
//   - Watch EgressPolicy CRDs across the cluster
//   - Resolve <color, endpoint> → upstream + segment list via operator-supplied config
//   - Distribute SR Policies over BGP (Color Extended Community / RFC 9012)
//   - Advertise the cluster pod CIDR per backbone upstream (NAT-less return)
//   - Update EgressPolicy status
//
// It is NAT-less L3VPN: no VIP is allocated; the pod source address is preserved.
// The BGP backend defaults to production gobgp over SR Policy SAFI (the headend
// installs the advertised policy and steers on its BSID). Bring-up and tests can
// fall back to the logging stub with --bgp-backend=stub.
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

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/bgp"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/config"
	"github.com/projectcalico/vpp-dataplane/v3/srv6egress/internal/controller"
)

var (
	scheme = runtime.NewScheme()
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(srv6egressv1.AddToScheme(scheme))
}

func main() {
	var (
		configPath           string
		metricsAddr          string
		probeAddr            string
		enableLeaderElection bool
		bgpBackend           string
		bgpEncoding          string
		gobgpAddr            string
	)
	flag.StringVar(&configPath, "config", "/etc/srv6egress/controller-config.yaml",
		"Path to the operator-supplied controller config (color/upstream mapping).")
	flag.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "Address for metrics endpoint.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "Address for liveness/readiness probes.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election (set when running multiple controller replicas).")
	flag.StringVar(&bgpBackend, "bgp-backend", "gobgp",
		"BGP distributor backend: 'gobgp' (real gRPC, default) or 'stub' (logging only, for bring-up/tests).")
	flag.StringVar(&bgpEncoding, "bgp-encoding", "sr-policy",
		"gobgp on-the-wire encoding: 'sr-policy' (SR Policy SAFI 73 with full segment list, default — the headend installs the policy and steers on its BSID) or 'color-route' (colored IPv6 /128 + Color Ext-Community, RFC 9012 §3.4.2; requires the SR Policy to be provisioned on the headend out-of-band).")
	flag.StringVar(&gobgpAddr, "gobgp-addr", "127.0.0.1:50051",
		"gobgp gRPC address (used when --bgp-backend=gobgp).")
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

	// Cluster SR Policy encoding (colored route or SR Policy SAFI) is selected
	// here; the controller stays encoding-agnostic and the transport below is
	// independent of it.
	var encoder bgp.Encoder
	switch bgpEncoding {
	case "sr-policy":
		encoder = bgp.NewSRPolicyEncoder(bgp.SRPolicyOptions{})
	case "color-route":
		encoder = bgp.NewColoredEncoder()
	default:
		log.Error(fmt.Errorf("unknown bgp-encoding %q", bgpEncoding), "invalid flag")
		os.Exit(1)
	}

	var bgpDist bgp.Distributor
	switch bgpBackend {
	case "gobgp":
		bgpDist, err = bgp.NewGoBGPDistributor(gobgpAddr, log.WithName("bgp"))
		if err != nil {
			log.Error(err, "init gobgp distributor")
			os.Exit(1)
		}
		log.Info("BGP backend: gobgp", "encoding", bgpEncoding, "addr", gobgpAddr)
	case "stub":
		bgpDist = bgp.NewLoggingStub(log.WithName("bgp"))
		log.Info("WARNING: BGP backend is logging stub (no real BGP UPDATE; not for production)")
	default:
		log.Error(fmt.Errorf("unknown bgp-backend %q", bgpBackend), "invalid flag")
		os.Exit(1)
	}

	// One backbone-facing distributor per stitched upstream (the per-VRF gobgp
	// on the egress GW holding the eBGP session to the PE). Empty when no
	// backbone is configured — AdvertiseClusterReturn is then a no-op.
	backboneBGP := map[string]bgp.Distributor{}
	if cfg.Backbone != nil {
		for upstream, peer := range cfg.Backbone.Peers {
			dist, err := bgp.NewGoBGPDistributor(peer.GoBGPAddr, log.WithName("backbone").WithValues("upstream", upstream))
			if err != nil {
				log.Error(err, "init backbone distributor", "upstream", upstream, "addr", peer.GoBGPAddr)
				os.Exit(1)
			}
			backboneBGP[upstream] = dist
			log.Info("backbone peer wired (RFC 9252 service routes)", "upstream", upstream, "addr", peer.GoBGPAddr)
		}
	}

	if err := (&controller.EgressPolicyReconciler{
		Client:  mgr.GetClient(),
		Scheme:  mgr.GetScheme(),
		Config:  cfg,
		BGP:     bgpDist,
		Encoder: encoder,
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

	// Advertise the cluster pod CIDR to each backbone upstream once at startup
	// (NAT-less return reachability). Idempotent; re-announced on restart.
	if err := controller.AdvertiseClusterReturn(context.Background(), cfg, backboneBGP, log); err != nil {
		log.Error(err, "advertise cluster return reachability")
		os.Exit(1)
	}

	log.Info("starting bgp-controller", "version", versionString())
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "run manager")
		os.Exit(1)
	}
}

// versionString is intentionally unfilled in v1; ldflags inject later.
var (
	buildVersion = "v1-dev"
	buildCommit  = "unknown"
)

func versionString() string {
	return fmt.Sprintf("%s (%s)", buildVersion, buildCommit)
}
