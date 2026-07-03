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
	"flag"
	"fmt"
	"net"
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
		// The headend keys its SR Policy install on the BSID, so under this
		// encoding every color needs one. Fail fast at load instead of letting
		// a bsid-less color go non-Ready yet un-deletable (BuildPath would fail
		// on both Announce and Withdraw).
		for color, cc := range cfg.Colors {
			if cc.BSID == "" {
				log.Error(fmt.Errorf("color %d: bsid is required with --bgp-encoding=sr-policy", color), "invalid config")
				os.Exit(1)
			}
		}
		encoder = bgp.NewSRPolicyEncoder(bgp.SRPolicyOptions{})
	case "color-route":
		// Under the colored-route encoding the NLRI is the terminal SID /128 and
		// the color is only an attribute, so two colors ending at the same SID
		// collapse onto one BGP path: the second Announce replaces the first and
		// withdrawing either withdraws the shared route. Reject that at load.
		seenSID := map[string]uint32{}
		for color, cc := range cfg.Colors {
			if len(cc.SegmentList) == 0 {
				continue // empty segmentList is already rejected by config.Validate
			}
			last := net.ParseIP(cc.SegmentList[len(cc.SegmentList)-1])
			if last == nil {
				continue // malformed SID is already rejected by config.Validate
			}
			if other, dup := seenSID[last.String()]; dup {
				log.Error(fmt.Errorf("colors %d and %d share terminal SID %s; they collide under color-route encoding", color, other, last), "invalid config")
				os.Exit(1)
			}
			seenSID[last.String()] = color
		}
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

	// Keep the cluster pod CIDR advertised to each backbone upstream (NAT-less
	// return reachability) via a leader-elected Runnable that re-asserts it
	// periodically, instead of a one-shot at startup that a non-leader would
	// also fire and a gobgp restart would silently lose.
	if err := mgr.Add(&controller.ClusterReturnAdvertiser{Config: cfg, BackboneBGP: backboneBGP, Log: log}); err != nil {
		log.Error(err, "add cluster-return advertiser")
		os.Exit(1)
	}

	log.Info("starting bgp-controller", "version", versionString())
	startErr := mgr.Start(ctrl.SetupSignalHandler())

	// Release the gobgp gRPC connections on shutdown.
	if err := bgpDist.Close(); err != nil {
		log.Error(err, "close bgp distributor")
	}
	for upstream, dist := range backboneBGP {
		if err := dist.Close(); err != nil {
			log.Error(err, "close backbone distributor", "upstream", upstream)
		}
	}

	if startErr != nil {
		log.Error(startErr, "run manager")
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
