package srv6egress

import (
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	listerscorev1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
)

const resolverResync = 5 * time.Minute

// PodResolverImpl backs PodResolver with shared informers: a node-scoped pod
// informer (field selector spec.nodeName=<this node>, so the cache only holds
// local pods) and a cluster-wide namespace informer (namespaces are few). Pod
// and namespace events fire OnChange so the Manager re-reconciles when
// membership changes.
type PodResolverImpl struct {
	log       *logrus.Entry
	nodeName  string
	podLister listerscorev1.PodLister
	nsLister  listerscorev1.NamespaceLister
	podFac    informers.SharedInformerFactory
	nsFac     informers.SharedInformerFactory

	// OnChange is invoked on any pod/namespace event so the owner can
	// re-reconcile. Set by the caller before Start; nil = no callback.
	OnChange func()
}

// NewPodResolver builds the informers from cfg. nodeName scopes the pod
// informer to this node. Call Start before MatchingLocalPodIPs.
func NewPodResolver(log *logrus.Entry, cfg *rest.Config, nodeName string) (*PodResolverImpl, error) {
	if nodeName == "" {
		return nil, fmt.Errorf("nodeName is required to scope the pod informer")
	}
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build kubernetes clientset: %w", err)
	}

	podFac := informers.NewSharedInformerFactoryWithOptions(cs, resolverResync,
		informers.WithTweakListOptions(func(o *metav1.ListOptions) {
			o.FieldSelector = "spec.nodeName=" + nodeName
		}))
	nsFac := informers.NewSharedInformerFactory(cs, resolverResync)

	r := &PodResolverImpl{
		log:       log.WithField("component", "srv6egress-resolver"),
		nodeName:  nodeName,
		podLister: podFac.Core().V1().Pods().Lister(),
		nsLister:  nsFac.Core().V1().Namespaces().Lister(),
		podFac:    podFac,
		nsFac:     nsFac,
	}

	h := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(interface{}) { r.fire() },
		UpdateFunc: func(_, _ interface{}) { r.fire() },
		DeleteFunc: func(interface{}) { r.fire() },
	}
	if _, err := podFac.Core().V1().Pods().Informer().AddEventHandler(h); err != nil {
		return nil, fmt.Errorf("add pod event handler: %w", err)
	}
	if _, err := nsFac.Core().V1().Namespaces().Informer().AddEventHandler(h); err != nil {
		return nil, fmt.Errorf("add namespace event handler: %w", err)
	}
	return r, nil
}

func (r *PodResolverImpl) fire() {
	if r.OnChange != nil {
		r.OnChange()
	}
}

// Start launches the informers and blocks until their caches sync (or stopCh
// closes). After it returns nil the listers are usable.
func (r *PodResolverImpl) Start(stopCh <-chan struct{}) error {
	r.podFac.Start(stopCh)
	r.nsFac.Start(stopCh)
	for typ, ok := range r.podFac.WaitForCacheSync(stopCh) {
		if !ok {
			return fmt.Errorf("pod informer cache did not sync: %v", typ)
		}
	}
	for typ, ok := range r.nsFac.WaitForCacheSync(stopCh) {
		if !ok {
			return fmt.Errorf("namespace informer cache did not sync: %v", typ)
		}
	}
	r.log.WithField("node", r.nodeName).Info("pod/namespace informers synced")
	return nil
}

// MatchingLocalPodIPs returns the IPv6 addresses of local pods matching the
// selector: namespaces matched by NamespaceSelector ∩ pods matched by
// PodSelector (the pod cache is already node-scoped). A nil selector field
// matches everything in its scope.
func (r *PodResolverImpl) MatchingLocalPodIPs(sel srv6egressv1.Selector) ([]net.IP, error) {
	nsSelector, err := asSelector(sel.NamespaceSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid namespaceSelector: %w", err)
	}
	podSelector, err := asSelector(sel.PodSelector)
	if err != nil {
		return nil, fmt.Errorf("invalid podSelector: %w", err)
	}

	nses, err := r.nsLister.List(nsSelector)
	if err != nil {
		return nil, fmt.Errorf("list namespaces: %w", err)
	}
	nsMatch := make(map[string]bool, len(nses))
	for _, ns := range nses {
		nsMatch[ns.Name] = true
	}

	pods, err := r.podLister.List(podSelector)
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	var ips []net.IP
	for _, p := range pods {
		if !nsMatch[p.Namespace] {
			continue
		}
		for _, podIP := range p.Status.PodIPs {
			ip := net.ParseIP(podIP.IP)
			if ip == nil || ip.To4() != nil {
				continue // IPv6 only for v1
			}
			ips = append(ips, ip)
		}
	}
	return ips, nil
}

// asSelector converts a *metav1.LabelSelector to labels.Selector, treating nil
// as "match everything".
func asSelector(ls *metav1.LabelSelector) (labels.Selector, error) {
	if ls == nil {
		return labels.Everything(), nil
	}
	return metav1.LabelSelectorAsSelector(ls)
}
