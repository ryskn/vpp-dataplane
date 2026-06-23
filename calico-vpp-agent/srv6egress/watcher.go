package srv6egress

import (
	"context"

	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	srv6egressv1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1"
)

// Watcher subscribes to EgressPolicy events and dispatches them to the
// Manager. It uses controller-runtime's client.NewWithWatch underneath so we
// don't need to spin up a full controller-runtime manager inside the agent.
type Watcher struct {
	log     *logrus.Entry
	client  ctrlclient.WithWatch
	manager *Manager
	// gateway is the optional endpoint-side provisioner. It is fed the same
	// cluster-wide events and acts only on policies whose endpoint is this node.
	gateway *GatewayManager
}

// SetGatewayManager wires an endpoint-side GatewayManager to receive the same
// EgressPolicy events as the headend Manager. Optional; nil = headend only.
func (w *Watcher) SetGatewayManager(g *GatewayManager) { w.gateway = g }

// NewWatcher constructs a Watcher backed by the given Manager and rest.Config
// (typically obtained from rest.InClusterConfig in the agent's main).
func NewWatcher(log *logrus.Entry, cfg *rest.Config, mgr *Manager) (*Watcher, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(srv6egressv1.AddToScheme(scheme))

	c, err := ctrlclient.NewWithWatch(cfg, ctrlclient.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}
	return &Watcher{
		log:     log.WithField("component", "srv6egress-watcher"),
		client:  c,
		manager: mgr,
	}, nil
}

// Watch runs the watch loop until the tomb is killed.
func (w *Watcher) Watch(t *tomb.Tomb) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-t.Dying()
		cancel()
	}()

	// List-then-watch: feed the current state, prune policies deleted while no
	// watch was running (their Deleted events are gone for good), then watch
	// from the list's resourceVersion so nothing in between is missed.
	var list srv6egressv1.EgressPolicyList
	if err := w.client.List(ctx, &list); err != nil {
		return err
	}
	live := make(map[string]struct{}, len(list.Items))
	for i := range list.Items {
		ep := &list.Items[i]
		live[string(ep.UID)] = struct{}{}
		w.manager.OnPolicyUpdate(ep)
		if w.gateway != nil {
			w.gateway.OnPolicyUpdate(ep)
		}
	}
	w.manager.PruneExcept(live)
	if w.gateway != nil {
		w.gateway.PruneExcept(live)
	}

	wi, err := w.client.Watch(ctx, &list, &ctrlclient.ListOptions{
		FieldSelector: fields.Everything(),
		Raw:           &metav1.ListOptions{ResourceVersion: list.ResourceVersion},
	})
	if err != nil {
		return err
	}
	defer wi.Stop()

	w.log.Info("EgressPolicy watcher started")
	for {
		select {
		case <-t.Dying():
			return nil
		case ev, ok := <-wi.ResultChan():
			if !ok {
				w.log.Warn("watch channel closed; exiting")
				return nil
			}
			w.handleEvent(ev)
		}
	}
}

func (w *Watcher) handleEvent(ev watch.Event) {
	switch ev.Type {
	case watch.Added, watch.Modified:
		ep, ok := ev.Object.(*srv6egressv1.EgressPolicy)
		if !ok {
			w.log.WithField("type", ev.Type).Warn("unexpected object type in watch event")
			return
		}
		w.manager.OnPolicyUpdate(ep)
		if w.gateway != nil {
			w.gateway.OnPolicyUpdate(ep)
		}
	case watch.Deleted:
		ep, ok := ev.Object.(*srv6egressv1.EgressPolicy)
		if !ok {
			w.log.WithField("type", ev.Type).Warn("delete event with unexpected object type")
			return
		}
		w.manager.OnPolicyDelete(string(ep.UID))
		if w.gateway != nil {
			w.gateway.OnPolicyDelete(string(ep.UID))
		}
	case watch.Bookmark, watch.Error:
		w.log.WithField("type", ev.Type).Debug("watch meta-event")
	default:
		w.log.WithField("type", ev.Type).Debug("unknown watch event")
	}
}
