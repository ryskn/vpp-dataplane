package srv6egress

import (
	"context"

	"github.com/sirupsen/logrus"
	"gopkg.in/tomb.v2"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	srv6egressv1alpha1 "github.com/projectcalico/vpp-dataplane/v3/srv6egress/apis/v1alpha1"
)

// Watcher subscribes to EgressPolicy events and dispatches them to the
// Manager. It uses controller-runtime's client.NewWithWatch underneath so we
// don't need to spin up a full controller-runtime manager inside the agent.
type Watcher struct {
	log     *logrus.Entry
	client  ctrlclient.WithWatch
	manager *Manager
}

// NewWatcher constructs a Watcher backed by the given Manager and rest.Config
// (typically obtained from rest.InClusterConfig in the agent's main).
func NewWatcher(log *logrus.Entry, cfg *rest.Config, mgr *Manager) (*Watcher, error) {
	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(srv6egressv1alpha1.AddToScheme(scheme))

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

	var list srv6egressv1alpha1.EgressPolicyList
	wi, err := w.client.Watch(ctx, &list, &ctrlclient.ListOptions{
		FieldSelector: fields.Everything(),
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
		ep, ok := ev.Object.(*srv6egressv1alpha1.EgressPolicy)
		if !ok {
			w.log.WithField("type", ev.Type).Warn("unexpected object type in watch event")
			return
		}
		w.manager.OnPolicyUpdate(ep)
	case watch.Deleted:
		ep, ok := ev.Object.(*srv6egressv1alpha1.EgressPolicy)
		if !ok {
			w.log.WithField("type", ev.Type).Warn("delete event with unexpected object type")
			return
		}
		w.manager.OnPolicyDelete(string(ep.UID))
	case watch.Bookmark, watch.Error:
		w.log.WithField("type", ev.Type).Debug("watch meta-event")
	default:
		w.log.WithField("type", ev.Type).Debug("unknown watch event")
	}
}
