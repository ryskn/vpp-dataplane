package poolvalidator

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func scheme(t *testing.T) *runtime.Scheme {
	t.Helper()
	s := runtime.NewScheme()
	s.AddKnownTypeWithName(CalicoIPPoolGVK, &unstructured.Unstructured{})
	listGVK := CalicoIPPoolGVK
	listGVK.Kind = "IPPoolList"
	s.AddKnownTypeWithName(listGVK, &unstructured.UnstructuredList{})
	return s
}

func ippool(name string, allowedUses ...string) *unstructured.Unstructured {
	p := &unstructured.Unstructured{}
	p.SetGroupVersionKind(CalicoIPPoolGVK)
	p.SetName(name)
	if allowedUses != nil {
		_ = unstructured.SetNestedStringSlice(p.Object, allowedUses, "spec", "allowedUses")
	}
	return p
}

func newValidator(t *testing.T, objs ...*unstructured.Unstructured) Validator {
	t.Helper()
	b := fakeclient.NewClientBuilder().WithScheme(scheme(t))
	for _, o := range objs {
		b = b.WithObjects(o)
	}
	return NewCalico(b.Build())
}

func TestValidatePool_TunnelAccepted(t *testing.T) {
	v := newValidator(t, ippool("egress", "Tunnel"))
	if err := v.ValidatePool(context.Background(), "egress"); err != nil {
		t.Fatalf("Tunnel pool rejected: %v", err)
	}
}

func TestValidatePool_WorkloadRejected(t *testing.T) {
	v := newValidator(t, ippool("workload", "Workload"))
	if err := v.ValidatePool(context.Background(), "workload"); err == nil {
		t.Fatal("expected non-Tunnel pool to be rejected")
	}
}

func TestValidatePool_MissingAllowedUsesRejected(t *testing.T) {
	v := newValidator(t, ippool("nouses"))
	if err := v.ValidatePool(context.Background(), "nouses"); err == nil {
		t.Fatal("expected pool without allowedUses to be rejected")
	}
}

func TestValidatePool_EmptyNameRejected(t *testing.T) {
	v := newValidator(t)
	if err := v.ValidatePool(context.Background(), ""); err == nil {
		t.Fatal("expected empty pool name to be rejected")
	}
}

func TestValidatePool_MissingPoolRejected(t *testing.T) {
	v := newValidator(t)
	if err := v.ValidatePool(context.Background(), "nonexistent"); err == nil {
		t.Fatal("expected missing pool to be rejected")
	}
}
