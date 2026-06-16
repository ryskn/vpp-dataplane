package vipalloc

import (
	"context"
	"testing"
)

func TestAllocate_IdempotentPerPolicy(t *testing.T) {
	a := NewInMemory()
	ctx := context.Background()
	v1, err := a.Allocate(ctx, "uid-a", "pool")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := a.Allocate(ctx, "uid-a", "pool")
	if err != nil {
		t.Fatal(err)
	}
	if v1 != v2 {
		t.Fatalf("Allocate not idempotent: %q != %q", v1, v2)
	}
}

func TestAllocate_DistinctPoliciesDistinctVIPs(t *testing.T) {
	a := NewInMemory()
	ctx := context.Background()
	v1, _ := a.Allocate(ctx, "uid-a", "pool")
	v2, _ := a.Allocate(ctx, "uid-b", "pool")
	if v1 == v2 {
		t.Fatalf("two policies got the same VIP: %q", v1)
	}
}

func TestAllocate_EmptyPoolRejected(t *testing.T) {
	a := NewInMemory()
	if _, err := a.Allocate(context.Background(), "uid-a", ""); err == nil {
		t.Fatal("expected error for empty pool name")
	}
}

// After a controller restart the
// allocator is recreated blank. Register lets the reconciler re-seed existing
// VIPs from status so a fresh Allocate never collides with them.
func TestRegister_PreventsReissueAfterRestart(t *testing.T) {
	ctx := context.Background()

	// First "process lifetime": uid-a gets pool:mypool:1.
	a1 := NewInMemory()
	vipA, _ := a1.Allocate(ctx, "uid-a", "mypool")
	if vipA != "pool:mypool:1" {
		t.Fatalf("unexpected first VIP: %q", vipA)
	}

	// Restart: brand-new allocator. Reconciler re-registers uid-a's VIP from
	// its EgressPolicy status before allocating for a new policy uid-b.
	a2 := NewInMemory()
	if err := a2.Register(ctx, "uid-a", vipA); err != nil {
		t.Fatal(err)
	}
	vipB, _ := a2.Allocate(ctx, "uid-b", "mypool")
	if vipB == vipA {
		t.Fatalf("post-restart allocation collided with pre-restart VIP: %q", vipB)
	}
	if vipB != "pool:mypool:2" {
		t.Fatalf("expected counter advanced past registered VIP, got %q", vipB)
	}
}

func TestRegister_Idempotent(t *testing.T) {
	ctx := context.Background()
	a := NewInMemory()
	if err := a.Register(ctx, "uid-a", "pool:mypool:5"); err != nil {
		t.Fatal(err)
	}
	if err := a.Register(ctx, "uid-a", "pool:mypool:5"); err != nil {
		t.Fatal(err)
	}
	// Next allocation must skip past 5.
	v, _ := a.Allocate(ctx, "uid-b", "mypool")
	if v != "pool:mypool:6" {
		t.Fatalf("expected pool:mypool:6, got %q", v)
	}
}

func TestRegister_EmptyVIPRejected(t *testing.T) {
	if err := NewInMemory().Register(context.Background(), "uid-a", ""); err == nil {
		t.Fatal("expected error for empty vip")
	}
}

func TestRelease_FreesVIP(t *testing.T) {
	ctx := context.Background()
	a := NewInMemory()
	v1, _ := a.Allocate(ctx, "uid-a", "pool")
	if err := a.Release(ctx, "uid-a"); err != nil {
		t.Fatal(err)
	}
	// Re-allocate for the same policy: gets a fresh VIP (counter advanced),
	// and the old one is no longer marked taken.
	v2, _ := a.Allocate(ctx, "uid-a", "pool")
	if v1 == v2 {
		t.Fatalf("expected new VIP after release+realloc, got same %q", v1)
	}
}

func TestParseSyntheticVIP(t *testing.T) {
	cases := []struct {
		in       string
		wantPool string
		wantN    uint64
		wantOK   bool
	}{
		{"pool:mypool:7", "mypool", 7, true},
		{"pool:my:pool:3", "my:pool", 3, true}, // pool name containing colon
		{"2001:db8:e::a", "", 0, false},        // a real IPv6 VIP, not synthetic
		{"pool:mypool:notnum", "", 0, false},
		{"garbage", "", 0, false},
	}
	for _, c := range cases {
		pool, n, ok := parseSyntheticVIP(c.in)
		if ok != c.wantOK || pool != c.wantPool || n != c.wantN {
			t.Errorf("parseSyntheticVIP(%q) = (%q,%d,%v), want (%q,%d,%v)",
				c.in, pool, n, ok, c.wantPool, c.wantN, c.wantOK)
		}
	}
}
