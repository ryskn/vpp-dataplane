package routesync

import (
	"context"
	"reflect"
	"testing"

	"github.com/go-logr/logr"
)

func testCfg() *Config {
	return &Config{Upstreams: []Upstream{
		{Peer: "fda1::1", Table: 100, Interface: "virtio-0/0/12/0"},
		{Peer: "fda2::1", Table: 200, Interface: "virtio-0/0/12/0"},
	}}
}

// Real gobgp `global rib -a ipv6 -j` output (captured from the egress GW).
const sampleRIB = `{
"2001:db8:a::/64":[{"nlri":{"prefix":"2001:db8:a::/64"},"best":true,
  "neighbor-ip":"fda1::1",
  "attrs":[{"type":1,"value":0},{"type":2},
           {"type":14,"nexthop":"fda1::1","afi":2,"safi":1}]}],
"2001:db8:b::/64":[{"nlri":{"prefix":"2001:db8:b::/64"},"best":true,
  "neighbor-ip":"fda2::1",
  "attrs":[{"type":1,"value":0},{"type":2},
           {"type":14,"nexthop":"fda2::1","afi":2,"safi":1}]}]
}`

func TestParseRIB(t *testing.T) {
	got, err := ParseRIB([]byte(sampleRIB))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"2001:db8:a::/64": "fda1::1",
		"2001:db8:b::/64": "fda2::1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseRIB = %v, want %v", got, want)
	}
}

func TestParseRIB_Empty(t *testing.T) {
	for _, in := range []string{"", "null", "{}"} {
		m, err := ParseRIB([]byte(in))
		if err != nil {
			t.Fatalf("ParseRIB(%q) err: %v", in, err)
		}
		if len(m) != 0 {
			t.Fatalf("ParseRIB(%q) = %v, want empty", in, m)
		}
	}
}

func TestParseRIB_FallbackToNeighborIP(t *testing.T) {
	// No type-14 nexthop present → fall back to neighbor-ip.
	j := `{"2001:db8:c::/64":[{"nlri":{"prefix":"2001:db8:c::/64"},"best":true,"neighbor-ip":"fda1::1","attrs":[{"type":1,"value":0}]}]}`
	m, err := ParseRIB([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	if m["2001:db8:c::/64"] != "fda1::1" {
		t.Fatalf("fallback nexthop = %q, want fda1::1", m["2001:db8:c::/64"])
	}
}

func TestDesiredRoutes(t *testing.T) {
	rib := map[string]string{
		"2001:db8:a::/64": "fda1::1", // → table 100
		"2001:db8:b::/64": "fda2::1", // → table 200
		"2001:db8:z::/64": "fdff::9", // next-hop not an upstream → dropped
	}
	got := DesiredRoutes(rib, testCfg())
	want := []Route{
		{Prefix: "2001:db8:a::/64", Table: 100, Via: "fda1::1", Interface: "virtio-0/0/12/0"},
		{Prefix: "2001:db8:b::/64", Table: 200, Via: "fda2::1", Interface: "virtio-0/0/12/0"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("DesiredRoutes = %v, want %v", got, want)
	}
}

func TestRouteArgs(t *testing.T) {
	r := Route{Prefix: "2001:db8:a::/64", Table: 100, Via: "fda1::1", Interface: "virtio-0/0/12/0"}
	wantAdd := []string{"ip", "route", "add", "2001:db8:a::/64", "table", "100", "via", "fda1::1", "virtio-0/0/12/0"}
	if !reflect.DeepEqual(r.AddArgs(), wantAdd) {
		t.Fatalf("AddArgs = %v, want %v", r.AddArgs(), wantAdd)
	}
	if r.DelArgs()[2] != "del" {
		t.Fatalf("DelArgs op = %q, want del", r.DelArgs()[2])
	}
}

func TestReconcile(t *testing.T) {
	a := Route{Prefix: "2001:db8:a::/64", Table: 100, Via: "fda1::1", Interface: "e"}
	b := Route{Prefix: "2001:db8:b::/64", Table: 200, Via: "fda2::1", Interface: "e"}
	c := Route{Prefix: "2001:db8:c::/64", Table: 100, Via: "fda1::1", Interface: "e"}

	// installed {a,b}; desired {a,c} → add c, del b.
	add, del := Reconcile([]Route{a, c}, []Route{a, b})
	if len(add) != 1 || add[0].Key() != c.Key() {
		t.Fatalf("add = %v, want [c]", add)
	}
	if len(del) != 1 || del[0].Key() != b.Key() {
		t.Fatalf("del = %v, want [b]", del)
	}

	// steady state → no changes.
	add, del = Reconcile([]Route{a, b}, []Route{a, b})
	if len(add) != 0 || len(del) != 0 {
		t.Fatalf("steady-state add=%v del=%v, want none", add, del)
	}
}

// fakeProgrammer records calls for the syncer test.
type fakeProgrammer struct{ added, deleted []Route }

func (f *fakeProgrammer) Add(r Route) error { f.added = append(f.added, r); return nil }
func (f *fakeProgrammer) Del(r Route) error { f.deleted = append(f.deleted, r); return nil }

func TestSyncer_ReconcileConverges(t *testing.T) {
	fp := &fakeProgrammer{}
	rib := sampleRIB
	s := &Syncer{
		Cfg:       testCfg(),
		VPP:       fp,
		Log:       logr.Discard(),
		installed: map[string]Route{},
		Fetch:     func(_ context.Context) ([]byte, error) { return []byte(rib), nil },
	}

	// First pass: both prefixes installed.
	s.reconcileOnce(context.Background())
	if len(fp.added) != 2 || len(fp.deleted) != 0 {
		t.Fatalf("pass1 added=%d deleted=%d, want 2/0", len(fp.added), len(fp.deleted))
	}
	if len(s.installed) != 2 {
		t.Fatalf("installed=%d, want 2", len(s.installed))
	}

	// Second pass, same RIB: idempotent, no further programming.
	s.reconcileOnce(context.Background())
	if len(fp.added) != 2 || len(fp.deleted) != 0 {
		t.Fatalf("pass2 (idempotent) added=%d deleted=%d, want 2/0", len(fp.added), len(fp.deleted))
	}

	// Withdraw 2001:db8:a::/64 → it must be removed from VPP.
	rib = `{"2001:db8:b::/64":[{"nlri":{"prefix":"2001:db8:b::/64"},"best":true,"neighbor-ip":"fda2::1","attrs":[{"type":14,"nexthop":"fda2::1"}]}]}`
	s.reconcileOnce(context.Background())
	if len(fp.deleted) != 1 || fp.deleted[0].Prefix != "2001:db8:a::/64" {
		t.Fatalf("after withdraw deleted=%v, want [2001:db8:a::/64]", fp.deleted)
	}
	if len(s.installed) != 1 {
		t.Fatalf("installed=%d after withdraw, want 1", len(s.installed))
	}
}
