package routesync

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	gobgpb "github.com/osrg/gobgp/v3/pkg/packet/bgp"
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
	want := map[string]RIBEntry{
		"2001:db8:a::/64": {Nexthop: "fda1::1"},
		"2001:db8:b::/64": {Nexthop: "fda2::1"},
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
	if m["2001:db8:c::/64"].Nexthop != "fda1::1" {
		t.Fatalf("fallback nexthop = %q, want fda1::1", m["2001:db8:c::/64"].Nexthop)
	}
}

func TestDesiredRoutes(t *testing.T) {
	rib := map[string]RIBEntry{
		"2001:db8:a::/64": {Nexthop: "fda1::1"}, // → table 100
		"2001:db8:b::/64": {Nexthop: "fda2::1"}, // → table 200
		"2001:db8:z::/64": {Nexthop: "fdff::9"}, // next-hop not an upstream → dropped
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

func TestExecProgrammerArgs(t *testing.T) {
	var gotName string
	var gotArgs []string
	p := &ExecProgrammer{
		Prefix: []string{"vppctl"},
		Run: func(name string, args ...string) ([]byte, error) {
			gotName, gotArgs = name, args
			return nil, nil
		},
	}
	r := Route{Prefix: "2001:db8:a::/64", Table: 100, Via: "fda1::1", Interface: "virtio-0/0/12/0"}
	if err := p.Add(r); err != nil {
		t.Fatal(err)
	}
	wantAdd := []string{"ip", "route", "add", "2001:db8:a::/64", "table", "100", "via", "fda1::1", "virtio-0/0/12/0"}
	if gotName != "vppctl" || !reflect.DeepEqual(gotArgs, wantAdd) {
		t.Fatalf("Add ran %q %v, want vppctl %v", gotName, gotArgs, wantAdd)
	}
	if err := p.Del(r); err != nil {
		t.Fatal(err)
	}
	if gotArgs[2] != "del" {
		t.Fatalf("Del op = %q, want del", gotArgs[2])
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

// fakeProgrammer records Add/Del and serves a per-table FIB that reflects the
// applied routes (so the stateless syncer reads back its own writes).
type fakeProgrammer struct {
	added, deleted []Route
	fib            map[uint32]map[string]Route // table -> key -> route
}

func newFakeProgrammer() *fakeProgrammer {
	return &fakeProgrammer{fib: map[uint32]map[string]Route{}}
}

func (f *fakeProgrammer) Add(r Route) error {
	f.added = append(f.added, r)
	if f.fib[r.Table] == nil {
		f.fib[r.Table] = map[string]Route{}
	}
	f.fib[r.Table][r.Key()] = r
	return nil
}

func (f *fakeProgrammer) Del(r Route) error {
	f.deleted = append(f.deleted, r)
	if f.fib[r.Table] != nil {
		delete(f.fib[r.Table], r.Key())
	}
	return nil
}

// ServiceProgrammer returns nil: the plain fake does not support service routes.
func (f *fakeProgrammer) ServiceProgrammer() ServiceVPPProgrammer { return nil }

// InstalledRoutes renders the fake table in the real `show ip6 fib table N`
// shape and runs it through the actual ParseOwnedRoutes parser, so the syncer
// path still exercises the ownership filter.
func (f *fakeProgrammer) InstalledRoutes(table uint32, peers map[string]Upstream) ([]Route, error) {
	var b []byte
	b = append(b, []byte("ipv6-VRF:"+itoa(table)+", fib_index:11, flow hash:[...]\n")...)
	for _, r := range f.fib[table] {
		b = append(b, []byte(r.Prefix+" fib:11 index:1 locks:2\n")...)
		b = append(b, []byte("  CLI refs:1 src-flags:added,\n")...)
		b = append(b, []byte("      [@0]: ipv6 via "+r.Via+" "+r.Interface+": mtu:1500 next:3\n")...)
	}
	// Always include some noise routes (not ours) to prove the ownership filter.
	b = append(b, []byte("::/0\n  [@0]: dpo-drop ip6\n")...)
	b = append(b, []byte("fe80::/10\n  [@14]: ip6-link-local\n")...)
	return ParseOwnedRoutes(b, table, peers), nil
}

func itoa(u uint32) string {
	if u == 0 {
		return "0"
	}
	var d []byte
	for u > 0 {
		d = append([]byte{byte('0' + u%10)}, d...)
		u /= 10
	}
	return string(d)
}

func newSyncer(fp *fakeProgrammer, rib *string) *Syncer {
	return &Syncer{
		Cfg:   testCfg(),
		VPP:   fp,
		Log:   logr.Discard(),
		Fetch: func(_ context.Context) ([]byte, error) { return []byte(*rib), nil },
	}
}

func TestSyncer_ReconcileConverges(t *testing.T) {
	fp := newFakeProgrammer()
	rib := sampleRIB
	s := newSyncer(fp, &rib)

	// First pass: both prefixes installed.
	s.reconcileOnce(context.Background())
	if len(fp.added) != 2 || len(fp.deleted) != 0 {
		t.Fatalf("pass1 added=%d deleted=%d, want 2/0", len(fp.added), len(fp.deleted))
	}

	// Second pass, same RIB: idempotent (reads its own FIB back), no changes.
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
}

// Regression for the Codex finding: a route installed before a restart and
// withdrawn while the syncer was down must still be removed, because the
// installed set is read from VPP, not from lost in-memory state.
func TestSyncer_RemovesStaleRouteAfterRestart(t *testing.T) {
	fp := newFakeProgrammer()
	// Simulate pre-restart state: 2001:db8:a::/64 already in VPP table 100.
	_ = fp.Add(Route{Prefix: "2001:db8:a::/64", Table: 100, Via: "fda1::1", Interface: "virtio-0/0/12/0"})
	fp.added = nil // forget the call history; this represents a prior process

	// Fresh syncer (post-restart, no in-memory state). RIB no longer has a::/64.
	rib := `{"2001:db8:b::/64":[{"nlri":{"prefix":"2001:db8:b::/64"},"best":true,"neighbor-ip":"fda2::1","attrs":[{"type":14,"nexthop":"fda2::1"}]}]}`
	s := newSyncer(fp, &rib)

	s.reconcileOnce(context.Background())

	// The stale a::/64 (in VPP, absent from RIB) must be deleted; b::/64 added.
	foundDel := false
	for _, r := range fp.deleted {
		if r.Prefix == "2001:db8:a::/64" && r.Table == 100 {
			foundDel = true
		}
	}
	if !foundDel {
		t.Fatalf("stale route not removed after restart; deleted=%v", fp.deleted)
	}
	if _, ok := fp.fib[100][Route{Prefix: "2001:db8:a::/64", Table: 100}.Key()]; ok {
		t.Fatal("stale route still present in VPP FIB after reconcile")
	}
}

// A read failure must NOT cause deletions (avoid acting on a partial view).
func TestSyncer_SkipsOnFIBReadError(t *testing.T) {
	fp := newFakeProgrammer()
	_ = fp.Add(Route{Prefix: "2001:db8:a::/64", Table: 100, Via: "fda1::1", Interface: "e"})
	fp.added, fp.deleted = nil, nil
	fe := &failingReader{fakeProgrammer: fp}
	rib := `{}`
	s := &Syncer{Cfg: testCfg(), VPP: fe, Log: logr.Discard(),
		Fetch: func(_ context.Context) ([]byte, error) { return []byte(rib), nil }}
	s.reconcileOnce(context.Background())
	if len(fe.deleted) != 0 {
		t.Fatalf("expected no deletions on FIB read error, got %v", fe.deleted)
	}
}

type failingReader struct{ *fakeProgrammer }

func (f *failingReader) InstalledRoutes(uint32, map[string]Upstream) ([]Route, error) {
	return nil, errFIB
}

var errFIB = &fibErr{}

type fibErr struct{}

func (*fibErr) Error() string { return "vpp unreachable" }

// --- SRv6 service routes (RFC 9252, backbone stitching) ---

// servicePathJSON renders one RIB path whose Prefix-SID attribute is generated
// by gobgp's OWN MarshalJSON (the exact code path the gobgp CLI uses for -j),
// so this is a faithful wire-format regression guard for our parser.
func servicePathJSON(t *testing.T, prefix, nexthop, sid string, behavior uint16) string {
	t.Helper()
	psid := gobgpb.NewPathAttributePrefixSID(&gobgpb.SRv6L3ServiceAttribute{
		TLV: gobgpb.TLV{Type: gobgpb.TLVType(5)},
		SubTLVs: []gobgpb.PrefixSIDTLVInterface{
			&gobgpb.SRv6InformationSubTLV{
				SubTLV:           gobgpb.SubTLV{Type: gobgpb.SubTLVType(1)},
				SID:              net.ParseIP(sid).To16(),
				EndpointBehavior: behavior,
			},
		},
	})
	b, err := json.Marshal(psid)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(`{"nlri":{"prefix":"%s"},"best":true,"neighbor-ip":"%s",
		"attrs":[{"type":1,"value":0},{"type":14,"nexthop":"%s","afi":2,"safi":1},%s]}`,
		prefix, nexthop, nexthop, b)
}

func TestParseRIB_ServiceSID(t *testing.T) {
	j := fmt.Sprintf(`{"2001:db8:svc::/64":[%s]}`,
		servicePathJSON(t, "2001:db8:svc::/64", "fda1::1", "fcff:0:0:b:1::", 18))
	got, err := ParseRIB([]byte(j))
	if err != nil {
		t.Fatal(err)
	}
	e, ok := got["2001:db8:svc::/64"]
	if !ok {
		t.Fatalf("prefix missing: %v", got)
	}
	if e.Nexthop != "fda1::1" {
		t.Fatalf("nexthop = %q, want fda1::1", e.Nexthop)
	}
	if e.ServiceSID != "fcff:0:0:b:1::" {
		t.Fatalf("serviceSID = %q, want fcff:0:0:b:1::", e.ServiceSID)
	}
}

func TestDesiredRoutes_ServiceSplit(t *testing.T) {
	rib := map[string]RIBEntry{
		"2001:db8:a::/64":   {Nexthop: "fda1::1"},
		"2001:db8:svc::/64": {Nexthop: "fda1::1", ServiceSID: "fcff:0:0:b:1::"},
	}
	plain, service := SplitServiceRoutes(DesiredRoutes(rib, testCfg()))
	if len(plain) != 1 || plain[0].Prefix != "2001:db8:a::/64" {
		t.Fatalf("plain = %v", plain)
	}
	if len(service) != 1 || service[0].Prefix != "2001:db8:svc::/64" ||
		service[0].Table != 100 || service[0].ServiceSID != "fcff:0:0:b:1::" {
		t.Fatalf("service = %v", service)
	}
}

func TestDeriveServiceBSID(t *testing.T) {
	_, block, _ := net.ParseCIDR("cafe:f::/96")
	a := DeriveServiceBSID(block, net.ParseIP("fcff:0:0:b:1::"))
	b := DeriveServiceBSID(block, net.ParseIP("fcff:0:0:b:1::"))
	c := DeriveServiceBSID(block, net.ParseIP("fcff:0:0:b:2::"))
	if !a.Equal(b) {
		t.Fatalf("not deterministic: %s vs %s", a, b)
	}
	if a.Equal(c) {
		t.Fatalf("distinct SIDs collided: %s", a)
	}
	if !block.Contains(a) || !block.Contains(c) {
		t.Fatalf("BSID outside block: %s / %s", a, c)
	}
}

func TestRouteKey_IncludesServiceSID(t *testing.T) {
	plain := Route{Prefix: "2001:db8:svc::/64", Table: 100}
	svc := Route{Prefix: "2001:db8:svc::/64", Table: 100, ServiceSID: "fcff:0:0:b:1::"}
	if plain.Key() == svc.Key() {
		t.Fatal("service identity must be part of the route key")
	}
}

// fakeServiceProgrammer extends fakeProgrammer with the service interface,
// mirroring applied service routes per table.
type fakeServiceProgrammer struct {
	*fakeProgrammer
	svcAdded, svcDeleted []Route
	svc                  map[uint32]map[string]Route
}

func newFakeServiceProgrammer() *fakeServiceProgrammer {
	return &fakeServiceProgrammer{
		fakeProgrammer: newFakeProgrammer(),
		svc:            map[uint32]map[string]Route{},
	}
}

func (f *fakeServiceProgrammer) AddService(r Route) error {
	f.svcAdded = append(f.svcAdded, r)
	if f.svc[r.Table] == nil {
		f.svc[r.Table] = map[string]Route{}
	}
	f.svc[r.Table][r.Key()] = r
	return nil
}

func (f *fakeServiceProgrammer) DelService(r Route) error {
	f.svcDeleted = append(f.svcDeleted, r)
	if f.svc[r.Table] != nil {
		delete(f.svc[r.Table], r.Key())
	}
	return nil
}

func (f *fakeServiceProgrammer) InstalledServiceRoutes(table uint32) ([]Route, error) {
	var out []Route
	for _, r := range f.svc[table] {
		// VPP-side reconstruction carries only (prefix, table, sid).
		out = append(out, Route{Prefix: r.Prefix, Table: r.Table, ServiceSID: r.ServiceSID})
	}
	return out, nil
}

// ServiceProgrammer overrides the embedded plain fake to advertise service
// support (it returns itself, the ServiceVPPProgrammer).
func (f *fakeServiceProgrammer) ServiceProgrammer() ServiceVPPProgrammer { return f }

func TestSyncer_ServiceRoutesConverge(t *testing.T) {
	fp := newFakeServiceProgrammer()
	rib := fmt.Sprintf(`{"2001:db8:svc::/64":[%s]}`,
		servicePathJSON(t, "2001:db8:svc::/64", "fda1::1", "fcff:0:0:b:1::", 18))
	s := &Syncer{Cfg: testCfg(), VPP: fp, Log: logr.Discard(),
		Fetch: func(_ context.Context) ([]byte, error) { return []byte(rib), nil }}

	// Pass 1: service route installed (as a service, not a plain FIB route).
	s.reconcileOnce(context.Background())
	if len(fp.svcAdded) != 1 || fp.svcAdded[0].ServiceSID != "fcff:0:0:b:1::" || fp.svcAdded[0].Table != 100 {
		t.Fatalf("svcAdded = %v", fp.svcAdded)
	}
	if len(fp.added) != 0 {
		t.Fatalf("service route must not be installed as a plain route: %v", fp.added)
	}

	// Pass 2: idempotent.
	s.reconcileOnce(context.Background())
	if len(fp.svcAdded) != 1 || len(fp.svcDeleted) != 0 {
		t.Fatalf("pass2 svcAdded=%d svcDeleted=%d, want 1/0", len(fp.svcAdded), len(fp.svcDeleted))
	}

	// Withdraw → service install removed.
	rib = `{}`
	s.reconcileOnce(context.Background())
	if len(fp.svcDeleted) != 1 || fp.svcDeleted[0].Prefix != "2001:db8:svc::/64" {
		t.Fatalf("svcDeleted = %v", fp.svcDeleted)
	}
}

// A backend without service support must not break plain reconciliation when
// service routes appear (they are reported, not fatal).
func TestSyncer_ServiceUnsupportedBackend(t *testing.T) {
	fp := newFakeProgrammer() // plain-only backend
	rib := fmt.Sprintf(`{"2001:db8:a::/64":[{"nlri":{"prefix":"2001:db8:a::/64"},"best":true,"neighbor-ip":"fda1::1","attrs":[{"type":14,"nexthop":"fda1::1"}]}],"2001:db8:svc::/64":[%s]}`,
		servicePathJSON(t, "2001:db8:svc::/64", "fda1::1", "fcff:0:0:b:1::", 18))
	s := &Syncer{Cfg: testCfg(), VPP: fp, Log: logr.Discard(),
		Fetch: func(_ context.Context) ([]byte, error) { return []byte(rib), nil }}
	s.reconcileOnce(context.Background())
	if len(fp.added) != 1 || fp.added[0].Prefix != "2001:db8:a::/64" {
		t.Fatalf("plain route must still be reconciled: %v", fp.added)
	}
}

func TestParseOwnedRoutes(t *testing.T) {
	raw := []byte(`ipv6-VRF:100, fib_index:11, flow hash:[src dst]
2001:db8:a::/64 fib:11 index:121 locks:2
  CLI refs:1 src-flags:added,contributing,active,
      [@0]: ipv6 via fda1::1 virtio-0/0/12/0: mtu:1500 next:3 flags:[features]
2001:db8:other::/64 fib:11 index:99 locks:2
      [@0]: ipv6 via fdcc::9 virtio-0/0/12/0: mtu:1500 next:3
::/0
  [@0]: dpo-drop ip6
fe80::/10
  [@14]: ip6-link-local
`)
	peers := testCfg().PeerIndex()
	got := ParseOwnedRoutes(raw, 100, peers)
	if len(got) != 1 {
		t.Fatalf("ParseOwnedRoutes = %v, want exactly the via-fda1::1 route", got)
	}
	if got[0].Prefix != "2001:db8:a::/64" || got[0].Via != "fda1::1" || got[0].Table != 100 {
		t.Fatalf("parsed route = %+v", got[0])
	}
}
