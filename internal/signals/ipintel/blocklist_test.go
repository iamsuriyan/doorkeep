package ipintel

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const netset = `# FireHOL-style netset
#
1.10.16.0/20
5.188.10.0/23
185.220.101.7      ; single address, comment after
2a06:4880::/32
10.0.0.0/8         # bogon: must be ignored
192.168.0.0/16
0.0.0.0/8
8.0.0.0/7          # far too broad: ignored
not-an-address
::ffff:198.51.100.1
`

func TestParseBlocklistKeepsOnlyUsableRanges(t *testing.T) {
	ps := parseBlocklist(strings.NewReader(netset))
	got := map[string]bool{}
	for _, p := range ps {
		got[p.String()] = true
	}
	for _, want := range []string{"1.10.16.0/20", "5.188.10.0/23", "185.220.101.7/32", "2a06:4880::/32"} {
		if !got[want] {
			t.Errorf("missing %s (got %v)", want, got)
		}
	}
	if len(ps) != 4 {
		t.Errorf("kept %d prefixes, want 4 (bogons, broad ranges and documentation addresses dropped): %v", len(ps), got)
	}
}

func TestRangeSetLookup(t *testing.T) {
	rs := &rangeSet{}
	rs.add("a", []netip.Prefix{netip.MustParsePrefix("1.10.16.0/20"), netip.MustParsePrefix("1.10.20.0/24")})
	rs.add("b", []netip.Prefix{netip.MustParsePrefix("1.10.0.0/16"), netip.MustParsePrefix("5.5.5.5/32"), netip.MustParsePrefix("2a06:4880::/32")})
	rs.add("c", []netip.Prefix{netip.MustParsePrefix("1.10.255.0/24"), netip.MustParsePrefix("1.11.0.0/24")})
	rs.finish()
	for ip, in := range map[string]bool{
		"1.10.0.1": true, "1.10.16.5": true, "1.10.31.255": true, "1.10.255.255": true, "1.11.0.9": true,
		"1.11.1.0": false, "1.9.255.255": false, "5.5.5.5": true, "5.5.5.6": false,
		"2a06:4880::1": true, "2a06:4881::1": false, "255.255.255.255": false,
	} {
		if got := rs.lookup(netip.MustParseAddr(ip)) != ""; got != in {
			t.Errorf("%s: listed=%v, want %v", ip, got, in)
		}
	}
	// Nested and adjacent ranges merge: 1.10/16 swallows a's ranges, and
	// c's 1.10.255/24 and adjacent 1.11.0/24 join it.
	if n := len(rs.v4); n != 2 {
		t.Errorf("v4 spans after merge: %d, want 2: %+v", n, rs.v4)
	}
}

func TestBlocklistLoadAndUpdate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/level1.netset":
			w.Write([]byte(netset))
		case "/private":
			if u, p, ok := r.BasicAuth(); !ok || u != "user" || p != "secret" {
				http.Error(w, "auth", http.StatusUnauthorized)
				return
			}
			w.Write([]byte("45.155.205.0/24\n"))
		case "/empty":
			w.Write([]byte("# nothing\n10.0.0.0/8\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	oldSources, oldFeeds := Sources, crawlerFeeds
	defer func() { Sources, crawlerFeeds = oldSources, oldFeeds }()
	Sources, crawlerFeeds = nil, nil

	dir := t.TempDir()
	authURL := strings.Replace(srv.URL, "http://", "http://user:secret@", 1) + "/private"
	lists := []Blocklist{{"level1", srv.URL + "/level1.netset"}, {"crowdsec", authURL}}
	if err := Update(t.Context(), dir, srv.Client(), lists); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "sources.json")); strings.Contains(string(b), "secret") {
		t.Fatal("list credentials written to sources.json")
	}
	db, err := Load(dir, []string{"level1", "crowdsec"})
	if err != nil {
		t.Fatal(err)
	}
	if got := db.Lookup(netip.MustParseAddr("45.155.205.9")).Blocklist; got != "crowdsec" {
		t.Fatalf("crowdsec list: %q", got)
	}
	if got := db.Lookup(netip.MustParseAddr("1.10.20.1")).Blocklist; got != "level1" {
		t.Fatalf("level1 list: %q", got)
	}
	if got := db.Lookup(netip.MustParseAddr("10.1.2.3")).Blocklist; got != "" {
		t.Fatal("private address reported as blocklisted")
	}
	// A list removed from the configuration stops applying.
	db, _ = Load(dir, []string{"level1"})
	if db.Lookup(netip.MustParseAddr("45.155.205.9")).Blocklist != "" {
		t.Fatal("unconfigured list still applied")
	}
	// A list that turns out empty (or only bogons) does not replace the
	// previous good copy.
	if err := Update(t.Context(), dir, srv.Client(), []Blocklist{{"level1", srv.URL + "/empty"}}); err == nil {
		t.Fatal("empty list accepted")
	}
	db, _ = Load(dir, []string{"level1"})
	if db.Lookup(netip.MustParseAddr("1.10.20.1")).Blocklist == "" {
		t.Fatal("good list replaced by an empty download")
	}
}
