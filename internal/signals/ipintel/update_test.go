package ipintel

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
)

func gzTSV(s string) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	gz.Write([]byte(s))
	gz.Close()
	return buf.Bytes()
}

// TestUpdateKeepsGoodDataOnFailure runs one good update, then one where the
// ASN download is corrupt and a crawler feed is down: the previous ASN file
// and that crawler's ranges must survive.
func TestUpdateKeepsGoodDataOnFailure(t *testing.T) {
	var broken atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/asn":
			if broken.Load() {
				w.Write([]byte("<html>maintenance</html>"))
				return
			}
			w.Write(gzTSV(tsv))
		case "/tor":
			w.Write([]byte("185.220.101.1\n185.220.101.2\n"))
		case "/drop4":
			w.Write([]byte(`{"cidr":"192.0.2.0/24"}` + "\n"))
		case "/drop6":
			w.Write([]byte(`{"cidr":"2001:db8::/32"}` + "\n"))
		case "/google":
			if broken.Load() {
				http.Error(w, "down", 500)
				return
			}
			w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"66.249.66.0/27"}]}`))
		case "/bing":
			w.Write([]byte(`{"prefixes":[{"ipv4Prefix":"157.55.39.0/24"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	oldSources, oldFeeds := Sources, crawlerFeeds
	defer func() { Sources, crawlerFeeds = oldSources, oldFeeds }()
	Sources = []Source{
		{"asn", srv.URL + "/asn", FileASN, "test"},
		{"tor", srv.URL + "/tor", FileTor, "test"},
		{"drop4", srv.URL + "/drop4", FileDropV4, "test"},
		{"drop6", srv.URL + "/drop6", FileDropV6, "test"},
	}
	crawlerFeeds = map[string]string{"googlebot": srv.URL + "/google", "bingbot": srv.URL + "/bing"}

	dir := t.TempDir()
	if err := Update(t.Context(), dir, srv.Client(), nil); err != nil {
		t.Fatal(err)
	}
	check := func(stage string) {
		t.Helper()
		db, err := Load(dir, nil)
		if err != nil {
			t.Fatalf("%s: load: %v", stage, err)
		}
		c := db.Counts()
		if c["v4"] == 0 || c["tor"] != 2 || c["drop"] != 2 {
			t.Fatalf("%s: counts %v", stage, c)
		}
		if db.Lookup(netip.MustParseAddr("66.249.66.5")).Crawler != "googlebot" {
			t.Fatalf("%s: googlebot ranges lost", stage)
		}
		if db.Lookup(netip.MustParseAddr("157.55.39.9")).Crawler != "bingbot" {
			t.Fatalf("%s: bingbot ranges lost", stage)
		}
	}
	check("first update")

	broken.Store(true)
	if err := Update(t.Context(), dir, srv.Client(), nil); err == nil {
		t.Fatal("expected an error for the broken sources")
	}
	check("after failed update")
}

// A corrupt file must not stop the other sources from loading.
func TestLoadPartial(t *testing.T) {
	dir := writeFixture(t)
	if err := writeAtomic(dir+"/"+FileASN, []byte("not gzip")); err != nil {
		t.Fatal(err)
	}
	db, err := Load(dir, nil)
	if err == nil {
		t.Fatal("expected an error for the corrupt ASN file")
	}
	if c := db.Counts(); c["tor"] != 1 || c["drop"] != 1 {
		t.Fatalf("other sources dropped: %v", c)
	}
}

func TestShortKeywordsMatchWholeWords(t *testing.T) {
	cases := map[string]string{
		"ALTERNET-AS Alternet Systems": "isp",
		"EXAMPLE-LTE Mobile Broadband": "mobile",
		"FOO LTE NETWORKS":             "mobile",
		"RELIANCEJIO-IN Reliance Jio":  "mobile",
		"ACME UNIVERSITY NETWORK":      "edu",
	}
	for desc, want := range cases {
		if got := classify(1, desc, map[uint32]bool{}); got != want {
			t.Errorf("%q: %s, want %s", desc, got, want)
		}
	}
}
