package api

import (
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/signals/ipintel"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

func TestShareTrackerWindow(t *testing.T) {
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	tr := newShareTracker(func() time.Time { return now })
	for range 10 {
		tr.recordBlock(netip.MustParseAddr("2a06:4880::9"))
		tr.recordBlock(netip.MustParseAddr("45.155.205.17"))
		tr.recordBlock(netip.MustParseAddr("203.0.113.9")) // documentation range: never shared
	}
	for range 9 {
		tr.recordBlock(netip.MustParseAddr("198.51.100.1"))
	}
	tr.recordBlock(netip.MustParseAddr("10.1.2.3")) // private: never shared
	got := tr.listed(10)
	if len(got) != 2 || got[0] != "2a06:4880::/48" || got[1] != "45.155.205.0/24" {
		t.Fatalf("listed: %v", got)
	}
	now = now.Add(23 * time.Hour)
	if len(tr.listed(10)) != 2 {
		t.Fatal("expired before 24 hours")
	}
	now = now.Add(2 * time.Hour)
	if got := tr.listed(10); len(got) != 0 {
		t.Fatalf("still listed after 24 hours: %v", got)
	}
}

// End to end: blocked submissions from one network appear in the feed, the
// feed parses as a blocklist for another instance, and nothing is listed
// unless sharing is enabled.
func TestShareBlocklistFeed(t *testing.T) {
	h := newHarness(t)
	h.srv.Cfg.TrustedProxies = []string{"127.0.0.1"}
	h.srv.Cfg.Revalidate()
	block := func(xff string) {
		hdr := browserHeaders()
		hdr["X-Forwarded-For"] = xff
		_, out := h.post("/v1/session", `{"sk":"dk_pk_shop","a":"signup"}`, hdr)
		n := out["nonce"].(string)
		h.clock = h.clock.Add(5 * time.Second)
		p := humanPayloadAfter(n, 5*time.Second)
		p.FP.CV.H = n[:11]
		p.Auto.WD = 1
		h.post("/v1/submit", encode(p), hdr)
	}
	get := func() (int, string) {
		res, err := http.Get(h.http.URL + "/v1/share/blocklist")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	if code, _ := get(); code != 404 {
		t.Fatalf("feed served while sharing is off: %d", code)
	}
	h.srv.Cfg.ShareBlocklist, h.srv.Cfg.ShareMinBlocks = true, 3
	for i := range 3 {
		block("45.155.205." + string(rune('1'+i)))
	}
	block("185.220.101.4")
	// A deny-list block is the operator's call and is not shared.
	h.srv.Store.AddListEntry(t.Context(), &store.ListEntry{SiteID: "site1", Kind: "cidr", Value: "91.92.0.0/16", Action: scoring.ListDeny})
	for i := range 3 {
		block("91.92.1." + string(rune('1'+i)))
	}
	code, body := get()
	if code != 200 || !strings.Contains(body, "45.155.205.0/24\n") || strings.Contains(body, "185.220.101") || strings.Contains(body, "91.92.") {
		t.Fatalf("feed %d:\n%s", code, body)
	}
	// It is a valid blocklist for another instance.
	ps := ipintel.ParseBlocklist(strings.NewReader(body))
	if len(ps) != 1 || !ps[0].Contains(netip.MustParseAddr("45.155.205.77")) {
		t.Fatalf("feed parsed as %v", ps)
	}
}
