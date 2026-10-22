package api

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/challenge/pow"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/signals/ipintel"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

// withIPData loads a tiny ipintel table: 10.N.0.0/16 belongs to AS(64500+N),
// country in; 10.99.0.0/16 is AWS.
func withIPData(t *testing.T, h *harness) {
	var tsv bytes.Buffer
	for n := 0; n < 20; n++ {
		fmt.Fprintf(&tsv, "10.%d.0.0\t10.%d.255.255\t%d\tIN\tISP-%d\n", n, n, 64500+n, n)
	}
	fmt.Fprintf(&tsv, "10.99.0.0\t10.99.255.255\t16509\tUS\tAMAZON-02\n")
	dir := t.TempDir()
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	w.Write(tsv.Bytes())
	w.Close()
	os.WriteFile(filepath.Join(dir, ipintel.FileASN), gz.Bytes(), 0o600)
	db, err := ipintel.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	h.srv.IP.Set(db)
	h.srv.Cfg.TrustedProxies = []string{"127.0.0.1"}
	if err := h.srv.Cfg.Revalidate(); err != nil {
		t.Fatal(err)
	}
}

func (h *harness) submitFrom(ip string, run int) map[string]any {
	hdr := browserHeaders()
	hdr["X-Forwarded-For"] = ip
	code, out := h.post("/v1/session", `{"sk":"dk_pk_shop","a":"signup"}`, hdr)
	if code != 200 {
		h.t.Fatalf("session %d %v", code, out)
	}
	n := out["nonce"].(string)
	h.clock = h.clock.Add(12 * time.Second)
	p := humanPayloadAfter(n, 12*time.Second)
	// A real device draws a different seeded canvas every session; only the
	// static canvas is stable.
	p.FP.CV.H = fmt.Sprintf("seeded%05d", run)
	_, out = h.post("/v1/submit", encode(p), hdr)
	if out["status"] == "challenge" {
		pm := out["pow"].(map[string]any)
		params := pow.Params{Salt: pm["salt"].(string), Bits: int(pm["bits"].(float64)), N: int(pm["n"].(float64))}
		body, _ := json.Marshal(map[string]any{"n": n, "kind": "pow", "sol": pow.Solve(n, params)})
		_, out = h.post("/v1/challenge", string(body), hdr)
	}
	if out["status"] == "challenge" && out["kind"] == "visual" {
		body, _ := json.Marshal(map[string]any{"n": n, "kind": "visual", "answer": h.srv.Visual.Answer(n)})
		_, out = h.post("/v1/challenge", string(body), hdr)
	}
	tok, _ := out["token"].(string)
	if tok == "" {
		return map[string]any{"status": out["status"]}
	}
	return h.verify(tok, h.secret, nil)["doorkeep"].(map[string]any)
}

func reasonsOf(dk map[string]any) []string {
	if dk["reasons"] == nil {
		return nil
	}
	return anyStrings(dk["reasons"])
}

func TestProxyRotationDetected(t *testing.T) {
	h := newHarness(t)
	withIPData(t, h)
	var last map[string]any
	// Same device fingerprint from six different networks within an hour.
	for n := 0; n < 6; n++ {
		last = h.submitFrom(fmt.Sprintf("10.%d.1.%d", n, n+1), n)
	}
	if !slices.Contains(reasonsOf(last), "FP_MULTI_ASN") {
		t.Fatalf("proxy rotation not flagged: %v", last)
	}
	if slices.Contains(reasonsOf(last), "REPLAY_CANVAS_SEED") {
		t.Fatalf("fresh seeded canvases must not look like a replay: %v", last)
	}
}

func TestDatacenterAndCountry(t *testing.T) {
	h := newHarness(t)
	withIPData(t, h)
	dk := h.submitFrom("10.99.3.4", 0)
	if !slices.Contains(reasonsOf(dk), "IP_DATACENTER") {
		t.Fatalf("datacenter not flagged: %v", dk)
	}
	if dk["outcome"] != "allow" {
		t.Fatalf("datacenter alone must not block a human: %v", dk)
	}
}

func TestASNAllowListWins(t *testing.T) {
	h := newHarness(t)
	withIPData(t, h)
	if err := h.srv.Store.AddListEntry(t.Context(), &store.ListEntry{SiteID: "site1", Kind: "asn", Value: "AS16509", Action: scoring.ListAllow}); err != nil {
		t.Fatal(err)
	}
	dk := h.submitFrom("10.99.3.4", 0)
	if dk["risk"].(float64) != 0 || !slices.Contains(reasonsOf(dk), "ALLOWLIST_ASN") {
		t.Fatalf("asn allow-list not applied: %v", dk)
	}
}

func TestSessionRateLimit(t *testing.T) {
	h := newHarness(t)
	withIPData(t, h)
	hdr := browserHeaders()
	hdr["X-Forwarded-For"] = "10.5.5.5"
	limited := false
	for i := 0; i < sessionPerIPPerMin+5; i++ {
		code, _ := h.post("/v1/session", `{"sk":"dk_pk_shop"}`, hdr)
		if code == 429 {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("session endpoint never rate limited")
	}
	// A different IP is unaffected.
	hdr["X-Forwarded-For"] = "10.6.6.6"
	if code, _ := h.post("/v1/session", `{"sk":"dk_pk_shop"}`, hdr); code != 200 {
		t.Fatalf("other IP got %d", code)
	}
}

func TestUntrustedXFFIgnored(t *testing.T) {
	h := newHarness(t)
	withIPData(t, h)
	h.srv.Cfg.TrustedProxies = nil
	_ = h.srv.Cfg.Revalidate()
	dk := h.submitFrom("10.99.3.4", 0) // spoofed AWS address must be ignored
	if slices.Contains(reasonsOf(dk), "IP_DATACENTER") {
		t.Fatalf("X-Forwarded-For trusted from an untrusted peer: %v", dk)
	}
}

func storeFilterAll() store.EventFilter { return store.EventFilter{SiteID: "site1", Limit: 10} }
