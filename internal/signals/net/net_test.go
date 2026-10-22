package net

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/signals/payload"
)

const (
	chromeWin  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
	firefoxWin = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0"
)

// chromeReq is what Chrome sends on a fetch() over HTTPS.
func chromeReq() map[string]string {
	return map[string]string{
		"User-Agent":         chromeWin,
		"Sec-CH-UA":          `"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"`,
		"Sec-CH-UA-Mobile":   "?0",
		"Sec-CH-UA-Platform": `"Windows"`,
		"Sec-Fetch-Mode":     "cors",
		"Accept-Language":    "en-IN,en;q=0.9",
		"Accept":             "*/*",
	}
}

func analyze(t *testing.T, hdr map[string]string, https, trustProxy bool, jsUA string, langs []string) scoring.Features {
	t.Helper()
	r := httptest.NewRequest("POST", "http://shop.example/v1/submit", nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	if https {
		r.TLS = &tls.ConnectionState{}
	}
	f := scoring.NewFeatures()
	Analyze(f, r, trustProxy, jsUA, langs, payload.Classified{OSFamily: payload.OSFamily(hdr["User-Agent"])})
	return f
}

func want(t *testing.T, f scoring.Features, key string, v float64) {
	t.Helper()
	if !f.Has(key) {
		t.Fatalf("%s not set", key)
	}
	if got := f.Get(key); got != v {
		t.Fatalf("%s = %v, want %v", key, got, v)
	}
}

func TestRealChromeIsConsistent(t *testing.T) {
	f := analyze(t, chromeReq(), true, false, chromeWin, []string{"en-IN", "en"})
	for _, k := range []string{"net.ua_hdr_js_mismatch", "net.ch_missing", "net.ch_mismatch", "net.fetch_metadata_missing", "net.accept_lang_missing", "net.accept_lang_mismatch"} {
		want(t, f, k, 0)
	}
	if f.Has("net.ch_unexpected") || f.Has("net.accept_wrong") {
		t.Fatal("unexpected anomaly on real Chrome")
	}
}

func TestHeaderAnomalies(t *testing.T) {
	h := chromeReq()
	delete(h, "Sec-CH-UA")
	delete(h, "Sec-Fetch-Mode")
	h["Accept"] = "text/html,application/xhtml+xml"
	f := analyze(t, h, true, false, firefoxWin, []string{"de-DE"})
	want(t, f, "net.ua_hdr_js_mismatch", 1)
	want(t, f, "net.ch_missing", 1)
	want(t, f, "net.fetch_metadata_missing", 1)
	want(t, f, "net.accept_lang_mismatch", 1)
	want(t, f, "net.accept_wrong", 1)

	h = chromeReq()
	h["Sec-CH-UA-Platform"] = `"macOS"`
	want(t, analyze(t, h, true, false, chromeWin, nil), "net.ch_mismatch", 1)

	h = map[string]string{"User-Agent": firefoxWin, "Sec-CH-UA": `"Chromium";v="130"`}
	f = analyze(t, h, true, false, firefoxWin, nil)
	want(t, f, "net.ch_unexpected", 1)
	want(t, f, "net.accept_lang_missing", 1)
}

// Client Hints are only sent to secure contexts, so their absence over plain
// HTTP is neutral. A client must not be able to claim HTTPS itself.
func TestForwardedProtoOnlyFromTrustedProxy(t *testing.T) {
	h := chromeReq()
	delete(h, "Sec-CH-UA")
	h["X-Forwarded-Proto"] = "https"
	if f := analyze(t, h, false, false, chromeWin, nil); f.Has("net.ch_missing") {
		t.Fatal("untrusted X-Forwarded-Proto made the request secure")
	}
	want(t, analyze(t, h, false, true, chromeWin, nil), "net.ch_missing", 1)
}

func TestSecureLocalhost(t *testing.T) {
	for host, ok := range map[string]bool{"localhost:8080": true, "127.0.0.1": true, "[::1]:9": true, "a.localhost": true, "shop.example": false} {
		r := httptest.NewRequest("GET", "http://x/", nil)
		r.Host = host
		if Secure(r, false) != ok {
			t.Errorf("Secure(%s) = %v", host, !ok)
		}
	}
}
