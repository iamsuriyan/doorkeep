package api

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetrics(t *testing.T) {
	h := newHarness(t)
	// One human submit and its verification.
	n, _ := h.session("signup")
	h.clock = h.clock.Add(10 * time.Second)
	p := humanPayloadAfter(n, 10*time.Second)
	p.FP.CV.H = n[:11]
	_, out := h.post("/v1/submit", encode(p), browserHeaders())
	h.verify(out["token"].(string), h.secret, nil)
	h.verify("garbage", h.secret, nil)

	// Public admin (the test harness): /metrics needs an admin credential.
	if res, _ := http.Get(h.http.URL + "/metrics"); res.StatusCode != 401 {
		t.Fatalf("public /metrics without a token: %d", res.StatusCode)
	}
	tok, _ := NewAdminToken(t.Context(), h.srv.Store, "prometheus", h.clock, 0)
	req, _ := http.NewRequest("GET", h.http.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, err := http.DefaultClient.Do(req)
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("metrics with token: %v %d", err, res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	text := string(body)
	for _, want := range []string{
		`doorkeep_build_info{version="dev"`,
		`doorkeep_http_requests_total{route="POST /v1/submit",code="200"} 1`,
		`doorkeep_http_request_duration_seconds_count{route="POST /v1/session"} 1`,
		`doorkeep_submits_total{site="site1",outcome="allow"} 1`,
		`doorkeep_tokens_total{site="site1",outcome="allow",challenge="none"} 1`,
		`doorkeep_verifications_total{result="success"} 1`,
		`doorkeep_verifications_total{result="invalid"} 1`,
		`doorkeep_ipdata_entries{kind="blocklist"}`,
		"doorkeep_velocity_keys ",
		"go_goroutines ",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q", want)
		}
	}
	if t.Failed() {
		t.Log(text)
	}

	// Private admin listener: open, for a local Prometheus.
	h.srv.Cfg.AdminListen = "127.0.0.1:0"
	h.srv.routes()
	adm := httptest.NewServer(h.srv.AdminHandler())
	defer adm.Close()
	if res, _ := http.Get(adm.URL + "/metrics"); res.StatusCode != 200 {
		t.Fatalf("admin listener /metrics: %d", res.StatusCode)
	}
	if res, _ := http.Get(h.http.URL + "/metrics"); res.StatusCode != 404 {
		t.Fatalf("/metrics on the public listener with a private admin listener: %d", res.StatusCode)
	}
}
