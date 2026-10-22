package api

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/challenge/pow"
	"github.com/iamsuriyan/doorkeep/internal/config"
	"github.com/iamsuriyan/doorkeep/internal/pseudo"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/scoring/rules"
	"github.com/iamsuriyan/doorkeep/internal/signals/payload"
	"github.com/iamsuriyan/doorkeep/internal/store"
	"github.com/iamsuriyan/doorkeep/internal/store/sqlstore"
)

const (
	origin   = "https://shop.example"
	chromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)

type harness struct {
	t      *testing.T
	srv    *Server
	http   *httptest.Server
	clock  time.Time
	secret string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	t.Setenv("DOORKEEP_DATA_DIR", t.TempDir())
	// Most tests drive the admin API through the one test server.
	t.Setenv("DOORKEEP_ADMIN_LISTEN", "public")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatal(err)
	}
	db, err := sqlstore.Open(cfg.DataDir + "/dk.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rs, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{t: t, clock: time.Now(), secret: "dk_sk_test_secret_aaaaaaaaaaaaaaaaaaaa"}
	h.srv = New(cfg, db, rs, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.srv.Now = func() time.Time { return h.clock }
	for _, s := range []*store.Site{
		{ID: "site1", Name: "Shop", SiteKey: "dk_pk_shop", SecretHash: pseudo.SecretHash(h.secret), Origins: []string{origin}, Mode: scoring.ModeEnforce},
		{ID: "site2", Name: "Other", SiteKey: "dk_pk_other", SecretHash: pseudo.SecretHash("dk_sk_other"), Origins: []string{"https://other.example"}, Mode: scoring.ModeEnforce},
	} {
		if err := db.CreateSite(t.Context(), s); err != nil {
			t.Fatal(err)
		}
	}
	h.http = httptest.NewServer(h.srv)
	t.Cleanup(h.http.Close)
	return h
}

func (h *harness) post(path, body string, hdr map[string]string) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest("POST", h.http.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func browserHeaders() map[string]string {
	return map[string]string{
		"Origin":          origin,
		"User-Agent":      chromeUA,
		"Accept-Language": "en-IN,en;q=0.9",
		"Accept":          "*/*",
		// What real Chrome sends on a fetch() to a secure context.
		"Sec-CH-UA":          `"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"`,
		"Sec-CH-UA-Mobile":   "?0",
		"Sec-CH-UA-Platform": `"Windows"`,
		"Sec-Fetch-Site":     "same-site",
		"Sec-Fetch-Mode":     "cors",
		"Sec-Fetch-Dest":     "empty",
	}
}

func (h *harness) session(action string) (nonceID, seed string) {
	code, out := h.post("/v1/session", `{"sk":"dk_pk_shop","a":"`+action+`"}`, browserHeaders())
	if code != 200 {
		h.t.Fatalf("session %d %v", code, out)
	}
	return out["nonce"].(string), out["seed"].(string)
}

// humanPayload builds a payload for a session that lasted `elapsed` on the
// server clock; the client reports slightly less (it starts after issue).
func humanPayloadAfter(n string, elapsed time.Duration) payload.Payload {
	p := humanPayload(n)
	p.T.S = p.T.I + float64(elapsed.Milliseconds()) - 300
	return p
}

func humanPayload(n string) payload.Payload {
	return payload.Payload{
		V: 1, N: n, A: "signup",
		T:    payload.Timing{I: 120, F: 2400, S: 9500, D: float64(time.Now().UnixMilli())},
		Auto: payload.Auto{WD: 0, Geo: []float64{1280, 657, 1280, 760, 0}, Plg: []int{5, 0}, Chr: 1, Voices: 12, Eng: 0, Conn: 1},
		FP: payload.FP{
			UA: chromeUA, Scr: []float64{1920, 1080, 1920, 1040, 24, 1, 0}, TZ: "Asia/Kolkata", TZO: -330,
			Lang: []string{"en-IN", "en"}, GL: []string{"Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11)"},
			CV: payload.Canvas{H: "Ab3dEf9hIjk", S: "St4tIcCanvs"}, AU: "Zm9vYmFyYmF6", FN: "PwAAAA", HC: 8, DM: 8, Tch: 16, MTP: 0, Feat: "_w8",
		},
		Beh: payload.Beh{
			Ptr: []float64{180, 5400, 0.42, 0.8, 37, 61, 0.55, 0.02, 0, 3, 40, 90, 30, 12, 5},
			Clk: []float64{3, 96, 0.3, 0.05, 0},
			Key: []float64{24, 88, 0.28, 0.6, 0.08, 0, 0},
			Scr: []float64{6, 1, 1},
			Foc: []float64{1, 1, 0, 0},
			Raf: []float64{16.7, 0.08},
		},
		Env: payload.Env{Perm: 0b0101010101, Sto: 15, Perf: []float64{0, 340, 22, 0}, Quota: 120000, SV: 1},
	}
}

func headlessPayload(n string) payload.Payload {
	p := humanPayload(n)
	p.Auto.WD = 1
	p.Auto.Leaks = 2
	p.Auto.HUA = true
	p.Auto.Geo = []float64{800, 600, 800, 600, 0}
	p.FP.UA = strings.Replace(chromeUA, "Chrome/", "HeadlessChrome/", 1)
	p.FP.GL = []string{"Google Inc. (Google)", "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (Subzero)), SwiftShader driver)"}
	p.FP.Scr = []float64{800, 600, 800, 600, 24, 1, 0}
	p.FP.TZ = "UTC"
	p.FP.TZO = 0
	p.Beh = payload.Beh{Foc: []float64{0, 0, 0, 0}}
	p.T = payload.Timing{I: 10, S: 60, D: float64(time.Now().UnixMilli())}
	return p
}

func encode(p payload.Payload) string { b, _ := json.Marshal(p); return string(b) }

func (h *harness) verify(tok, secret string, extra url.Values) map[string]any {
	h.t.Helper()
	v := url.Values{"secret": {secret}, "response": {tok}}
	for k, x := range extra {
		v[k] = x
	}
	res, err := http.Post(h.http.URL+"/v1/siteverify", "application/x-www-form-urlencoded", bytes.NewBufferString(v.Encode()))
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return out
}

func TestHumanFlowAllowed(t *testing.T) {
	h := newHarness(t)
	n, _ := h.session("signup")
	h.clock = h.clock.Add(18 * time.Second)
	hdr := browserHeaders()
	code, out := h.post("/v1/submit", encode(humanPayloadAfter(n, 18*time.Second)), hdr)
	if code != 200 || out["status"] != "ok" {
		t.Fatalf("submit %d %v", code, out)
	}
	if _, leaked := out["risk"]; leaked {
		t.Fatal("risk leaked to the client")
	}
	v := h.verify(out["token"].(string), h.secret, url.Values{"expected_action": {"signup"}, "expected_hostname": {"shop.example"}})
	if v["success"] != true {
		t.Fatalf("verify %v", v)
	}
	dk := v["doorkeep"].(map[string]any)
	if dk["outcome"] != "allow" || dk["risk"].(float64) >= 35 {
		t.Fatalf("human scored %v", dk)
	}
	if v["score"].(float64) < 0.65 {
		t.Fatalf("score %v", v["score"])
	}
	// Second verify of the same token: Turnstile semantics.
	v2 := h.verify(out["token"].(string), h.secret, nil)
	if v2["success"] != false || v2["error-codes"].([]any)[0] != "timeout-or-duplicate" {
		t.Fatalf("duplicate verify %v", v2)
	}
}

func TestHeadlessBlocked(t *testing.T) {
	h := newHarness(t)
	n, _ := h.session("signup")
	hdr := browserHeaders()
	hdr["User-Agent"] = strings.Replace(chromeUA, "Chrome/", "HeadlessChrome/", 1)
	hdr["Sec-CH-UA"] = `"Chromium";v="130", "HeadlessChrome";v="130"`
	code, out := h.post("/v1/submit", encode(headlessPayload(n)), hdr)
	if code != 200 || out["status"] != "ok" {
		t.Fatalf("submit %d %v", code, out)
	}
	v := h.verify(out["token"].(string), h.secret, nil)
	dk := v["doorkeep"].(map[string]any)
	if v["success"] != false || dk["outcome"] != "block" {
		t.Fatalf("headless not blocked: %v", v)
	}
	reasons := dk["reasons"].([]any)
	joined := ""
	for _, r := range reasons {
		joined += r.(string) + " "
	}
	for _, want := range []string{"HEADLESS_UA", "AUTOMATION_WEBDRIVER", "AUTOMATION_GLOBALS", "SOFTWARE_GPU"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing reason %s in %s", want, joined)
		}
	}
}

func TestBorderlineGetsPoWChallenge(t *testing.T) {
	h := newHarness(t)
	n, _ := h.session("signup")
	h.clock = h.clock.Add(10 * time.Second)
	p := humanPayloadAfter(n, 10*time.Second)
	p.FP.GL = []string{"Mesa", "llvmpipe (LLVM 17.0.6, 256 bits)"} // software GPU: +25
	p.Auto.CDP = true                                              // +25
	p.Auto.Notif = true                                            // +15; -25 human evidence -> 40, challenge band
	code, out := h.post("/v1/submit", encode(p), browserHeaders())
	if code != 200 || out["status"] != "challenge" || out["kind"] != "pow" {
		t.Fatalf("expected pow challenge, got %d %v", code, out)
	}
	pm := out["pow"].(map[string]any)
	params := pow.Params{Salt: pm["salt"].(string), Bits: int(pm["bits"].(float64)), N: int(pm["n"].(float64))}
	// Wrong solution first.
	bad, _ := json.Marshal(map[string]any{"n": n, "kind": "pow", "sol": make([]uint32, params.N)})
	if code, _ := h.post("/v1/challenge", string(bad), browserHeaders()); code != 400 {
		t.Fatalf("bad solution code %d", code)
	}
	good, _ := json.Marshal(map[string]any{"n": n, "kind": "pow", "sol": pow.Solve(n, params)})
	code, out = h.post("/v1/challenge", string(good), browserHeaders())
	if code != 200 || out["status"] != "ok" {
		t.Fatalf("solve %d %v", code, out)
	}
	v := h.verify(out["token"].(string), h.secret, nil)
	dk := v["doorkeep"].(map[string]any)
	if v["success"] != true || dk["challenge"] != "pow" {
		t.Fatalf("after pow: %v", v)
	}
	// Reusing the solved challenge must fail.
	if code, _ := h.post("/v1/challenge", string(good), browserHeaders()); code != 409 {
		t.Fatalf("challenge reuse code %d", code)
	}
}

func TestReplayAndCrossSite(t *testing.T) {
	h := newHarness(t)
	n, _ := h.session("signup")
	h.clock = h.clock.Add(15 * time.Second)
	body := encode(humanPayloadAfter(n, 15*time.Second))
	_, out := h.post("/v1/submit", body, browserHeaders())
	tok := out["token"].(string)

	// Same nonce again.
	if code, _ := h.post("/v1/submit", body, browserHeaders()); code != 409 {
		t.Fatalf("nonce replay code %d", code)
	}
	// Token verified with another site's secret.
	if v := h.verify(tok, "dk_sk_other", nil); v["success"] != false || v["error-codes"].([]any)[0] != "invalid-input-response" {
		t.Fatalf("cross-site verify %v", v)
	}
	// Captured payload replayed under a fresh nonce: same canvas, new seed.
	n2, _ := h.session("signup")
	h.clock = h.clock.Add(15 * time.Second)
	p := humanPayloadAfter(n2, 15*time.Second)
	_, out = h.post("/v1/submit", encode(p), browserHeaders())
	v := h.verify(out["token"].(string), h.secret, nil)
	if v["success"] != false || !strings.Contains(strings.Join(anyStrings(v["doorkeep"].(map[string]any)["reasons"]), " "), "REPLAY_CANVAS_SEED") {
		t.Fatalf("payload replay not caught: %v", v)
	}
}

func TestOriginEnforced(t *testing.T) {
	h := newHarness(t)
	hdr := browserHeaders()
	hdr["Origin"] = "https://evil.example"
	if code, _ := h.post("/v1/session", `{"sk":"dk_pk_shop"}`, hdr); code != 403 {
		t.Fatalf("foreign origin got %d", code)
	}
}

func TestMalformedPayloadRejected(t *testing.T) {
	h := newHarness(t)
	for _, body := range []string{"", "{}", `{"v":2}`, strings.Repeat("A", 40000), `{"v":1,"n":"short"}`} {
		if code, _ := h.post("/v1/submit", body, browserHeaders()); code != 400 {
			t.Errorf("body %.20q got %d", body, code)
		}
	}
}

func anyStrings(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func (h *harness) postForm(path string, v url.Values) map[string]any {
	h.t.Helper()
	res, err := http.Post(h.http.URL+path, "application/x-www-form-urlencoded", bytes.NewBufferString(v.Encode()))
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return out
}
