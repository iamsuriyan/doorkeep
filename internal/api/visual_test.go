package api

import (
	"encoding/json"
	"image/png"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/challenge/pow"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
)

// highBand builds a submit that lands at risk ~60: above the point where
// proof of work alone can clear the challenge band.
func (h *harness) highBand() (nonceID string, out map[string]any) {
	n, _ := h.session("signup")
	h.clock = h.clock.Add(10 * time.Second)
	p := humanPayloadAfter(n, 10*time.Second)
	p.FP.GL = []string{"Mesa", "llvmpipe (LLVM 17.0.6, 256 bits)"} // +25
	p.Auto.Notif = true                                            // +15
	p.Auto.CDP = true                                              // +25
	p.Auto.Plg = []int{5, 2}                                       // +20
	p.FP.CV.H = n[:11]                                             // fresh seeded canvas per session
	_, out = h.post("/v1/submit", encode(p), browserHeaders())
	return n, out
}

func (h *harness) solvePoW(n string, out map[string]any) map[string]any {
	return h.solvePoWWith(n, out, browserHeaders())
}

func (h *harness) solvePoWWith(n string, out map[string]any, hdr map[string]string) map[string]any {
	pm := out["pow"].(map[string]any)
	params := pow.Params{Salt: pm["salt"].(string), Bits: int(pm["bits"].(float64)), N: int(pm["n"].(float64))}
	body, _ := json.Marshal(map[string]any{"n": n, "kind": "pow", "sol": pow.Solve(n, params)})
	_, res := h.post("/v1/challenge", string(body), hdr)
	return res
}

func (h *harness) answer(n, ans string) (int, map[string]any) {
	body, _ := json.Marshal(map[string]any{"n": n, "kind": "visual", "answer": ans})
	return h.post("/v1/challenge", string(body), browserHeaders())
}

func TestPoWEscalatesToVisual(t *testing.T) {
	h := newHarness(t)
	n, out := h.highBand()
	if out["kind"] != "pow" {
		t.Fatalf("expected pow first: %v", out)
	}
	out = h.solvePoW(n, out)
	if out["status"] != "challenge" || out["kind"] != "visual" {
		t.Fatalf("expected escalation to visual: %v", out)
	}
	vi := out["visual"].(map[string]any)

	// Media is served while the challenge is open.
	res, err := http.Get(h.http.URL + vi["image"].(string))
	if err != nil || res.StatusCode != 200 {
		t.Fatalf("image %v %v", err, res.StatusCode)
	}
	if _, err := png.Decode(res.Body); err != nil {
		t.Fatalf("not a PNG: %v", err)
	}
	res.Body.Close()
	res, _ = http.Get(h.http.URL + vi["audio"].(string))
	if res.StatusCode != 200 || res.Header.Get("Content-Type") != "audio/wav" {
		t.Fatalf("audio %d %s", res.StatusCode, res.Header.Get("Content-Type"))
	}
	res.Body.Close()

	// A wrong answer leaves attempts; the right one (case-insensitive) wins.
	if code, r := h.answer(n, "zzzzz"); code != 200 || r["status"] != "retry" || r["visual"].(map[string]any)["attempts_left"].(float64) != 2 {
		t.Fatalf("wrong answer: %d %v", code, r)
	}
	_, r := h.answer(n, strings.ToLower(h.srv.Visual.Answer(n)))
	if r["status"] != "ok" {
		t.Fatalf("right answer: %v", r)
	}
	v := h.verify(r["token"].(string), h.secret, nil)
	dk := v["doorkeep"].(map[string]any)
	if v["success"] != true || dk["challenge"] != "visual" {
		t.Fatalf("verify after visual: %v", v)
	}
	// Media is gone once the challenge is closed.
	res, _ = http.Get(h.http.URL + vi["image"].(string))
	if res.StatusCode != 404 {
		t.Fatalf("image still served after solve: %d", res.StatusCode)
	}
}

func TestVisualExhaustion(t *testing.T) {
	h := newHarness(t)
	n, out := h.highBand()
	h.solvePoW(n, out)
	for i := 0; i < 2; i++ {
		if _, r := h.answer(n, "zzzzz"); r["status"] != "retry" {
			t.Fatalf("attempt %d: %v", i, r)
		}
	}
	if code, r := h.answer(n, "zzzzz"); code != 409 || r["error"] != "challenge-exhausted" {
		t.Fatalf("third miss: %d %v", code, r)
	}
	// Even the right answer is refused now.
	if code, _ := h.answer(n, h.srv.Visual.Answer(n)); code != 409 {
		t.Fatalf("burned nonce accepted an answer: %d", code)
	}
}

func TestVisualAnswerBoundToNonce(t *testing.T) {
	h := newHarness(t)
	n1, o1 := h.highBand()
	h.solvePoW(n1, o1)
	n2, o2 := h.highBand()
	h.solvePoW(n2, o2)
	if _, r := h.answer(n2, h.srv.Visual.Answer(n1)); r["status"] == "ok" {
		t.Fatal("answer for one nonce accepted for another")
	}
}

// In challenge_only mode block-band traffic, even with a proof floor, is
// challenged rather than blocked, and must pass the visual challenge: proof
// of work alone never clears it.
func TestChallengeOnlyBlockBandGoesToVisual(t *testing.T) {
	h := newHarness(t)
	site, _ := h.srv.Store.SiteByID(t.Context(), "site1")
	site.Mode = scoring.ModeChallengeOnly
	if err := h.srv.Store.UpdateSite(t.Context(), site); err != nil {
		t.Fatal(err)
	}
	n, _ := h.session("signup")
	h.clock = h.clock.Add(10 * time.Second)
	p := humanPayloadAfter(n, 10*time.Second)
	p.Auto.WD = 1 // navigator.webdriver: proof floor in the block band
	p.Auto.CDP = true
	p.FP.CV.H = n[:11]
	_, out := h.post("/v1/submit", encode(p), browserHeaders())
	if out["status"] != "challenge" || out["kind"] != "pow" {
		t.Fatalf("challenge_only must challenge block-band risk: %v", out)
	}
	out = h.solvePoW(n, out)
	if out["status"] != "challenge" || out["kind"] != "visual" {
		t.Fatalf("proof of work alone cleared block-band risk: %v", out)
	}
	_, r := h.answer(n, h.srv.Visual.Answer(n))
	if r["status"] != "ok" {
		t.Fatalf("visual answer: %v", r)
	}
	v := h.verify(r["token"].(string), h.secret, nil)
	if v["success"] != true {
		t.Fatalf("challenge_only after visual: %v", v)
	}
}
