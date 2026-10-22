package api

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/signals/payload"
)

func (h *harness) submitPayload(ip string, mutate func(*payload.Payload)) map[string]any {
	hdr := browserHeaders()
	hdr["X-Forwarded-For"] = ip
	_, out := h.post("/v1/session", `{"sk":"dk_pk_shop","a":"signup"}`, hdr)
	n := out["nonce"].(string)
	gap := time.Duration(8000+rand.IntN(40000)) * time.Millisecond
	h.clock = h.clock.Add(gap)
	p := humanPayloadAfter(n, gap)
	p.FP.CV.H = n[:11]
	mutate(&p)
	_, out = h.post("/v1/submit", encode(p), hdr)
	if out["status"] == "challenge" && out["kind"] == "pow" {
		out = h.solvePoWWith(n, out, hdr)
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

func TestModelFlagsJointlyUnusualVector(t *testing.T) {
	h := newHarness(t)
	h.srv.Cfg.TrustedProxies = []string{"127.0.0.1"}
	_ = h.srv.Cfg.Revalidate()
	r := rand.New(rand.NewPCG(11, 12))
	for i := 0; i < 260; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", r.IntN(200), r.IntN(250), 1+r.IntN(250))
		h.submitPayload(ip, func(p *payload.Payload) {
			p.Beh.Ptr = []float64{float64(40 + r.IntN(160)), 3000 + r.Float64()*4000, 0.3 + r.Float64()*0.5, 0.5 + r.Float64()*1.5,
				float64(10 + r.IntN(50)), float64(20 + r.IntN(60)), 0.3 + r.Float64()*0.9, r.Float64() * 0.05, 0, 3, 30, 80, 30, 10, 5}
			p.Beh.Key = []float64{float64(10 + r.IntN(40)), 60 + r.Float64()*80, 0.15 + r.Float64()*0.4, 0.3 + r.Float64()*0.8, r.Float64() * 0.1, 0, 0}
			p.FP.HC = []int{4, 8, 8, 12, 16}[r.IntN(5)]
		})
	}
	st := h.srv.Models.Status("site1")
	if !st.HBOSActive {
		t.Fatalf("model not active after warm-up: %+v", st)
	}
	// Dodges every individual rule (few samples, few keys) but is jointly
	// unlike anything this site has seen.
	dk := h.submitPayload("10.201.1.1", func(p *payload.Payload) {
		p.Beh.Ptr = []float64{6, 300, 0.99, 0.01, 0, 0, 0.01, 0.5, 0, 0, 6, 0, 0, 0, 0}
		p.Beh.Key = []float64{5, 3, 0.01, 0.01, 0, 0, 0}
		p.FP.HC = 64
	})
	reasons := reasonsOf(dk)
	t.Logf("unusual vector: risk=%v outcome=%v reasons=%v", dk["risk"], dk["outcome"], reasons)
	if !slices.Contains(reasons, "MODEL_ANOMALY") {
		t.Fatalf("model did not flag the vector: %v", reasons)
	}
	if !slices.ContainsFunc(reasons, func(s string) bool { return strings.HasPrefix(s, "MODEL:beh.") }) {
		t.Fatalf("no behaviour feature named in the explanation: %v", reasons)
	}
	if dk["outcome"] == "block" {
		t.Fatal("model alone must never block")
	}
}

func TestReportTrainsSupervisedModel(t *testing.T) {
	h := newHarness(t)
	dk := h.submitPayload("127.0.0.1", func(*payload.Payload) {})
	res := h.postForm("/v1/report", url.Values{"secret": {h.secret}, "event_id": {dk["event_id"].(string)}, "label": {"bot"}})
	if res["success"] != true {
		t.Fatalf("report: %v", res)
	}
	if st := h.srv.Models.Status("site1").LR; st.Labels != 1 || st.Bots != 1 {
		t.Fatalf("label not learned: %+v", st)
	}
	// Another site's secret cannot label this site's events.
	res = h.postForm("/v1/report", url.Values{"secret": {"dk_sk_other"}, "event_id": {dk["event_id"].(string)}, "label": {"human"}})
	if res["success"] != false {
		t.Fatalf("cross-site report accepted: %v", res)
	}
}
