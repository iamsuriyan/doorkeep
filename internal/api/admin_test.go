package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/signals/payload"
)

type adminClient struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
	bear string
	hdr  map[string]string // extra request headers (e.g. X-Forwarded-For)
}

func (h *harness) admin(t *testing.T) *adminClient {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.srv.Store.CreateAdmin(t.Context(), "ops", hash, h.clock); err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	return &adminClient{t: t, base: h.http.URL, c: &http.Client{Jar: jar}}
}

func (a *adminClient) do(method, path string, body any) (int, map[string]any, []any) {
	a.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, a.base+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if a.csrf != "" {
		req.Header.Set("X-CSRF-Token", a.csrf)
	}
	if a.bear != "" {
		req.Header.Set("Authorization", "Bearer "+a.bear)
	}
	for k, v := range a.hdr {
		req.Header.Set(k, v)
	}
	res, err := a.c.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var obj map[string]any
	var arr []any
	if json.Unmarshal(raw, &obj) != nil {
		_ = json.Unmarshal(raw, &arr)
	}
	return res.StatusCode, obj, arr
}

func (a *adminClient) login(pw string) int {
	code, out, _ := a.do("POST", "/admin/v1/login", map[string]string{"user": "ops", "password": pw})
	if code == 200 {
		a.csrf = out["csrf"].(string)
	}
	return code
}

func TestAdminAuth(t *testing.T) {
	h := newHarness(t)
	a := h.admin(t)
	if code, _, _ := a.do("GET", "/admin/v1/sites", nil); code != 401 {
		t.Fatalf("unauthenticated list: %d", code)
	}
	if a.login("wrong password here") != 401 {
		t.Fatal("wrong password accepted")
	}
	if a.login("correct horse battery staple") != 200 {
		t.Fatal("login failed")
	}
	if code, _, arr := a.do("GET", "/admin/v1/sites", nil); code != 200 || len(arr) != 2 {
		t.Fatalf("list sites: %d %v", code, arr)
	}
	// Writes need the CSRF token.
	saved := a.csrf
	a.csrf = ""
	if code, _, _ := a.do("PATCH", "/admin/v1/sites/site1", map[string]any{"name": "x"}); code != 403 {
		t.Fatalf("write without CSRF: %d", code)
	}
	a.csrf = saved
	// Lockout after repeated failures.
	b := h.admin(t)
	for i := 0; i < loginMaxFails; i++ {
		b.login("nope nope nope")
	}
	if code := b.login("correct horse battery staple"); code != 429 {
		t.Fatalf("no lockout after %d failures: %d", loginMaxFails, code)
	}
	// Bearer tokens work without CSRF.
	tok, err := NewAdminToken(t.Context(), h.srv.Store, "ci", h.clock, 0)
	if err != nil {
		t.Fatal(err)
	}
	c := &adminClient{t: t, base: h.http.URL, c: http.DefaultClient, bear: tok}
	if code, _, _ := c.do("PATCH", "/admin/v1/sites/site1", map[string]any{"name": "Shop 2"}); code != 200 {
		t.Fatalf("bearer write: %d", code)
	}
	if _, out, _ := c.do("GET", "/admin/v1/sites/site1", nil); out["name"] != "Shop 2" {
		t.Fatalf("patch not applied: %v", out)
	}
	_, _, audit := a.do("GET", "/admin/v1/audit", nil)
	if len(audit) < 3 {
		t.Fatalf("audit entries missing: %v", audit)
	}
}

func TestAdminSitesValidation(t *testing.T) {
	h := newHarness(t)
	a := h.admin(t)
	a.login("correct horse battery staple")
	code, out, _ := a.do("POST", "/admin/v1/sites", map[string]any{"name": "Blog", "origins": []string{"https://blog.example/"}})
	if code != 201 || !strings.HasPrefix(out["secret"].(string), "dk_sk_") {
		t.Fatalf("create: %d %v", code, out)
	}
	for _, bad := range []map[string]any{
		{"origins": []string{"blog.example"}},
		{"origins": []string{"https://blog.example/path"}},
		{"thresholds": map[string]int{"t_challenge": 80, "t_block": 50}},
		{"mode": "yolo"},
		{"accessibility_url": "javascript:alert(1)"},
	} {
		if code, _, _ := a.do("PATCH", "/admin/v1/sites/site1", bad); code != 400 {
			t.Errorf("accepted invalid patch %v: %d", bad, code)
		}
	}
}

func TestAdminEventsRulesLabAndStats(t *testing.T) {
	h := newHarness(t)
	a := h.admin(t)
	a.login("correct horse battery staple")
	// Ten sessions, half from a "datacenter-like" software GPU.
	for i := 0; i < 10; i++ {
		h.submitPayload("127.0.0.1", func(p *payload.Payload) {
			if i%2 == 0 {
				p.FP.GL = []string{"Mesa", "llvmpipe (LLVM 17)"}
			}
		})
	}
	_, _, evs := a.do("GET", "/admin/v1/sites/site1/events?limit=50", nil)
	if len(evs) != 10 {
		t.Fatalf("events: %d", len(evs))
	}
	first := evs[0].(map[string]any)
	id := first["id"].(string)
	if _, ok := first["ip24_hash"]; ok {
		t.Fatal("IP hash exposed in event list")
	}
	// Event detail exposes grouped features; another site cannot read it.
	if code, out, _ := a.do("GET", "/admin/v1/sites/site1/events/"+id, nil); code != 200 || out["feature_groups"] == nil {
		t.Fatalf("event detail: %d", code)
	}
	if code, _, _ := a.do("GET", "/admin/v1/sites/site2/events/"+id, nil); code != 404 {
		t.Fatalf("cross-site event read: %d", code)
	}
	// Label an event; the supervised model learns it.
	if code, _, _ := a.do("POST", "/admin/v1/sites/site1/events/"+id+"/label", map[string]string{"label": "bot"}); code != 200 {
		t.Fatalf("label: %d", code)
	}
	if h.srv.Models.Status("site1").LR.Labels != 1 {
		t.Fatal("label did not reach the model")
	}
	// Rule lab: what would SOFTWARE_GPU at weight 60 do over the last week?
	code, lab, _ := a.do("POST", "/admin/v1/sites/site1/rules-lab", map[string]any{"rule": "SOFTWARE_GPU", "override": map[string]any{"weight": 60}})
	if code != 200 || lab["fired"].(float64) != 5 || lab["changed"].(float64) != 5 {
		t.Fatalf("lab: %d %v", code, lab)
	}
	// A broken custom rule is rejected; a valid one changes live scoring.
	if code, _, _ := a.do("PUT", "/admin/v1/sites/site1/rules/MY_RULE", map[string]any{"custom": true, "when": "fp.nope == 1", "weight": 10}); code != 400 {
		t.Fatalf("broken rule accepted: %d", code)
	}
	if code, _, _ := a.do("PUT", "/admin/v1/sites/site1/rules/IP_DATACENTER", map[string]any{"mode": "shadow"}); code != 200 {
		t.Fatalf("override: %d", code)
	}
	_, _, rl := a.do("GET", "/admin/v1/sites/site1/rules", nil)
	found := false
	for _, x := range rl {
		m := x.(map[string]any)
		if m["id"] == "IP_DATACENTER" {
			found = m["mode"] == "shadow" && m["overridden"] == true
		}
	}
	if !found {
		t.Fatal("override not visible in rule list")
	}
	// Stats: live hour counts all ten.
	h.clock = h.clock.Add(time.Minute)
	code, st, _ := a.do("GET", "/admin/v1/sites/site1/stats?range=24h", nil)
	if code != 200 || st["total"].(float64) != 10 {
		t.Fatalf("stats: %d %v", code, st["total"])
	}
	// Rollup then stats again: same total from aggregates.
	h.clock = h.clock.Add(2 * time.Hour)
	if err := h.srv.Rollup(t.Context(), 3); err != nil {
		t.Fatal(err)
	}
	_, st, _ = a.do("GET", "/admin/v1/sites/site1/stats?range=24h", nil)
	if st["total"].(float64) != 10 {
		t.Fatalf("stats after rollup: %v", st["total"])
	}
	// DSAR delete.
	if code, _, _ := a.do("DELETE", "/admin/v1/sites/site1/events/"+id, nil); code != 204 {
		t.Fatalf("delete: %d", code)
	}
}

func TestAdminListenSeparatesAdmin(t *testing.T) {
	h := newHarness(t)
	h.srv.Cfg.AdminListen = "127.0.0.1:0"
	h.srv.routes()
	// Public listener: no dashboard, no admin API.
	for _, p := range []string{"/admin/", "/admin/v1/sites"} {
		res, err := http.Get(h.http.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		if res.StatusCode != 404 {
			t.Fatalf("public %s: %d, want 404", p, res.StatusCode)
		}
	}
	// Admin handler: present (401 without login).
	adm := httptest.NewServer(h.srv.AdminHandler())
	defer adm.Close()
	res, _ := http.Get(adm.URL + "/admin/v1/sites")
	if res.StatusCode != 401 {
		t.Fatalf("admin listener: %d, want 401", res.StatusCode)
	}
	// And the public API is not on the admin listener.
	res, _ = http.Post(adm.URL+"/v1/siteverify", "application/x-www-form-urlencoded", nil)
	if res.StatusCode != 404 {
		t.Fatalf("public API on admin listener: %d", res.StatusCode)
	}
}

func TestBulkLabel(t *testing.T) {
	h := newHarness(t)
	ids := map[string]string{}
	for i, headless := range []bool{false, false, true, true, true} {
		n, _ := h.session("signup")
		h.clock = h.clock.Add(10 * time.Second)
		p := humanPayloadAfter(n, 10*time.Second)
		p.FP.CV.H = n[:11]
		if headless {
			p.Auto.WD = 1
		}
		h.post("/v1/submit", encode(p), browserHeaders())
		nn, _ := h.srv.Store.Get(t.Context(), n)
		ids[fmt.Sprint(i)] = nn.EventID
	}
	a := h.admin(t)
	a.login("correct horse battery staple")

	// By filter: every blocked event.
	code, out, _ := a.do("POST", "/admin/v1/sites/site1/labels", map[string]any{"label": "bot", "filter": map[string]string{"outcome": "block"}})
	if code != 200 || out["labelled"] != float64(3) {
		t.Fatalf("by filter: %d %v", code, out)
	}
	// By ids, including one from another site and one unknown: ignored.
	code, out, _ = a.do("POST", "/admin/v1/sites/site1/labels", map[string]any{"label": "human", "ids": []string{ids["0"], ids["1"], "evt_unknown"}})
	if code != 200 || out["labelled"] != float64(2) {
		t.Fatalf("by ids: %d %v", code, out)
	}
	_, _, arr := a.do("GET", "/admin/v1/sites/site1/events?label=bot", nil)
	if len(arr) != 3 {
		t.Fatalf("bot-labelled events: %d", len(arr))
	}
	if st := h.srv.Models.Status("site1"); st.LR.Labels != 5 {
		t.Fatalf("model saw %d labels, want 5", st.LR.Labels)
	}
	// Cross-site ids are never labelled.
	code, out, _ = a.do("POST", "/admin/v1/sites/site2/labels", map[string]any{"label": "bot", "ids": []string{ids["0"]}})
	if code != 200 || out["labelled"] != float64(0) {
		t.Fatalf("cross-site: %d %v", code, out)
	}
	// Exactly one of ids or filter.
	for _, bad := range []map[string]any{{"label": "bot"}, {"label": "bot", "ids": []string{"x"}, "filter": map[string]string{}}, {"label": "spam", "ids": []string{"x"}}} {
		if code, _, _ := a.do("POST", "/admin/v1/sites/site1/labels", bad); code != 400 {
			t.Errorf("%v: %d", bad, code)
		}
	}
}
