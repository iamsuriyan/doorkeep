package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

func TestSafeReturnRejectsBrowserNormalisedHosts(t *testing.T) {
	bad := []string{"/\t/evil.com", "/\n/evil.com", "/ /evil.com", "/\\evil.com", "/x\\y", "/\x00", "/\x7f", "http://evil", "evil", "//evil"}
	for _, in := range bad {
		if got := safeReturn(in); got != "/" {
			t.Errorf("%q passed as %q", in, got)
		}
	}
	for _, in := range []string{"/", "/search?q=doors", "/a/b#frag", "/%09/x"} {
		if got := safeReturn(in); got != in {
			t.Errorf("%q rewritten to %q", in, got)
		}
	}
}

// edgeHarness serves site1 at https://shop.example behind a trusted proxy.
func edgeHarness(t *testing.T) *harness {
	h := newHarness(t)
	h.srv.Cfg.TrustedProxies = []string{"127.0.0.1"}
	if err := h.srv.Cfg.Revalidate(); err != nil {
		t.Fatal(err)
	}
	s, _ := h.srv.Store.SiteByID(t.Context(), "site1")
	s.Origins = append(s.Origins, "https://shop.example")
	if err := h.srv.Store.UpdateSite(t.Context(), s); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestInterstitialNeutralisesEncodedTab(t *testing.T) {
	h := edgeHarness(t)
	req, _ := http.NewRequest("GET", h.http.URL+"/challenge?rd="+url.QueryEscape("/\t/evil.com"), nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "shop.example")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if strings.Contains(string(page), "evil.com") {
		t.Fatal("interstitial carried the tab-smuggled host into the page")
	}
}

func TestEdgeListsApplyToExistingCookies(t *testing.T) {
	h := edgeHarness(t)
	cookie := h.passInterstitial(t)
	if res := h.edgeAuth(cookie, nil); res.StatusCode != 200 {
		t.Fatalf("valid cookie: %d", res.StatusCode)
	}
	add := func(action scoring.ListAction) {
		if err := h.srv.Store.AddListEntry(t.Context(), &store.ListEntry{SiteID: "site1", Kind: "ip", Value: "127.0.0.1", Action: action}); err != nil {
			t.Fatal(err)
		}
	}
	// An always_challenge entry added after the cookie was minted applies:
	// a cookie earned without a challenge no longer passes.
	add(scoring.ListAlwaysChallenge)
	if res := h.edgeAuth(cookie, nil); res.StatusCode != 401 {
		t.Fatalf("always_challenge with an unchallenged cookie: %d", res.StatusCode)
	}
	add(scoring.ListDeny)
	if res := h.edgeAuth(cookie, nil); res.StatusCode != 403 {
		t.Fatalf("deny with a valid cookie: %d", res.StatusCode)
	}
}

func TestEdgeStrictIP(t *testing.T) {
	h := edgeHarness(t)
	s, _ := h.srv.Store.SiteByID(t.Context(), "site1")
	s.StrictIP = true
	h.srv.Store.UpdateSite(t.Context(), s)
	// Mint just before UTC midnight; the cookie must survive the day change.
	h.clock = time.Date(2026, 10, 22, 23, 59, 40, 0, time.UTC)
	cookie := h.passInterstitial(t)
	h.clock = h.clock.Add(2 * time.Minute)
	if res := h.edgeAuth(cookie, nil); res.StatusCode != 200 {
		t.Fatalf("same network after midnight: %d", res.StatusCode)
	}
	if res := h.edgeAuth(cookie, map[string]string{"X-Forwarded-For": "198.51.100.7"}); res.StatusCode != 401 {
		t.Fatalf("cookie from another network: %d", res.StatusCode)
	}
}

// A session that crosses UTC midnight must not report an IP change.
func TestSubmitAcrossMidnightKeepsIP(t *testing.T) {
	h := newHarness(t)
	h.clock = time.Date(2026, 10, 22, 23, 59, 55, 0, time.UTC)
	n, _ := h.session("signup")
	h.clock = h.clock.Add(10 * time.Second)
	p := humanPayloadAfter(n, 10*time.Second)
	p.FP.CV.H = n[:11]
	_, out := h.post("/v1/submit", encode(p), browserHeaders())
	v := h.verify(out["token"].(string), h.secret, nil)
	for _, r := range v["doorkeep"].(map[string]any)["reasons"].([]any) {
		if strings.Contains(r.(string), "IP") && strings.Contains(r.(string), "CHANG") {
			t.Fatalf("false IP change across midnight: %v", v)
		}
	}
}

func TestSubmitHonoursDenyAndAlwaysChallenge(t *testing.T) {
	h := newHarness(t)
	submit := func() map[string]any {
		n, _ := h.session("signup")
		h.clock = h.clock.Add(10 * time.Second)
		p := humanPayloadAfter(n, 10*time.Second)
		p.FP.CV.H = n[:11]
		_, out := h.post("/v1/submit", encode(p), browserHeaders())
		return out
	}
	if out := submit(); out["status"] != "ok" {
		t.Fatalf("baseline human: %v", out)
	}
	h.srv.Store.AddListEntry(t.Context(), &store.ListEntry{SiteID: "site1", Kind: "ip", Value: "127.0.0.1", Action: scoring.ListAlwaysChallenge})
	if out := submit(); out["status"] != "challenge" {
		t.Fatalf("always_challenge: %v", out)
	}
	h.srv.Store.AddListEntry(t.Context(), &store.ListEntry{SiteID: "site1", Kind: "cidr", Value: "127.0.0.0/8", Action: scoring.ListDeny})
	out := submit()
	v := h.verify(out["token"].(string), h.secret, nil)
	if v["success"] != false || v["doorkeep"].(map[string]any)["outcome"] != "block" {
		t.Fatalf("deny list: %v", v)
	}
}

func TestLogoutNeedsCSRF(t *testing.T) {
	h := newHarness(t)
	a := h.admin(t)
	if a.login("correct horse battery staple") != 200 {
		t.Fatal("login")
	}
	saved := a.csrf
	a.csrf = ""
	if code, _, _ := a.do("POST", "/admin/v1/logout", nil); code != 403 {
		t.Fatalf("logout without CSRF: %d", code)
	}
	if code, _, _ := a.do("GET", "/admin/v1/me", nil); code != 200 {
		t.Fatal("session ended by a CSRF-less logout")
	}
	a.csrf = saved
	if code, _, _ := a.do("POST", "/admin/v1/logout", nil); code != 204 {
		t.Fatalf("logout: %d", code)
	}
	if code, _, _ := a.do("GET", "/admin/v1/me", nil); code != 401 {
		t.Fatalf("session survived logout: %d", code)
	}
}

// Failed logins from one network must not lock the admin out everywhere.
func TestLoginLockoutIsPerNetwork(t *testing.T) {
	h := newHarness(t)
	h.srv.Cfg.TrustedProxies = []string{"127.0.0.1"}
	h.srv.Cfg.Revalidate()
	attacker := h.admin(t)
	attacker.hdr = map[string]string{"X-Forwarded-For": "203.0.113.5"}
	for range loginMaxFails {
		attacker.login("nope nope nope")
	}
	if code := attacker.login("correct horse battery staple"); code != 429 {
		t.Fatalf("attacker network not locked: %d", code)
	}
	jar, _ := cookiejar.New(nil)
	owner := &adminClient{t: t, base: h.http.URL, c: &http.Client{Jar: jar}, hdr: map[string]string{"X-Forwarded-For": "198.51.100.7"}}
	if code := owner.login("correct horse battery staple"); code != 200 {
		t.Fatalf("owner locked out by another network's failures: %d", code)
	}
}

func TestSessionCookieSecureOnlyViaTrustedProxy(t *testing.T) {
	h := newHarness(t)
	a := h.admin(t)
	a.hdr = map[string]string{"X-Forwarded-Proto": "https"}
	req, _ := http.NewRequest("POST", h.http.URL+"/admin/v1/login", strings.NewReader(`{"user":"ops","password":"correct horse battery staple"}`))
	req.Header.Set("X-Forwarded-Proto", "https")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	for _, c := range res.Cookies() {
		if c.Name == sessionCookie && c.Secure {
			t.Fatal("untrusted X-Forwarded-Proto set the Secure flag")
		}
	}
}

func TestAdminTokenLifecycle(t *testing.T) {
	h := newHarness(t)
	a := h.admin(t)
	a.login("correct horse battery staple")
	code, out, _ := a.do("POST", "/admin/v1/tokens", map[string]any{"name": "terraform", "ttl_days": 1})
	if code != 201 {
		t.Fatalf("create token: %d %v", code, out)
	}
	bot := &adminClient{t: t, base: h.http.URL, c: http.DefaultClient, bear: out["token"].(string)}
	if code, _, _ := bot.do("GET", "/admin/v1/sites", nil); code != 200 {
		t.Fatalf("fresh token: %d", code)
	}
	if code, _, arr := a.do("GET", "/admin/v1/tokens", nil); code != 200 || len(arr) != 1 || arr[0].(map[string]any)["last_used_at"] == nil {
		t.Fatalf("list tokens: %d %v", code, arr)
	}
	h.clock = h.clock.Add(25 * time.Hour)
	if code, _, _ := bot.do("GET", "/admin/v1/sites", nil); code != 401 {
		t.Fatalf("expired token: %d", code)
	}
	// Revocation.
	a.login("correct horse battery staple")
	_, out, _ = a.do("POST", "/admin/v1/tokens", map[string]any{"name": "ci"})
	bot.bear = out["token"].(string)
	if code, _, _ := a.do("DELETE", "/admin/v1/tokens/"+out["id"].(string), nil); code != 204 {
		t.Fatalf("revoke: %d", code)
	}
	if code, _, _ := bot.do("GET", "/admin/v1/sites", nil); code != 401 {
		t.Fatalf("revoked token: %d", code)
	}
	if code, _, _ := bot.do("GET", "/admin/v1/sites", nil); code != 401 {
		t.Fatal("invalid bearer accepted")
	}
	if code, _, _ := a.do("DELETE", "/admin/v1/tokens/zzzz", nil); code != 404 {
		t.Fatalf("revoke unknown: %d", code)
	}
}

func TestAdminMaintenanceEndpoints(t *testing.T) {
	h := newHarness(t)
	a := h.admin(t)
	a.login("correct horse battery staple")
	code, out, _ := a.do("POST", "/admin/v1/sites/site1/rotate-secret", nil)
	if code != 200 || !strings.HasPrefix(out["secret"].(string), "dk_sk_") {
		t.Fatalf("rotate: %d %v", code, out)
	}
	if v := h.verify("x", h.secret, nil); v["error-codes"].([]any)[0] != "invalid-input-secret" {
		t.Fatalf("old secret still valid: %v", v)
	}
	if code, _, _ := a.do("POST", "/admin/v1/sites/site1/model/promote", map[string]bool{"on": true}); code != 409 {
		t.Fatalf("promote without labels: %d", code)
	}
	for _, p := range []string{"/admin/v1/privacy", "/admin/v1/ipdata", "/admin/v1/features", "/admin/v1/audit"} {
		if code, _, _ := a.do("GET", p, nil); code != 200 {
			t.Errorf("%s: %d", p, code)
		}
	}
	// Internal errors never leak details: an unknown site is a clean 404.
	if code, out, _ := a.do("GET", "/admin/v1/sites/nope/events", nil); code != 404 || strings.Contains(out["detail"].(string), "sql") {
		t.Fatalf("unknown site: %d %v", code, out)
	}
}

// Session expiry: a session older than sessionTTL is refused.
func TestAdminSessionExpires(t *testing.T) {
	h := newHarness(t)
	a := h.admin(t)
	a.login("correct horse battery staple")
	h.clock = h.clock.Add(sessionTTL + time.Minute)
	if code, _, _ := a.do("GET", "/admin/v1/me", nil); code != 401 {
		t.Fatalf("expired session: %d", code)
	}
}

// nginx sends the return path unencoded; its own "&" parameters must survive.
func TestInterstitialRawReturnFromNginx(t *testing.T) {
	h := edgeHarness(t)
	for raw, want := range map[string]string{
		"rd=/search?q=doors&page=2":           "/search?q=doors&page=2",
		"rd=" + url.QueryEscape("/a?b=1&c=2"): "/a?b=1&c=2",
		"rd=//evil.example/x&y=1":             "/",
	} {
		req, _ := http.NewRequest("GET", h.http.URL+"/challenge?"+raw, nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "shop.example")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		page, _ := io.ReadAll(res.Body)
		res.Body.Close()
		// The page embeds rd as a JS (JSON-compatible) string literal.
		_, lit, _ := strings.Cut(string(page), "var rd = ")
		lit, _, _ = strings.Cut(lit, ";")
		var got string
		if err := json.Unmarshal([]byte(lit), &got); err != nil || got != want {
			t.Errorf("%s: rd %q (%v), want %q", raw, got, err, want)
		}
	}
}
