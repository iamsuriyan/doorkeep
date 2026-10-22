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
)

// edgeClient talks to doorkeep as a proxy would, with the browser's cookies.
func (h *harness) edgeAuth(cookie string, hdr map[string]string) *http.Response {
	req, _ := http.NewRequest("GET", h.http.URL+"/v1/auth", nil)
	req.Host = "shop.example"
	req.Header.Set("User-Agent", chromeUA)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "shop.example")
	req.Header.Set("X-Original-URI", "/search?q=doors")
	if cookie != "" {
		req.Header.Set("Cookie", edgeCookie+"="+cookie)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	return res
}

// passInterstitial performs what the hosted page does in a browser:
// session (action edge), submit, then exchange the token for the cookie.
func (h *harness) passInterstitial(t *testing.T) string {
	hdr := browserHeaders()
	_, out := h.post("/v1/session", `{"sk":"dk_pk_shop","a":"edge"}`, hdr)
	n := out["nonce"].(string)
	h.clock = h.clock.Add(6 * time.Second)
	p := humanPayloadAfter(n, 6*time.Second)
	p.A = "edge"
	p.FP.CV.H = n[:11]
	_, out = h.post("/v1/submit", encode(p), hdr)
	tok := out["token"].(string)
	body, _ := json.Marshal(map[string]string{"token": tok, "rd": "//evil.example/x"})
	jar, _ := cookiejar.New(nil)
	req, _ := http.NewRequest("POST", h.http.URL+"/v1/edge/claim", strings.NewReader(string(body)))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "shop.example")
	res, err := (&http.Client{Jar: jar}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var j map[string]string
	json.NewDecoder(res.Body).Decode(&j)
	if res.StatusCode != 200 || j["location"] != "/" {
		t.Fatalf("claim: %d %v (open redirect must be neutralised)", res.StatusCode, j)
	}
	for _, c := range res.Cookies() {
		if c.Name == edgeCookie {
			if !c.HttpOnly || !c.Secure {
				t.Fatalf("edge cookie flags: %+v", c)
			}
			// Claiming the same token twice fails (single use).
			req2, _ := http.NewRequest("POST", h.http.URL+"/v1/edge/claim", strings.NewReader(string(body)))
			for k, v := range hdr {
				req2.Header.Set(k, v)
			}
			req2.Header.Set("X-Forwarded-Proto", "https")
			req2.Header.Set("X-Forwarded-Host", "shop.example")
			if r2, _ := http.DefaultClient.Do(req2); r2.StatusCode != 409 {
				t.Fatalf("token claimed twice: %d", r2.StatusCode)
			}
			return c.Value
		}
	}
	t.Fatal("no edge cookie set")
	return ""
}

func TestEdgeMode(t *testing.T) {
	h := newHarness(t)
	h.srv.Cfg.TrustedProxies = []string{"127.0.0.1"}
	_ = h.srv.Cfg.Revalidate()
	// The site is served over https://shop.example behind the proxy.
	s, _ := h.srv.Store.SiteByID(t.Context(), "site1")
	s.Origins = append(s.Origins, "https://shop.example")
	h.srv.Store.UpdateSite(t.Context(), s)

	if res := h.edgeAuth("", nil); res.StatusCode != 401 {
		t.Fatalf("no cookie: %d", res.StatusCode)
	}
	res := h.edgeAuth("", map[string]string{"X-Doorkeep-Mode": "redirect", "Accept": "text/html"})
	if res.StatusCode != 302 || res.Header.Get("Location") != "https://shop.example/_dk/challenge?rd="+url.QueryEscape("/search?q=doors") {
		t.Fatalf("redirect mode: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	// The interstitial page renders for the site.
	req, _ := http.NewRequest("GET", h.http.URL+"/challenge?rd=/search", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "shop.example")
	pr, _ := http.DefaultClient.Do(req)
	page, _ := io.ReadAll(pr.Body)
	if pr.StatusCode != 200 || !strings.Contains(string(page), `data-sitekey="dk_pk_shop"`) || !strings.Contains(string(page), `"/search"`) {
		t.Fatalf("interstitial: %d", pr.StatusCode)
	}

	cookie := h.passInterstitial(t)
	if res := h.edgeAuth(cookie, nil); res.StatusCode != 200 || res.Header.Get("X-Doorkeep-Risk") == "" {
		t.Fatalf("valid cookie: %d", res.StatusCode)
	}
	// Cookie replayed with a different browser family is refused.
	if res := h.edgeAuth(cookie, map[string]string{"User-Agent": "curl/8.5.0"}); res.StatusCode != 401 {
		t.Fatalf("cookie with another UA: %d", res.StatusCode)
	}
	// Expired after an hour.
	h.clock = h.clock.Add(61 * time.Minute)
	if res := h.edgeAuth(cookie, nil); res.StatusCode != 401 {
		t.Fatalf("expired cookie: %d", res.StatusCode)
	}
}

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{"/a?b=1": "/a?b=1", "//evil": "/", "https://evil": "/", "/\\evil": "/", "": "/", "/x\r\nSet-Cookie: a": "/"} {
		if got := safeReturn(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}
