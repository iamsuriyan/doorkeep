package api

import (
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/nonce"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/signals/payload"
	"github.com/iamsuriyan/doorkeep/internal/store"
	"github.com/iamsuriyan/doorkeep/internal/token"
)

// Edge mode (design section 8.3): a reverse proxy asks GET /v1/auth before
// serving a protected path (nginx auth_request, Caddy forward_auth, Traefik
// ForwardAuth). A valid __dk_edge cookie passes; otherwise the browser is
// sent to the hosted interstitial at /challenge, which runs the normal
// snippet flow and exchanges the resulting token for the cookie.

const (
	edgeCookie = "__dk_edge"
	edgeTTL    = time.Hour
	edgeAction = "edge"
)

// siteForRequest finds the site whose origins include the request's
// scheme://host as seen by the client (forwarded headers from trusted
// proxies, otherwise the request itself).
func (s *Server) siteForRequest(r *http.Request) (*store.Site, string) {
	host := r.Host
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	if s.fromTrustedProxy(r) {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = strings.TrimSpace(strings.Split(h, ",")[0])
		}
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			proto = strings.TrimSpace(strings.Split(p, ",")[0])
		}
	}
	origin := proto + "://" + host
	sites, err := s.Store.ListSites(r.Context())
	if err != nil {
		return nil, origin
	}
	for _, site := range sites {
		for _, o := range site.Origins {
			if strings.EqualFold(strings.TrimRight(o, "/"), origin) {
				return site, origin
			}
		}
	}
	return nil, origin
}

func uaFamilyOf(ua string) string {
	f, _ := payload.UAFamily(ua)
	return f
}

// handleEdgeAuth answers the proxy's sub-request.
func (s *Server) handleEdgeAuth(w http.ResponseWriter, r *http.Request) {
	site, origin := s.siteForRequest(r)
	if site == nil {
		http.Error(w, "unknown site", http.StatusForbidden)
		return
	}
	ip := s.clientIP(r)
	info := s.IP.Get().Lookup(ip)
	if info.Crawler != "" {
		s.metrics.inc("doorkeep_edge_decisions_total", "result", "pass")
		w.Header().Set("X-Doorkeep-Reasons", "VERIFIED_CRAWLER_"+strings.ToUpper(info.Crawler))
		w.Header().Set("X-Doorkeep-Risk", "0")
		w.WriteHeader(http.StatusOK)
		return
	}
	now := s.Now()
	act, code := s.matchLists(r.Context(), site.ID, ip, info, "", r.UserAgent(), now)
	switch act {
	case scoring.ListAllow:
		s.metrics.inc("doorkeep_edge_decisions_total", "result", "pass")
		w.Header().Set("X-Doorkeep-Reasons", code)
		w.Header().Set("X-Doorkeep-Risk", "0")
		w.WriteHeader(http.StatusOK)
		return
	case scoring.ListDeny:
		s.metrics.inc("doorkeep_edge_decisions_total", "result", "deny")
		http.Error(w, "denied", http.StatusForbidden)
		return
	}
	if c, err := r.Cookie(edgeCookie); err == nil {
		// Lists are checked on every request, so an always_challenge entry
		// added after the cookie was minted still applies: only a cookie
		// earned through a solved challenge satisfies it.
		if cl, err := s.Ring.Open(c.Value, site.SiteKey); err == nil && cl.Action == edgeAction &&
			cl.Outcome == string(scoring.Allow) && cl.UA == uaFamilyOf(r.UserAgent()) &&
			(act != scoring.ListAlwaysChallenge || (cl.Challenge != "" && cl.Challenge != "none")) &&
			(!site.StrictIP || s.Keys.IPHashMatches(ip, cl.IP24, time.Unix(cl.IssuedAt, 0), now)) {
			s.metrics.inc("doorkeep_edge_decisions_total", "result", "pass")
			w.Header().Set("X-Doorkeep-Risk", strconv.Itoa(cl.Risk))
			w.Header().Set("X-Doorkeep-Reasons", strings.Join(cl.Reasons, ","))
			w.WriteHeader(http.StatusOK)
			return
		}
	}
	s.metrics.inc("doorkeep_edge_decisions_total", "result", "check")
	// Caddy's forward_auth copies a 3xx Location; nginx maps 401 to a
	// redirect itself (error_page). Browsers get redirected, API clients 401.
	if r.Header.Get("X-Doorkeep-Mode") == "redirect" && strings.Contains(r.Header.Get("Accept"), "text/html") {
		rd := r.Header.Get("X-Original-URI")
		if rd == "" {
			rd = r.Header.Get("X-Forwarded-Uri")
		}
		// Absolute, on the site's own origin: Traefik's ForwardAuth resolves a
		// relative Location against the auth server's address, which would
		// send the browser to doorkeep's internal URL. origin comes from a
		// registered site, so this is never an open redirect.
		http.Redirect(w, r, origin+"/_dk/challenge?rd="+url.QueryEscape(safeReturn(rd)), http.StatusFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(`{"error":"doorkeep-check-required","challenge":"/_dk/challenge"}` + "\n"))
}

// safeReturn only allows same-site relative paths, never //host or schemes.
// Browsers strip ASCII tab and newline from URLs and treat a backslash like
// a slash, so "/\t/evil.com" or "/\\evil.com" would become "//evil.com":
// any control character, space or backslash is rejected outright, and the
// result must parse with no scheme or host.
func safeReturn(rd string) string {
	if !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || len(rd) > 2048 {
		return "/"
	}
	for i := 0; i < len(rd); i++ {
		if c := rd[i]; c <= 0x20 || c == 0x7f || c == '\\' {
			return "/"
		}
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return rd
}

// returnParam reads the interstitial's rd parameter. doorkeep's own
// redirects encode it (rd=%2Fsearch%3Fq%3D...), but nginx cannot encode, so
// its error_page sends the raw $request_uri (rd=/search?q=a&b=c). A raw value
// starts with "/" and runs to the end of the query string, so its own "&"
// parameters are kept rather than split off.
func returnParam(r *http.Request) string {
	if raw, ok := strings.CutPrefix(r.URL.RawQuery, "rd=/"); ok {
		return "/" + raw
	}
	return r.URL.Query().Get("rd")
}

var interstitial = template.Must(template.New("i").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Checking your browser</title>
<meta name="robots" content="noindex">
<style>
:root{color-scheme:light dark;--bg:#fcfcfb;--fg:#0b0b0b;--muted:#52514e;--line:#e2e1dc;--accent:#256abf}
@media (prefers-color-scheme:dark){:root{--bg:#1a1a19;--fg:#fff;--muted:#c3c2b7;--line:#2f2f2c;--accent:#6da7ec}}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:440px;padding:24px;text-align:center}
h1{font-size:20px;margin:0 0 8px}
p{color:var(--muted);margin:0 0 8px}
.bar{height:4px;background:var(--line);border-radius:2px;overflow:hidden;margin:18px auto;width:200px}
.bar i{display:block;height:100%;width:40%;background:var(--accent);animation:m 1.2s ease-in-out infinite}
@keyframes m{0%{transform:translateX(-100%)}100%{transform:translateX(250%)}}
@media (prefers-reduced-motion:reduce){.bar i{animation:none;width:100%}}
a{color:var(--accent)}
</style>
<script src="v1/dk.js" data-sitekey="{{.SiteKey}}" async></script>
</head><body><main>
<h1>Checking your browser</h1>
<p id="msg" role="status" aria-live="polite">This takes a moment and happens once an hour. No personal data leaves this site.</p>
<div class="bar" aria-hidden="true"><i></i></div>
<noscript><p>Please enable JavaScript to continue.</p></noscript>
{{if .Accessibility}}<p><a href="{{.Accessibility}}">Having trouble? Use another way to continue.</a></p>{{end}}
</main>
<script>
(function(){
  var rd = {{.Return}};
  var msg = document.getElementById("msg");
  function fail(t){ msg.textContent = t; document.querySelector(".bar").style.display="none"; }
  function go(){
    if (!window.doorkeep) return setTimeout(go, 50);
    window.doorkeep.execute(undefined, {action: "edge"}).then(function(tok){
      return fetch("v1/edge/claim", {method:"POST", headers:{"Content-Type":"text/plain"}, body: JSON.stringify({token: tok, rd: rd}), credentials:"same-origin"});
    }).then(function(r){ return r.json().then(function(j){ return {ok: r.ok, j: j}; }); })
      .then(function(x){ if (x.ok && x.j.location) location.replace(x.j.location); else fail("We could not verify your browser. Reload the page to try again."); })
      .catch(function(){ fail("We could not verify your browser. Reload the page to try again."); });
  }
  go();
})();
</script>
</body></html>`))

// handleInterstitial serves the hosted check page (via the proxy at
// /_dk/challenge, so relative URLs resolve to /_dk/v1/...).
func (s *Server) handleInterstitial(w http.ResponseWriter, r *http.Request) {
	site, _ := s.siteForRequest(r)
	if site == nil {
		http.Error(w, "unknown site", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self'; connect-src 'self'; worker-src blob:; frame-ancestors 'none'; base-uri 'self'")
	_ = interstitial.Execute(w, map[string]any{
		"SiteKey": site.SiteKey, "Return": safeReturn(returnParam(r)), "Accessibility": site.AccessibilityURL,
	})
}

// handleEdgeClaim exchanges a minted snippet token for the edge cookie. It
// consumes the token exactly like siteverify (single use).
func (s *Server) handleEdgeClaim(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
		RD    string `json:"rd"`
	}
	if err := decodeJSON(r, &in, 8<<10); err != nil || in.Token == "" {
		clientError(w, http.StatusBadRequest, "bad-request")
		return
	}
	site, origin := s.siteForRequest(r)
	if site == nil || !originAllowed(site, requestOrigin(r)) {
		clientError(w, http.StatusForbidden, "origin-not-allowed")
		return
	}
	c, err := s.Ring.Open(in.Token, site.SiteKey)
	if err != nil || c.Action != edgeAction {
		clientError(w, http.StatusForbidden, "invalid-token")
		return
	}
	now := s.Now()
	if _, err := s.Store.Transition(r.Context(), c.NonceID, []nonce.State{nonce.Minted}, nonce.Verified, now, nil); err != nil {
		clientError(w, http.StatusConflict, "timeout-or-duplicate")
		return
	}
	_ = s.Store.MarkEventVerified(r.Context(), c.EventID, now)
	if c.Outcome != string(scoring.Allow) {
		clientError(w, http.StatusForbidden, "not-allowed")
		return
	}
	cookie, err := s.Ring.Mint(token.Claims{
		NonceID: c.NonceID, SiteID: site.ID, Origin: origin, Action: edgeAction, EventID: c.EventID,
		Risk: c.Risk, Outcome: c.Outcome, Reasons: c.Reasons, Challenge: c.Challenge,
		IP24: s.Keys.IPHash(s.clientIP(r), now), UA: uaFamilyOf(r.UserAgent()),
	}, site.SiteKey, edgeTTL)
	if err != nil {
		clientError(w, http.StatusInternalServerError, "internal-error")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: edgeCookie, Value: cookie, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode,
		Secure: strings.HasPrefix(origin, "https://"), MaxAge: int(edgeTTL.Seconds()),
	})
	writeJSON(w, http.StatusOK, map[string]string{"location": safeReturn(in.RD)})
}
