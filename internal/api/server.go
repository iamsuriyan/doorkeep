// Package api implements doorkeep's public HTTP endpoints: snippet
// delivery, session issue, submit/score, challenge, and the
// Turnstile/reCAPTCHA-compatible siteverify (design section 7).
package api

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/config"
	"github.com/iamsuriyan/doorkeep/internal/pseudo"
	"github.com/iamsuriyan/doorkeep/internal/scoring/rules"
	"github.com/iamsuriyan/doorkeep/internal/signals/ipintel"
	"github.com/iamsuriyan/doorkeep/internal/signals/velocity"
	"github.com/iamsuriyan/doorkeep/internal/store"
	"github.com/iamsuriyan/doorkeep/internal/token"
)

//go:embed assets
var assets embed.FS

// Server holds dependencies for the HTTP handlers.
type Server struct {
	Cfg   *config.Config
	Store store.Store
	Rules *rules.Set
	Ring  *token.Ring
	Keys  *pseudo.Keyer
	IP    *ipintel.Store
	Vel   *velocity.Tracker
	Log   *slog.Logger
	Now   func() time.Time
	mux   *http.ServeMux
}

// New wires a server.
func New(cfg *config.Config, st store.Store, rs *rules.Set, log *slog.Logger) *Server {
	ring := &token.Ring{Active: token.Key{ID: cfg.TokenKeys[0].ID, Secret: config.KeyBytes(cfg.TokenKeys[0])}}
	for _, k := range cfg.TokenKeys[1:] {
		ring.Older = append(ring.Older, token.Key{ID: k.ID, Secret: config.KeyBytes(k)})
	}
	s := &Server{Cfg: cfg, Store: st, Rules: rs, Ring: ring, Keys: pseudo.New(cfg.SecretBytes()), IP: &ipintel.Store{}, Log: log, Now: time.Now}
	ring.Now = func() time.Time { return s.Now() }
	s.Vel = velocity.New(func() time.Time { return s.Now() })
	s.routes()
	return s
}

func (s *Server) routes() {
	m := http.NewServeMux()
	m.HandleFunc("GET /v1/dk.js", s.handleSnippet)
	m.HandleFunc("POST /v1/session", s.cors(s.handleSession))
	m.HandleFunc("POST /v1/submit", s.cors(s.handleSubmit))
	m.HandleFunc("POST /v1/challenge", s.cors(s.handleChallenge))
	m.HandleFunc("OPTIONS /v1/", s.handlePreflight)
	m.HandleFunc("POST /v1/siteverify", s.handleVerify)
	m.HandleFunc("POST /v1/verify", s.handleVerify)
	m.HandleFunc("POST /v1/report", s.handleReport)
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	m.HandleFunc("GET /readyz", s.handleReady)
	s.mux = m
}

// ServeHTTP implements http.Handler with security headers and panic safety.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if rec := recover(); rec != nil {
			s.Log.Error("panic", "path", r.URL.Path, "err", rec)
			http.Error(w, "internal error", http.StatusInternalServerError)
		}
	}()
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if _, err := s.Store.ListSites(ctx); err != nil {
		http.Error(w, "store unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Write([]byte("ready\n"))
}

func (s *Server) handleSnippet(w http.ResponseWriter, r *http.Request) {
	b, err := assets.ReadFile("assets/dk.js")
	if err != nil {
		http.Error(w, "snippet not built", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Write(b)
}

// ---------- CORS ----------

// cors allows registered origins only. Origin validation per site happens
// in the handler (it needs the site); here we reflect the Origin so
// same-origin proxied deployments and direct cross-origin both work, and the
// handler rejects unregistered origins before doing any work.
func (s *Server) cors(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Vary", "Origin")
		}
		next(w, r)
	}
}

func (s *Server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	if o := r.Header.Get("Origin"); o != "" {
		w.Header().Set("Access-Control-Allow-Origin", o)
		w.Header().Set("Access-Control-Allow-Methods", "POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "600")
		w.Header().Set("Vary", "Origin")
	}
	w.WriteHeader(http.StatusNoContent)
}

// originAllowed checks the request origin against the site's list. "*" in
// the list allows any origin (development only).
func originAllowed(site *store.Site, origin string) bool {
	if origin == "" {
		return false
	}
	for _, o := range site.Origins {
		if o == "*" || strings.EqualFold(strings.TrimRight(o, "/"), origin) {
			return true
		}
	}
	return false
}

// requestOrigin returns Origin, falling back to the Referer's origin.
func requestOrigin(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		return o
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil && u.Host != "" {
			return u.Scheme + "://" + u.Host
		}
	}
	return ""
}

// clientIP returns the client address, honouring X-Forwarded-For only from
// trusted proxies (rightmost untrusted hop).
func (s *Server) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	addr = addr.Unmap()
	if !s.Cfg.Trusted(addr) {
		return addr
	}
	hops := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !s.Cfg.Trusted(a) {
			return a
		}
		addr = a
	}
	return addr
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func clientError(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"status": "error", "error": code})
}

func newEventID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "evt_" + base64.RawURLEncoding.EncodeToString(b)
}

func isMobileUA(ua string) bool {
	return strings.Contains(ua, "Mobile") || strings.Contains(ua, "Android") || strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad")
}

var interactiveDefault = []string{"signup", "register", "login", "contact", "comment", "checkout", "default"}

func interactive(site *store.Site) []string {
	if len(site.InteractiveActions) > 0 {
		return site.InteractiveActions
	}
	return interactiveDefault
}

func validAction(a string) bool {
	if a == "" || len(a) > 64 {
		return false
	}
	return !slices.ContainsFunc([]rune(a), func(r rune) bool {
		return !(r == '_' || r == '-' || r == '.' || r == '/' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	})
}

func netipFromIP(ip net.IP) (netip.Addr, bool) {
	a, ok := netip.AddrFromSlice(ip)
	return a.Unmap(), ok
}
