package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/iamsuriyan/doorkeep/internal/pseudo"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

// argon2id parameters: OWASP's minimum recommendation (19 MiB, t=2, p=1),
// chosen so login stays fast on small self-hosted machines.
const (
	argonMem     = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32

	sessionTTL      = 12 * time.Hour
	sessionCookie   = "dk_admin"
	loginFailWindow = 15 * time.Minute
	loginMaxFails   = 5
	// loginSlowFails is the per-user failure count (from any network) after
	// which every attempt for that user is slowed down. A hard per-user lock
	// would let anyone who can reach the listener lock the admin out, so
	// hard locks are per (user, /24) and per address only.
	loginSlowFails = 20
	loginSlowDelay = 2 * time.Second

	// DefaultAdminTokenTTL is the lifetime of a bearer token unless chosen.
	DefaultAdminTokenTTL = 90 * 24 * time.Hour
)

// HashPassword returns an argon2id PHC string.
func HashPassword(pw string) (string, error) {
	if len(pw) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMem, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", argonMem, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// checkPassword verifies pw against a PHC string in constant time.
func checkPassword(pw, phc string) bool {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash equalises timing for unknown users.
var dummyHash, _ = HashPassword("doorkeep-dummy-password")

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// NewAdminToken creates a bearer token for automation and returns it once.
// ttl <= 0 creates a token that does not expire.
func NewAdminToken(ctx context.Context, st store.Store, name string, now time.Time, ttl time.Duration) (string, error) {
	tok := "dk_admin_" + randToken(32)
	var exp time.Time
	if ttl > 0 {
		exp = now.Add(ttl)
	}
	return tok, st.CreateAdminToken(ctx, sha256hex(tok), name, now, exp)
}

type actorKey struct{}

// actor returns who is making an admin request.
func actor(r *http.Request) string {
	a, _ := r.Context().Value(actorKey{}).(string)
	return a
}

// adminAuth authenticates by session cookie (with CSRF on writes) or bearer
// token, and attaches the actor to the request context.
func (s *Server) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			name, err := s.Store.AdminTokenName(ctx, sha256hex(strings.TrimPrefix(h, "Bearer ")), s.Now())
			if err != nil {
				problem(w, http.StatusUnauthorized, "unauthorized", "invalid admin token")
				return
			}
			next(w, r.WithContext(context.WithValue(ctx, actorKey{}, "token:"+name)))
			return
		}
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			problem(w, http.StatusUnauthorized, "unauthorized", "login required")
			return
		}
		sess, err := s.Store.GetSession(ctx, sha256hex(c.Value), s.Now())
		if err != nil {
			problem(w, http.StatusUnauthorized, "unauthorized", "session expired")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CSRF)) != 1 {
				problem(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token")
				return
			}
		}
		next(w, r.WithContext(context.WithValue(ctx, actorKey{}, "user:"+sess.User)))
	}
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req, 4096); err != nil || req.User == "" {
		problem(w, http.StatusBadRequest, "bad-request", "user and password required")
		return
	}
	ip := s.clientIP(r)
	kUser := "login-user:" + s.Keys.VelKey(req.User)
	kUserNet := "login-usernet:" + s.Keys.VelKey(req.User+"|"+pseudo.Prefix(ip))
	kIP := "login-ip:" + s.Keys.VelKey(ip.String())
	if s.Vel.Count(kUserNet, loginFailWindow) >= loginMaxFails || s.Vel.Count(kIP, loginFailWindow) >= loginMaxFails*4 {
		w.Header().Set("Retry-After", "900")
		problem(w, http.StatusTooManyRequests, "locked", "too many failed logins; try again later")
		return
	}
	if s.Vel.Count(kUser, loginFailWindow) >= loginSlowFails {
		select {
		case <-time.After(loginSlowDelay):
		case <-r.Context().Done():
			return
		}
	}
	hash, err := s.Store.AdminPasswordHash(r.Context(), req.User)
	if err != nil {
		hash = dummyHash
	}
	if !checkPassword(req.Password, hash) || err != nil {
		s.Vel.Add(kUser)
		s.Vel.Add(kUserNet)
		s.Vel.Add(kIP)
		_ = s.Store.Audit(r.Context(), store.AuditEntry{TS: s.Now(), Actor: "anonymous", Action: "login.failed", Target: req.User})
		problem(w, http.StatusUnauthorized, "unauthorized", "invalid user or password")
		return
	}
	tok, csrf := randToken(32), randToken(24)
	if err := s.Store.CreateSession(r.Context(), &store.AdminSession{TokenHash: sha256hex(tok), User: req.User, CSRF: csrf, ExpiresAt: s.Now().Add(sessionTTL)}, s.Now()); err != nil {
		problem(w, http.StatusInternalServerError, "internal", "could not create session")
		return
	}
	http.SetCookie(w, &http.Cookie{
		// No Path: the browser scopes the cookie to the API directory it was
		// set from (.../admin/v1), which also works under a proxy prefix.
		Name: sessionCookie, Value: tok, HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure: s.requestIsHTTPS(r), MaxAge: int(sessionTTL.Seconds()),
	})
	_ = s.Store.Audit(r.Context(), store.AuditEntry{TS: s.Now(), Actor: "user:" + req.User, Action: "login", Target: req.User})
	writeJSON(w, http.StatusOK, map[string]string{"user": req.User, "csrf": csrf})
}

// requestIsHTTPS reports whether the client connection is HTTPS, trusting
// X-Forwarded-Proto only from configured proxies.
func (s *Server) requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return s.fromTrustedProxy(r) && strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		// Logging out is a state change, so it needs the session's CSRF
		// token like every other write.
		if sess, err := s.Store.GetSession(r.Context(), sha256hex(c.Value), s.Now()); err == nil {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CSRF)) != 1 {
				problem(w, http.StatusForbidden, "csrf", "missing or invalid CSRF token")
				return
			}
			_ = s.Store.DeleteSession(r.Context(), sha256hex(c.Value))
		}
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	out := map[string]string{"actor": actor(r)}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if sess, err := s.Store.GetSession(r.Context(), sha256hex(c.Value), s.Now()); err == nil {
			out["csrf"] = sess.CSRF
		}
	}
	writeJSON(w, http.StatusOK, out)
}
