package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/nonce"
	"github.com/iamsuriyan/doorkeep/internal/pseudo"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/scoring/model"
	"github.com/iamsuriyan/doorkeep/internal/token"
)

// verifyResp is wire-compatible with Cloudflare Turnstile's siteverify and
// carries reCAPTCHA v3's score; doorkeep detail lives under "doorkeep".
type verifyResp struct {
	Success     bool          `json:"success"`
	ChallengeTS string        `json:"challenge_ts,omitempty"`
	Hostname    string        `json:"hostname,omitempty"`
	Action      string        `json:"action,omitempty"`
	CData       string        `json:"cdata"`
	ErrorCodes  []string      `json:"error-codes"`
	Score       *float64      `json:"score,omitempty"`
	Doorkeep    *verifyDetail `json:"doorkeep,omitempty"`
}

type verifyDetail struct {
	EventID    string   `json:"event_id"`
	Risk       int      `json:"risk"`
	Outcome    string   `json:"outcome"`
	Reasons    []string `json:"reasons"`
	Challenge  string   `json:"challenge"`
	VerifiedAt string   `json:"verified_at"`
}

// readParams accepts form-encoded or JSON bodies, like Turnstile.
func readParams(r *http.Request) (url.Values, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8*1024))
	if err != nil {
		return nil, err
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct == "application/json" {
		var m map[string]any
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, err
		}
		v := url.Values{}
		for k, x := range m {
			if s, ok := x.(string); ok {
				v.Set(k, s)
			}
		}
		return v, nil
	}
	return url.ParseQuery(string(body))
}

func (s *Server) verifyFail(w http.ResponseWriter, code string) {
	s.metrics.inc("doorkeep_verifications_total", "result", "invalid")
	verifyFail(w, code)
}

func verifyFail(w http.ResponseWriter, code string) {
	writeJSON(w, http.StatusOK, verifyResp{Success: false, ErrorCodes: []string{code}})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	v, err := readParams(r)
	if err != nil {
		s.verifyFail(w, "bad-request")
		return
	}
	secret, resp := v.Get("secret"), v.Get("response")
	switch {
	case secret == "":
		s.verifyFail(w, "missing-input-secret")
		return
	case resp == "":
		s.verifyFail(w, "missing-input-response")
		return
	}
	ctx := r.Context()
	site, err := s.Store.SiteBySecretHash(ctx, pseudo.SecretHash(secret))
	if err != nil {
		s.verifyFail(w, "invalid-input-secret")
		return
	}
	c, err := s.Ring.Open(resp, site.SiteKey)
	switch {
	case errors.Is(err, token.ErrExpired):
		s.verifyFail(w, "timeout-or-duplicate")
		return
	case err != nil || c.SiteID != site.ID:
		s.verifyFail(w, "invalid-input-response")
		return
	}
	now := s.Now()
	if site.StrictIP {
		if ipStr := v.Get("remoteip"); ipStr != "" {
			if a, err := netip.ParseAddr(ipStr); err == nil && !s.tokenIPMatches(a, c, now) {
				s.verifyFail(w, "invalid-input-response")
				return
			}
		}
	}
	// Single use: the token is not a bearer credential on its own.
	if _, err := s.Store.Transition(ctx, c.NonceID, []nonce.State{nonce.Minted}, nonce.Verified, now, nil); err != nil {
		s.verifyFail(w, "timeout-or-duplicate")
		return
	}
	_ = s.Store.MarkEventVerified(ctx, c.EventID, now)

	host := hostOf(c.Origin)
	out := verifyResp{
		ChallengeTS: time.Unix(c.IssuedAt, 0).UTC().Format(time.RFC3339),
		Hostname:    host, Action: c.Action, ErrorCodes: []string{},
	}
	score := float64(100-c.Risk) / 100
	out.Score = &score
	out.Doorkeep = &verifyDetail{
		EventID: c.EventID, Risk: c.Risk, Outcome: c.Outcome, Reasons: c.Reasons, Challenge: c.Challenge,
		VerifiedAt: now.UTC().Format(time.RFC3339),
	}
	out.Success = c.Outcome == string(scoring.Allow)
	if exp := v.Get("expected_hostname"); exp != "" && !strings.EqualFold(exp, host) {
		out.Success = false
		out.ErrorCodes = append(out.ErrorCodes, "hostname-mismatch")
	}
	if exp := v.Get("expected_action"); exp != "" && exp != c.Action {
		out.Success = false
		out.ErrorCodes = append(out.ErrorCodes, "action-mismatch")
	}
	result := "failure"
	if out.Success {
		result = "success"
	}
	s.metrics.inc("doorkeep_verifications_total", "result", result)
	writeJSON(w, http.StatusOK, out)
}

// tokenIPMatches checks a client address against the token's IP hash. The
// hash was taken when the session was issued, up to nonce.TTL plus
// nonce.ChallengeTTL before the token was minted, possibly on the previous
// UTC day.
func (s *Server) tokenIPMatches(a netip.Addr, c *token.Claims, now time.Time) bool {
	minted := time.Unix(c.IssuedAt, 0)
	return s.Keys.IPHashMatches(a, c.IP24, minted, now) ||
		s.Keys.IPHashMatches(a, c.IP24, minted.Add(-nonce.TTL-nonce.ChallengeTTL), minted)
}

func hostOf(origin string) string {
	u, err := url.Parse(origin)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// handleReport lets a site backend label an event (feedback loop for the
// model layer, design section 4.4).
func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	v, err := readParams(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "error-codes": []string{"bad-request"}})
		return
	}
	site, err := s.Store.SiteBySecretHash(r.Context(), pseudo.SecretHash(v.Get("secret")))
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"success": false, "error-codes": []string{"invalid-input-secret"}})
		return
	}
	ev, err := s.Store.GetEvent(r.Context(), v.Get("event_id"))
	if err != nil || ev.SiteID != site.ID {
		writeJSON(w, http.StatusOK, map[string]any{"success": false, "error-codes": []string{"invalid-event"}})
		return
	}
	label := v.Get("label")
	if label != "bot" && label != "human" {
		writeJSON(w, http.StatusOK, map[string]any{"success": false, "error-codes": []string{"invalid-label"}})
		return
	}
	if err := s.Store.LabelEvent(r.Context(), ev.ID, label, "api"); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"success": false, "error-codes": []string{"internal-error"}})
		return
	}
	s.Models.Label(site.ID, ev.Features, label == "bot", model.WeightStrong)
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "error-codes": []string{}})
}
