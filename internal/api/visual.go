package api

import (
	"context"
	"crypto/subtle"
	"net/http"

	"github.com/iamsuriyan/doorkeep/internal/challenge/visual"
	"github.com/iamsuriyan/doorkeep/internal/nonce"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/scoring/model"
)

const visualAttempts = 3

func (s *Server) visualResp(ctx context.Context, n *nonce.Nonce) submitResp {
	site, _ := s.Store.SiteByID(ctx, n.SiteID)
	acc := ""
	if site != nil {
		acc = site.AccessibilityURL
	}
	return submitResp{
		Status: "challenge", Kind: "visual", Exp: n.ExpiresAt.UnixMilli(),
		Visual: &visualInfo{
			Image: "/v1/challenge/visual.png?n=" + n.ID, Audio: "/v1/challenge/audio.wav?n=" + n.ID,
			AudioSlow: "/v1/challenge/audio.wav?slow=1&n=" + n.ID, Length: visual.Length,
			Attempts: visualAttempts - n.Attempts, Accessibility: acc,
		},
	}
}

// visualNonce returns the nonce if it is currently in the visual challenge.
func (s *Server) visualNonce(w http.ResponseWriter, r *http.Request) *nonce.Nonce {
	n, err := s.Store.Get(r.Context(), r.URL.Query().Get("n"))
	if err != nil || n.State != nonce.ChallengedVisual || !s.Now().Before(n.ExpiresAt) {
		http.Error(w, "not found", http.StatusNotFound)
		return nil
	}
	return n
}

func (s *Server) handleVisualPNG(w http.ResponseWriter, r *http.Request) {
	n := s.visualNonce(w, r)
	if n == nil {
		return
	}
	b, err := s.Visual.PNG(n.ID)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Write(b)
}

func (s *Server) handleVisualWAV(w http.ResponseWriter, r *http.Request) {
	n := s.visualNonce(w, r)
	if n == nil {
		return
	}
	b, err := s.Visual.WAV(n.ID, r.URL.Query().Get("slow") == "1")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "audio/wav")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Write(b)
}

func (s *Server) handleVisualAnswer(w http.ResponseWriter, r *http.Request, req challengeReq) {
	ctx := r.Context()
	now := s.Now()
	n, err := s.Store.Get(ctx, req.N)
	if err != nil || n.State != nonce.ChallengedVisual {
		clientError(w, http.StatusConflict, "nonce-used-or-expired")
		return
	}
	site, err := s.Store.SiteByID(ctx, n.SiteID)
	if err != nil || !originAllowed(site, requestOrigin(r)) {
		clientError(w, http.StatusForbidden, "origin-not-allowed")
		return
	}
	got := s.Keys.AnswerMAC(n.ID, visual.Normalise(req.Answer))
	if subtle.ConstantTimeCompare([]byte(got), []byte(n.AnswerMAC)) != 1 {
		s.Vel.Add(s.challengeFailKey(s.clientIP(r)))
		n2, err := s.Store.Transition(ctx, n.ID, []nonce.State{nonce.ChallengedVisual}, nonce.ChallengedVisual, now, func(x *nonce.Nonce) {
			x.Attempts++
			if x.Attempts >= visualAttempts {
				x.State = nonce.Burned
			}
		})
		if err != nil || n2.State == nonce.Burned {
			_ = s.Store.UpdateEventChallenge(ctx, n.EventID, "visual", false, max(n.Risk, site.ThresholdsFor(n.Action).Block), scoring.Block, nil)
			if ev, err := s.Store.GetEvent(ctx, n.EventID); err == nil {
				s.Models.Label(site.ID, ev.Features, true, model.WeightWeak)
			}
			clientError(w, http.StatusConflict, "challenge-exhausted")
			return
		}
		resp := s.visualResp(ctx, n2)
		resp.Status = "retry"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	ev, err := s.Store.GetEvent(ctx, n.EventID)
	if err != nil {
		clientError(w, http.StatusInternalServerError, "internal-error")
		return
	}
	th := site.ThresholdsFor(n.Action)
	d := scoring.Decision{Risk: n.Risk, Floor: n.Floor, Reasons: ev.Reasons, Outcome: scoring.Challenge}
	d = scoring.ApplyChallengeCredit(d, creditVisual, th, site.Mode)
	for i := range d.Reasons {
		if d.Reasons[i].Code == "CHALLENGE_SOLVED" && i == len(d.Reasons)-1 {
			d.Reasons[i].Code = "VISUAL_CHALLENGE_SOLVED"
		}
	}
	_ = s.Store.UpdateEventChallenge(ctx, ev.ID, "visual", true, d.Risk, d.Outcome, d.Reasons)
	s.Models.Label(site.ID, ev.Features, false, model.WeightWeak)
	s.mintAndRespond(w, r, site, n, d, "visual", []nonce.State{nonce.ChallengedVisual})
}

func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	b, err := assets.ReadFile("assets/dk-ui.js")
	if err != nil {
		http.Error(w, "challenge UI not built", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Write(b)
}
