package api

import (
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/challenge/pow"
	"github.com/iamsuriyan/doorkeep/internal/nonce"
	"github.com/iamsuriyan/doorkeep/internal/pseudo"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/scoring/rules"
	signet "github.com/iamsuriyan/doorkeep/internal/signals/net"
	"github.com/iamsuriyan/doorkeep/internal/signals/payload"
	"github.com/iamsuriyan/doorkeep/internal/store"
	"github.com/iamsuriyan/doorkeep/internal/token"
)

// Challenge credits (design section 4.5).
const (
	creditPoW      = 20
	maxAttempts    = 3
	canvasWindow   = 24 * time.Hour
	sessionBodyMax = 1024
)

type sessionReq struct {
	SiteKey string `json:"sk"`
	Action  string `json:"a"`
}

type sessionResp struct {
	Nonce   string   `json:"nonce"`
	Exp     int64    `json:"exp"`
	Seed    string   `json:"seed"`
	Now     int64    `json:"now"`
	Mod     []string `json:"mod"`
	DeferMS int      `json:"deferMs"`
}

func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	var req sessionReq
	body, _ := io.ReadAll(io.LimitReader(r.Body, sessionBodyMax))
	if err := json.Unmarshal(body, &req); err != nil || req.SiteKey == "" {
		clientError(w, http.StatusBadRequest, "bad-request")
		return
	}
	if req.Action == "" {
		req.Action = "default"
	}
	if !validAction(req.Action) {
		clientError(w, http.StatusBadRequest, "bad-action")
		return
	}
	site, err := s.Store.SiteByKey(r.Context(), req.SiteKey)
	if err != nil {
		clientError(w, http.StatusBadRequest, "invalid-sitekey")
		return
	}
	origin := requestOrigin(r)
	if !originAllowed(site, origin) {
		clientError(w, http.StatusForbidden, "origin-not-allowed")
		return
	}
	now := s.Now()
	ip := s.clientIP(r)
	n := &nonce.Nonce{
		ID: nonce.NewID(), SiteID: site.ID, Origin: origin, Action: req.Action, Seed: nonce.NewSeed(),
		IssuedAt: now, ExpiresAt: now.Add(nonce.TTL), State: nonce.Issued,
		IPHash: s.Keys.IPHash(ip, now), UAHash: pseudo.UAHash(r.UserAgent()),
	}
	if err := s.Store.Create(r.Context(), n); err != nil {
		s.Log.Error("nonce create", "err", err)
		clientError(w, http.StatusInternalServerError, "internal-error")
		return
	}
	writeJSON(w, http.StatusOK, sessionResp{
		Nonce: n.ID, Exp: n.ExpiresAt.UnixMilli(), Seed: n.Seed, Now: now.UnixMilli(),
		Mod: []string{"auto", "fp", "beh", "env", "audio", "fonts", "raf"}, DeferMS: 500,
	})
}

type submitResp struct {
	Status string      `json:"status"` // ok | challenge
	Token  string      `json:"token,omitempty"`
	Kind   string      `json:"kind,omitempty"`
	PoW    *pow.Params `json:"pow,omitempty"`
	Exp    int64       `json:"exp,omitempty"`
}

func (s *Server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	p, err := payload.Decode(r.Body)
	if err != nil {
		clientError(w, http.StatusBadRequest, "bad-payload")
		return
	}
	ctx := r.Context()
	now := s.Now()
	n, err := s.Store.Get(ctx, p.N)
	if err != nil {
		clientError(w, http.StatusBadRequest, "invalid-nonce")
		return
	}
	site, err := s.Store.SiteByID(ctx, n.SiteID)
	if err != nil {
		clientError(w, http.StatusBadRequest, "invalid-nonce")
		return
	}
	origin := requestOrigin(r)
	if !originAllowed(site, origin) {
		clientError(w, http.StatusForbidden, "origin-not-allowed")
		return
	}
	// Single atomic consume. A second submit of the same nonce fails here.
	n, err = s.Store.Transition(ctx, n.ID, []nonce.State{nonce.Issued}, nonce.Submitted, now, func(x *nonce.Nonce) {
		x.EventID = newEventID()
	})
	if err != nil {
		clientError(w, http.StatusConflict, "nonce-used-or-expired")
		return
	}

	ip := s.clientIP(r)
	feats, cls := payload.Normalise(p, payload.ServerContext{
		ElapsedMS: float64(now.Sub(n.IssuedAt).Milliseconds()),
		NowMS:     float64(now.UnixMilli()),
	})
	signet.Analyze(feats, r, p.FP.UA, cls.Langs, cls)
	feats.SetBool("net.origin_mismatch", origin != n.Origin)
	feats.SetBool("net.ua_changed", pseudo.UAHash(r.UserAgent()) != n.UAHash)
	feats.SetBool("net.ip24_changed", s.Keys.IPHash(ip, now) != n.IPHash)
	if !p.FP.CV.B && cls.CanvasHash != "" {
		conflict, err := s.Store.CanvasSeen(ctx, site.ID, cls.CanvasHash, s.Keys.SeedHash(n.Seed), now, canvasWindow)
		if err == nil {
			feats.SetBool("net.canvas_seed_conflict", conflict)
		}
	}

	fpHash := s.Keys.FPHash(site.ID, now, pseudo.FPInput{
		CanvasHash: cls.CanvasHash, GLHash: cls.GLHash, FontMask: cls.FontMask, ScreenKey: cls.ScreenKey,
		TZ: p.FP.TZ, Langs: cls.Langs, UAFamily: cls.UAFamily, OSFamily: cls.OSFamily, HCBucket: cls.HCBucket,
	})

	res := s.Rules.Eval(rules.Context(feats.Env(), n.Action, interactive(site)))
	listAction, listCode := s.matchLists(ctx, site.ID, ip, fpHash, r.UserAgent(), now)
	th := site.ThresholdsFor(n.Action)
	d := scoring.CombineWithFloor(res.Risk, res.Floor, toReasons(res.Hits), toReasons(res.Shadow), res.ShadowRisk,
		0, 0, listAction, listCode, th, site.Mode)

	ev := &store.Event{
		ID: n.EventID, SiteID: site.ID, TS: now, Action: n.Action, Risk: d.Risk, Outcome: d.Outcome, WouldBe: d.WouldBe,
		Reasons: d.Reasons, Shadow: d.Shadow, ShadowRisk: d.ShadowRisk, Features: feats, FPHash: fpHash,
		IP24Hash: s.Keys.IPHash(ip, now), UAFamily: cls.UAFamily, UAMajor: cls.UAMajor, OSFamily: cls.OSFamily,
		ASNClass: feats.Cat["net.asn_class"],
	}
	if err := s.Store.InsertEvent(ctx, ev); err != nil {
		s.Log.Error("event insert", "err", err)
	}

	if d.Outcome == scoring.Challenge {
		params := pow.ForRisk(d.Risk, isMobileUA(r.UserAgent()), false)
		n, err = s.Store.Transition(ctx, n.ID, []nonce.State{nonce.Submitted}, nonce.ChallengedPoW, now, func(x *nonce.Nonce) {
			x.PoWSalt, x.PoWBits, x.PoWN, x.Risk, x.Floor = params.Salt, params.Bits, params.N, d.Risk, d.Floor
			x.ExpiresAt = now.Add(nonce.ChallengeTTL)
		})
		if err != nil {
			clientError(w, http.StatusConflict, "nonce-used-or-expired")
			return
		}
		writeJSON(w, http.StatusOK, submitResp{Status: "challenge", Kind: "pow", PoW: &params, Exp: n.ExpiresAt.UnixMilli()})
		return
	}
	s.mintAndRespond(w, r, site, n, d, "none", []nonce.State{nonce.Submitted})
}

// mintAndRespond issues the token for the final decision. The client always
// gets a token, including on block; only the site backend learns the
// outcome (design section 2.1).
func (s *Server) mintAndRespond(w http.ResponseWriter, r *http.Request, site *store.Site, n *nonce.Nonce, d scoring.Decision, ch string, from []nonce.State) {
	now := s.Now()
	ttl := s.Cfg.TokenTTL
	n, err := s.Store.Transition(r.Context(), n.ID, from, nonce.Minted, now, func(x *nonce.Nonce) {
		x.ExpiresAt = now.Add(ttl)
		x.Risk = d.Risk
	})
	if err != nil {
		clientError(w, http.StatusConflict, "nonce-used-or-expired")
		return
	}
	codes := make([]string, 0, len(d.Reasons))
	for _, rc := range d.Reasons {
		codes = append(codes, rc.Code)
	}
	tok, err := s.Ring.Mint(token.Claims{
		NonceID: n.ID, SiteID: site.ID, Origin: n.Origin, Action: n.Action, EventID: n.EventID,
		Risk: d.Risk, Outcome: string(d.Outcome), Reasons: codes, Challenge: ch,
		IP24: n.IPHash,
	}, site.SiteKey, ttl)
	if err != nil {
		s.Log.Error("mint", "err", err)
		clientError(w, http.StatusInternalServerError, "internal-error")
		return
	}
	writeJSON(w, http.StatusOK, submitResp{Status: "ok", Token: tok})
}

type challengeReq struct {
	N    string   `json:"n"`
	Kind string   `json:"kind"`
	Sol  []uint32 `json:"sol"`
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req challengeReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 8*1024)).Decode(&req); err != nil || req.Kind != "pow" {
		clientError(w, http.StatusBadRequest, "bad-request")
		return
	}
	ctx := r.Context()
	now := s.Now()
	n, err := s.Store.Get(ctx, req.N)
	if err != nil || n.State != nonce.ChallengedPoW {
		clientError(w, http.StatusConflict, "nonce-used-or-expired")
		return
	}
	site, err := s.Store.SiteByID(ctx, n.SiteID)
	if err != nil || !originAllowed(site, requestOrigin(r)) {
		clientError(w, http.StatusForbidden, "origin-not-allowed")
		return
	}
	params := pow.Params{Salt: n.PoWSalt, Bits: n.PoWBits, N: n.PoWN}
	if !pow.Verify(n.ID, params, req.Sol) {
		_, err := s.Store.Transition(ctx, n.ID, []nonce.State{nonce.ChallengedPoW}, nonce.ChallengedPoW, now, func(x *nonce.Nonce) {
			x.Attempts++
			if x.Attempts >= maxAttempts {
				x.State = nonce.Burned
			}
		})
		if err != nil {
			clientError(w, http.StatusConflict, "nonce-used-or-expired")
			return
		}
		clientError(w, http.StatusBadRequest, "challenge-failed")
		return
	}
	ev, err := s.Store.GetEvent(ctx, n.EventID)
	if err != nil {
		clientError(w, http.StatusInternalServerError, "internal-error")
		return
	}
	th := site.ThresholdsFor(n.Action)
	d := scoring.Decision{Risk: n.Risk, Floor: n.Floor, Reasons: ev.Reasons, Outcome: scoring.Challenge}
	d = scoring.ApplyChallengeCredit(d, creditPoW, th, site.Mode)
	if err := s.Store.UpdateEventChallenge(ctx, ev.ID, "pow", true, d.Risk, d.Outcome, d.Reasons); err != nil {
		s.Log.Error("event update", "err", err)
	}
	s.mintAndRespond(w, r, site, n, d, "pow", []nonce.State{nonce.ChallengedPoW})
}

func toReasons(h []rules.Hit) []scoring.Reason {
	out := make([]scoring.Reason, 0, len(h))
	for _, x := range h {
		out = append(out, scoring.Reason{Code: x.ID, Weight: x.Weight})
	}
	return out
}
