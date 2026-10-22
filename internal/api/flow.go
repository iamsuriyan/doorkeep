package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/challenge/pow"
	"github.com/iamsuriyan/doorkeep/internal/nonce"
	"github.com/iamsuriyan/doorkeep/internal/pseudo"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/scoring/model"
	"github.com/iamsuriyan/doorkeep/internal/scoring/rules"
	"github.com/iamsuriyan/doorkeep/internal/signals/ipintel"
	signet "github.com/iamsuriyan/doorkeep/internal/signals/net"
	"github.com/iamsuriyan/doorkeep/internal/signals/payload"
	"github.com/iamsuriyan/doorkeep/internal/signals/velocity"
	"github.com/iamsuriyan/doorkeep/internal/store"
	"github.com/iamsuriyan/doorkeep/internal/token"
)

// CanvasReplayWindow is how long a seeded canvas hash is remembered for
// replay detection; older records are purged.
const CanvasReplayWindow = 24 * time.Hour

// Challenge credits (design section 4.5).
// Session rate limits (design section 3.5), applied before any work.
const (
	sessionPerIPPerMin = 60
	sessionPer24PerMin = 600
	creditPoW          = 20
	creditVisual       = 45
	maxAttempts        = 3
	sessionBodyMax     = 1024
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
	kIP, k24 := "sess-ip:"+s.Keys.VelKey(ip.String()), "sess-24:"+s.Keys.VelKey(pseudo.Prefix(ip))
	c := s.Vel.Batch([]velocity.Op{{Key: kIP}, {Key: k24}}, []velocity.Query{{Key: kIP, Dur: time.Minute}, {Key: k24, Dur: time.Minute}})
	if c[0] > sessionPerIPPerMin || c[1] > sessionPer24PerMin {
		w.Header().Set("Retry-After", "30")
		clientError(w, http.StatusTooManyRequests, "rate-limited")
		return
	}
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
	Visual *visualInfo `json:"visual,omitempty"`
	Exp    int64       `json:"exp,omitempty"`
}

type visualInfo struct {
	Image         string `json:"image"`      // path relative to the doorkeep endpoint
	Audio         string `json:"audio"`      // WAV
	AudioSlow     string `json:"audio_slow"` // slower WAV
	Length        int    `json:"length"`     // characters to type
	Attempts      int    `json:"attempts_left"`
	Accessibility string `json:"accessibility_url,omitempty"`
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
	signet.Analyze(feats, r, s.fromTrustedProxy(r), p.FP.UA, cls.Langs, cls)
	ja4, offersH2, h2, h2Text := s.connPrints(r)
	hdrFamily, _ := payload.UAFamily(r.UserAgent())
	applyConnFeatures(feats, ja4, offersH2, h2, h2Text, hdrFamily, payload.OSFamily(r.UserAgent()))
	feats.SetBool("net.origin_mismatch", origin != n.Origin)
	feats.SetBool("net.ua_changed", pseudo.UAHash(r.UserAgent()) != n.UAHash)
	feats.SetBool("net.ip24_changed", !s.Keys.IPHashMatches(ip, n.IPHash, n.IssuedAt, now))
	if !p.FP.CV.B && cls.CanvasHash != "" {
		conflict, err := s.Store.CanvasSeen(ctx, site.ID, cls.CanvasHash, s.Keys.SeedHash(n.Seed), now, CanvasReplayWindow)
		if err == nil {
			feats.SetBool("net.canvas_seed_conflict", conflict)
		}
	}

	fpHash := s.Keys.FPHash(site.ID, now, pseudo.FPInput{
		CanvasHash: cls.CanvasStatic, GLHash: cls.GLHash, FontMask: cls.FontMask, ScreenKey: cls.ScreenKey,
		TZ: p.FP.TZ, Langs: cls.Langs, UAFamily: cls.UAFamily, OSFamily: cls.OSFamily, HCBucket: cls.HCBucket,
	})

	info := s.IP.Get().Lookup(ip)
	applyIPInfo(feats, info, cls.TZCountry)
	s.applyVelocity(feats, site.ID, ip, fpHash, cls, info)
	surge := s.applySiteRate(ctx, feats, site, now)

	res := s.siteRules(ctx, site.ID).Eval(rules.Context(feats.Env(), n.Action, interactive(site)))
	listAction, listCode := s.matchLists(ctx, site.ID, ip, info, fpHash, r.UserAgent(), now)
	th := site.ThresholdsFor(n.Action)
	mr := s.Models.Score(site.ID, feats)
	d := scoring.CombineWithFloor(res.Risk, res.Floor, toReasons(res.Hits), toReasons(res.Shadow), res.ShadowRisk,
		mr.Risk, mr.Weight, listAction, listCode, th, site.Mode)
	if slices.ContainsFunc(d.Reasons, func(r scoring.Reason) bool { return r.Code == "MODEL_ANOMALY" }) {
		for _, c := range mr.Contributions {
			d.Reasons = append(d.Reasons, scoring.Reason{Code: "MODEL:" + c.Feature})
		}
	}
	if mr.ShadowLR >= 0 {
		d.Shadow = append(d.Shadow, scoring.Reason{Code: "MODEL_SUPERVISED", Weight: int(float64(mr.ShadowLR) * model.WeightPromoted)})
	}
	s.Models.ObserveAllowed(site.ID, feats, d.Risk, d.WouldBe)

	ev := &store.Event{
		ID: n.EventID, SiteID: site.ID, TS: now, Action: n.Action, Risk: d.Risk, Outcome: d.Outcome, WouldBe: d.WouldBe,
		Reasons: d.Reasons, Shadow: d.Shadow, ShadowRisk: d.ShadowRisk, Features: feats, FPHash: fpHash,
		IP24Hash: s.Keys.IPHash(ip, now), UAFamily: cls.UAFamily, UAMajor: cls.UAMajor, OSFamily: cls.OSFamily,
		ASNClass: info.Class, ASN: int(info.ASN), Country: info.Country,
	}
	if err := s.Store.InsertEvent(ctx, ev); err != nil {
		s.Log.Error("event insert", "err", err)
	}

	if d.Outcome == scoring.Challenge {
		params := pow.ForRisk(d.Risk, isMobileUA(r.UserAgent()), surge)
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
	N      string   `json:"n"`
	Kind   string   `json:"kind"`
	Sol    []uint32 `json:"sol"`
	Answer string   `json:"answer"`
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	var req challengeReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 8*1024)).Decode(&req); err != nil || (req.Kind != "pow" && req.Kind != "visual") {
		clientError(w, http.StatusBadRequest, "bad-request")
		return
	}
	if req.Kind == "visual" {
		s.handleVisualAnswer(w, r, req)
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
		s.Vel.Add(s.challengeFailKey(s.clientIP(r)))
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
	d = scoring.ApplyChallengeCredit(d, creditPoW, th, scoring.ModeEnforce)
	// Proof of work clears only the lower part of the challenge band. If the
	// risk is still at or above the challenge threshold after its credit,
	// escalate to the visual/audio challenge within the same nonce. In
	// challenge_only mode (never block) anything proof of work alone would
	// not allow, including block-band risk, goes to the visual challenge.
	escalate := site.Mode != scoring.ModeMonitor && ((n.Risk-creditPoW >= th.Challenge && n.Risk < th.Block) ||
		(site.Mode == scoring.ModeChallengeOnly && d.WouldBe != scoring.Allow))
	if escalate {
		n2, err := s.Store.Transition(ctx, n.ID, []nonce.State{nonce.ChallengedPoW}, nonce.ChallengedVisual, now, func(x *nonce.Nonce) {
			x.Attempts = 0
			x.Risk = n.Risk - creditPoW
			x.AnswerMAC = s.Keys.AnswerMAC(x.ID, s.Visual.Answer(x.ID))
		})
		if err != nil {
			clientError(w, http.StatusConflict, "nonce-used-or-expired")
			return
		}
		_ = s.Store.UpdateEventChallenge(ctx, ev.ID, "pow", true, n2.Risk, scoring.Challenge, append(ev.Reasons, scoring.Reason{Code: "CHALLENGE_SOLVED", Weight: -creditPoW}))
		writeJSON(w, http.StatusOK, s.visualResp(ctx, n2))
		return
	}
	d = scoring.Decision{Risk: n.Risk, Floor: n.Floor, Reasons: ev.Reasons, Outcome: scoring.Challenge}
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

// applyIPInfo sets network-reputation features.
func applyIPInfo(f scoring.Features, info ipintel.Info, tzCountry string) {
	f.SetCat("net.asn_class", info.Class)
	f.SetBool("net.ip_tor", info.Tor)
	f.SetBool("net.ip_drop", info.Drop)
	f.SetBool("net.ip_known_crawler", info.Crawler != "")
	if info.Country != "" {
		f.SetCat("net.ip_country", info.Country)
	}
	switch {
	case info.Country == "" || tzCountry == "":
		f.Set("net.tz_ip_country_match", 2)
	case info.Country == tzCountry:
		f.Set("net.tz_ip_country_match", 1)
	default:
		f.Set("net.tz_ip_country_match", 0)
	}
}

// applyVelocity records this submit and reads back windowed counts in one
// batch. Keys are keyed hashes of addresses and prefixes, never raw IPs, and
// live in memory (or Redis) for at most an hour (design section 6.1).
func (s *Server) applyVelocity(f scoring.Features, siteID string, ip netip.Addr, fpHash string, cls payload.Classified, info ipintel.Info) {
	p24 := "24:" + s.Keys.VelKey(pseudo.Prefix(ip))
	ipKey := "ip:" + s.Keys.VelKey(ip.String())
	k24 := "24:" + siteID + ":" + p24
	kfp := "fp:" + fpHash
	ksite := "site:" + siteID
	asn := "asn:" + strconv.FormatUint(uint64(info.ASN), 10)
	ops := []velocity.Op{{Key: ipKey}, {Key: k24, Members: []string{"fp:" + fpHash}}, {Key: kfp, Members: []string{asn, p24}}, {Key: ksite}}
	kcv := ""
	if cls.CanvasStatic != "" {
		kcv = "cv:" + siteID + ":" + cls.CanvasStatic
		ops = append(ops, velocity.Op{Key: kcv, Members: []string{"ua:" + cls.UAFamily}})
	}
	type read struct {
		feature string
		q       velocity.Query
	}
	var reads []read
	for _, w := range velocity.Windows {
		reads = append(reads,
			read{"vel.ip_submits_" + w.Name, velocity.Query{Key: ipKey, Dur: w.Dur}},
			read{"vel.ip24_submits_" + w.Name, velocity.Query{Key: k24, Dur: w.Dur}},
			read{"vel.ip24_distinct_fp_" + w.Name, velocity.Query{Key: k24, Dur: w.Dur, Prefix: "fp:"}},
			read{"vel.fp_submits_" + w.Name, velocity.Query{Key: kfp, Dur: w.Dur}},
			read{"vel.fp_distinct_ip24_" + w.Name, velocity.Query{Key: kfp, Dur: w.Dur, Prefix: "24:"}},
			read{"vel.fp_distinct_asn_" + w.Name, velocity.Query{Key: kfp, Dur: w.Dur, Prefix: "asn:"}},
			read{"vel.site_submits_" + w.Name, velocity.Query{Key: ksite, Dur: w.Dur}},
		)
		if kcv != "" {
			reads = append(reads, read{"vel.canvas_distinct_ua_" + w.Name, velocity.Query{Key: kcv, Dur: w.Dur, Prefix: "ua:"}})
		}
	}
	reads = append(reads, read{"vel.ip_challenge_fail_1h", velocity.Query{Key: s.challengeFailKey(ip), Dur: time.Hour}})
	qs := make([]velocity.Query, len(reads))
	for i, r := range reads {
		qs[i] = r.q
	}
	for i, n := range s.Vel.Batch(ops, qs) {
		f.Set(reads[i].feature, float64(n))
	}
	f.Set("vel.fp_interval_cv", s.Vel.IntervalCV(kfp))
}

// challengeFailKey counts failed challenges per client address.
func (s *Server) challengeFailKey(ip netip.Addr) string {
	return "chfail:" + s.Keys.VelKey(ip.String())
}
