package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/pseudo"
	"github.com/iamsuriyan/doorkeep/internal/scoring"
	"github.com/iamsuriyan/doorkeep/internal/scoring/model"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

// adminRoutes mounts the admin API (design section 7). Every event route is
// scoped to one site in its path; there is deliberately no cross-site event
// search, so doorkeep cannot be configured into a cross-site tracker.
func (s *Server) adminRoutes(m *http.ServeMux) {
	a := s.adminAuth
	m.HandleFunc("GET /admin/", s.handleDashboard)
	m.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/admin/", http.StatusFound) })
	m.HandleFunc("POST /admin/v1/login", s.handleLogin)
	m.HandleFunc("POST /admin/v1/logout", s.handleLogout)
	m.HandleFunc("GET /admin/v1/me", a(s.handleMe))
	m.HandleFunc("GET /admin/v1/sites", a(s.adminListSites))
	m.HandleFunc("POST /admin/v1/sites", a(s.adminCreateSite))
	m.HandleFunc("GET /admin/v1/sites/{site}", a(s.adminGetSite))
	m.HandleFunc("PATCH /admin/v1/sites/{site}", a(s.adminPatchSite))
	m.HandleFunc("POST /admin/v1/sites/{site}/rotate-secret", a(s.adminRotateSecret))
	m.HandleFunc("GET /admin/v1/sites/{site}/events", a(s.adminListEvents))
	m.HandleFunc("GET /admin/v1/sites/{site}/events/{event}", a(s.adminGetEvent))
	m.HandleFunc("DELETE /admin/v1/sites/{site}/events/{event}", a(s.adminDeleteEvent))
	m.HandleFunc("POST /admin/v1/sites/{site}/events/{event}/label", a(s.adminLabelEvent))
	m.HandleFunc("GET /admin/v1/sites/{site}/stats", a(s.adminStats))
	m.HandleFunc("GET /admin/v1/sites/{site}/rules", a(s.adminListRules))
	m.HandleFunc("PUT /admin/v1/sites/{site}/rules/{rule}", a(s.adminPutRule))
	m.HandleFunc("DELETE /admin/v1/sites/{site}/rules/{rule}", a(s.adminDeleteRule))
	m.HandleFunc("POST /admin/v1/sites/{site}/rules-lab", a(s.adminRuleLab))
	m.HandleFunc("GET /admin/v1/sites/{site}/lists", a(s.adminListLists))
	m.HandleFunc("POST /admin/v1/sites/{site}/lists", a(s.adminAddList))
	m.HandleFunc("DELETE /admin/v1/sites/{site}/lists/{id}", a(s.adminDeleteList))
	m.HandleFunc("GET /admin/v1/sites/{site}/model", a(s.adminModel))
	m.HandleFunc("POST /admin/v1/sites/{site}/model/promote", a(s.adminPromote))
	m.HandleFunc("GET /admin/v1/privacy", a(s.adminPrivacy))
	m.HandleFunc("GET /admin/v1/audit", a(s.adminAudit))
	m.HandleFunc("GET /admin/v1/ipdata", a(s.adminIPData))
	m.HandleFunc("GET /admin/v1/features", a(s.adminFeatures))
}

// problem writes an RFC 9457 problem+json error.
func problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"type": "https://doorkeep.dev/problems/" + typ, "title": http.StatusText(status), "status": status, "detail": detail})
}

func decodeJSON(r *http.Request, v any, max int64) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, max))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (s *Server) audit(r *http.Request, action, target string, detail map[string]any) {
	_ = s.Store.Audit(r.Context(), store.AuditEntry{TS: s.Now(), Actor: actor(r), Action: action, Target: target, Detail: detail})
}

func (s *Server) site(w http.ResponseWriter, r *http.Request) *store.Site {
	site, err := s.Store.SiteByID(r.Context(), r.PathValue("site"))
	if err != nil {
		problem(w, http.StatusNotFound, "not-found", "unknown site")
		return nil
	}
	return site
}

// ---------------- sites ----------------

func (s *Server) adminListSites(w http.ResponseWriter, r *http.Request) {
	sites, err := s.Store.ListSites(r.Context())
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if sites == nil {
		sites = []*store.Site{}
	}
	writeJSON(w, http.StatusOK, sites)
}

type siteInput struct {
	Name               *string                    `json:"name"`
	Origins            []string                   `json:"origins"`
	Mode               *scoring.SiteMode          `json:"mode"`
	Thresholds         *scoring.Thresholds        `json:"thresholds"`
	InteractiveActions []string                   `json:"interactive_actions"`
	StrictIP           *bool                      `json:"strict_ip"`
	AccessibilityURL   *string                    `json:"accessibility_url"`
	Actions            map[string]store.ActionCfg `json:"actions"`
}

func validOrigin(o string) bool {
	if o == "*" {
		return true
	}
	u, err := url.Parse(o)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && (u.Path == "" || u.Path == "/") && u.RawQuery == ""
}

func (in *siteInput) apply(site *store.Site) error {
	if in.Name != nil {
		if strings.TrimSpace(*in.Name) == "" {
			return errors.New("name must not be empty")
		}
		site.Name = strings.TrimSpace(*in.Name)
	}
	if in.Origins != nil {
		for i, o := range in.Origins {
			o = strings.TrimRight(strings.TrimSpace(o), "/")
			if !validOrigin(o) {
				return errors.New("invalid origin " + o + " (use scheme://host[:port])")
			}
			in.Origins[i] = o
		}
		if len(in.Origins) == 0 {
			return errors.New("at least one origin is required")
		}
		site.Origins = in.Origins
	}
	if in.Mode != nil {
		switch *in.Mode {
		case scoring.ModeEnforce, scoring.ModeMonitor, scoring.ModeChallengeOnly:
			site.Mode = *in.Mode
		default:
			return errors.New("mode must be enforce, monitor or challenge_only")
		}
	}
	if in.Thresholds != nil {
		t := *in.Thresholds
		if t.Challenge < 1 || t.Block > 100 || t.Challenge >= t.Block {
			return errors.New("thresholds must satisfy 1 <= t_challenge < t_block <= 100")
		}
		site.Thresholds = t
	}
	if in.InteractiveActions != nil {
		for _, a := range in.InteractiveActions {
			if !validAction(a) {
				return errors.New("invalid action name " + a)
			}
		}
		site.InteractiveActions = in.InteractiveActions
	}
	if in.StrictIP != nil {
		site.StrictIP = *in.StrictIP
	}
	if in.AccessibilityURL != nil {
		if *in.AccessibilityURL != "" {
			u, err := url.Parse(*in.AccessibilityURL)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
				return errors.New("accessibility_url must be an http(s) URL")
			}
		}
		site.AccessibilityURL = *in.AccessibilityURL
	}
	if in.Actions != nil {
		for a, c := range in.Actions {
			if !validAction(a) {
				return errors.New("invalid action name " + a)
			}
			if c.Thresholds != nil && (c.Thresholds.Challenge < 1 || c.Thresholds.Block > 100 || c.Thresholds.Challenge >= c.Thresholds.Block) {
				return errors.New("invalid thresholds for action " + a)
			}
		}
		site.Actions = in.Actions
	}
	return nil
}

func (s *Server) adminCreateSite(w http.ResponseWriter, r *http.Request) {
	var in siteInput
	if err := decodeJSON(r, &in, 16<<10); err != nil || in.Name == nil {
		problem(w, http.StatusBadRequest, "bad-request", "name and origins are required")
		return
	}
	site := &store.Site{ID: "site_" + randToken(9), SiteKey: "dk_pk_" + randToken(18), Mode: scoring.ModeEnforce, Thresholds: scoring.DefaultThresholds, CreatedAt: s.Now()}
	if err := in.apply(site); err != nil || len(site.Origins) == 0 {
		msg := "at least one origin is required"
		if err != nil {
			msg = err.Error()
		}
		problem(w, http.StatusBadRequest, "invalid", msg)
		return
	}
	secret := "dk_sk_" + randToken(32)
	site.SecretHash = pseudo.SecretHash(secret)
	if err := s.Store.CreateSite(r.Context(), site); err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(r, "site.create", site.ID, map[string]any{"name": site.Name, "origins": site.Origins})
	writeJSON(w, http.StatusCreated, map[string]any{"site": site, "secret": secret})
}

func (s *Server) adminGetSite(w http.ResponseWriter, r *http.Request) {
	if site := s.site(w, r); site != nil {
		writeJSON(w, http.StatusOK, site)
	}
}

func (s *Server) adminPatchSite(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	var in siteInput
	if err := decodeJSON(r, &in, 16<<10); err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	before := *site
	if err := in.apply(site); err != nil {
		problem(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if err := s.Store.UpdateSite(r.Context(), site); err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(r, "site.update", site.ID, map[string]any{"before": before, "after": site})
	writeJSON(w, http.StatusOK, site)
}

func (s *Server) adminRotateSecret(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	secret := "dk_sk_" + randToken(32)
	site.SecretHash = pseudo.SecretHash(secret)
	if err := s.Store.UpdateSite(r.Context(), site); err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(r, "site.rotate_secret", site.ID, nil)
	writeJSON(w, http.StatusOK, map[string]string{"secret": secret})
}

// ---------------- events ----------------

type eventView struct {
	*store.Event
	FPShort  string             `json:"fp"`
	Features map[string]any     `json:"features,omitempty"`
	Groups   map[string][]fview `json:"feature_groups,omitempty"`
}

type fview struct {
	Key   string `json:"key"`
	Value any    `json:"value"`
	Desc  string `json:"desc"`
}

func view(e *store.Event, withFeatures bool) eventView {
	v := eventView{Event: e}
	if len(e.FPHash) >= 8 {
		v.FPShort = e.FPHash[:8]
	}
	if withFeatures {
		v.Groups = map[string][]fview{}
		for _, d := range scoring.Registry() {
			var val any
			if d.Kind == scoring.KindCat {
				c, ok := e.Features.Cat[d.Key()]
				if !ok {
					continue
				}
				val = c
			} else {
				n, ok := e.Features.Num[d.Key()]
				if !ok {
					continue
				}
				val = n
			}
			v.Groups[string(d.Group)] = append(v.Groups[string(d.Group)], fview{Key: d.Key(), Value: val, Desc: d.Desc})
		}
	}
	return v
}

func (s *Server) adminListEvents(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	q := r.URL.Query()
	f := store.EventFilter{SiteID: site.ID, Outcome: scoring.Outcome(q.Get("outcome")), Reason: q.Get("reason"), FPHash: q.Get("fp"), Label: q.Get("label")}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	if d, err := time.ParseDuration(q.Get("range")); err == nil {
		f.Since = s.Now().Add(-d)
	}
	if ip := q.Get("ip"); ip != "" {
		// Only today's IP hash exists: IP lookups work for today, by design.
		a, err := netip.ParseAddr(ip)
		if err != nil {
			problem(w, http.StatusBadRequest, "bad-request", "invalid ip")
			return
		}
		f.IP24 = s.Keys.IPHash(a, s.Now())
	}
	evs, err := s.Store.ListEvents(r.Context(), f)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	out := make([]eventView, 0, len(evs))
	for _, e := range evs {
		out = append(out, view(e, false))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) event(w http.ResponseWriter, r *http.Request) (*store.Site, *store.Event) {
	site := s.site(w, r)
	if site == nil {
		return nil, nil
	}
	e, err := s.Store.GetEvent(r.Context(), r.PathValue("event"))
	if err != nil || e.SiteID != site.ID {
		problem(w, http.StatusNotFound, "not-found", "unknown event")
		return nil, nil
	}
	return site, e
}

func (s *Server) adminGetEvent(w http.ResponseWriter, r *http.Request) {
	if _, e := s.event(w, r); e != nil {
		writeJSON(w, http.StatusOK, view(e, true))
	}
}

// adminDeleteEvent supports data subject requests (design section 6.4).
func (s *Server) adminDeleteEvent(w http.ResponseWriter, r *http.Request) {
	site, e := s.event(w, r)
	if e == nil {
		return
	}
	if err := s.Store.DeleteEvent(r.Context(), e.ID); err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(r, "event.delete", site.ID+"/"+e.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) adminLabelEvent(w http.ResponseWriter, r *http.Request) {
	site, e := s.event(w, r)
	if e == nil {
		return
	}
	var in struct {
		Label string `json:"label"`
	}
	if err := decodeJSON(r, &in, 1024); err != nil || (in.Label != "bot" && in.Label != "human" && in.Label != "") {
		problem(w, http.StatusBadRequest, "bad-request", "label must be bot, human or empty")
		return
	}
	if err := s.Store.LabelEvent(r.Context(), e.ID, in.Label, "dashboard"); err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if in.Label != "" {
		s.Models.Label(site.ID, e.Features, in.Label == "bot", model.WeightStrong)
	}
	s.audit(r, "event.label", site.ID+"/"+e.ID, map[string]any{"label": in.Label})
	writeJSON(w, http.StatusOK, map[string]string{"label": in.Label})
}

// ---------------- lists ----------------

func (s *Server) adminListLists(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	l, err := s.Store.ListEntries(r.Context(), site.ID, s.Now())
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if l == nil {
		l = []store.ListEntry{}
	}
	writeJSON(w, http.StatusOK, l)
}

var listKinds = map[string]bool{"ip": true, "cidr": true, "asn": true, "country": true, "fp": true, "ua_regex": true, "crawler": true, "tor": true}

func (s *Server) adminAddList(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	var e store.ListEntry
	if err := decodeJSON(r, &e, 4096); err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	e.SiteID, e.ID = site.ID, 0
	if !listKinds[e.Kind] {
		problem(w, http.StatusBadRequest, "invalid", "kind must be one of ip, cidr, asn, country, fp, ua_regex, crawler, tor")
		return
	}
	if e.Action != scoring.ListAllow && e.Action != scoring.ListDeny && e.Action != scoring.ListAlwaysChallenge {
		problem(w, http.StatusBadRequest, "invalid", "action must be allow, deny or always_challenge")
		return
	}
	if err := validateListValue(e.Kind, e.Value); err != nil {
		problem(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	if err := s.Store.AddListEntry(r.Context(), &e); err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(r, "list.add", site.ID, map[string]any{"entry": e})
	writeJSON(w, http.StatusCreated, e)
}

func validateListValue(kind, v string) error {
	switch kind {
	case "ip":
		_, err := netip.ParseAddr(v)
		return err
	case "cidr":
		_, err := netip.ParsePrefix(v)
		return err
	case "asn":
		_, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(v), "AS"), 10, 32)
		return err
	case "country":
		if len(v) != 2 {
			return errors.New("country must be a two-letter code")
		}
	case "ua_regex":
		_, err := compileRegexp(v)
		return err
	}
	return nil
}

func (s *Server) adminDeleteList(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		problem(w, http.StatusBadRequest, "bad-request", "invalid id")
		return
	}
	if err := s.Store.DeleteListEntry(r.Context(), site.ID, id); err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	s.audit(r, "list.delete", site.ID, map[string]any{"id": id})
	w.WriteHeader(http.StatusNoContent)
}

// ---------------- model ----------------

func (s *Server) adminModel(w http.ResponseWriter, r *http.Request) {
	if site := s.site(w, r); site != nil {
		writeJSON(w, http.StatusOK, s.Models.Status(site.ID))
	}
}

func (s *Server) adminPromote(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	var in struct {
		On bool `json:"on"`
	}
	if err := decodeJSON(r, &in, 256); err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	if !s.Models.Promote(site.ID, in.On) {
		problem(w, http.StatusConflict, "not-ready", "the supervised model needs at least 200 labels with 50 bots and 50 humans")
		return
	}
	s.audit(r, "model.promote", site.ID, map[string]any{"on": in.On})
	writeJSON(w, http.StatusOK, s.Models.Status(site.ID))
}

// ---------------- privacy, audit, ipdata, features ----------------

func (s *Server) adminPrivacy(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"event_retention_days": int(s.Cfg.EventRetention.Hours() / 24),
		"data_map":             dataMap,
		"never_collected":      []string{"geolocation", "media device labels", "battery", "clipboard", "form values", "page URL beyond origin", "cookies (none set by default)"},
		"pseudonymisation": map[string]string{
			"fingerprint": "HMAC per site per month; the same device cannot be linked across sites or months",
			"ip":          "HMAC of the /24 (IPv4) or /48 (IPv6) per day; raw IPs live in memory for at most an hour",
		},
	})
}

var dataMap = []map[string]string{
	{"item": "IP address", "at_rest": "day-keyed HMAC of /24 or /48; ASN; country", "purpose": "abuse velocity, network reputation", "retention": "events 30 d, counters 1 h", "gdpr": "personal data; legitimate interest, Art. 6(1)(f), Recital 49", "dpdp": "personal data processed for the purpose in the site's notice; self-hosting keeps it in-country"},
	{"item": "Browser fingerprint", "at_rest": "per-site per-month HMAC; bucketed features", "purpose": "consistency checks, device velocity", "retention": "30 d", "gdpr": "pseudonymised, purpose-limited", "dpdp": "minimisation by bucketing"},
	{"item": "Behaviour statistics", "at_rest": "aggregates only (no coordinates or keys)", "purpose": "bot/human discrimination", "retention": "30 d", "gdpr": "not identifying alone", "dpdp": "as GDPR"},
	{"item": "Risk, outcome, reasons", "at_rest": "plain", "purpose": "security decision, operator audit", "retention": "30 d; hourly aggregates 13 months", "gdpr": "challenge path and accessibility link keep a human route (Art. 22)", "dpdp": "sites should disclose automated abuse screening"},
	{"item": "Operator labels", "at_rest": "with the event", "purpose": "model training", "retention": "with the event", "gdpr": "", "dpdp": ""},
}

func (s *Server) adminAudit(w http.ResponseWriter, r *http.Request) {
	l, err := s.Store.ListAudit(r.Context(), 200)
	if err != nil {
		problem(w, http.StatusInternalServerError, "internal", err.Error())
		return
	}
	if l == nil {
		l = []store.AuditEntry{}
	}
	writeJSON(w, http.StatusOK, l)
}

func (s *Server) adminIPData(w http.ResponseWriter, r *http.Request) {
	db := s.IP.Get()
	writeJSON(w, http.StatusOK, map[string]any{"loaded": db.Loaded, "counts": db.Counts(), "sources": db.Sources})
}

func (s *Server) adminFeatures(w http.ResponseWriter, r *http.Request) {
	type fd struct {
		Key   string `json:"key"`
		Kind  string `json:"kind"`
		Desc  string `json:"desc"`
		Model bool   `json:"model"`
	}
	var out []fd
	for _, d := range scoring.Registry() {
		out = append(out, fd{d.Key(), d.Kind.String(), d.Desc, d.Model})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDashboard serves the embedded dashboard SPA with a strict CSP.
func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/admin/")
	ctype := map[string]string{"app.js": "text/javascript; charset=utf-8", "app.css": "text/css; charset=utf-8"}[name]
	if ctype == "" {
		name, ctype = "index.html", "text/html; charset=utf-8"
	}
	b, err := assets.ReadFile("assets/admin/" + name)
	if err != nil {
		http.Error(w, "dashboard not built: run make dashboard", http.StatusNotFound)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ctype)
	h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
	h.Set("X-Frame-Options", "DENY")
	w.Write(b)
}
