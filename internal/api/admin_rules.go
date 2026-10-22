package api

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/iamsuriyan/doorkeep/internal/scoring/rules"
	"github.com/iamsuriyan/doorkeep/internal/store"
)

// ruleCache holds each site's compiled effective rule set. Entries expire
// after ruleCacheTTL so edits made on another cluster node take effect.
type ruleCache struct {
	mu   sync.RWMutex
	sets map[string]*rules.Set
	at   map[string]time.Time
}

const ruleCacheTTL = 30 * time.Second

func (s *Server) siteRules(ctx context.Context, siteID string) *rules.Set {
	s.rc.mu.RLock()
	set, at := s.rc.sets[siteID], s.rc.at[siteID]
	s.rc.mu.RUnlock()
	if set != nil && time.Since(at) < ruleCacheTTL {
		return set
	}
	set = nil
	ov, err := s.overrides(ctx, siteID)
	if err == nil && len(ov) > 0 {
		if eff, err := rules.Effective(s.Rules, ov, "site"); err == nil {
			set = eff
		} else {
			s.Log.Error("site rules invalid; using built-ins", "site", siteID, "err", err)
		}
	}
	if set == nil {
		set = s.Rules
	}
	s.rc.mu.Lock()
	s.rc.sets[siteID] = set
	if s.rc.at == nil {
		s.rc.at = map[string]time.Time{}
	}
	s.rc.at[siteID] = time.Now()
	s.rc.mu.Unlock()
	return set
}

func (s *Server) invalidateRules(siteID string) {
	s.rc.mu.Lock()
	delete(s.rc.sets, siteID)
	s.rc.mu.Unlock()
}

func (s *Server) overrides(ctx context.Context, siteID string) (map[string]rules.Override, error) {
	rs, err := s.Store.SiteRules(ctx, siteID)
	if err != nil {
		return nil, err
	}
	out := map[string]rules.Override{}
	for _, r := range rs {
		var o rules.Override
		if json.Unmarshal(r.Spec, &o) == nil {
			out[r.RuleID] = o
		}
	}
	return out, nil
}

type ruleView struct {
	rules.Rule
	Builtin    bool `json:"builtin"`
	Overridden bool `json:"overridden"`
}

func (s *Server) adminListRules(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	ov, err := s.overrides(r.Context(), site.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	builtin := map[string]bool{}
	for _, b := range s.Rules.Rules() {
		builtin[b.ID] = true
	}
	var out []ruleView
	for _, rule := range s.siteRules(r.Context(), site.ID).Rules() {
		_, o := ov[rule.ID]
		out = append(out, ruleView{Rule: rule, Builtin: builtin[rule.ID], Overridden: o})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) adminPutRule(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	id := r.PathValue("rule")
	if !validRuleID(id) {
		problem(w, http.StatusBadRequest, "invalid", "rule id must be UPPER_SNAKE_CASE")
		return
	}
	var o rules.Override
	if err := decodeJSON(r, &o, 16<<10); err != nil {
		problem(w, http.StatusBadRequest, "bad-request", err.Error())
		return
	}
	if o.Mode != "" && o.Mode != rules.ModeEnforce && o.Mode != rules.ModeShadow && o.Mode != rules.ModeOff {
		problem(w, http.StatusBadRequest, "invalid", "mode must be enforce, shadow or off")
		return
	}
	ov, err := s.overrides(r.Context(), site.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	before, had := ov[id]
	ov[id] = o
	if _, err := rules.Effective(s.Rules, ov, "check"); err != nil {
		problem(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	spec, _ := json.Marshal(o)
	if err := s.Store.PutSiteRule(r.Context(), store.SiteRule{SiteID: site.ID, RuleID: id, Spec: spec, UpdatedAt: s.Now()}); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.invalidateRules(site.ID)
	detail := map[string]any{"after": o}
	if had {
		detail["before"] = before
	}
	s.audit(r, "rule.put", site.ID+"/"+id, detail)
	writeJSON(w, http.StatusOK, o)
}

func (s *Server) adminDeleteRule(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	id := r.PathValue("rule")
	if err := s.Store.DeleteSiteRule(r.Context(), site.ID, id); err != nil {
		s.internalError(w, r, err)
		return
	}
	s.invalidateRules(site.ID)
	s.audit(r, "rule.reset", site.ID+"/"+id, nil)
	w.WriteHeader(http.StatusNoContent)
}

var ruleIDRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{1,63}$`)

func validRuleID(id string) bool { return ruleIDRe.MatchString(id) }

// labResult reports what a candidate rule would have done to past events.
type labResult struct {
	Rule        string         `json:"rule"`
	Days        int            `json:"days"`
	Events      int            `json:"events"`
	Fired       int            `json:"fired"`
	Changed     int            `json:"changed"`
	Transitions map[string]int `json:"transitions"` // "allow->challenge": n
	Labelled    struct {
		BotsFired   int `json:"bots_fired"`
		BotsTotal   int `json:"bots_total"`
		HumansFired int `json:"humans_fired"`
		HumansTotal int `json:"humans_total"`
	} `json:"labelled"`
	Samples []string `json:"samples"` // event ids whose outcome would change
}

// adminRuleLab replays a candidate rule over stored events. This works
// because every event keeps its bucketed feature vector. The new risk is
// the stored risk minus the rule's old enforced contribution plus its new
// one; list and model effects are kept as they were.
func (s *Server) adminRuleLab(w http.ResponseWriter, r *http.Request) {
	site := s.site(w, r)
	if site == nil {
		return
	}
	var in struct {
		Rule     string         `json:"rule"`
		Override rules.Override `json:"override"`
		Days     int            `json:"days"`
	}
	if err := decodeJSON(r, &in, 16<<10); err != nil || !validRuleID(in.Rule) {
		problem(w, http.StatusBadRequest, "bad-request", "rule and override are required")
		return
	}
	if in.Days <= 0 || in.Days > 30 {
		in.Days = 7
	}
	ov, err := s.overrides(r.Context(), site.ID)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if in.Override.Mode == "" {
		in.Override.Mode = rules.ModeEnforce
	}
	ov[in.Rule] = in.Override
	cand, err := rules.Effective(s.Rules, ov, "lab")
	if err != nil {
		problem(w, http.StatusBadRequest, "invalid", err.Error())
		return
	}
	res := labResult{Rule: in.Rule, Days: in.Days, Transitions: map[string]int{}, Samples: []string{}}
	err = s.Store.StreamEvents(r.Context(), store.EventFilter{SiteID: site.ID, Since: s.Now().Add(-time.Duration(in.Days) * 24 * time.Hour)}, func(e *store.Event) error {
		res.Events++
		env := rules.Context(e.Features.Env(), e.Action, interactive(site))
		fired, weight, _ := cand.EvalOne(in.Rule, env)
		if in.Override.Mode != rules.ModeEnforce {
			weight = 0
		}
		old := 0
		for _, rc := range e.Reasons {
			if rc.Code == in.Rule {
				old = rc.Weight
			}
		}
		newRisk := e.Risk - old
		if fired {
			res.Fired++
			newRisk += weight
		}
		newRisk = max(0, min(100, newRisk))
		th := site.ThresholdsFor(e.Action)
		was, now := e.WouldBe, th.Band(newRisk)
		if was == "" {
			was = th.Band(e.Risk)
		}
		if now != was {
			res.Changed++
			res.Transitions[string(was)+"->"+string(now)]++
			if len(res.Samples) < 20 {
				res.Samples = append(res.Samples, e.ID)
			}
		}
		switch e.Label {
		case "bot":
			res.Labelled.BotsTotal++
			if fired {
				res.Labelled.BotsFired++
			}
		case "human":
			res.Labelled.HumansTotal++
			if fired {
				res.Labelled.HumansFired++
			}
		}
		return nil
	})
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}
